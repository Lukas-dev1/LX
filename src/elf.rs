//! ELF64 loader: maps PT_LOAD segments, patches `syscall`, builds the initial Linux stack.
//! The image is untrusted input: every offset/size read from it is bounds-checked.
use crate::win::*;
use std::ptr;

const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const PAGE: u64 = 0x1000;

pub struct Image {
    pub entry: u64,
    pub phdr: u64,
    pub phnum: u64,
    /// Load address of the lowest segment (AT_BASE when this is the interpreter).
    pub base: u64,
    /// PT_INTERP: the dynamic linker to load alongside, e.g. /lib/ld-musl-x86_64.so.1.
    pub interp: Option<String>,
    pub syscall_sites: usize,
}

fn rd<const N: usize>(f: &[u8], off: u64) -> Result<[u8; N], String> {
    let off = usize::try_from(off).map_err(|_| "offset overflow")?;
    f.get(off..off.checked_add(N).ok_or("offset overflow")?)
        .map(|s| s.try_into().unwrap())
        .ok_or_else(|| format!("truncated ELF at {off:#x}"))
}
fn u16_(f: &[u8], o: u64) -> Result<u64, String> { Ok(u16::from_le_bytes(rd(f, o)?) as u64) }
fn u32_(f: &[u8], o: u64) -> Result<u32, String> { Ok(u32::from_le_bytes(rd(f, o)?)) }
fn u64_(f: &[u8], o: u64) -> Result<u64, String> { Ok(u64::from_le_bytes(rd(f, o)?)) }

struct Seg { flags: u32, off: u64, vaddr: u64, filesz: u64, memsz: u64 }

pub fn load(f: &[u8]) -> Result<Image, String> {
    if f.get(..4) != Some(b"\x7fELF") || f.get(4) != Some(&2) || f.get(5) != Some(&1) {
        return Err("not a 64-bit little-endian ELF".into());
    }
    let (ty, machine) = (u16_(f, 0x10)?, u16_(f, 0x12)?);
    if machine != 62 { return Err(format!("e_machine {machine} is not x86-64")); }
    if ty != 2 && ty != 3 { return Err(format!("e_type {ty} is not EXEC/DYN")); }
    let (entry, phoff, phent, phnum) = (u64_(f, 0x18)?, u64_(f, 0x20)?, u16_(f, 0x36)?, u16_(f, 0x38)?);
    if phent != 56 { return Err("bad e_phentsize".into()); }

    let mut segs = Vec::new();
    let mut phdr_vaddr = None;
    let mut interp = None;
    for i in 0..phnum {
        let p = phoff + i * 56;
        match u32_(f, p)? {
            PT_INTERP => {
                let (off, len) = (u64_(f, p + 8)? as usize, u64_(f, p + 0x20)? as usize);
                let s = f.get(off..off.saturating_add(len)).ok_or("bad PT_INTERP")?;
                interp = Some(String::from_utf8_lossy(s).trim_end_matches('\0').to_string());
            }
            PT_PHDR => phdr_vaddr = Some(u64_(f, p + 0x10)?),
            PT_LOAD => {
                let s = Seg { flags: u32_(f, p + 4)?, off: u64_(f, p + 8)?, vaddr: u64_(f, p + 0x10)?,
                              filesz: u64_(f, p + 0x20)?, memsz: u64_(f, p + 0x28)? };
                let file_end = s.off.checked_add(s.filesz).ok_or("segment overflow")?;
                if s.filesz > s.memsz || file_end > f.len() as u64 || s.vaddr.checked_add(s.memsz).is_none() {
                    return Err(format!("malformed PT_LOAD at vaddr {:#x}", s.vaddr));
                }
                segs.push(s);
            }
            _ => {}
        }
    }
    if segs.is_empty() { return Err("no PT_LOAD segments".into()); }

    // One reservation for the whole span. NT reservations are 64K-aligned.
    let lo = segs.iter().map(|s| s.vaddr).min().unwrap() & !0xffff;
    let hi = segs.iter().map(|s| s.vaddr + s.memsz).max().unwrap().next_multiple_of(PAGE);
    let want = (ty == 2).then_some(lo); // ET_EXEC at its link address; ET_DYN (PIE, ld.so) anywhere
    let base = crate::syscall::alloc(want, hi - lo)
        .ok_or_else(|| format!("cannot map image at {lo:#x}..{hi:#x} (address in use?)"))?;
    let bias = base - lo;

    let mut sites = 0;
    for s in &segs {
        let dst = (s.vaddr + bias) as *mut u8;
        unsafe { ptr::copy_nonoverlapping(f.as_ptr().add(s.off as usize), dst, s.filesz as usize) };
        if s.flags & 1 != 0 {
            sites += crate::syscall::patch_code(s.vaddr + bias, s.filesz as usize);
        }
    }
    for s in &segs {
        let prot = match (s.flags & 1 != 0, s.flags & 2 != 0) {
            (true, true) => 0x40,  // PAGE_EXECUTE_READWRITE
            (true, false) => 0x20, // PAGE_EXECUTE_READ
            (false, true) => 0x04, // PAGE_READWRITE
            (false, false) => 0x02, // PAGE_READONLY
        };
        // ponytail: segments sharing a page get the later segment's protection; union them if a binary needs it.
        let start = (s.vaddr + bias) & !(PAGE - 1);
        let end = (s.vaddr + bias + s.memsz).next_multiple_of(PAGE);
        let mut old = 0;
        if unsafe { VirtualProtect(start as *mut _, (end - start) as usize, prot, &mut old) } == 0 {
            return Err(format!("VirtualProtect {start:#x} failed"));
        }
    }

    // AT_PHDR: PT_PHDR if present, else the PT_LOAD that covers e_phoff.
    let phdr = phdr_vaddr
        .or_else(|| segs.iter().find(|s| phoff >= s.off && phoff < s.off + s.filesz).map(|s| s.vaddr + phoff - s.off))
        .ok_or("program headers not mapped")?;
    Ok(Image { entry: entry + bias, phdr: phdr + bias, phnum, base, interp, syscall_sites: sites })
}

/// Initial process stack per the SysV x86-64 ABI: argc, argv[], 0, envp[], 0, auxv[], AT_NULL.
/// Returns (initial rsp, stack low, stack high).
pub fn build_stack(img: &Image, interp_base: u64, argv: &[&str], envp: &[&str]) -> Result<(u64, u64, u64), String> {
    const SIZE: usize = 8 << 20;
    let base = crate::syscall::alloc_stack(SIZE as u64).ok_or("stack allocation failed")?;
    let mut sp = base + SIZE as u64;
    let mut push = |bytes: &[u8]| -> u64 {
        sp -= bytes.len() as u64;
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), sp as *mut u8, bytes.len()) };
        sp
    };
    let cstr = |s: &str| [s.as_bytes(), b"\0"].concat();

    let mut random = [0u8; 16];
    unsafe { BCryptGenRandom(ptr::null_mut(), random.as_mut_ptr(), 16, 2) }; // SYSTEM_PREFERRED_RNG
    let at_random = push(&random);
    let platform = push(b"x86_64\0");
    let execfn = push(&cstr(argv[0]));
    let argv_p: Vec<u64> = argv.iter().map(|a| push(&cstr(a))).collect();
    let envp_p: Vec<u64> = envp.iter().map(|e| push(&cstr(e))).collect();

    let mut w = vec![argv.len() as u64];
    w.extend(&argv_p);
    w.push(0);
    w.extend(&envp_p);
    w.push(0);
    #[rustfmt::skip]
    w.extend([
        3, img.phdr, 4, 56, 5, img.phnum, 6, PAGE,       // AT_PHDR, AT_PHENT, AT_PHNUM, AT_PAGESZ
        7, interp_base, 8, 0, 9, img.entry,              // AT_BASE, AT_FLAGS, AT_ENTRY
        11, 0, 12, 0, 13, 0, 14, 0,                      // AT_UID, AT_EUID, AT_GID, AT_EGID
        15, platform, 16, 0, 17, 100, 23, 0,             // AT_PLATFORM, AT_HWCAP, AT_CLKTCK, AT_SECURE
        25, at_random, 31, execfn, 0, 0,                 // AT_RANDOM, AT_EXECFN, AT_NULL
    ]);
    let rsp = (sp - 8 * w.len() as u64) & !15; // rsp must be 16-aligned at _start
    unsafe { ptr::copy_nonoverlapping(w.as_ptr(), rsp as *mut u64, w.len()) };
    Ok((rsp, base, base + SIZE as u64))
}
