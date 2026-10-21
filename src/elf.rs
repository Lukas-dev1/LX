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
    /// Guest address range, used to tell guest faults from our own.
    pub lo: u64,
    pub hi: u64,
    /// Addresses of `syscall` instructions rewritten to `ud2` (sorted).
    pub syscall_sites: Vec<u64>,
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
    for i in 0..phnum {
        let p = phoff + i * 56;
        match u32_(f, p)? {
            PT_INTERP => return Err("dynamically linked (PT_INTERP); only static binaries for now".into()),
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
    let want = if ty == 2 { lo as *mut _ } else { ptr::null_mut() }; // ET_DYN (static-pie) goes anywhere
    let base = unsafe { VirtualAlloc(want, (hi - lo) as usize, MEM_COMMIT_RESERVE, PAGE_READWRITE) } as u64;
    if base == 0 || (ty == 2 && base != lo) {
        return Err(format!("cannot map image at {lo:#x}..{hi:#x} (address in use?)"));
    }
    let bias = base - lo;

    let mut sites = Vec::new();
    for s in &segs {
        let dst = (s.vaddr + bias) as *mut u8;
        unsafe { ptr::copy_nonoverlapping(f.as_ptr().add(s.off as usize), dst, s.filesz as usize) };
        if s.flags & 1 != 0 {
            let ip = s.vaddr + bias;
            let code = &f[s.off as usize..(s.off + s.filesz) as usize];
            let found = find_syscalls(code, ip);
            let raw = code.windows(2).filter(|w| w == b"\x0f\x05").count();
            if raw != found.len() {
                eprintln!("[lx] {:#x}: {} of {raw} 0F05 byte pairs are not instructions, left alone", ip, raw - found.len());
            }
            for &a in &found {
                unsafe { *((a + 1) as *mut u8) = 0x0b }; // syscall (0F 05) -> ud2 (0F 0B)
            }
            sites.extend(found);
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
    sites.sort_unstable();
    Ok(Image { entry: entry + bias, phdr: phdr + bias, phnum, lo: base, hi: hi + bias, syscall_sites: sites })
}

/// Addresses of real `syscall` instructions, by linear-sweep decoding.
/// ponytail: linear sweep can desync on data embedded in .text (rare in compiler output, which is why the
/// raw-byte count above is logged). Upgrade path: decode lazily along control flow (DESIGN.md §3).
fn find_syscalls(code: &[u8], ip: u64) -> Vec<u64> {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic};
    Decoder::with_ip(64, code, ip, DecoderOptions::NONE)
        .into_iter()
        .filter(|i| i.mnemonic() == Mnemonic::Syscall)
        .map(|i| i.ip())
        .collect()
}

#[test]
fn syscall_inside_immediate_is_not_patched() {
    // imul eax,eax,0xfd050f80 (contains 0F 05) ; syscall ; ret
    let code = [0x69, 0xc0, 0x80, 0x0f, 0x05, 0xfd, 0x0f, 0x05, 0xc3];
    assert_eq!(find_syscalls(&code, 0x1000), vec![0x1006]);
}

/// Initial process stack per the SysV x86-64 ABI: argc, argv[], 0, envp[], 0, auxv[], AT_NULL.
pub fn build_stack(img: &Image, argv: &[&str], envp: &[&str]) -> Result<u64, String> {
    const SIZE: usize = 8 << 20;
    let base = unsafe { VirtualAlloc(ptr::null_mut(), SIZE, MEM_COMMIT_RESERVE, PAGE_READWRITE) } as u64;
    if base == 0 { return Err("stack allocation failed".into()); }
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
        7, 0, 8, 0, 9, img.entry,                        // AT_BASE, AT_FLAGS, AT_ENTRY
        11, 0, 12, 0, 13, 0, 14, 0,                      // AT_UID, AT_EUID, AT_GID, AT_EGID
        15, platform, 16, 0, 17, 100, 23, 0,             // AT_PLATFORM, AT_HWCAP, AT_CLKTCK, AT_SECURE
        25, at_random, 31, execfn, 0, 0,                 // AT_RANDOM, AT_EXECFN, AT_NULL
    ]);
    let rsp = (sp - 8 * w.len() as u64) & !15; // rsp must be 16-aligned at _start
    unsafe { ptr::copy_nonoverlapping(w.as_ptr(), rsp as *mut u64, w.len()) };
    Ok(rsp)
}
