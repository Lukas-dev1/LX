//! Syscall interception + Linux TLS (FS base) emulation, both driven by one vectored exception handler.
//!
//! - `syscall` sites in guest code are rewritten to `ud2` (`patch_code`); the #UD lands here and is dispatched.
//! - NT resets FS base to 0 on context switches, so a guest `%fs:` access faults (low/kernel address).
//!   We bounce through `fs_tramp`, which reloads FS base in user mode and resumes the faulting instruction.
//!   Every return to the guest goes through the trampoline, because NtContinue also loses FS base.
use crate::fs;
use crate::win::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Ok(value) or Err(positive errno); the guest sees -errno.
pub type R = Result<i64, i64>;
pub const EIO: i64 = 5;
pub const EBADF: i64 = 9;
pub const ENOMEM: i64 = 12;
pub const EACCES: i64 = 13;
pub const EFAULT: i64 = 14;
pub const EBUSY: i64 = 16;
pub const EEXIST: i64 = 17;
pub const ENOTDIR: i64 = 20;
pub const EISDIR: i64 = 21;
pub const EINVAL: i64 = 22;
pub const ENOTTY: i64 = 25;
pub const ESPIPE: i64 = 29;
pub const ERANGE: i64 = 34;
pub const ENAMETOOLONG: i64 = 36;
pub const ENOSYS: i64 = 38;
pub const ENOTEMPTY: i64 = 39;
pub const ELOOP: i64 = 40;
pub const ENOENT: i64 = 2;

// ponytail: one guest thread, so plain globals. Move to TEB TLS slots (gs:[0x1480+8*i]) when clone() lands.
#[unsafe(no_mangle)]
static LX_GUEST_FS: AtomicU64 = AtomicU64::new(0);
#[unsafe(no_mangle)]
static LX_RESUME_RIP: AtomicU64 = AtomicU64::new(0);
static FS_RELOADS: AtomicU64 = AtomicU64::new(0);
static START: Mutex<Option<Instant>> = Mutex::new(None);

/// Guest code ranges and the patched syscall sites inside them (sorted).
struct Code {
    regions: Vec<(u64, u64)>,
    sites: Vec<u64>,
}
static CODE: Mutex<Code> = Mutex::new(Code { regions: Vec::new(), sites: Vec::new() });

// Clobbers nothing the guest can see: skips the 128-byte red zone, touches only rax (restored).
// wrfsbase is emitted as bytes so we don't need the fsgsbase target feature.
std::arch::global_asm!(
    ".globl lx_fs_tramp",
    "lx_fs_tramp:",
    "lea rsp, [rsp - 128]",
    "push rax",
    "mov rax, qword ptr [rip + LX_GUEST_FS]",
    ".byte 0xf3, 0x48, 0x0f, 0xae, 0xd0", // wrfsbase rax
    "pop rax",
    "lea rsp, [rsp + 128]",
    "jmp qword ptr [rip + LX_RESUME_RIP]",
);
unsafe extern "C" {
    fn lx_fs_tramp();
}

const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;

pub fn install() {
    START.lock().unwrap().get_or_insert_with(Instant::now);
    unsafe { AddVectoredExceptionHandler(1, veh) };
}

/// Rewrite every `syscall` in writable guest code at [addr, addr+len) to `ud2` and register the range.
pub fn patch_code(addr: u64, len: usize) -> usize {
    let code = unsafe { std::slice::from_raw_parts_mut(addr as *mut u8, len) };
    let found = find_syscalls(code, addr);
    let raw = code.windows(2).filter(|w| w == b"\x0f\x05").count();
    if raw != found.len() {
        eprintln!("[lx] {addr:#x}: {} of {raw} 0F05 byte pairs are not instructions, left alone", raw - found.len());
    }
    for &a in &found {
        code[(a - addr) as usize + 1] = 0x0b; // syscall (0F 05) -> ud2 (0F 0B)
    }
    let mut c = CODE.lock().unwrap();
    c.regions.push((addr, addr + len as u64));
    c.sites.extend(&found);
    c.sites.sort_unstable();
    c.sites.dedup();
    found.len()
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

fn resume(c: &mut Context, rip: u64) -> i32 {
    LX_RESUME_RIP.store(rip, Relaxed);
    c.rip = lx_fs_tramp as *const () as u64;
    EXCEPTION_CONTINUE_EXECUTION
}

unsafe extern "system" fn veh(ep: *mut ExceptionPointers) -> i32 {
    let (rec, c) = unsafe { (&*(*ep).record, &mut *(*ep).context) };
    let (region, is_site) = {
        let code = CODE.lock().unwrap();
        let r = code.regions.iter().find(|(lo, hi)| (*lo..*hi).contains(&c.rip)).copied();
        (r, code.sites.binary_search(&c.rip).is_ok())
    };
    let Some((_, end)) = region else {
        return EXCEPTION_CONTINUE_SEARCH; // not guest code: our own bug, let it crash normally
    };
    match rec.code {
        STATUS_ILLEGAL_INSTRUCTION if is_site => {
            let ret = dispatch(c);
            let next = c.rip + 2;
            (c.rax, c.rcx, c.r11) = (ret as u64, next, c.eflags as u64); // kernel ABI: rcx=rip, r11=rflags
            resume(c, next)
        }
        STATUS_ACCESS_VIOLATION if LX_GUEST_FS.load(Relaxed) != 0 && lost_fs_base(c, rec.info[1] as u64, end) => {
            FS_RELOADS.fetch_add(1, Relaxed);
            resume(c, c.rip)
        }
        _ => guest_crash(rec, c),
    }
}

/// Did this fault come from a `%fs:` access executed with NT's zeroed FS base (rather than a real bug)?
/// Exact: recompute the operand address with FS base 0 and compare with the faulting address.
fn lost_fs_base(c: &Context, fault_addr: u64, code_end: u64) -> bool {
    use iced_x86::{Decoder, DecoderOptions, Register as Reg};
    let len = (code_end - c.rip).min(15) as usize;
    let bytes = unsafe { std::slice::from_raw_parts(c.rip as *const u8, len) };
    let ins = Decoder::with_ip(64, bytes, c.rip, DecoderOptions::NONE).decode();
    if ins.memory_segment() != Reg::FS {
        return false;
    }
    let reg = |r: Reg, _, _| {
        let v = match r.full_register() {
            Reg::RAX => c.rax, Reg::RCX => c.rcx, Reg::RDX => c.rdx, Reg::RBX => c.rbx,
            Reg::RSP => c.rsp, Reg::RBP => c.rbp, Reg::RSI => c.rsi, Reg::RDI => c.rdi,
            Reg::R8 => c.r8, Reg::R9 => c.r9, Reg::R10 => c.r10, Reg::R11 => c.r11,
            Reg::R12 => c.r12, Reg::R13 => c.r13, Reg::R14 => c.r14, Reg::R15 => c.r15,
            Reg::FS => 0,
            _ => return None,
        };
        Some(if r.size() == 4 { v as u32 as u64 } else { v })
    };
    (0..ins.op_count()).any(|op| ins.virtual_address(op, 0, reg) == Some(fault_addr))
}

fn guest_crash(rec: &ExceptionRecord, c: &Context) -> ! {
    eprintln!("[lx] guest fault {:#x} at rip {:#x} (addr {:#x})", rec.code, c.rip, rec.info[1]);
    unsafe { ExitProcess(139) } // 128 + SIGSEGV, like a shell would report
}

/// The dispatch table. Linux ABI: nr in rax, args rdi rsi rdx r10 r8 r9, result (or -errno) in rax.
fn dispatch(c: &mut Context) -> i64 {
    use fs::{AT_FDCWD as CWD, AT_SYMLINK_NOFOLLOW};
    let a = [c.rdi, c.rsi, c.rdx, c.r10, c.r8, c.r9];
    let r = match c.rax {
        0 => fs::read(a[0], a[1], a[2]),
        1 => fs::write(a[0], a[1], a[2]),
        2 => fs::openat(CWD, a[0], a[1]),
        3 => fs::close(a[0]),
        4 => fs::fstatat(CWD, a[0], a[1], 0),
        5 => fs::fstat(a[0], a[1]),
        6 => fs::fstatat(CWD, a[0], a[1], AT_SYMLINK_NOFOLLOW),
        8 => fs::lseek(a[0], a[1] as i64, a[2]),
        9 => mmap(a[0], a[1], a[2], a[3], a[4], a[5]),
        10 => mprotect(a[0], a[1], a[2]),
        11 => munmap(a[0], a[1]),
        12 => Ok(0),                   // brk: always "fails"; musl and glibc fall back to mmap
        13 | 14 | 131 => Ok(0),        // rt_sigaction, rt_sigprocmask, sigaltstack. ponytail: no signals yet
        16 => Err(ENOTTY),             // ioctl: no terminals yet
        20 => fs::writev(a[0], a[1], a[2]),
        21 => fs::faccessat(CWD, a[0]),
        28 => Ok(0),                   // madvise: advice only
        32 => fs::dup(a[0], 0),
        33 => fs::dup3(a[0], a[1]),
        35 => nanosleep(a[0]),
        39 | 186 => Ok(1),             // getpid, gettid: pid 1 in the container
        60 | 231 => exit(a[0]),        // exit, exit_group (single thread)
        63 => uname(a[0]),
        72 => fs::fcntl(a[0], a[1], a[2]),
        79 => fs::getcwd(a[0], a[1]),
        80 => fs::chdir(a[0]),
        81 => fs::fchdir(a[0]),
        82 => fs::renameat(CWD, a[0], CWD, a[1]),
        83 => fs::mkdirat(CWD, a[0]),
        84 => fs::unlinkat(CWD, a[0], 0x200),
        87 => fs::unlinkat(CWD, a[0], 0),
        88 => fs::symlinkat(a[0], CWD, a[1]),
        89 => fs::readlinkat(CWD, a[0], a[1], a[2]),
        95 => Ok(0o022),               // umask
        96 => gettimeofday(a[0]),
        102 | 104 | 107 | 108 => Ok(0), // getuid, getgid, geteuid, getegid: root in the container
        110 => Ok(0),                  // getppid
        158 if a[0] == 0x1002 => { LX_GUEST_FS.store(a[1], Relaxed); Ok(0) } // arch_prctl(ARCH_SET_FS)
        217 => fs::getdents64(a[0], a[1], a[2]),
        218 => Ok(1),                  // set_tid_address
        228 => clock_gettime(a[0], a[1]),
        257 => fs::openat(a[0], a[1], a[2]),
        258 => fs::mkdirat(a[0], a[1]),
        262 => fs::fstatat(a[0], a[1], a[2], a[3]),
        263 => fs::unlinkat(a[0], a[1], a[2]),
        264 | 316 => fs::renameat(a[0], a[1], a[2], a[3]),
        266 => fs::symlinkat(a[0], a[1], a[2]),
        267 => fs::readlinkat(a[0], a[1], a[2], a[3]),
        269 | 439 => fs::faccessat(a[0], a[1]),
        273 => Ok(0),                  // set_robust_list
        292 => fs::dup3(a[0], a[1]),
        318 => getrandom(a[0], a[1]),
        334 => Err(ENOSYS),            // rseq: optional, glibc copes
        nr => {
            eprintln!("[lx] unimplemented syscall {nr} ({:#x}, {:#x}, {:#x})", a[0], a[1], a[2]);
            Err(ENOSYS)
        }
    };
    r.unwrap_or_else(|e| -e)
}

// ---- guest memory helpers. The guest shares our address space; these trust its pointers. ----

/// ponytail: a bad guest pointer crashes lx instead of returning EFAULT; add a guarded copy when it matters.
pub unsafe fn guest_mut<'a>(addr: u64, len: usize) -> &'a mut [u8] {
    unsafe { std::slice::from_raw_parts_mut(addr as *mut u8, len) }
}

pub fn cstr(addr: u64) -> Result<String, i64> {
    if addr == 0 {
        return Err(EFAULT);
    }
    let p = addr as *const u8;
    let len = (0..4096).find(|&i| unsafe { *p.add(i) } == 0).ok_or(ENAMETOOLONG)?;
    Ok(String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(p, len) }).into_owned())
}

// Guest buffers go straight to the NT kernel, which probes them: a bad pointer is an error, not a crash.
pub fn write_handle(h: isize, buf: u64, len: u64) -> R {
    let mut done = 0u32;
    let len = len.min(u32::MAX as u64) as u32;
    if unsafe { WriteFile(h, buf as *const u8, len, &mut done, std::ptr::null_mut()) } == 0 { Err(EIO) } else { Ok(done as i64) }
}

pub fn read_handle(h: isize, buf: u64, len: u64) -> R {
    let mut done = 0u32;
    let len = len.min(u32::MAX as u64) as u32;
    if unsafe { ReadFile(h, buf as *mut u8, len, &mut done, std::ptr::null_mut()) } != 0 {
        return Ok(done as i64);
    }
    if unsafe { GetLastError() } == 109 { Ok(0) } else { Err(EIO) } // ERROR_BROKEN_PIPE is EOF
}

// ---- memory ----

const PAGE: u64 = 0x1000;

fn page_prot(prot: u64) -> u32 {
    match (prot & 4 != 0, prot & 2 != 0, prot & 1 != 0) {
        (true, true, _) => 0x40,      // PAGE_EXECUTE_READWRITE
        (true, false, _) => 0x20,     // PAGE_EXECUTE_READ
        (false, true, _) => 0x04,     // PAGE_READWRITE
        (false, false, true) => 0x02, // PAGE_READONLY
        _ => 0x01,                    // PAGE_NOACCESS
    }
}

/// VirtualProtect refuses to span allocations, so walk the range region by region (skipping reserved holes).
fn protect(addr: u64, len: u64, prot: u32) -> bool {
    let (mut p, end) = (addr, addr + len);
    while p < end {
        let mut mbi = MemoryBasicInformation::default();
        if unsafe { VirtualQuery(p as *const _, &mut mbi, size_of::<MemoryBasicInformation>()) } == 0 {
            return false;
        }
        let next = (mbi.base as u64 + mbi.region_size as u64).min(end);
        let mut old = 0;
        if mbi.state == MEM_COMMIT && unsafe { VirtualProtect(p as *mut _, (next - p) as usize, prot, &mut old) } == 0 {
            return false;
        }
        p = next;
    }
    true
}

fn mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> R {
    const MAP_FIXED: u64 = 0x10;
    const MAP_ANONYMOUS: u64 = 0x20;
    if len == 0 || addr % PAGE != 0 || off % PAGE != 0 {
        return Err(EINVAL);
    }
    let len = len.next_multiple_of(PAGE);
    let p = if flags & MAP_FIXED != 0 {
        // Inside one of our reservations (the usual case: ld.so carving up a library span) just commit;
        // otherwise try a fresh reservation at that address.
        // ponytail: a fixed range spanning two reservations fails with ENOMEM.
        let mut p = unsafe { VirtualAlloc(addr as *mut _, len as usize, MEM_COMMIT, PAGE_READWRITE) } as u64;
        if p == 0 {
            p = unsafe { VirtualAlloc(addr as *mut _, len as usize, MEM_COMMIT_RESERVE, PAGE_READWRITE) } as u64;
        }
        if p != addr || !protect(addr, len, PAGE_READWRITE as u32) {
            return Err(ENOMEM);
        }
        unsafe { guest_mut(addr, len as usize) }.fill(0);
        p
    } else {
        // ponytail: address hints ignored; every mapping gets its own 64K-aligned reservation.
        let p = unsafe { VirtualAlloc(std::ptr::null_mut(), len as usize, MEM_COMMIT_RESERVE, PAGE_READWRITE) } as u64;
        if p == 0 { return Err(ENOMEM) }
        p
    };
    if flags & MAP_ANONYMOUS == 0 {
        // ponytail: file mappings are private copies; MAP_SHARED writes never reach the file.
        fs::read_at(fd, unsafe { guest_mut(p, len as usize) }, off)?;
    }
    if prot & 4 != 0 {
        patch_code(p, len as usize);
    }
    protect(p, len, page_prot(prot));
    Ok(p as i64)
}

fn mprotect(addr: u64, len: u64, prot: u64) -> R {
    let len = len.next_multiple_of(PAGE);
    if prot & 4 != 0 {
        // Newly executable memory (JITs, ld.so): scan before it can run. Already-patched code rescans clean.
        protect(addr, len, PAGE_READWRITE as u32);
        patch_code(addr, len as usize);
    }
    if protect(addr, len, page_prot(prot)) { Ok(0) } else { Err(ENOMEM) }
}

fn munmap(addr: u64, len: u64) -> R {
    // ponytail: decommit only; the address space stays reserved (and leaks) until exit.
    unsafe { VirtualFree(addr as *mut _, len.next_multiple_of(PAGE) as usize, MEM_DECOMMIT) };
    Ok(0)
}

// ---- process, time, misc ----

fn exit(code: u64) -> R {
    eprintln!("[lx] exit {}, {} fs-base reloads", code as u8, FS_RELOADS.load(Relaxed));
    unsafe { ExitProcess(code as u32 & 0xff) }
}

fn uname(buf: u64) -> R {
    let out = unsafe { guest_mut(buf, 65 * 6) };
    out.fill(0);
    for (i, s) in ["Linux", "lx", "6.6.0-lx", "#1 SMP lx", "x86_64", "(none)"].iter().enumerate() {
        out[i * 65..i * 65 + s.len()].copy_from_slice(s.as_bytes());
    }
    Ok(0)
}

fn now(clock: u64) -> (u64, u64) {
    let d = if clock == 0 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default() // CLOCK_REALTIME
    } else {
        START.lock().unwrap().unwrap().elapsed() // every other clock: monotonic since start
    };
    (d.as_secs(), d.subsec_nanos() as u64)
}

fn clock_gettime(clock: u64, ts: u64) -> R {
    let (s, ns) = now(clock);
    unsafe { *(ts as *mut [u64; 2]) = [s, ns] };
    Ok(0)
}

fn gettimeofday(tv: u64) -> R {
    if tv != 0 {
        let (s, ns) = now(0);
        unsafe { *(tv as *mut [u64; 2]) = [s, ns / 1000] };
    }
    Ok(0)
}

fn nanosleep(ts: u64) -> R {
    let [s, ns] = unsafe { *(ts as *const [u64; 2]) };
    std::thread::sleep(std::time::Duration::new(s, ns as u32));
    Ok(0)
}

fn getrandom(buf: u64, len: u64) -> R {
    let len = len.min(u32::MAX as u64);
    unsafe { BCryptGenRandom(std::ptr::null_mut(), buf as *mut u8, len as u32, 2) };
    Ok(len as i64)
}
