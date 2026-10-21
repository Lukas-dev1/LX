//! Syscall interception + Linux TLS (FS base) emulation, both driven by one vectored exception handler.
//!
//! - `syscall` sites in guest code are rewritten to `ud2` (`patch_code`); the #UD lands here and is dispatched.
//! - NT resets FS base to 0 on context switches, so a guest `%fs:` access faults (low/kernel address).
//!   We bounce through `fs_tramp`, which reloads FS base in user mode and resumes the faulting instruction.
//!   Every return to the guest goes through the trampoline, because NtContinue also loses FS base.
use crate::{fs, net, proc, signal};
use crate::win::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Ok(value) or Err(positive errno); the guest sees -errno.
pub type R = Result<i64, i64>;
pub const ESRCH: i64 = 3;
pub const EINTR: i64 = 4;
pub const ENXIO: i64 = 6;
pub const EIO: i64 = 5;
pub const E2BIG: i64 = 7;
pub const ENOEXEC: i64 = 8;
pub const ECHILD: i64 = 10;
pub const EAGAIN: i64 = 11;
pub const EPIPE: i64 = 32;
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
pub const ENOTSOCK: i64 = 88;
pub const ENOPROTOOPT: i64 = 92;
pub const EAFNOSUPPORT: i64 = 97;

// ponytail: one guest thread, so plain globals. Move to TEB TLS slots (gs:[0x1480+8*i]) when clone() lands.
#[unsafe(no_mangle)]
static LX_GUEST_FS: AtomicU64 = AtomicU64::new(0);
#[unsafe(no_mangle)]
static LX_RESUME_RIP: AtomicU64 = AtomicU64::new(0);
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
// Enter or resume the guest with a full register set: [rax rcx rdx rbx rsp rbp rsi rdi r8..r15 rip rflags].
// Flags are restored first (on our stack), then plain movs (which leave flags alone), and the jump goes
// through lx_fs_tramp so FS base is set on the way in.
std::arch::global_asm!(
    ".globl lx_resume",
    "lx_resume:",
    "push qword ptr [rcx + 17*8]",
    "popfq",
    "mov rax, qword ptr [rcx + 16*8]",
    "mov qword ptr [rip + LX_RESUME_RIP], rax",
    "mov rax, qword ptr [rcx + 0*8]",
    "mov rdx, qword ptr [rcx + 2*8]",
    "mov rbx, qword ptr [rcx + 3*8]",
    "mov rsp, qword ptr [rcx + 4*8]",
    "mov rbp, qword ptr [rcx + 5*8]",
    "mov rsi, qword ptr [rcx + 6*8]",
    "mov rdi, qword ptr [rcx + 7*8]",
    "mov r8, qword ptr [rcx + 8*8]",
    "mov r9, qword ptr [rcx + 9*8]",
    "mov r10, qword ptr [rcx + 10*8]",
    "mov r11, qword ptr [rcx + 11*8]",
    "mov r12, qword ptr [rcx + 12*8]",
    "mov r13, qword ptr [rcx + 13*8]",
    "mov r14, qword ptr [rcx + 14*8]",
    "mov r15, qword ptr [rcx + 15*8]",
    "mov rcx, qword ptr [rcx + 1*8]",
    "jmp lx_fs_tramp",
);
unsafe extern "C" {
    fn lx_fs_tramp();
    fn lx_resume(regs: *const [u64; 18]) -> !;
}

/// Guest stack bounds, published in the TEB because our handler code runs on the guest stack
/// (big frames, e.g. __chkstk inside CreateProcess, probe against them). Forked children reuse them.
static STACK: Mutex<(u64, u64)> = Mutex::new((0, 0));

/// Jump into guest code. Never returns: the guest ends the process with exit_group.
pub fn enter(regs: [u64; 18], stack_lo: u64, stack_hi: u64) -> ! {
    *STACK.lock().unwrap() = (stack_lo, stack_hi);
    let regs = Box::leak(Box::new(regs));
    // Lowest committed byte of the stack: where NT's guard-page growth continues from.
    let mut limit = stack_hi;
    while limit > stack_lo {
        let mut m = MemoryBasicInformation::default();
        unsafe { VirtualQuery((limit - 1) as *const _, &mut m, size_of::<MemoryBasicInformation>()) };
        if m.state != MEM_COMMIT || m.protect & PAGE_GUARD != 0 {
            break;
        }
        limit = m.base as u64;
    }
    unsafe {
        std::arch::asm!(
            "mov qword ptr gs:[0x08], {hi}",   // NT_TIB.StackBase
            "mov qword ptr gs:[0x10], {lim}",  // NT_TIB.StackLimit
            "mov qword ptr gs:[0x1478], {lo}", // TEB.DeallocationStack: lets NT grow the stack on demand
            hi = in(reg) stack_hi, lim = in(reg) limit, lo = in(reg) stack_lo);
        lx_resume(regs)
    }
}

// ---- guest address space registry (what fork has to recreate) ----

/// Every guest allocation (base, size).
static ALLOCS: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());
/// Non-fixed guest memory comes from a window far from where NT puts host heaps, stacks and DLLs, so
/// a forked lx can re-reserve the same addresses. ponytail: bump pointer, freed space is never reused.
const WINDOW: (u64, u64) = (0x2000_0000_0000, 0x6000_0000_0000);
static NEXT: AtomicU64 = AtomicU64::new(WINDOW.0);

/// The guest stack, grown on demand like a Win32 thread stack: reserve `len`, commit the top
/// 256K, and put a guard page under it. With the TEB bounds set (`enter`), NT itself commits further
/// pages as the stack grows, so a process doesn't pay for 8 MB it never touches.
pub fn alloc_stack(len: u64) -> Option<u64> {
    const COMMIT: u64 = 256 << 10;
    let len = len.next_multiple_of(0x10000);
    let base = loop {
        let a = NEXT.fetch_add(len, Relaxed);
        if a + len > WINDOW.1 {
            return None;
        }
        if unsafe { VirtualAlloc(a as *mut _, len as usize, MEM_RESERVE, PAGE_READWRITE) } as u64 == a {
            break a;
        }
    };
    let top = base + len - COMMIT;
    unsafe {
        VirtualAlloc(top as *mut _, COMMIT as usize, MEM_COMMIT, PAGE_READWRITE);
        VirtualAlloc((top - PAGE) as *mut _, PAGE as usize, MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD);
    }
    ALLOCS.lock().unwrap().push((base, len));
    Some(base)
}

/// Reserve+commit RW guest memory, at `fixed` or anywhere in the guest window.
pub fn alloc(fixed: Option<u64>, len: u64) -> Option<u64> {
    let len = len.next_multiple_of(PAGE);
    let at = |a: u64| unsafe { VirtualAlloc(a as *mut _, len as usize, MEM_COMMIT_RESERVE, PAGE_READWRITE) } as u64;
    let p = match fixed {
        Some(a) => Some(a).filter(|&a| at(a) == a)?,
        None => loop {
            let a = NEXT.fetch_add(len.next_multiple_of(0x10000), Relaxed);
            if a + len > WINDOW.1 {
                return None;
            }
            if at(a) == a {
                break a;
            }
        },
    };
    ALLOCS.lock().unwrap().push((p, len));
    Some(p)
}

/// After exec: this process only waits for its successor, so give back the old program's memory.
/// The guest stack stays: our own code is running on it.
pub fn release_guest_memory() {
    let (lo, _) = *STACK.lock().unwrap();
    let mut allocs = ALLOCS.lock().unwrap();
    allocs.retain(|&(base, len)| {
        if (base..base + len).contains(&lo) {
            return true;
        }
        unsafe { VirtualFree(base as *mut _, 0, MEM_RELEASE) };
        false
    });
    CODE.lock().unwrap().regions.clear(); // nothing of the old program runs any more
}

/// Serialize everything a forked child needs to rebuild the guest's address space and runtime state.
/// Committed sub-ranges carry their protection; the child copies their contents from us.
pub fn snapshot() -> Vec<String> {
    let mut v: Vec<u64> = Vec::new();
    let allocs = ALLOCS.lock().unwrap().clone();
    v.push(allocs.len() as u64);
    let mut committed = Vec::new();
    for &(base, len) in &allocs {
        v.extend([base, len]);
        let mut p = base;
        while p < base + len {
            let mut m = MemoryBasicInformation::default();
            if unsafe { VirtualQuery(p as *const _, &mut m, size_of::<MemoryBasicInformation>()) } == 0 {
                break;
            }
            let end = (m.base as u64 + m.region_size as u64).min(base + len);
            if m.state == MEM_COMMIT {
                committed.extend([p, end - p, m.protect as u64]);
            }
            p = end;
        }
    }
    v.push(committed.len() as u64 / 3);
    v.extend(committed);
    let code = CODE.lock().unwrap();
    v.push(code.regions.len() as u64);
    v.extend(code.regions.iter().flat_map(|&(a, b)| [a, b]));
    v.push(code.sites.len() as u64);
    v.extend(&code.sites);
    let stack = *STACK.lock().unwrap();
    v.extend([NEXT.load(Relaxed), LX_GUEST_FS.load(Relaxed), stack.0, stack.1]);
    v.into_iter().map(|n| n.to_string()).collect()
}

/// Child side of fork: recreate the guest address space from `snapshot()` fields, copying memory
/// out of the (paused) parent. Returns the guest stack bounds and the unparsed rest of the fields.
pub fn restore<'a>(f: &'a [String], parent: isize) -> Result<((u64, u64), &'a [String]), String> {
    let mut it = f.iter();
    let mut next = || -> Result<u64, String> {
        it.next().and_then(|s| s.parse().ok()).ok_or_else(|| "malformed fork state".to_string())
    };
    for _ in 0..next()? {
        let (base, len) = (next()?, next()?);
        if unsafe { VirtualAlloc(base as *mut _, len as usize, MEM_RESERVE, PAGE_READWRITE) } as u64 != base {
            return Err(format!("guest range {base:#x}+{len:#x} is taken in the child"));
        }
        ALLOCS.lock().unwrap().push((base, len));
    }
    for _ in 0..next()? {
        let (a, len, prot) = (next()?, next()?, next()? as u32);
        unsafe { VirtualAlloc(a as *mut _, len as usize, MEM_COMMIT, PAGE_READWRITE) };
        let mut done = 0;
        // PAGE_NOACCESS ranges can't be read and don't need to be: their contents are unobservable.
        // Guard pages are untouched by definition (touching one commits it), so they're zero too.
        let copy = prot != 0x01 && prot & PAGE_GUARD == 0;
        if copy && unsafe { ReadProcessMemory(parent, a as *const _, a as *mut _, len as usize, &mut done) } == 0 {
            return Err(format!("copying guest memory {a:#x}+{len:#x} failed ({})", unsafe { GetLastError() }));
        }
        let mut old = 0;
        unsafe { VirtualProtect(a as *mut _, len as usize, prot, &mut old) };
    }
    let mut code = CODE.lock().unwrap();
    for _ in 0..next()? {
        code.regions.push((next()?, next()?));
    }
    for _ in 0..next()? {
        code.sites.push(next()?);
    }
    drop(code);
    NEXT.store(next()?, Relaxed);
    LX_GUEST_FS.store(next()?, Relaxed);
    let stack = (next()?, next()?);
    let used = f.len() - it.len();
    Ok((stack, &f[used..]))
}

const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;

/// Verbose [lx] diagnostics, enabled by setting LX_DEBUG in the host environment.
pub fn debug() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("LX_DEBUG").is_some())
}

pub fn install() {
    START.lock().unwrap().get_or_insert_with(Instant::now);
    unsafe { AddVectoredExceptionHandler(1, veh) };
    signal::listen();
}

/// Rewrite every `syscall` in writable guest code at [addr, addr+len) to `ud2` and register the range.
pub fn patch_code(addr: u64, len: usize) -> usize {
    let code = unsafe { std::slice::from_raw_parts_mut(addr as *mut u8, len) };
    let found = find_syscalls(code, addr);
    let raw = code.windows(2).filter(|w| w == b"\x0f\x05").count();
    if raw != found.len() && debug() {
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

/// A signal frame waiting to be placed at the guest's (new) rsp. It can't be written from the handler:
/// NT keeps the CONTEXT we're editing, and our own call frames, right below the guest rsp, exactly
/// where the frame goes. lx_sig_tramp copies it after NtContinue, when that area is dead.
#[unsafe(no_mangle)]
static mut LX_FRAME: [u8; signal::FRAME_MAX] = [0; signal::FRAME_MAX];
#[unsafe(no_mangle)]
static LX_FRAME_LEN: AtomicU64 = AtomicU64::new(0);

std::arch::global_asm!(
    ".globl lx_sig_tramp",
    "lx_sig_tramp:", // rsp = frame start; rdi/rsi/rdx already hold the handler's arguments
    "push rsi",
    "push rdi",
    "push rcx",
    "lea rdi, [rsp + 24]",
    "lea rsi, [rip + LX_FRAME]",
    "mov rcx, qword ptr [rip + LX_FRAME_LEN]",
    "cld",
    "rep movsb",
    "pop rcx",
    "pop rdi",
    "pop rsi",
    "jmp lx_fs_tramp",
);
unsafe extern "C" {
    fn lx_sig_tramp();
}

/// Resume, entering a signal handler first if `deliver` prepared a frame.
fn resume_with_signals(c: &mut Context) -> i32 {
    match signal::deliver(c) {
        Some(frame) => {
            unsafe { (&raw mut LX_FRAME).cast::<u8>().copy_from_nonoverlapping(frame.as_ptr(), frame.len()) };
            LX_FRAME_LEN.store(frame.len() as u64, Relaxed);
            LX_RESUME_RIP.store(c.rip, Relaxed);
            c.rip = lx_sig_tramp as *const () as u64;
            EXCEPTION_CONTINUE_EXECUTION
        }
        None => resume(c, c.rip),
    }
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
        STATUS_ILLEGAL_INSTRUCTION if is_site && c.rax == 15 => {
            signal::sigreturn(c); // rt_sigreturn: back to where the signal interrupted
            resume_with_signals(c)
        }
        STATUS_ILLEGAL_INSTRUCTION if is_site => {
            let ret = dispatch(c);
            let next = c.rip + 2;
            (c.rax, c.rcx, c.r11, c.rip) = (ret as u64, next, c.eflags as u64, next); // kernel ABI: rcx=rip, r11=rflags
            resume_with_signals(c)
        }
        STATUS_ACCESS_VIOLATION if LX_GUEST_FS.load(Relaxed) != 0 && lost_fs_base(c, rec.info[1] as u64, end) => {
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
    proc::exit(139) // 128 + SIGSEGV, like a shell would report
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
        25 => mremap(a[0], a[1], a[2], a[3]),
        12 => Ok(0),                   // brk: always "fails"; musl and glibc fall back to mmap
        13 => signal::sigaction(a[0], a[1], a[2]),
        14 => signal::sigprocmask(a[0], a[1], a[2]),
        131 => Ok(0),                  // sigaltstack. ponytail: handlers always run on the current stack
        7 => fs::poll(a[0], a[1], a[2] as i32 as i64),
        271 => fs::poll(a[0], a[1], timespec_ms(a[2])), // ppoll. ponytail: signal mask ignored
        34 => signal::sigsuspend(0),   // pause
        130 => signal::sigsuspend(a[0]),
        16 => fs::ioctl(a[0], a[1], a[2]),
        17 => fs::pread(a[0], a[1], a[2], a[3], false),
        18 => fs::pread(a[0], a[1], a[2], a[3], true),
        19 => fs::readv(a[0], a[1], a[2]),
        37 => { signal::set_alarm(a[0] * 1000, 0); Ok(0) } // alarm
        38 => setitimer(a[0], a[1], a[2]),
        24 => Ok(0),                   // sched_yield
        90 | 91 | 268 => Ok(0),        // chmod, fchmod, fchmodat. ponytail: modes aren't stored yet (DESIGN.md §6)
        92 | 93 | 94 | 260 => Ok(0),   // chown, fchown, lchown, fchownat: everything is root's anyway
        97 => rlimit(a[0], 0, a[1]),   // getrlimit
        160 => Ok(0),                  // setrlimit: accepted, not enforced
        302 => rlimit(a[1], a[2], a[3]), // prlimit64 (self only)
        98 => { unsafe { std::ptr::write_bytes(a[1] as *mut u8, 0, 144) }; Ok(0) } // getrusage: zeros
        204 => sched_getaffinity(a[1], a[2]),
        41 => net::sys_socket(a[0], a[1], a[2]),
        42 => net::sys_connect(a[0], a[1], a[2]),
        43 => net::sys_accept(a[0], a[1], a[2], 0),
        44 => net::sys_sendto(a[0], a[1], a[2], a[3], a[4], a[5]),
        45 => net::sys_recvfrom(a[0], a[1], a[2], a[3], a[4], a[5]),
        46 => net::sys_sendmsg(a[0], a[1], a[2]),
        47 => net::sys_recvmsg(a[0], a[1], a[2]),
        48 => net::sys_shutdown(a[0], a[1]),
        49 => net::sys_bind(a[0], a[1], a[2]),
        50 => net::sys_listen(a[0], a[1]),
        51 => net::sys_getsockname(a[0], a[1], a[2], false),
        52 => net::sys_getsockname(a[0], a[1], a[2], true),
        53 => net::sys_socketpair(a[0], a[1], a[2], a[3]),
        54 => net::sys_setsockopt(a[0], a[1], a[2], a[3], a[4]),
        55 => net::sys_getsockopt(a[0], a[1], a[2], a[3], a[4]),
        288 => net::sys_accept(a[0], a[1], a[2], a[3]),
        213 => net::sys_epoll_create(0),
        291 => net::sys_epoll_create(a[0]),
        233 => net::sys_epoll_ctl(a[0], a[1], a[2], a[3]),
        232 | 281 => net::sys_epoll_wait(a[0], a[1], a[2], a[3] as i32 as i64), // pwait: mask ignored
        441 => net::sys_epoll_wait(a[0], a[1], a[2], timespec_ms(a[3])),
        20 => fs::writev(a[0], a[1], a[2]),
        22 => fs::pipe2(a[0], 0),
        21 => fs::faccessat(CWD, a[0]),
        28 => Ok(0),                   // madvise: advice only
        32 => fs::dup(a[0], 0, false),
        33 => fs::dup3(a[0], a[1], 0),
        35 => nanosleep(a[0]),
        39 | 186 => proc::getpid(),
        40 => fs::sendfile(a[0], a[1], a[2], a[3]),    // getpid, gettid (single-threaded: tid == pid)
        56 => proc::clone(c, a[0], a[1]),
        57 | 58 => proc::fork(c, 0),   // fork, vfork
        59 => proc::execve(a[0], a[1], a[2]),
        60 | 231 => proc::exit(a[0]),  // exit, exit_group (single thread)
        61 => proc::wait4(a[0] as i64, a[1], a[2]),
        62 => proc::kill(a[0] as i64, a[1]),
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
        102 | 107 => Ok(proc::UID.load(Relaxed) as i64), // getuid, geteuid
        104 | 108 => Ok(proc::GID.load(Relaxed) as i64), // getgid, getegid
        105 => proc::set_id(&proc::UID, a[0]),            // setuid
        106 => proc::set_id(&proc::GID, a[0]),            // setgid
        113 | 117 => proc::set_id(&proc::UID, a[1]),      // setreuid, setresuid: the effective id
        114 | 119 => proc::set_id(&proc::GID, a[1]),      // setregid, setresgid
        118 => proc::get_res(&proc::UID, [a[0], a[1], a[2]]), // getresuid
        120 => proc::get_res(&proc::GID, [a[0], a[1], a[2]]), // getresgid
        157 => Ok(0),                  // prctl (PR_SET_NAME, PR_SET_DUMPABLE, PR_SET_PDEATHSIG, ...): accepted
        115 => Ok(0),                  // getgroups: no supplementary groups
        116 => Ok(0),                  // setgroups: accepted
        109 => Ok(0),                  // setpgid. ponytail: no process groups / job control
        110 => proc::getppid(),
        111 | 112 | 121 => proc::getpid(), // getpgrp, setsid, getpgid
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
        200 => proc::kill(proc::getpid().unwrap_or(0), a[1]), // tkill on ourselves (single thread)
        234 => proc::kill(proc::getpid().unwrap_or(0), a[2]), // tgkill
        292 => fs::dup3(a[0], a[1], a[2]),
        293 => fs::pipe2(a[0], a[1]),
        318 => getrandom(a[0], a[1]),
        334 => Err(ENOSYS),            // rseq: optional, glibc copes
        nr => {
            // Once per syscall number: a program retrying in a loop mustn't flood the output.
            static SEEN: Mutex<Vec<u64>> = Mutex::new(Vec::new());
            let mut seen = SEEN.lock().unwrap();
            if !seen.contains(&nr) {
                seen.push(nr);
                eprintln!("[lx] unimplemented syscall {nr} ({:#x}, {:#x}, {:#x})", a[0], a[1], a[2]);
            }
            Err(ENOSYS)
        }
    };
    if let Err(e) = r && debug() {
        eprintln!("[lx] syscall {} ({:#x}, {:#x}, {:#x}, {:#x}) -> -{e}", c.rax, a[0], a[1], a[2], a[3]);
    }
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
    if unsafe { WriteFile(h, buf as *const u8, len, &mut done, std::ptr::null_mut()) } != 0 {
        return Ok(done as i64);
    }
    // ERROR_NO_DATA / ERROR_BROKEN_PIPE: the reader is gone. ponytail: EPIPE without SIGPIPE.
    match unsafe { GetLastError() } {
        232 | 109 => Err(EPIPE),
        995 => Err(EINTR), // a signal cancelled the write
        _ => Err(EIO),
    }
}

pub fn read_handle(h: isize, buf: u64, len: u64) -> R {
    let mut done = 0u32;
    let len = len.min(u32::MAX as u64) as u32;
    if unsafe { ReadFile(h, buf as *mut u8, len, &mut done, std::ptr::null_mut()) } != 0 {
        return Ok(done as i64);
    }
    match unsafe { GetLastError() } {
        109 => Ok(0),       // ERROR_BROKEN_PIPE is EOF
        995 => Err(EINTR),  // ERROR_OPERATION_ABORTED: a signal cancelled the read
        _ => Err(EIO),
    }
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
            p = alloc(Some(addr), len).unwrap_or(0);
        }
        if p != addr || !protect(addr, len, PAGE_READWRITE as u32) {
            return Err(ENOMEM);
        }
        unsafe { guest_mut(addr, len as usize) }.fill(0);
        p
    } else {
        // ponytail: address hints ignored; every mapping gets its own 64K-aligned reservation.
        alloc(None, len).ok_or(ENOMEM)?
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

/// Moves only (MREMAP_MAYMOVE): reservations can't grow in place. Keeps the old protection.
fn mremap(old: u64, old_len: u64, new_len: u64, flags: u64) -> R {
    const MREMAP_MAYMOVE: u64 = 1;
    if flags & MREMAP_MAYMOVE == 0 || new_len == 0 {
        return Err(ENOMEM);
    }
    let mut m = MemoryBasicInformation::default();
    if unsafe { VirtualQuery(old as *const _, &mut m, size_of::<MemoryBasicInformation>()) } == 0 || m.state != MEM_COMMIT {
        return Err(EFAULT);
    }
    let new = alloc(None, new_len).ok_or(ENOMEM)?;
    unsafe { std::ptr::copy_nonoverlapping(old as *const u8, new as *mut u8, old_len.min(new_len) as usize) };
    protect(new, new_len.next_multiple_of(PAGE), m.protect);
    munmap(old, old_len)?;
    Ok(new as i64)
}

fn munmap(addr: u64, len: u64) -> R {
    // ponytail: decommit only; the address space stays reserved (and leaks) until exit.
    unsafe { VirtualFree(addr as *mut _, len.next_multiple_of(PAGE) as usize, MEM_DECOMMIT) };
    Ok(0)
}

// ---- process, time, misc ----

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
    // ponytail: on EINTR the remaining time isn't written back; callers (sleep) just exit.
    signal::interruptible_sleep(timespec_ms(ts).clamp(0, u32::MAX as i64 - 1) as u32)
}

/// Limits like a Docker container's defaults: 1M open files, 8 MB stack, the rest unlimited.
/// ponytail: new limits are accepted but not enforced.
fn rlimit(resource: u64, _new: u64, old: u64) -> R {
    const INF: u64 = u64::MAX;
    let (cur, max) = match resource {
        3 => (8 << 20, INF),        // RLIMIT_STACK
        7 => (1 << 20, 1 << 20),    // RLIMIT_NOFILE
        _ => (INF, INF),
    };
    if old != 0 {
        unsafe { *(old as *mut [u64; 2]) = [cur, max] };
    }
    Ok(0)
}

/// All host CPUs are ours. Returns the mask size like the kernel does.
fn sched_getaffinity(len: u64, mask: u64) -> R {
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get()).min(64);
    if len < 8 {
        return Err(EINVAL);
    }
    let bits = if cpus == 64 { u64::MAX } else { (1u64 << cpus) - 1 };
    unsafe { *(mask as *mut u64) = bits };
    Ok(8)
}

/// setitimer(ITIMER_REAL, {interval, value} as timevals, old).
fn setitimer(which: u64, new: u64, old: u64) -> R {
    if which != 0 {
        return Err(EINVAL); // ITIMER_VIRTUAL / ITIMER_PROF
    }
    if old != 0 {
        unsafe { *(old as *mut [u64; 4]) = [0; 4] };
    }
    if new != 0 {
        let [is, ius, vs, vus] = unsafe { *(new as *const [u64; 4]) };
        signal::set_alarm(vs * 1000 + vus / 1000, is * 1000 + ius / 1000);
    }
    Ok(0)
}

/// A `struct timespec *` timeout in ms; NULL means wait forever (-1).
fn timespec_ms(ts: u64) -> i64 {
    if ts == 0 {
        return -1;
    }
    let [s, ns] = unsafe { *(ts as *const [i64; 2]) };
    s.saturating_mul(1000).saturating_add(ns / 1_000_000)
}

pub fn getrandom(buf: u64, len: u64) -> R {
    let len = len.min(u32::MAX as u64);
    unsafe { BCryptGenRandom(std::ptr::null_mut(), buf as *mut u8, len as u32, 2) };
    Ok(len as i64)
}

