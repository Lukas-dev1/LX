//! Syscall interception + Linux TLS (FS base) emulation, both driven by one vectored exception handler.
//!
//! - `syscall` sites in guest code are rewritten to `ud2` (`patch_code`); the #UD lands here and is dispatched.
//! - NT resets FS base to 0 on context switches, so a guest `%fs:` access faults (low/kernel address).
//!   We bounce through `fs_tramp`, which reloads FS base in user mode and resumes the faulting instruction.
//!   Every return to the guest goes through the trampoline, because NtContinue also loses FS base.
use crate::{fs, net, proc, signal, thread};
use crate::win::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Ok(value) or Err(positive errno); the guest sees -errno.
pub type R = Result<i64, i64>;
pub const EPERM: i64 = 1;
pub const ESRCH: i64 = 3;
pub const EINTR: i64 = 4;
pub const ENXIO: i64 = 6;
pub const ENODEV: i64 = 19;
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
pub const EROFS: i64 = 30;
pub const ENOTSOCK: i64 = 88;
pub const ENOPROTOOPT: i64 = 92;
pub const EAFNOSUPPORT: i64 = 97;

/// Per guest thread: what the trampolines need (fixed offsets, read from assembly) plus Linux thread state.
#[repr(C)]
pub struct ThreadState {
    /// Guest FS base (arch_prctl / CLONE_SETTLS). Offset 0.
    pub fs: u64,
    /// Where lx_fs_tramp jumps. Offset 8.
    resume: u64,
    /// Pending signal frame for lx_sig_tramp (exception path only): length here, bytes in `frame`.
    frame_len: u64,
    /// lx_sys_entry: the guest's rsp while we run on `host_stack`.
    guest_rsp: u64,
    /// Top of this thread's lx stack: traps and direct syscalls run here, never on the guest's.
    host_stack: u64,
    frame: [u8; signal::FRAME_MAX],
    /// Guest stack bounds, published in the TEB because our handler code runs on the guest stack
    /// (big frames, e.g. __chkstk inside CreateProcess, probe against them). Forked children reuse them.
    pub stack: (u64, u64),
    /// set_tid_address / CLONE_CHILD_CLEARTID: zeroed and futex-woken when the thread exits.
    pub clear_tid: u64,
    /// sigaltstack: (base, size), or None when disabled.
    pub altstack: Option<(u64, u64)>,
    /// This thread's blocked signals, and the one to restore after rt_sigsuspend's handler.
    pub sigmask: u64,
    pub suspended_mask: Option<u64>,
    /// Signals sent to this thread alone (tkill/tgkill), and the futex address it sleeps on (0 = none),
    /// so a sender can wake it. Read and written by other threads.
    pub tpending: std::sync::atomic::AtomicU64,
    pub futex_addr: std::sync::atomic::AtomicU64,
    /// Whether we're running on host_stack right now.
    on_host: bool,
    /// The TEB's own stack fields (StackBase, StackLimit, DeallocationStack) before the guest took over.
    /// ExitThread frees whatever DeallocationStack names, so they go back before a thread exits.
    pub host_teb: Option<[u64; 3]>,
}

const TS_RESUME: usize = std::mem::offset_of!(ThreadState, resume);
const TS_FRAME_LEN: usize = std::mem::offset_of!(ThreadState, frame_len);
const TS_FRAME: usize = std::mem::offset_of!(ThreadState, frame);
const TS_GUEST_RSP: usize = std::mem::offset_of!(ThreadState, guest_rsp);
const TS_HOST_STACK: usize = std::mem::offset_of!(ThreadState, host_stack);
const _: () = assert!(std::mem::offset_of!(ThreadState, fs) == 0);

/// TEB offset of our TLS slot (gs:[0x1480 + 8*index]); the trampolines load the ThreadState pointer from it.
#[unsafe(no_mangle)]
static LX_TLS_OFF: AtomicU64 = AtomicU64::new(0);
static TLS_INDEX: AtomicU64 = AtomicU64::new(u64::MAX);
/// TEB offset of a per-thread scratch slot (its value, not a pointer): FS-site stubs park rax there.
static SCRATCH_OFF: AtomicU64 = AtomicU64::new(0);

/// (ThreadState pointer slot, scratch slot) as TEB offsets; FS-site stubs embed both.
pub fn tls_slot_offsets() -> (u32, u32) {
    (LX_TLS_OFF.load(Relaxed) as u32, SCRATCH_OFF.load(Relaxed) as u32)
}

/// Every guest thread's ThreadState by Windows tid, for signals sent to one thread (they're leaked, so
/// the pointers stay valid; an exiting thread takes itself out).
static THREAD_TS: Mutex<Vec<(u32, usize)>> = Mutex::new(Vec::new());

pub fn ts_of(tid: u32) -> Option<&'static ThreadState> {
    THREAD_TS.lock().unwrap().iter().find(|e| e.0 == tid).map(|e| unsafe { &*(e.1 as *const ThreadState) })
}

pub fn forget_ts() {
    let me = unsafe { GetCurrentThreadId() };
    THREAD_TS.lock().unwrap().retain(|e| e.0 != me);
}

/// This thread's state, created on first use.
pub fn ts() -> &'static mut ThreadState {
    let idx = TLS_INDEX.load(Relaxed) as u32;
    let p = unsafe { TlsGetValue(idx) } as *mut ThreadState;
    if !p.is_null() {
        return unsafe { &mut *p };
    }
    let host = unsafe { VirtualAlloc(std::ptr::null_mut(), HOST_STACK, MEM_COMMIT_RESERVE, PAGE_READWRITE) } as u64;
    assert!(host != 0, "no memory for a thread's lx stack");
    let st = Box::leak(Box::new(ThreadState {
        fs: 0, resume: 0, frame_len: 0, guest_rsp: 0, host_stack: host + HOST_STACK as u64,
        frame: [0; signal::FRAME_MAX], stack: (0, 0), clear_tid: 0, altstack: None, sigmask: 0, suspended_mask: None,
        tpending: std::sync::atomic::AtomicU64::new(0), futex_addr: std::sync::atomic::AtomicU64::new(0),
        on_host: false, host_teb: None,
    }));
    unsafe { TlsSetValue(idx, st as *mut ThreadState as *mut _) };
    THREAD_TS.lock().unwrap().push((unsafe { GetCurrentThreadId() }, st as *const ThreadState as usize));
    st
}
static START: Mutex<Option<Instant>> = Mutex::new(None);

/// Guest code ranges and the patched syscall sites inside them (sorted).
struct Code {
    regions: Vec<(u64, u64)>,
    sites: Vec<u64>,
}
static CODE: Mutex<Code> = Mutex::new(Code { regions: Vec::new(), sites: Vec::new() });

// Clobbers nothing the guest can see: skips the 128-byte red zone, saves rax, and leaves flags alone.
// The resume address is pushed, then jumped to from just below the restored rsp (nothing writes a
// thread's user stack asynchronously). wrfsbase is bytes so we don't need the fsgsbase target feature.
std::arch::global_asm!(
    ".globl lx_fs_tramp",
    "lx_fs_tramp:",
    "lea rsp, [rsp - 128]",
    "push rax",
    "mov rax, qword ptr [rip + LX_TLS_OFF]",
    "mov rax, qword ptr gs:[rax]",        // ThreadState*
    "push qword ptr [rax + {resume}]",
    "mov rax, qword ptr [rax]",           // fs
    ".byte 0xf3, 0x48, 0x0f, 0xae, 0xd0", // wrfsbase rax
    "mov rax, qword ptr [rsp + 8]",
    "lea rsp, [rsp + 144]",
    "jmp qword ptr [rsp - 144]",
    resume = const TS_RESUME,
);
// Enter or resume the guest with a full register set: [rax rcx rdx rbx rsp rbp rsi rdi r8..r15 rip rflags].
// FS base first, then an iretq frame on the stack we're on (never the guest's): iretq loads rip, rsp and
// rflags together, so no guest memory is written and no register is needed for the jump.
std::arch::global_asm!(
    ".globl lx_resume",
    "lx_resume:",
    "mov rax, qword ptr [rip + LX_TLS_OFF]",
    "mov rax, qword ptr gs:[rax]",        // ThreadState*
    "mov rax, qword ptr [rax]",           // fs
    ".byte 0xf3, 0x48, 0x0f, 0xae, 0xd0", // wrfsbase rax
    "mov eax, ss",
    "push rax",
    "push qword ptr [rcx + 4*8]",         // rsp
    "push qword ptr [rcx + 17*8]",        // rflags
    "mov eax, cs",
    "push rax",
    "push qword ptr [rcx + 16*8]",        // rip
    "mov rax, qword ptr [rcx + 0*8]",
    "mov rdx, qword ptr [rcx + 2*8]",
    "mov rbx, qword ptr [rcx + 3*8]",
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
    "iretq",
);

// The direct syscall path. A rewritten site arrives here from its stub with r11 = return address and
// every other register as the guest left it (rcx is free: a Linux syscall clobbers it). Before
// anything is written, rsp moves to this thread's lx stack (only movs, which touch neither memory nor
// flags); the first write is pushfq onto the lx stack. A Context-shaped frame is built there for
// lx_direct, and the way back is an iretq frame on the lx stack too.
std::arch::global_asm!(
    ".globl lx_sys_entry",
    "lx_sys_entry:",
    "mov rcx, qword ptr [rip + LX_TLS_OFF]",
    "mov rcx, qword ptr gs:[rcx]",        // ThreadState*
    "mov qword ptr [rcx + {guest_rsp}], rsp",
    "mov rsp, qword ptr [rcx + {host_stack}]",
    "pushfq",                             // DirectFrame.flags (offset 0x108)
    "lea rsp, [rsp - 0x108]",             // DirectFrame.ctx (Context layout)
    "mov qword ptr [rsp + 0x78], rax",
    "mov qword ptr [rsp + 0x88], rdx",
    "mov qword ptr [rsp + 0x90], rbx",
    "mov qword ptr [rsp + 0xa0], rbp",
    "mov qword ptr [rsp + 0xa8], rsi",
    "mov qword ptr [rsp + 0xb0], rdi",
    "mov qword ptr [rsp + 0xb8], r8",
    "mov qword ptr [rsp + 0xc0], r9",
    "mov qword ptr [rsp + 0xc8], r10",
    "mov qword ptr [rsp + 0xd8], r12",
    "mov qword ptr [rsp + 0xe0], r13",
    "mov qword ptr [rsp + 0xe8], r14",
    "mov qword ptr [rsp + 0xf0], r15",
    "mov qword ptr [rsp + 0xf8], r11",    // rip: where the syscall returns to
    "mov qword ptr [rsp + 0x80], r11",    // rcx, as the kernel leaves it
    "mov rax, qword ptr [rcx + {guest_rsp}]",
    "mov qword ptr [rsp + 0x98], rax",
    "mov rax, qword ptr [rsp + 0x108]",
    "mov qword ptr [rsp + 0xd0], rax",    // r11 = rflags, as the kernel leaves it
    "mov dword ptr [rsp + 0x44], eax",    // Context.EFlags
    "mov rcx, rsp",
    "sub rsp, 32",
    "call lx_direct",
    "add rsp, 32",
    "mov rax, qword ptr [rip + LX_TLS_OFF]",
    "mov rax, qword ptr gs:[rax]",
    "mov rax, qword ptr [rax]",           // fs
    ".byte 0xf3, 0x48, 0x0f, 0xae, 0xd0", // wrfsbase rax
    "mov rax, rsp",                       // the frame
    "mov ecx, ss",
    "push rcx",
    "push qword ptr [rax + 0x98]",        // rsp
    "push qword ptr [rax + 0x108]",       // rflags
    "mov ecx, cs",
    "push rcx",
    "push qword ptr [rax + 0xf8]",        // rip
    "mov rcx, qword ptr [rax + 0x80]",
    "mov rdx, qword ptr [rax + 0x88]",
    "mov rbx, qword ptr [rax + 0x90]",
    "mov rbp, qword ptr [rax + 0xa0]",
    "mov rsi, qword ptr [rax + 0xa8]",
    "mov rdi, qword ptr [rax + 0xb0]",
    "mov r8, qword ptr [rax + 0xb8]",
    "mov r9, qword ptr [rax + 0xc0]",
    "mov r10, qword ptr [rax + 0xc8]",
    "mov r11, qword ptr [rax + 0xd0]",
    "mov r12, qword ptr [rax + 0xd8]",
    "mov r13, qword ptr [rax + 0xe0]",
    "mov r14, qword ptr [rax + 0xe8]",
    "mov r15, qword ptr [rax + 0xf0]",
    "mov rax, qword ptr [rax + 0x78]",
    "iretq",
    guest_rsp = const TS_GUEST_RSP,
    host_stack = const TS_HOST_STACK,
);
unsafe extern "C" {
    fn lx_fs_tramp();
    fn lx_resume(regs: *const [u64; 18]) -> !;
    fn lx_sys_entry();
}

/// lx_sys_entry's frame: a Context (so dispatch and signals work unchanged) plus the 64-bit rflags.
#[repr(C)]
struct DirectFrame {
    ctx: Context,
    _pad: u64,
    flags: u64,
}
const _: () = assert!(std::mem::offset_of!(DirectFrame, flags) == 0x108);
const _: () = assert!(size_of::<DirectFrame>() == 0x110);

pub fn sys_entry_addr() -> u64 {
    lx_sys_entry as *const () as u64
}

pub static FALLBACK_TRAPS: AtomicU64 = AtomicU64::new(0);
/// FS-base reload faults (NT dropped FS base on a context switch; the next %fs: access faulted).
pub static FS_FAULTS: AtomicU64 = AtomicU64::new(0);

/// Rust half of the direct path, on the thread's lx stack. Same semantics as the exception path.
#[unsafe(no_mangle)]
unsafe extern "system" fn lx_direct(f: *mut DirectFrame) {
    let f = unsafe { &mut *f };
    let c = &mut f.ctx;
    let t = ts();
    t.on_host = true;
    let (base, limit): (u64, u64);
    let top = t.host_stack;
    unsafe {
        // TEB bounds describe the stack we're on (for __chkstk); the guest's go back on the way out.
        std::arch::asm!("mov {b}, qword ptr gs:[0x08]", "mov {l}, qword ptr gs:[0x10]", b = out(reg) base, l = out(reg) limit);
        std::arch::asm!("mov qword ptr gs:[0x08], {b}", "mov qword ptr gs:[0x10], {l}", b = in(reg) top, l = in(reg) top - HOST_STACK as u64);
    }
    if c.rax == 15 {
        signal::sigreturn(c); // rt_sigreturn: everything comes from the ucontext
    } else {
        let next = c.rip;
        c.rip = next - 2; // what the trap path sees: the address of the syscall instruction
        let ret = dispatch(c);
        (c.rax, c.rcx, c.r11, c.rip) = (ret as u64, next, c.eflags as u64, next);
    }
    if let Some(frame) = signal::deliver(c) {
        // Unlike the trap path, nothing of ours lives on the guest stack: the frame goes straight there.
        unsafe { std::ptr::copy_nonoverlapping(frame.as_ptr(), c.rsp as *mut u8, frame.len()) };
    }
    f.flags = c.eflags as u64;
    unsafe { std::arch::asm!("mov qword ptr gs:[0x08], {b}", "mov qword ptr gs:[0x10], {l}", b = in(reg) base, l = in(reg) limit) };
    ts().on_host = false;
}

/// Jump into guest code on this thread. Never returns: the guest ends it with exit or exit_group.
pub fn enter(regs: [u64; 18], stack_lo: u64, stack_hi: u64) -> ! {
    let t = ts();
    t.stack = (stack_lo, stack_hi);
    if t.host_teb.is_none() {
        let (b, l, d): (u64, u64, u64);
        unsafe {
            std::arch::asm!("mov {b}, qword ptr gs:[0x08]", "mov {l}, qword ptr gs:[0x10]", "mov {d}, qword ptr gs:[0x1478]",
                b = out(reg) b, l = out(reg) l, d = out(reg) d);
        }
        t.host_teb = Some([b, l, d]);
    }
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

/// The main guest stack, committed whole. Linux grows a main stack for any access within RLIMIT_STACK,
/// so binaries built without stack probes make frames of hundreds of KB that jump straight past a guard
/// page (numpy's OpenBLAS does); NT only grows a stack page by page through its guard page, and a fault
/// with no committed memory under rsp can't even be dispatched. Committing costs commit charge only:
/// untouched pages never enter the working set, so this uses no RAM until the program touches it.
pub fn alloc_stack(len: u64) -> Option<u64> {
    alloc(None, len)
}

/// Reserve+commit RW guest memory, at `fixed` or anywhere in the guest window.
pub fn alloc(fixed: Option<u64>, len: u64) -> Option<u64> {
    alloc_ex(fixed, len, true)
}

/// Like `alloc`, optionally reserve-only: Linux PROT_NONE reservations (Go reserves hundreds of GB up
/// front) must not count against the commit limit.
fn alloc_ex(fixed: Option<u64>, len: u64, commit: bool) -> Option<u64> {
    let len = len.next_multiple_of(PAGE);
    let (ty, prot) = if commit { (MEM_COMMIT_RESERVE, PAGE_READWRITE) } else { (MEM_RESERVE, 0x01) }; // PAGE_NOACCESS
    let at = |a: u64| unsafe { VirtualAlloc(a as *mut _, len as usize, ty, prot) } as u64;
    let p = match fixed {
        Some(a) => match at(a) {
            got if got == a => a,
            0 => return None,
            got => {
                // NT rounded an unaligned address down to its 64K granularity: not what was asked for.
                unsafe { VirtualFree(got as *mut _, 0, MEM_RELEASE) };
                return None;
            }
        },
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
    let (lo, _) = ts().stack;
    let mut allocs = ALLOCS.lock().unwrap();
    allocs.retain(|&(base, len)| {
        if (base..base + len).contains(&lo) {
            return true;
        }
        unsafe { VirtualFree(base as *mut _, 0, MEM_RELEASE) };
        false
    });
    CODE.lock().unwrap().regions.clear(); // nothing of the old program runs any more
    unmap_views(0, u64::MAX);
    crate::jump::clear();
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
    // Only the forking thread survives a fork, as on Linux: its FS base and stack come along.
    let t = ts();
    v.extend([NEXT.load(Relaxed), t.fs, t.stack.0, t.stack.1]);
    v.extend(views_snapshot());
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
            const ERROR_PARTIAL_COPY: u32 = 299;
            if unsafe { GetLastError() } != ERROR_PARTIAL_COPY {
                return Err(format!("copying guest memory {a:#x}+{len:#x} failed ({})", unsafe { GetLastError() }));
            }
            // Another of the parent's threads unmapped or protected part of the range after the snapshot
            // (Go forks from a running program). Copy what's still readable, page by page; the rest stays
            // zero, which nothing the child runs before exec can tell from gone.
            for p in (a..a + len).step_by(PAGE as usize) {
                unsafe { ReadProcessMemory(parent, p as *const _, p as *mut _, PAGE as usize, &mut done) };
            }
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
    ts().fs = next()?;
    let stack = (next()?, next()?);
    // Shared views: the same sections (inherited at the same handle values), at the same addresses.
    for _ in 0..next()? {
        let (base, len, section, off, access) = (next()?, next()?, next()? as isize, next()?, next()? as u32);
        let got = unsafe { MapViewOfFileEx(section, access, (off >> 32) as u32, off as u32, len as usize, base as *mut _) } as u64;
        if got != base {
            return Err(format!("shared mapping {base:#x}+{len:#x} can't be placed in the child ({})", unsafe { GetLastError() }));
        }
        unsafe { SetHandleInformation(section, 1, 0) };
        VIEWS.lock().unwrap().push(View { base, len, section, off, access });
    }
    let used = f.len() - it.len();
    Ok((stack, &f[used..]))
}

const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
const STATUS_BREAKPOINT: u32 = 0x8000_0003;

/// One debug line, written in one piece and tagged with the thread id (threads interleave otherwise).
pub fn dlog(msg: std::fmt::Arguments) {
    let line = format!("[lx t{}] {msg}
", unsafe { GetCurrentThreadId() });
    let _ = std::io::Write::write_all(&mut std::io::stderr(), line.as_bytes());
}

/// Signal-event trace only (LX_SIGLOG): cheap enough not to change timing the way LX_DEBUG does.
pub fn siglog() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("LX_SIGLOG").is_some() || debug())
}

/// LX_STRACE=1: log every syscall with its arguments and result (see dispatch).
pub fn strace() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("LX_STRACE").is_some())
}

/// Verbose [lx] diagnostics, enabled by setting LX_DEBUG in the host environment.
pub fn debug() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("LX_DEBUG").is_some())
}

pub fn install() {
    START.lock().unwrap().get_or_insert_with(Instant::now);
    let idx = unsafe { TlsAlloc() };
    assert!(idx < 64, "TLS index {idx} is past the TEB's inline slots"); // inline slots: gs:[0x1480 + 8*i]
    TLS_INDEX.store(idx as u64, Relaxed);
    LX_TLS_OFF.store(0x1480 + 8 * idx as u64, Relaxed);
    let scratch = unsafe { TlsAlloc() };
    assert!(scratch < 64, "TLS index {scratch} is past the TEB's inline slots");
    SCRATCH_OFF.store(0x1480 + 8 * scratch as u64, Relaxed);
    crate::thread::set_main();
    unsafe { AddVectoredExceptionHandler(1, veh) };
    signal::listen();
}

/// Rewrite every `syscall` in writable guest code at [addr, addr+len) to `ud2` and register the range.
pub fn patch_code(addr: u64, len: usize) -> usize {
    let code = unsafe { std::slice::from_raw_parts_mut(addr as *mut u8, len) };
    let all = find_syscalls(code, addr).len();
    let raw = code.windows(2).filter(|w| w == b"\x0f\x05").count();
    if raw != all && debug() {
        eprintln!("[lx] {addr:#x}: {} of {raw} 0F05 byte pairs are not instructions, left alone", raw - all);
    }
    // What's left needs the trap fallback. LX_NOJUMP=1 keeps every site on it (comparison, escape hatch).
    static NOJUMP: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let (fs0, left0) = (crate::jump::FS_REWRITTEN.load(Relaxed), crate::jump::FS_LEFT.load(Relaxed));
    let found = if *NOJUMP.get_or_init(|| std::env::var_os("LX_NOJUMP").is_some()) {
        find_syscalls(code, addr)
    } else {
        crate::jump::rewrite(code, addr)
    };
    if patchlog() {
        dlog(format_args!("code {addr:#x}+{len:#x}: syscall sites {} rewritten / {} fallback; fs sites {} rewritten / {} left",
            all - found.len(), found.len(), crate::jump::FS_REWRITTEN.load(Relaxed) - fs0, crate::jump::FS_LEFT.load(Relaxed) - left0));
        for &a in &found {
            dlog(format_args!("  fallback site {a:#x}: {}", crate::jump::describe(code, addr, a)));
        }
    }
    for &a in &found {
        code[(a - addr) as usize + 1] = 0x0b; // syscall (0F 05) -> ud2 (0F 0B)
    }
    let mut c = CODE.lock().unwrap();
    c.regions.push((addr, addr + len as u64));
    c.sites.extend(&found);
    c.sites.sort_unstable();
    c.sites.dedup();
    all
}

/// Register [lo, hi) as guest code (stub areas): faults there are the guest's, not ours.
pub fn register_code(lo: u64, hi: u64) {
    CODE.lock().unwrap().regions.push((lo, hi));
}

/// Fallback statistics on stderr (LX_PATCHLOG): which sites were rewritten, which traps were taken.
pub fn patchlog() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("LX_PATCHLOG").is_some())
}

/// RWX guest memory at exactly `a` (stub areas, which must be within rel32 reach of their code).
pub fn alloc_rwx_at(a: u64, len: u64) -> Option<u64> {
    let p = unsafe { VirtualAlloc(a as *mut _, len as usize, MEM_COMMIT_RESERVE, 0x40) } as u64; // PAGE_EXECUTE_READWRITE
    if p == 0 {
        return None;
    }
    if p != a {
        unsafe { VirtualFree(p as *mut _, 0, MEM_RELEASE) };
        return None;
    }
    ALLOCS.lock().unwrap().push((p, len));
    Some(p)
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
    ts().resume = rip;
    c.rip = lx_fs_tramp as *const () as u64;
    EXCEPTION_CONTINUE_EXECUTION
}

// A signal frame waiting to be placed at the guest's (new) rsp (ThreadState.frame). It can't be written
// from the handler: NT keeps the CONTEXT we're editing, and our own call frames, right below the guest
// rsp, exactly where the frame goes. lx_sig_tramp copies it after NtContinue, when that area is dead.
std::arch::global_asm!(
    ".globl lx_sig_tramp",
    "lx_sig_tramp:", // rsp = frame start; rdi/rsi/rdx already hold the handler's arguments
    "push rsi",
    "push rdi",
    "push rcx",
    "mov rsi, qword ptr [rip + LX_TLS_OFF]",
    "mov rsi, qword ptr gs:[rsi]",        // ThreadState*
    "mov rcx, qword ptr [rsi + {frame_len}]",
    "lea rsi, [rsi + {frame}]",
    "lea rdi, [rsp + 24]",
    "cld",
    "rep movsb",
    "pop rcx",
    "pop rdi",
    "pop rsi",
    "jmp lx_fs_tramp",
    frame_len = const TS_FRAME_LEN,
    frame = const TS_FRAME,
);
unsafe extern "C" {
    fn lx_sig_tramp();
}

/// Resume, entering a signal handler first if `deliver` prepared a frame.
fn resume_with_signals(c: &mut Context) -> i32 {
    match signal::deliver(c) {
        Some(frame) => enter_handler(c, frame),
        None => resume(c, c.rip),
    }
}

/// Continue in the signal handler `c` now points at; the trampoline puts `frame` at its rsp.
fn enter_handler(c: &mut Context, frame: Vec<u8>) -> i32 {
    let t = ts();
    t.frame[..frame.len()].copy_from_slice(&frame);
    t.frame_len = frame.len() as u64;
    t.resume = c.rip;
    c.rip = lx_sig_tramp as *const () as u64;
    EXCEPTION_CONTINUE_EXECUTION
}

// Call f(arg) with rsp switched to `top` (Win64 ABI: rcx = top, rdx = f, r8 = arg).
std::arch::global_asm!(
    ".globl lx_on_stack",
    "lx_on_stack:",
    "push rbp",
    "mov rbp, rsp",
    "lea rsp, [rcx - 32]", // shadow space; top is 16-aligned
    "mov rcx, r8",
    "call rdx",
    "mov rsp, rbp",
    "pop rbp",
    "ret",
);
unsafe extern "system" {
    fn lx_on_stack(top: u64, f: unsafe extern "system" fn(*mut ExceptionPointers) -> i32, arg: *mut ExceptionPointers) -> i32;
}

const HOST_STACK: usize = 512 << 10;

/// Entry for every exception. A Linux kernel never touches the user stack, and guests rely on that (Go
/// runs syscalls on 16 KB stacks), so all real work happens on a per-thread host stack. Only NT's own
/// exception frame lands on the guest stack. While on our stack, the TEB bounds describe it (for
/// __chkstk); nested faults (our own bugs) stay where they are.
unsafe extern "system" fn veh(ep: *mut ExceptionPointers) -> i32 {
    if debug() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        let here: u64;
        unsafe { std::arch::asm!("mov {}, rsp", out(reg) here) };
        let guest_rsp = unsafe { (*(*ep).context).rsp };
        ONCE.call_once(|| dlog(format_args!("trap uses {} bytes of guest stack before our handler", guest_rsp - here)));
    }
    let t = ts();
    if t.on_host {
        return unsafe { veh_body(ep) };
    }
    if t.host_stack == 0 {
        let lo = unsafe { VirtualAlloc(std::ptr::null_mut(), HOST_STACK, MEM_COMMIT_RESERVE, PAGE_READWRITE) } as u64;
        if lo == 0 {
            return unsafe { veh_body(ep) }; // no memory for a stack: best effort on the guest's
        }
        t.host_stack = lo + HOST_STACK as u64;
    }
    let top = t.host_stack;
    let (base, limit): (u64, u64);
    unsafe {
        std::arch::asm!("mov {b}, qword ptr gs:[0x08]", "mov {l}, qword ptr gs:[0x10]", b = out(reg) base, l = out(reg) limit);
        std::arch::asm!("mov qword ptr gs:[0x08], {b}", "mov qword ptr gs:[0x10], {l}", b = in(reg) top, l = in(reg) top - HOST_STACK as u64);
    }
    t.on_host = true;
    let r = unsafe { lx_on_stack(top, veh_body, ep) };
    let t = ts();
    t.on_host = false;
    unsafe { std::arch::asm!("mov qword ptr gs:[0x08], {b}", "mov qword ptr gs:[0x10], {l}", b = in(reg) base, l = in(reg) limit) };
    r
}

unsafe extern "system" fn veh_body(ep: *mut ExceptionPointers) -> i32 {
    let (rec, c) = unsafe { (&*(*ep).record, &mut *(*ep).context) };
    let (region, is_site) = {
        let code = CODE.lock().unwrap();
        let r = code.regions.iter().find(|(lo, hi)| (*lo..*hi).contains(&c.rip)).copied();
        (r, code.sites.binary_search(&c.rip).is_ok())
    };
    // Guest code is a loaded ELF region, or memory outside every Windows module: JIT code (HotSpot,
    // V8) lives in plain mmap'd pages and faults on purpose.
    let jit = region.is_none() && {
        const FROM_ADDRESS: u32 = 4;
        const UNCHANGED_REFCOUNT: u32 = 2;
        let mut m = 0isize;
        (unsafe { GetModuleHandleExW(FROM_ADDRESS | UNCHANGED_REFCOUNT, c.rip as *const _, &mut m) }) == 0
    };
    // For JIT code, decode only what's committed at rip: a guest that jumped into unmapped memory faults
    // there, and reading 15 bytes past it made our own handler crash.
    let jit_end = || {
        let mut m = MemoryBasicInformation::default();
        let ok = unsafe { VirtualQuery(c.rip as *const _, &mut m, size_of::<MemoryBasicInformation>()) } != 0;
        let readable = ok && m.state == MEM_COMMIT && m.protect & 0xff & !0x01 != 0; // not PAGE_NOACCESS
        if readable { (m.base as u64 + m.region_size as u64).min(c.rip + 15) } else { c.rip }
    };
    let Some((_, end)) = region.or(jit.then(|| (c.rip, jit_end()))) else {
        if debug() && rec.code == STATUS_ACCESS_VIOLATION {
            let base = unsafe { GetModuleHandleW(std::ptr::null()) } as u64;
            let msg = format!("[lx] host fault at rip {:#x} (lx.exe+{:#x}) addr {:#x} tid {}
",
                c.rip, c.rip.wrapping_sub(base), rec.info[1], unsafe { GetCurrentThreadId() });
            let _ = std::io::Write::write_all(&mut std::io::stderr(), msg.as_bytes());
        }
        return EXCEPTION_CONTINUE_SEARCH; // not guest code: our own bug, let it crash normally
    };
    match rec.code {
        STATUS_ILLEGAL_INSTRUCTION if is_site && c.rax == 15 => {
            signal::sigreturn(c); // rt_sigreturn: back to where the signal interrupted
            resume_with_signals(c)
        }
        STATUS_BREAKPOINT if crate::jump::redirect(c.rip).is_some() => {
            // A jump we couldn't see landed inside a rewritten site: continue at that instruction's copy.
            let to = crate::jump::redirect(c.rip).unwrap();
            if patchlog() {
                dlog(format_args!("entered rewritten site mid-way at {:#x}, continuing in its stub", c.rip));
            }
            resume(c, to)
        }
        STATUS_ILLEGAL_INSTRUCTION if is_site => {
            FALLBACK_TRAPS.fetch_add(1, Relaxed);
            let ret = dispatch(c);
            let next = c.rip + 2;
            (c.rax, c.rcx, c.r11, c.rip) = (ret as u64, next, c.eflags as u64, next); // kernel ABI: rcx=rip, r11=rflags
            resume_with_signals(c)
        }
        STATUS_ACCESS_VIOLATION if ts().fs != 0 && lost_fs_base(c, rec.info[1] as u64, end) => {
            FS_FAULTS.fetch_add(1, Relaxed);
            if patchlog() { dlog(format_args!("FS-base fault at rip {:#x} rsp {:#x}", c.rip, c.rsp)); }
            resume(c, c.rip)
        }
        _ => match fault_signal(rec, c).and_then(|(sig, code, addr)| signal::fault(c, sig, code, addr)) {
            Some(frame) => enter_handler(c, frame),
            None => guest_crash(rec, c),
        },
    }
}

/// The Linux signal for a guest fault: (signal, si_code, si_addr).
fn fault_signal(rec: &ExceptionRecord, c: &Context) -> Option<(u64, u64, u64)> {
    const STATUS_GUARD_PAGE: u32 = 0x8000_0001;
    const STATUS_INT_DIVIDE_BY_ZERO: u32 = 0xC000_0094;
    const STATUS_INT_OVERFLOW: u32 = 0xC000_0095;
    match rec.code {
        STATUS_ACCESS_VIOLATION | STATUS_GUARD_PAGE => {
            let addr = rec.info[1] as u64;
            let mut m = MemoryBasicInformation::default();
            unsafe { VirtualQuery(addr as *const _, &mut m, size_of::<MemoryBasicInformation>()) };
            const MEM_COMMIT: u32 = 0x1000;
            Some((11, if m.state == MEM_COMMIT { 2 } else { 1 }, addr)) // SIGSEGV: SEGV_ACCERR / SEGV_MAPERR
        }
        STATUS_INT_DIVIDE_BY_ZERO => Some((8, 1, c.rip)), // SIGFPE, FPE_INTDIV
        STATUS_INT_OVERFLOW => Some((8, 2, c.rip)),       // FPE_INTOVF
        STATUS_ILLEGAL_INSTRUCTION => Some((4, 1, c.rip)), // SIGILL, ILL_ILLOPC
        _ => None,
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
    // One line, one write: several threads may fault at once.
    let mut m = MemoryBasicInformation::default();
    unsafe { VirtualQuery(rec.info[1] as *const _, &mut m, size_of::<MemoryBasicInformation>()) };
    let msg = format!("[lx] guest fault {:#x} at rip {:#x} (addr {:#x}: state {:#x} protect {:#x} alloc {:#x}) tid {} rsp {:#x} fs {:#x}
",
        rec.code, c.rip, rec.info[1], m.state, m.protect, m.allocation_base, unsafe { GetCurrentThreadId() }, c.rsp, ts().fs);
    let _ = std::io::Write::write_all(&mut std::io::stderr(), msg.as_bytes());
    proc::exit(139) // 128 + SIGSEGV, like a shell would report
}

/// The dispatch table. Linux ABI: nr in rax, args rdi rsi rdx r10 r8 r9, result (or -errno) in rax.
/// The syscall the guest is in right now (nr + 1, 0 = none) and its first three arguments, for
/// LX_SIGLOG: when a signal arrives, it shows what the guest was doing. ponytail: the last thread to
/// enter wins; per-thread slots if multithreaded hangs need it.
pub static IN_SYSCALL: [AtomicU64; 4] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

fn dispatch(c: &mut Context) -> i64 {
    let a = [c.rdi, c.rsi, c.rdx, c.r10, c.r8, c.r9];
    for (slot, v) in IN_SYSCALL.iter().zip([c.rax + 1, a[0], a[1], a[2]]) {
        slot.store(v, Relaxed);
    }
    let r = dispatch_nr(c, a);
    IN_SYSCALL[0].store(0, Relaxed);
    r
}

fn dispatch_nr(c: &mut Context, a: [u64; 6]) -> i64 {
    use fs::{AT_FDCWD as CWD, AT_SYMLINK_NOFOLLOW};
    let r = match c.rax {
        0 => fs::read(a[0], a[1], a[2]),
        1 => fs::write(a[0], a[1], a[2]),
        2 => fs::openat(CWD, a[0], a[1], a[2]),
        85 => fs::openat(CWD, a[0], 0o1101, a[1]), // creat: O_CREAT | O_WRONLY | O_TRUNC
        3 => fs::close(a[0]),
        4 => fs::fstatat(CWD, a[0], a[1], 0),
        5 => fs::fstat(a[0], a[1]),
        6 => fs::fstatat(CWD, a[0], a[1], AT_SYMLINK_NOFOLLOW),
        8 => fs::lseek(a[0], a[1] as i64, a[2]),
        9 => mmap(a[0], a[1], a[2], a[3], a[4], a[5]),
        10 => mprotect(a[0], a[1], a[2]),
        11 => munmap(a[0], a[1], c.rsp),
        29 => shmget(a[0], a[1], a[2]),
        30 => shmat(a[0], a[1], a[2]),
        67 => shmdt(a[0], c.rsp),
        31 => shmctl(a[0], a[1], a[2]),
        25 => mremap(a[0], a[1], a[2], a[3]),
        26 => msync(a[0], a[1]),
        27 => mincore(a[0], a[1], a[2]),
        12 => Ok(0),                   // brk: always "fails"; musl and glibc fall back to mmap
        13 => signal::sigaction(a[0], a[1], a[2]),
        14 => signal::sigprocmask(a[0], a[1], a[2]),
        131 => signal::sigaltstack(a[0], a[1], c.rsp),
        7 => fs::poll(a[0], a[1], a[2] as i32 as i64),
        23 => fs::select(a[0], a[1], a[2], a[3], timeval_ms(a[4])),   // ponytail: the timeout isn't updated
        270 => fs::select(a[0], a[1], a[2], a[3], timespec_ms(a[4])), // pselect6: signal mask ignored
        271 => fs::poll(a[0], a[1], timespec_ms(a[2])), // ppoll. ponytail: signal mask ignored
        34 => signal::sigsuspend(0),   // pause
        130 => signal::sigsuspend(a[0]),
        128 => signal::sigtimedwait(a[0], a[1], if a[2] == 0 { -1 } else { let [s, ns] = unsafe { *(a[2] as *const [u64; 2]) }; (s * 1000 + ns.div_ceil(1_000_000)) as i64 }),
        16 => fs::ioctl(a[0], a[1], a[2]),
        17 => fs::pread(a[0], a[1], a[2], a[3], false),
        18 => fs::pread(a[0], a[1], a[2], a[3], true),
        19 => fs::readv(a[0], a[1], a[2]),
        295 | 327 => fs::preadv(a[0], a[1], a[2], a[3], false), // preadv, preadv2 (flags ignored)
        296 | 328 => fs::preadv(a[0], a[1], a[2], a[3], true),  // pwritev, pwritev2
        285 => fs::fallocate(a[0], a[1], a[2], a[3]),
        37 => { signal::set_alarm(a[0] * 1000, 0); Ok(0) } // alarm
        38 => setitimer(a[0], a[1], a[2]),
        90 => fs::chmeta_at(CWD, a[0], true, Some(a[1]), None),                     // chmod
        91 => fs::fchmeta(a[0], Some(a[1]), None),                                  // fchmod
        268 => fs::chmeta_at(a[0], a[1], true, Some(a[2]), None),                   // fchmodat (no flags)
        452 => fs::fchmodat2(a[0], a[1], a[2], a[3]),
        92 => fs::chmeta_at(CWD, a[0], true, None, Some((a[1], a[2]))),             // chown
        93 => fs::fchmeta(a[0], None, Some((a[1], a[2]))),                          // fchown
        94 => fs::chmeta_at(CWD, a[0], false, None, Some((a[1], a[2]))),            // lchown
        260 if a[4] & 0x1000 != 0 && cstr(a[1]).is_ok_and(|p| p.is_empty()) => fs::fchmeta(a[0], None, Some((a[2], a[3]))), // fchownat(AT_EMPTY_PATH)
        260 => fs::chmeta_at(a[0], a[1], a[4] & AT_SYMLINK_NOFOLLOW == 0, None, Some((a[2], a[3]))), // fchownat
        97 => rlimit(a[0], 0, a[1]),   // getrlimit
        160 => Ok(0),                  // setrlimit: accepted, not enforced
        302 => rlimit(a[1], a[2], a[3]), // prlimit64 (self only)
        98 => { unsafe { std::ptr::write_bytes(a[1] as *mut u8, 0, 144) }; Ok(0) } // getrusage: zeros
        99 => sysinfo(a[0]),
        100 => times(a[0]),
        309 => getcpu(a[0], a[1]),
        204 => sched_getaffinity(a[1], a[2]),
        // Scheduling policy: everything is SCHED_OTHER at priority 0; changes are accepted, not applied.
        // (pthread_getschedparam failing aborted Abseil's mutex setup in node's npm.)
        143 => { if a[1] != 0 { unsafe { *(a[1] as *mut i32) = 0 } }; Ok(0) } // sched_getparam
        145 => Ok(0),                         // sched_getscheduler: SCHED_OTHER
        142 | 144 | 203 => Ok(0),             // sched_setparam, sched_setscheduler, sched_setaffinity
        146 => Ok(if a[0] == 1 || a[0] == 2 { 99 } else { 0 }), // sched_get_priority_max (FIFO, RR: 99)
        147 => Ok(if a[0] == 1 || a[0] == 2 { 1 } else { 0 }),  // sched_get_priority_min
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
        28 => madvise(a[0], a[1], a[2]),
        32 => fs::dup(a[0], 0, false),
        33 => fs::dup3(a[0], a[1], 0),
        35 => nanosleep(a[0]),
        39 => proc::getpid(),
        186 => thread::gettid(),
        24 => thread::sched_yield(),
        40 => fs::sendfile(a[0], a[1], a[2], a[3]),
        56 => proc::clone(c, a[0], a[1], a[2], a[3], a[4]),
        435 => proc::clone3(c, a[0], a[1]),
        57 | 58 => proc::fork(c, 0),   // fork, vfork
        59 => proc::execve(a[0], a[1], a[2]),
        60 => thread::exit(a[0]),      // exit: this thread (the process when it's the last one)
        231 => proc::exit(a[0]),       // exit_group
        61 => proc::wait4(a[0] as i32 as i64, a[1], a[2]),
        125 => capget(a[0], a[1]),
        126 => Ok(0), // capset: accepted. ponytail: capabilities aren't enforced
        // Callers fall back from these, so no "unimplemented" noise: io_uring (out of scope, DESIGN §5),
        // pidfd_open (Go, libuv), copy_file_range (Go's io.Copy), waitid (Go waits with wait4 then).
        425..=427 | 434 | 326 | 247 => Err(ENOSYS),
        62 => proc::kill(a[0] as i32 as i64, a[1]),
        63 => uname(a[0]),
        72 => fs::fcntl(a[0], a[1], a[2]),
        73 => fs::flock(a[0], a[1]),
        74 | 75 => fs::fsync(a[0]),    // fsync, fdatasync
        277 => fs::fsync(a[0]),        // sync_file_range: the whole file (dpkg flushes before renaming)
        162 | 306 => Ok(0),            // sync, syncfs: NT writes back on its own; fsync covers durability
        79 => fs::getcwd(a[0], a[1]),
        80 => fs::chdir(a[0]),
        81 => fs::fchdir(a[0]),
        82 => fs::renameat(CWD, a[0], CWD, a[1]),
        83 => fs::mkdirat(CWD, a[0], a[1]),
        133 => fs::mknodat(CWD, a[0], a[1]),
        84 => fs::unlinkat(CWD, a[0], 0x200),
        87 => fs::unlinkat(CWD, a[0], 0),
        76 => fs::truncate(CWD, a[0], None, a[1]),
        77 => fs::truncate(0, 0, Some(a[0]), a[1]),
        88 => fs::symlinkat(a[0], CWD, a[1]),
        89 => fs::readlinkat(CWD, a[0], a[1], a[2]),
        95 => fs::umask(a[0]),
        96 => gettimeofday(a[0]),
        102 | 107 => Ok(proc::UID.load(Relaxed) as i64), // getuid, geteuid
        104 | 108 => Ok(proc::GID.load(Relaxed) as i64), // getgid, getegid
        105 => proc::set_id(&proc::UID, a[0]),            // setuid
        106 => proc::set_id(&proc::GID, a[0]),            // setgid
        113 | 117 => proc::set_id(&proc::UID, a[1]),      // setreuid, setresuid: the effective id
        114 | 119 => proc::set_id(&proc::GID, a[1]),      // setregid, setresgid
        118 => proc::get_res(&proc::UID, [a[0], a[1], a[2]]), // getresuid
        120 => proc::get_res(&proc::GID, [a[0], a[1], a[2]]), // getresgid
        157 => prctl(a[0], a[1]),
        115 => Ok(0),                  // getgroups: no supplementary groups
        116 => Ok(0),                  // setgroups: accepted
        109 => Ok(0),                  // setpgid. ponytail: no process groups / job control
        110 => proc::getppid(),
        111 | 112 | 121 => proc::getpid(), // getpgrp, setsid, getpgid
        158 if a[0] == 0x1002 => { ts().fs = a[1]; Ok(0) } // arch_prctl(ARCH_SET_FS)
        217 => fs::getdents64(a[0], a[1], a[2]),
        202 => thread::futex(a[0], a[1], a[2], a[3], a[5]),
        324 => thread::membarrier(a[0]),
        284 => fs::eventfd(a[0], 0),
        283 => fs::timerfd_create(a[0], a[1]),
        286 => fs::timerfd_settime(a[0], a[1], a[2], a[3]),
        287 => fs::timerfd_gettime(a[0], a[1]),
        290 => fs::eventfd(a[0], a[1]),
        319 => fs::memfd_create(a[0], a[1]),
        282 => fs::signalfd(a[0], a[1], a[2], 0),
        289 => fs::signalfd(a[0], a[1], a[2], a[3]),
        218 => { ts().clear_tid = a[0]; thread::gettid() } // set_tid_address
        230 => clock_nanosleep(a[0], a[1], a[2]),
        228 => clock_gettime(a[0], a[1]),
        229 => clock_getres(a[1]),
        201 => time(a[0]),
        221 => Ok(0),                  // fadvise64: advice only
        237 | 238 => Ok(0),            // mbind, set_mempolicy: NUMA placement has no meaning here; accept it
        239 => Err(ENOSYS),            // get_mempolicy: callers treat this as "no NUMA" 
        188..=199 => Err(95),          // *xattr: EOPNOTSUPP, like a filesystem without extended attributes
        436 => fs::close_range(a[0], a[1], a[2]),
        86 => fs::linkat(CWD, a[0], CWD, a[1], 0),
        265 => fs::linkat(a[0], a[1], a[2], a[3], a[4]),
        280 => fs::utimensat(a[0], a[1], a[2], a[3]),
        137 => fs::statfs(Some(a[0]), None, a[1]),
        138 => fs::statfs(None, Some(a[0]), a[1]),
        299 => net::sys_mmsg(a[0], a[1], a[2], a[3], false), // recvmmsg
        307 => net::sys_mmsg(a[0], a[1], a[2], a[3], true),  // sendmmsg
        257 => fs::openat(a[0], a[1], a[2], a[3]),
        258 => fs::mkdirat(a[0], a[1], a[2]),
        259 => fs::mknodat(a[0], a[1], a[2]),
        262 => fs::fstatat(a[0], a[1], a[2], a[3]),
        332 => fs::statx(a[0], a[1], a[2], a[4]),
        263 => fs::unlinkat(a[0], a[1], a[2]),
        264 | 316 => fs::renameat(a[0], a[1], a[2], a[3]),
        266 => fs::symlinkat(a[0], a[1], a[2]),
        267 => fs::readlinkat(a[0], a[1], a[2], a[3]),
        269 | 439 => fs::faccessat(a[0], a[1]),
        273 => Ok(0),                  // set_robust_list
        // tkill, tgkill. ponytail: signals are process-wide; whichever thread returns from a syscall next runs it.
        200 => signal::send_thread(a[0], a[1]),        // tkill
        234 => if crate::proc::host_pid(a[0] as u32) == crate::proc::pid() { signal::send_thread(a[1], a[2]) } else { proc::kill(a[0] as i32 as i64, a[2]) }, // tgkill
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
    if strace() {
        // Every syscall, like strace: pid, number, first four arguments, result.
        let res = match r { Ok(v) => format!("{v:#x}"), Err(e) => format!("-{e}") };
        dlog(format_args!("pid {} syscall {} ({:#x}, {:#x}, {:#x}, {:#x}) = {res}", unsafe { GetCurrentProcessId() }, c.rax, a[0], a[1], a[2], a[3]));
    } else if let Err(e) = r && debug() {
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

/// Visit [addr, addr+len) region by region: NT calls refuse to span allocations.
/// Returns false if part of the range isn't reserved at all, or `f` fails.
fn each_region(addr: u64, len: u64, mut f: impl FnMut(u64, u64, u32) -> bool) -> bool {
    let (mut p, end) = (addr, addr + len);
    while p < end {
        let mut mbi = MemoryBasicInformation::default();
        if unsafe { VirtualQuery(p as *const _, &mut mbi, size_of::<MemoryBasicInformation>()) } == 0 {
            return false;
        }
        let next = (mbi.base as u64 + mbi.region_size as u64).min(end);
        if mbi.state == MEM_FREE || !f(p, next - p, mbi.state) {
            return false;
        }
        p = next;
    }
    true
}

/// Set protection over a range, committing reserved pages on the way (Linux: mprotect of a PROT_NONE
/// reservation makes it usable). PROT_NONE leaves reserved pages reserved.
fn protect(addr: u64, len: u64, prot: u32) -> bool {
    each_region(addr, len, |p, n, state| {
        let mut old = 0;
        match state {
            MEM_COMMIT => unsafe { VirtualProtect(p as *mut _, n as usize, prot, &mut old) != 0 },
            _ if prot == 0x01 => true, // reserved and staying inaccessible
            _ => unsafe { !VirtualAlloc(p as *mut _, n as usize, MEM_COMMIT, prot).is_null() },
        }
    })
}

/// Drop the contents of a range (reserved again, zero on next commit) without touching the pages.
fn decommit(addr: u64, len: u64) -> bool {
    each_region(addr, len, |p, n, state| {
        state != MEM_COMMIT || unsafe { VirtualFree(p as *mut _, n as usize, MEM_DECOMMIT) != 0 }
    })
}

fn mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> R {
    const MAP_SHARED: u64 = 0x01;
    const MAP_FIXED: u64 = 0x10;
    const MAP_ANONYMOUS: u64 = 0x20;
    if len == 0 || addr % PAGE != 0 || off % PAGE != 0 {
        return Err(EINVAL);
    }
    let len = len.next_multiple_of(PAGE);
    let reserve_only = prot == 0 && flags & MAP_ANONYMOUS != 0; // PROT_NONE: address space, no memory
    if flags & MAP_SHARED != 0 && !reserve_only {
        return mmap_shared(addr, len, prot, flags & MAP_FIXED != 0, (flags & MAP_ANONYMOUS == 0).then_some(fd), off);
    }
    let p = if flags & MAP_FIXED != 0 {
        // Inside our reservations (ld.so carving up a library span, Go committing arena chunks): replace the
        // contents with fresh zero pages; elsewhere, a new reservation at exactly that address.
        if decommit(addr, len) {
            if !reserve_only && !protect(addr, len, PAGE_READWRITE as u32) {
                return Err(ENOMEM);
            }
        } else if alloc_ex(Some(addr), len, !reserve_only) != Some(addr) {
            return Err(ENOMEM); // ponytail: partly free, partly ours
        }
        addr
    } else {
        // A free hint is honored, like Linux (Go places its heap with hints); otherwise our own window.
        let hinted = (addr != 0).then(|| alloc_ex(Some(addr), len, !reserve_only)).flatten();
        hinted.or_else(|| alloc_ex(None, len, !reserve_only)).ok_or(ENOMEM)?
    };
    if reserve_only {
        return Ok(p as i64);
    }
    if flags & MAP_ANONYMOUS == 0 {
        // ponytail: file mappings are private copies; MAP_SHARED writes never reach the file.
        fs::read_at(fd, unsafe { guest_mut(p, len as usize) }, off)?;
    }
    if prot & 4 != 0 {
        // A file mapping: patch only its executable sections (see elf::exec_ranges); anonymous: all of it.
        let ranges = (flags & MAP_ANONYMOUS == 0)
            .then(|| {
                let mut read = |o: u64, buf: &mut [u8]| fs::read_at(fd, buf, o).is_ok_and(|n| n as usize == buf.len());
                crate::elf::exec_ranges(&mut read, off, len)
            })
            .flatten()
            .unwrap_or(vec![(off, len)]);
        for (o, n) in ranges {
            patch_code(p + (o - off), n as usize);
        }
    }
    protect(p, len, page_prot(prot));
    Ok(p as i64)
}

// ---- MAP_SHARED: views of NT sections ----
//
// A shared mapping is a view of a section: pagefile-backed for anonymous memory, the file's own for a
// file. Every process mapping it (forked children included) sees the same pages, and writes reach the
// file. Views aren't in ALLOCS, so fork doesn't copy them: the child maps the same section at the same
// address instead (`snapshot` / `restore`). Views must start on NT's 64K granularity, so an offset that
// isn't 64K-aligned maps from the aligned offset below it and returns a pointer into the view.
// ponytail: munmap of part of a view unmaps all of it; mremap of a view makes a private copy.

struct View {
    base: u64,
    len: u64,
    section: isize,
    off: u64,
    access: u32,
}
static VIEWS: Mutex<Vec<View>> = Mutex::new(Vec::new());

const FILE_MAP_WRITE: u32 = 0x2;
const FILE_MAP_READ: u32 = 0x4;
const FILE_MAP_EXECUTE: u32 = 0x20;

fn mmap_shared(addr: u64, len: u64, prot: u64, fixed: bool, file: Option<u64>, off: u64) -> R {
    let write = prot & 2 != 0;
    let delta = off % 0x10000;
    let aoff = off - delta;
    let mut vlen = delta + len;
    let section = match file {
        None => unsafe { CreateFileMappingW(-1, std::ptr::null_mut(), PAGE_READWRITE, (len >> 32) as u32, len as u32, std::ptr::null()) },
        Some(fd) => {
            let (h, size) = fs::file_handle(fd)?;
            if size <= aoff {
                return Err(ENXIO); // ponytail: mapping wholly past the end of the file (Linux: SIGBUS on touch)
            }
            // NT views can't reach past the file's end (it maps the last partial page whole anyway).
            vlen = vlen.min(size - aoff);
            let exec = prot & 4 != 0;
            let rw = if exec { 0x40 } else { PAGE_READWRITE }; // PAGE_EXECUTE_READWRITE
            let mut s = unsafe { CreateFileMappingW(h, std::ptr::null_mut(), rw, 0, 0, std::ptr::null()) };
            if s == 0 && !write {
                // A file opened read-only can still be mapped for reading.
                s = unsafe { CreateFileMappingW(h, std::ptr::null_mut(), if exec { 0x20 } else { 0x02 }, 0, 0, std::ptr::null()) };
            }
            if s == 0 {
                return Err(EACCES);
            }
            s
        }
    };
    if section == 0 {
        return Err(ENOMEM);
    }
    let access = if write { FILE_MAP_WRITE } else { FILE_MAP_READ } | if prot & 4 != 0 { FILE_MAP_EXECUTE } else { 0 };
    let view_at = |base: u64| unsafe { MapViewOfFileEx(section, access, (aoff >> 32) as u32, aoff as u32, vlen as usize, base as *mut _) } as u64;
    let base = if fixed {
        if delta != 0 {
            unsafe { CloseHandle(section) };
            return Err(EINVAL);
        }
        unmap_views(addr, len); // replacing an earlier shared mapping there
        let whole = ALLOCS.lock().unwrap().iter().position(|&(b, l)| b == addr && l == len);
        if let Some(i) = whole {
            // Replacing one whole private mapping of ours: give its address space back first.
            unsafe { VirtualFree(addr as *mut _, 0, MEM_RELEASE) };
            ALLOCS.lock().unwrap().remove(i);
        }
        match view_at(addr) {
            got if got == addr => addr,
            _ => {
                unsafe { CloseHandle(section) };
                return Err(ENOMEM); // ponytail: a fixed shared mapping over part of a private one
            }
        }
    } else {
        loop {
            let a = NEXT.fetch_add(vlen.next_multiple_of(0x10000), Relaxed);
            if a + vlen > WINDOW.1 {
                unsafe { CloseHandle(section) };
                return Err(ENOMEM);
            }
            if view_at(a) == a {
                break a;
            }
            // Only "that address is taken" is worth trying elsewhere; any other refusal is final.
            const ERROR_INVALID_ADDRESS: u32 = 487;
            let e = unsafe { GetLastError() };
            if e != ERROR_INVALID_ADDRESS {
                unsafe { CloseHandle(section) };
                return Err(if e == 5 { EACCES } else { ENOMEM });
            }
        }
    };
    if prot == 0 {
        let mut old = 0;
        unsafe { VirtualProtect(base as *mut _, vlen as usize, 0x01, &mut old) }; // PROT_NONE
    }
    VIEWS.lock().unwrap().push(View { base, len: vlen, section, off: aoff, access });
    Ok((base + delta) as i64)
}

/// Unmap every shared view overlapping [addr, addr+len). Returns whether there was one.
fn unmap_views(addr: u64, len: u64) -> bool {
    let mut views = VIEWS.lock().unwrap();
    let before = views.len();
    views.retain(|v| {
        if v.base < addr + len && addr < v.base + v.len {
            unsafe {
                UnmapViewOfFile(v.base as *mut _);
                CloseHandle(v.section);
            }
            false
        } else {
            true
        }
    });
    views.len() != before
}

/// Is `addr` inside a MAP_SHARED view (memory other processes may also see)?
pub fn in_shared_view(addr: u64) -> bool {
    VIEWS.lock().unwrap().iter().any(|v| (v.base..v.base + v.len).contains(&addr))
}

fn msync(addr: u64, len: u64) -> R {
    unsafe { FlushViewOfFile(addr as *const _, len as usize) };
    Ok(0)
}

/// Shared views for a forked child: (base, len, section, offset, access) with the sections made
/// inheritable for the duration of the fork (`views_inheritable(false)` afterwards).
fn views_snapshot() -> Vec<u64> {
    let views = VIEWS.lock().unwrap();
    let mut v = vec![views.len() as u64];
    for w in views.iter() {
        unsafe { SetHandleInformation(w.section, 1, 1) };
        v.extend([w.base, w.len, w.section as u64, w.off, w.access as u64]);
    }
    v
}

/// Back to non-inheritable once the fork child has its copies (an exec'd successor mustn't keep them).
pub fn views_inheritable(on: bool) {
    for w in VIEWS.lock().unwrap().iter() {
        unsafe { SetHandleInformation(w.section, 1, on as u32) };
    }
}

fn mprotect(addr: u64, len: u64, prot: u64) -> R {
    let len = len.next_multiple_of(PAGE);
    if prot & 4 != 0 {
        // Newly executable memory (JITs, ld.so): scan before it can run. Already-patched code rescans clean.
        // RWX while patching, not RW: another thread may already be running code in this range.
        protect(addr, len, 0x40);
        patch_code(addr, len as usize);
    }
    if protect(addr, len, page_prot(prot)) { Ok(0) } else { Err(ENOMEM) }
}

/// Moves only (MREMAP_MAYMOVE): reservations can't grow in place. Keeps the old protection.
fn mremap(old: u64, old_len: u64, new_len: u64, flags: u64) -> R {
    const MREMAP_MAYMOVE: u64 = 1;
    if new_len == 0 {
        return Err(EINVAL);
    }
    // Unmapped is EFAULT before anything else: musl's pthread_getattr_np finds the main thread's stack
    // size by growing pages below it in place until one isn't mapped (ENOMEM means "mapped, keep going").
    let mut m = MemoryBasicInformation::default();
    if unsafe { VirtualQuery(old as *const _, &mut m, size_of::<MemoryBasicInformation>()) } == 0 || m.state != MEM_COMMIT {
        return Err(EFAULT);
    }
    let (old_pages, new_pages) = (old_len.next_multiple_of(PAGE), new_len.next_multiple_of(PAGE));
    if new_pages <= old_pages {
        if new_pages < old_pages {
            munmap(old + new_pages, old_pages - new_pages, 0)?; // shrinking stays in place
        }
        return Ok(old as i64);
    }
    if flags & MREMAP_MAYMOVE == 0 {
        return Err(ENOMEM); // ponytail: never grown in place
    }
    let new = alloc(None, new_len).ok_or(ENOMEM)?;
    unsafe { std::ptr::copy_nonoverlapping(old as *const u8, new as *mut u8, old_len.min(new_len) as usize) };
    protect(new, new_len.next_multiple_of(PAGE), m.protect);
    munmap(old, old_len, 0)?;
    Ok(new as i64)
}

// CHOWN DAC_OVERRIDE FOWNER FSETID KILL SETGID SETUID SETPCAP NET_BIND_SERVICE NET_RAW SYS_CHROOT MKNOD
// AUDIT_WRITE SETFCAP: what `docker run` grants by default (and its bounding set).
const DOCKER_CAPS: u32 = 1 | 1 << 1 | 1 << 3 | 1 << 4 | 1 << 5 | 1 << 6 | 1 << 7 | 1 << 8 | 1 << 10 | 1 << 13
    | 1 << 18 | 1 << 27 | 1 << 29 | 1 << 31;
const CAP_LAST_CAP: u64 = 40;

/// prctl(option, arg2): the capability queries answer like Docker's default set, everything else is
/// accepted (PR_SET_NAME, PR_SET_DUMPABLE, PR_SET_PDEATHSIG, ...). setpriv and libcap find the highest
/// capability by asking PR_CAPBSET_READ for 0, 1, 2, ... until EINVAL; answering 0 forever hung the stock
/// redis image's entrypoint (`setpriv -d`).
fn prctl(option: u64, arg2: u64) -> R {
    const PR_CAPBSET_READ: u64 = 23;
    const PR_CAP_AMBIENT: u64 = 47;
    match option {
        PR_CAPBSET_READ if arg2 > CAP_LAST_CAP => Err(EINVAL),
        PR_CAPBSET_READ => Ok((arg2 < 32 && DOCKER_CAPS & 1 << arg2 != 0) as i64),
        PR_CAP_AMBIENT => Ok(0), // nothing ambient (IS_SET answers 0; raising one is accepted)
        _ => Ok(0),
    }
}

/// capget(header, data): Docker's default capability set for root, none for other users (node asks at
/// startup). A null `data` just reports the version (v3, two 32-bit words per set).
fn capget(header: u64, data: u64) -> R {
    const V3: u32 = 0x2008_0522;
    const DOCKER: u32 = DOCKER_CAPS;
    if header == 0 {
        return Err(EFAULT);
    }
    unsafe { *(header as *mut u32) = V3 };
    if data != 0 {
        let caps = if crate::proc::UID.load(Relaxed) == 0 { DOCKER } else { 0 };
        unsafe { *(data as *mut [u32; 6]) = [caps, caps, 0, 0, 0, 0] }; // effective, permitted, inheritable x2
    }
    Ok(0)
}

// ---- System V shared memory ----
//
// Postgres keeps a small segment beside its mmap'd shared memory. An attached segment is anonymous
// MAP_SHARED memory (a section view, so forked children share it). ponytail: the key table is per lx
// process, so unrelated processes don't find each other's segments, and attaching one segment twice in
// a process gives two separate copies. Neither happens in postgres (it attaches once, children fork).

struct Shm {
    key: u64,
    size: u64,
}
static SHMS: Mutex<Vec<Shm>> = Mutex::new(Vec::new());
static SHM_AT: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new()); // attached (address, size)

fn shmget(key: u64, size: u64, flags: u64) -> R {
    const IPC_CREAT: u64 = 0o1000;
    const IPC_EXCL: u64 = 0o2000;
    let mut t = SHMS.lock().unwrap();
    if key != 0 && let Some(i) = t.iter().position(|s| s.key == key) {
        return if flags & (IPC_CREAT | IPC_EXCL) == IPC_CREAT | IPC_EXCL { Err(EEXIST) } else { Ok(i as i64 + 1) };
    }
    if key != 0 && flags & IPC_CREAT == 0 {
        return Err(ENOENT);
    }
    t.push(Shm { key, size });
    Ok(t.len() as i64)
}

fn shmat(id: u64, addr: u64, flags: u64) -> R {
    const SHM_RDONLY: u64 = 0o10000;
    let size = SHMS.lock().unwrap().get((id as usize).wrapping_sub(1)).ok_or(EINVAL)?.size;
    let prot = if flags & SHM_RDONLY != 0 { 1 } else { 3 };
    let p = mmap(addr, size, prot, 0x21 | if addr != 0 { 0x10 } else { 0 }, u64::MAX, 0)? as u64; // MAP_SHARED|ANONYMOUS
    SHM_AT.lock().unwrap().push((p, size));
    Ok(p as i64)
}

fn shmdt(addr: u64, rsp: u64) -> R {
    let mut at = SHM_AT.lock().unwrap();
    let i = at.iter().position(|&(a, _)| a == addr).ok_or(EINVAL)?;
    let (a, size) = at.remove(i);
    drop(at);
    munmap(a, size, rsp)
}

/// IPC_RMID and IPC_SET are accepted; IPC_STAT reports the size and one attachment.
fn shmctl(id: u64, cmd: u64, buf: u64) -> R {
    let size = SHMS.lock().unwrap().get((id as usize).wrapping_sub(1)).ok_or(EINVAL)?.size;
    if cmd == 2 && buf != 0 {
        let mut ds = [0u64; 14]; // struct shmid_ds: ipc_perm (48 bytes), then shm_segsz, times, pids, shm_nattch
        (ds[6], ds[11]) = (size, 1);
        unsafe { *(buf as *mut [u64; 14]) = ds };
    }
    Ok(0)
}

fn munmap(addr: u64, len: u64, rsp: u64) -> R {
    let len = len.next_multiple_of(PAGE);
    // A thread unmapping its own stack is about to exit (musl's detached-thread exit does this); NT
    // still needs that stack to dispatch the final exit syscall, so leave it mapped.
    if (addr..addr + len).contains(&rsp) {
        return Ok(0);
    }
    if unmap_views(addr, len) {
        return Ok(0);
    }
    // ponytail: decommit only; the address space stays reserved (and leaks) until exit.
    decommit(addr, len);
    Ok(0)
}

/// madvise: MADV_DONTNEED / MADV_REMOVE must make private anonymous pages read back as zeros (Go's
/// scavenger counts on it); everything else is advice. Decommit + recommit gives fresh zero pages
/// without touching them. ponytail: a private file mapping should re-read the file instead.
fn madvise(addr: u64, len: u64, advice: u64) -> R {
    const MADV_DONTNEED: u64 = 4;
    const MADV_REMOVE: u64 = 9;
    if advice != MADV_DONTNEED && advice != MADV_REMOVE {
        return Ok(0);
    }
    let ok = each_region(addr, len.next_multiple_of(PAGE), |p, n, state| {
        if state != MEM_COMMIT {
            return true;
        }
        let mut m = MemoryBasicInformation::default();
        unsafe {
            VirtualQuery(p as *const _, &mut m, size_of::<MemoryBasicInformation>());
            VirtualFree(p as *mut _, n as usize, MEM_DECOMMIT) != 0
                && !VirtualAlloc(p as *mut _, n as usize, MEM_COMMIT, m.protect).is_null()
        }
    });
    if ok { Ok(0) } else { Err(ENOMEM) }
}

/// The registered guest allocation containing `addr`, as (low, high).
pub fn alloc_containing(addr: u64) -> Option<(u64, u64)> {
    ALLOCS.lock().unwrap().iter().find(|&&(b, l)| (b..b + l).contains(&addr)).map(|&(b, l)| (b, b + l))
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

pub fn now(clock: u64) -> (u64, u64) {
    let d = if clock == 0 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default() // CLOCK_REALTIME
    } else {
        START.lock().unwrap().unwrap().elapsed() // every other clock: monotonic since start
    };
    (d.as_secs(), d.subsec_nanos() as u64)
}

/// time(): seconds since the epoch, also stored at `out` if given.
fn time(out: u64) -> R {
    let (s, _) = now(0);
    if out != 0 {
        unsafe { *(out as *mut u64) = s };
    }
    Ok(s as i64)
}

/// All our clocks tick in nanoseconds (QueryPerformanceCounter is finer than that on modern hardware).
fn clock_getres(ts: u64) -> R {
    if ts != 0 {
        unsafe { *(ts as *mut [u64; 2]) = [0, 1] };
    }
    Ok(0)
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

/// Limits like a Docker container's defaults (8 MB stack, the rest unlimited), except a 1024 soft
/// open-file limit: without /proc/self/fd, apt and others fcntl every fd number up to it.
/// ponytail: new limits are accepted but not enforced.
fn rlimit(resource: u64, _new: u64, old: u64) -> R {
    const INF: u64 = u64::MAX;
    let (cur, max) = match resource {
        3 => (8 << 20, INF),        // RLIMIT_STACK
        7 => (1024, 1 << 20),       // RLIMIT_NOFILE
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

fn clock_nanosleep(clock: u64, flags: u64, req: u64) -> R {
    const TIMER_ABSTIME: u64 = 1;
    let [s, ns] = unsafe { *(req as *const [u64; 2]) };
    let want = std::time::Duration::new(s, ns as u32);
    let wait = if flags & TIMER_ABSTIME != 0 {
        let (s, ns) = now(clock);
        want.saturating_sub(std::time::Duration::new(s, ns as u32))
    } else {
        want
    };
    std::thread::sleep(wait);
    Ok(0)
}

/// A `struct timeval *` timeout in ms; NULL means wait forever (-1).
fn timeval_ms(tv: u64) -> i64 {
    if tv == 0 {
        return -1;
    }
    let [s, us] = unsafe { *(tv as *const [i64; 2]) };
    s.saturating_mul(1000).saturating_add((us + 999) / 1000) // rounded up: 0.5 ms must not become a busy poll
}

/// A `struct timespec *` timeout in ms; NULL means wait forever (-1).
fn timespec_ms(ts: u64) -> i64 {
    if ts == 0 {
        return -1;
    }
    let [s, ns] = unsafe { *(ts as *const [i64; 2]) };
    s.saturating_mul(1000).saturating_add((ns + 999_999) / 1_000_000) // rounded up, like timeval_ms
}

pub fn getrandom(buf: u64, len: u64) -> R {
    let len = len.min(u32::MAX as u64);
    unsafe { BCryptGenRandom(std::ptr::null_mut(), buf as *mut u8, len as u32, 2) };
    Ok(len as i64)
}


/// sysinfo: uptime, RAM and page file from Windows (dpkg sizes its buffers by free RAM).
/// ponytail: load averages, shared/buffer RAM and the process count are 0.
fn sysinfo(info: u64) -> R {
    let mut m = [0u64; 8]; // MEMORYSTATUSEX: dwLength + dwMemoryLoad, then ullTotalPhys, ullAvailPhys, ...
    m[0] = 64;
    if unsafe { crate::win::GlobalMemoryStatusEx(&mut m) } == 0 {
        return Err(EFAULT);
    }
    // struct sysinfo: uptime, loads[3], totalram, freeram, sharedram, bufferram, totalswap, freeswap,
    // procs (u16) + pad, totalhigh, freehigh, mem_unit (u32) + pad: 14 words on x86-64.
    let mut s = [0u64; 14];
    s[0] = unsafe { crate::win::GetTickCount64() } / 1000;
    (s[4], s[5]) = (m[1], m[2]);
    (s[8], s[9]) = (m[3].saturating_sub(m[1]), m[4].saturating_sub(m[2]));
    s[13] = 1; // mem_unit: bytes
    unsafe { *(info as *mut [u64; 14]) = s };
    Ok(0)
}

/// times: clock ticks (USER_HZ 100) since boot. ponytail: the process CPU times are 0.
fn times(buf: u64) -> R {
    if buf != 0 {
        unsafe { *(buf as *mut [u64; 4]) = [0; 4] };
    }
    Ok((unsafe { crate::win::GetTickCount64() } / 10) as i64)
}

/// getcpu: the CPU this thread runs on now, NUMA node 0.
fn getcpu(cpu: u64, node: u64) -> R {
    if cpu != 0 {
        unsafe { *(cpu as *mut u32) = crate::win::GetCurrentProcessorNumber() };
    }
    if node != 0 {
        unsafe { *(node as *mut u32) = 0 };
    }
    Ok(0)
}
/// mincore: one byte per page, 1 where committed. ENOMEM if part of the range isn't mapped at all,
/// which callers use to probe for holes (grep's stack-limit scan loops until it sees one).
fn mincore(addr: u64, len: u64, vec: u64) -> R {
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_FREE: u32 = 0x10000;
    let (start, end) = (addr & !0xfff, (addr + len + 0xfff) & !0xfff);
    let mut p = start;
    while p < end {
        let mut m = MemoryBasicInformation::default();
        if unsafe { VirtualQuery(p as *const _, &mut m, size_of::<MemoryBasicInformation>()) } == 0 || m.state == MEM_FREE {
            return Err(ENOMEM);
        }
        let top = (m.base as u64 + m.region_size as u64).min(end);
        let n = ((top - p) / 4096) as usize;
        unsafe { std::ptr::write_bytes((vec + (p - start) / 4096) as *mut u8, (m.state == MEM_COMMIT) as u8, n) };
        p = top;
    }
    Ok(0)
}

#[link(name = "winmm")]
unsafe extern "system" {
    fn timeBeginPeriod(ms: u32) -> u32;
}

/// Linux timers are ~1 ms; NT's default tick is 15.6 ms, so a 1 ms futex or condition wait took 16.
/// Turned on by the first short timed wait (per-process on Windows 11) and left on: processes that only
/// wait long, like an idle server, keep the coarse tick and its lower power use.
pub fn fine_timer() {
    static ON: std::sync::Once = std::sync::Once::new();
    ON.call_once(|| unsafe {
        timeBeginPeriod(1);
    });
}
