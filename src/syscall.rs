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
pub const EMFILE: i64 = 24;
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
    /// The syscall that just returned EINTR, + 1, if a handler with SA_RESTART should restart it (0: no).
    pub restart: u64,
    /// Signals sent to this thread alone (tkill/tgkill), and the futex address it sleeps on (0 = none),
    /// so a sender can wake it. Read and written by other threads.
    pub tpending: std::sync::atomic::AtomicU64,
    pub futex_addr: std::sync::atomic::AtomicU64,
    /// A thread other than the main one: its own auto-reset event for signal::intr_event (0 until it
    /// first waits), so a signal sent to it alone breaks its sleeps and waits too.
    pub wake: std::sync::atomic::AtomicIsize,
    /// Whether we're running on host_stack right now.
    on_host: bool,
    /// The TEB's own stack fields (StackBase, StackLimit, DeallocationStack) before the guest took over.
    /// ExitThread frees whatever DeallocationStack names, so they go back before a thread exits.
    pub host_teb: Option<[u64; 3]>,
    /// The guest's extended register state (x87/SSE/AVX...) while a direct syscall runs: Linux preserves
    /// every vector register across syscall, and our handler code doesn't. 64-byte aligned for xsave.
    xsave: Xsave,
    /// Inside lx_direct: the guest's FP state is in `xsave`, not in an exception CONTEXT.
    in_direct: bool,
    /// signal::kick sent this thread from guest code into lx_kick_entry for a pending signal: where it
    /// was, and the rcx and r11 that lx_sys_entry treats as clobbered. Written while it's suspended.
    pub kick: [std::sync::atomic::AtomicU64; 3],
    pub kicked: std::sync::atomic::AtomicBool,
    /// Set by lx_kick_entry itself: this entry into lx_direct really came from a kick. `kicked` alone
    /// can't say so: a redirect may be lost (the thread was mid exception dispatch, and NtContinue put
    /// its old context back), and its next real syscall must not be taken for the kick.
    via_kick: u8,
}

const TS_RESUME: usize = std::mem::offset_of!(ThreadState, resume);
const TS_FRAME_LEN: usize = std::mem::offset_of!(ThreadState, frame_len);
const TS_FRAME: usize = std::mem::offset_of!(ThreadState, frame);
const TS_GUEST_RSP: usize = std::mem::offset_of!(ThreadState, guest_rsp);
const TS_KICK_RIP: usize = std::mem::offset_of!(ThreadState, kick);
const TS_VIA_KICK: usize = std::mem::offset_of!(ThreadState, via_kick);
const TS_HOST_STACK: usize = std::mem::offset_of!(ThreadState, host_stack);
const TS_XSAVE: usize = std::mem::offset_of!(ThreadState, xsave);

/// Room for the largest XSAVE area of the enabled features (AVX-512 is 2,696 bytes); checked at start.
const XSAVE_MAX: usize = 4096;
#[repr(C, align(64))]
struct Xsave([u8; XSAVE_MAX]);
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

impl ThreadState {
    /// In lx's own code (a syscall, an exception): not to be interrupted by signal::kick.
    pub fn on_host(&self) -> bool {
        unsafe { std::ptr::read_volatile(&self.on_host) }
    }
}

pub fn ts_of(tid: u32) -> Option<&'static ThreadState> {
    THREAD_TS.lock().unwrap().iter().find(|e| e.0 == tid).map(|e| unsafe { &*(e.1 as *const ThreadState) })
}

/// A signal for the whole process: wake every thread parked in a futex, so one that doesn't block it
/// takes it (EINTR, then delivery). Go parks all its threads in futexes while idle, and its signal
/// handling waits for any thread to take the signal; the others just wait again (a spurious wakeup).
pub fn wake_futex_waiters() {
    for &(_, ts) in THREAD_TS.lock().unwrap().iter() {
        let ts = unsafe { &*(ts as *const ThreadState) };
        let addr = ts.futex_addr.load(Relaxed);
        if addr != 0 {
            unsafe { crate::win::WakeByAddressAll(addr as *const _) };
        }
        let ev = ts.wake.load(Relaxed);
        if ev != 0 {
            unsafe { crate::win::SetEvent(ev) }; // and one in a sleep or a pipe wait
        }
    }
}

pub fn forget_ts() {
    let me = unsafe { GetCurrentThreadId() };
    THREAD_TS.lock().unwrap().retain(|e| e.0 != me);
    let ev = ts().wake.swap(0, Relaxed);
    if ev != 0 {
        unsafe { CloseHandle(ev) };
    }
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
        frame: [0; signal::FRAME_MAX], stack: (0, 0), clear_tid: 0, altstack: None, sigmask: 0, suspended_mask: None, restart: 0,
        tpending: std::sync::atomic::AtomicU64::new(0), futex_addr: std::sync::atomic::AtomicU64::new(0),
        wake: std::sync::atomic::AtomicIsize::new(0), on_host: false, host_teb: None, xsave: Xsave([0; XSAVE_MAX]), in_direct: false,
        kick: Default::default(), kicked: Default::default(), via_kick: 0,
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
    // signal::kick's way in: like a syscall from where the thread was (r11 = that rip), only movs before
    // the pushfq so its flags stay as they were; lx_direct restores the rcx and r11 that kick saved.
    ".globl lx_kick_entry",
    "lx_kick_entry:",
    "mov rcx, qword ptr [rip + LX_TLS_OFF]",
    "mov rcx, qword ptr gs:[rcx]",
    "mov r11, qword ptr [rcx + {kick_rip}]",
    "mov byte ptr [rcx + {via_kick}], 1",  // only this entry sets it (a mov: the flags are untouched)
    "jmp 2f",
    "lx_sys_entry:",
    "mov rcx, qword ptr [rip + LX_TLS_OFF]",
    "mov rcx, qword ptr gs:[rcx]",        // ThreadState*
    "2:",
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
    // The guest's vector state: our Rust and Windows code below clobbers xmm/ymm, Linux preserves them.
    "mov r8, qword ptr [rip + LX_TLS_OFF]",
    "mov r8, qword ptr gs:[r8]",
    "lea r8, [r8 + {xsave}]",
    "mov eax, -1",
    "mov edx, -1",
    ".byte 0x49, 0x0f, 0xae, 0x30",       // xsaveopt64 [r8]: every enabled component, unchanged ones skipped
    "mov rcx, rsp",
    "sub rsp, 32",
    "call lx_direct",
    "add rsp, 32",
    "mov r8, qword ptr [rip + LX_TLS_OFF]",
    "mov r8, qword ptr gs:[r8]",
    "lea r8, [r8 + {xsave}]",
    "mov eax, -1",
    "mov edx, -1",
    ".byte 0x49, 0x0f, 0xae, 0x28",       // xrstor64 [r8]
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
    xsave = const TS_XSAVE,
    kick_rip = const TS_KICK_RIP,
    via_kick = const TS_VIA_KICK,
);
unsafe extern "C" {
    fn lx_fs_tramp();
    fn lx_resume(regs: *const [u64; 18]) -> !;
    fn lx_sys_entry();
    fn lx_kick_entry();
}

pub fn kick_entry_addr() -> u64 {
    lx_kick_entry as *const () as u64
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

/// A syscall that returned EINTR and that Linux restarts after a handler with SA_RESTART (ERESTARTSYS):
/// its number + 1, else 0. Not poll/select/epoll_wait, sleeps or sigsuspend, which return EINTR anyway.
fn restartable(nr: u64, ret: i64) -> u64 {
    // read write pread pwrite readv writev sendfile connect accept sendto recvfrom sendmsg recvmsg wait4
    // fcntl (F_SETLKW) flock futex waitid openat accept4 preadv pwritev splice tee
    const NRS: [u64; 25] = [0, 1, 17, 18, 19, 20, 40, 42, 43, 44, 45, 46, 47, 61, 72, 73, 202, 247, 257, 288, 295, 296, 275, 276, 16];
    if ret == -EINTR && NRS.contains(&nr) { nr + 1 } else { 0 }
}

/// Rust half of the direct path, on the thread's lx stack. Same semantics as the exception path.
#[unsafe(no_mangle)]
unsafe extern "system" fn lx_direct(f: *mut DirectFrame) {
    let f = unsafe { &mut *f };
    let c = &mut f.ctx;
    let t = ts();
    t.on_host = true;
    t.in_direct = true;
    let (base, limit): (u64, u64);
    let top = t.host_stack;
    unsafe {
        // TEB bounds describe the stack we're on (for __chkstk); the guest's go back on the way out.
        std::arch::asm!("mov {b}, qword ptr gs:[0x08]", "mov {l}, qword ptr gs:[0x10]", b = out(reg) base, l = out(reg) limit);
        std::arch::asm!("mov qword ptr gs:[0x08], {b}", "mov qword ptr gs:[0x10], {l}", b = in(reg) top, l = in(reg) top - HOST_STACK as u64);
    }
    // A kick's flag is cleared on any entry: if this isn't the kick's (its redirect was lost), the next
    // kick may go ahead.
    t.kicked.store(false, std::sync::atomic::Ordering::SeqCst);
    if std::mem::take(&mut t.via_kick) != 0 {
        // Not a syscall: signal::kick stopped the thread in guest code. Every register is as it was.
        c.rcx = t.kick[1].load(std::sync::atomic::Ordering::SeqCst);
        c.r11 = t.kick[2].load(std::sync::atomic::Ordering::SeqCst);
    } else if c.rax == 15 {
        signal::sigreturn(c); // rt_sigreturn: everything comes from the ucontext
    } else {
        let next = c.rip;
        c.rip = next - 2; // what the trap path sees: the address of the syscall instruction
        let nr = c.rax;
        let ret = dispatch(c);
        t.restart = restartable(nr, ret);
        (c.rax, c.rcx, c.r11, c.rip) = (ret as u64, next, c.eflags as u64, next);
    }
    if let Some(frame) = signal::deliver(c) {
        // Unlike the trap path, nothing of ours lives on the guest stack: the frame goes straight there.
        unsafe { std::ptr::copy_nonoverlapping(frame.as_ptr(), c.rsp as *mut u8, frame.len()) };
    }
    f.flags = c.eflags as u64;
    unsafe { std::arch::asm!("mov qword ptr gs:[0x08], {b}", "mov qword ptr gs:[0x10], {l}", b = in(reg) base, l = in(reg) limit) };
    ts().on_host = false;
    ts().in_direct = false;
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
    // We may still be running on the guest's stack (a trapped execve's handler), so the allocation that
    // holds it stays reserved, but only the pages near where we are stay committed: Go's thread stacks
    // live in its heap arenas, and keeping all of that made every waiting exec proxy hold its copy of
    // the parent's heap (Grafana: 13 proxies, ~1 GB).
    let here = &lo as *const u64 as u64;
    let (keep_lo, keep_hi) = ((here & !(PAGE - 1)).saturating_sub(256 << 10), (here & !(PAGE - 1)) + (1 << 20));
    let mut allocs = ALLOCS.lock().unwrap();
    allocs.retain(|&(base, len)| {
        if (base..base + len).contains(&lo) || (base..base + len).contains(&here) {
            let end = base + len;
            decommit(base, keep_lo.clamp(base, end) - base);
            decommit(keep_hi.clamp(base, end), end - keep_hi.clamp(base, end));
            return true;
        }
        release_span(base, len); // a shared image (map_image) is several allocations
        false
    });
    CODE.lock().unwrap().regions.clear(); // nothing of the old program runs any more
    unmap_views(0, u64::MAX);
    crate::jump::clear();
}

/// execve in place: the old program's memory, views, shared memory attachments and code patches go,
/// so the new one starts in an empty guest address space. We run on our own stack here (lx_direct or the
/// exception handler's), but an allocation holding it would stay.
pub fn reset_for_exec() {
    let marker = 0u64;
    let here = &marker as *const u64 as u64;
    ALLOCS.lock().unwrap().retain(|&(base, len)| {
        if (base..base + len).contains(&here) {
            return true;
        }
        release_span(base, len);
        false
    });
    unmap_views(0, u64::MAX);
    for v in COW_VIEWS.lock().unwrap().drain(..) {
        unsafe { CloseHandle(v.section) };
    }
    SHM_AT.lock().unwrap().clear();
    {
        let mut c = CODE.lock().unwrap();
        c.regions.clear();
        c.sites.clear();
    }
    crate::jump::clear();
    MAP_GEN.fetch_add(1, Relaxed);
    let t = ts();
    (t.fs, t.clear_tid) = (0, 0);
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
        // The parent's copy-on-write file views (mmap_cow) have WRITECOPY protections, which private
        // memory can't take (VirtualProtect fails, leaving code READWRITE: not executable): the private kind.
        let prot = match prot & 0xff {
            0x08 => prot & !0xff | 0x04, // PAGE_WRITECOPY -> PAGE_READWRITE
            0x80 => prot & !0xff | 0x40, // PAGE_EXECUTE_WRITECOPY -> PAGE_EXECUTE_READWRITE
            _ => prot,
        };
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
        VIEWS.lock().unwrap().push(View { base, len, section, off, access, full: len, file: 0, prot: (0, 0) });
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
    // CPUID.(EAX=0Dh,ECX=0).EBX: the XSAVE area size for what the OS enabled (XCR0).
    let need = std::arch::x86_64::__cpuid_count(0xd, 0).ebx as usize;
    assert!(need <= XSAVE_MAX, "XSAVE area of {need} bytes doesn't fit the {XSAVE_MAX} reserved");
    assert!(std::arch::x86_64::__cpuid_count(0xd, 1).eax & 1 != 0, "this CPU lacks XSAVEOPT"); // every Windows 11 CPU has it
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
    // Counting the sites takes a whole decode of its own: only for the debug report.
    let all = if debug() || patchlog() { find_syscalls(code, addr).len() } else { 0 };
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
            let nr = c.rax;
            let ret = dispatch(c);
            ts().restart = restartable(nr, ret);
            let next = c.rip + 2;
            (c.rax, c.rcx, c.r11, c.rip) = (ret as u64, next, c.eflags as u64, next); // kernel ABI: rcx=rip, r11=rflags
            resume_with_signals(c)
        }
        STATUS_ACCESS_VIOLATION if grow_view(rec.info[1] as u64, rec.info[0] == 1) => resume(c, c.rip),
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

/// " in <file> at file offset <n>" when `rip` is in a file's copy-on-write view (shared libraries), for crash
/// reports: which library and where, without a map of the guest's address space.
fn code_file(rip: u64) -> String {
    unsafe extern "system" {
        fn K32GetMappedFileNameW(process: isize, addr: *const std::ffi::c_void, name: *mut u16, size: u32) -> u32;
    }
    let mut name = [0u16; 512];
    let n = unsafe { K32GetMappedFileNameW(GetCurrentProcess(), rip as *const _, name.as_mut_ptr(), name.len() as u32) } as usize;
    let Some(v) = COW_VIEWS.try_lock().ok().and_then(|vs| vs.iter().find(|v| (v.base..v.base + v.len).contains(&rip)).map(|v| (v.base, v.off))) else {
        return String::new();
    };
    let path = String::from_utf16_lossy(&name[..n]);
    format!(" in {} at file offset {:#x}", path.rsplit('\\').next().unwrap_or(&path), v.1 + (rip - v.0))
}

fn guest_crash(rec: &ExceptionRecord, c: &Context) -> ! {
    // One line, one write: several threads may fault at once.
    let mut m = MemoryBasicInformation::default();
    unsafe { VirtualQuery(rec.info[1] as *const _, &mut m, size_of::<MemoryBasicInformation>()) };
    let msg = format!("[lx] guest fault {:#x} at rip {:#x}{} (addr {:#x}: state {:#x} protect {:#x} alloc {:#x}) tid {} rsp {:#x} fs {:#x}
",
        rec.code, c.rip, code_file(c.rip), rec.info[1], m.state, m.protect, m.allocation_base, unsafe { GetCurrentThreadId() }, c.rsp, ts().fs);
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
    // mmap, mprotect, munmap, mremap, brk, shmat/shmdt, truncate/ftruncate (views re-mapped): what a
    // page that put_guest checked once may no longer be.
    if matches!(c.rax, 9 | 10 | 11 | 12 | 25 | 30 | 67 | 76 | 77) {
        MAP_GEN.fetch_add(1, Relaxed);
    }
    for (slot, v) in IN_SYSCALL.iter().zip([c.rax + 1, a[0], a[1], a[2]]) {
        slot.store(v, Relaxed);
    }
    let main = unsafe { GetCurrentThreadId() } == crate::thread::MAIN_TID.load(Relaxed);
    if main {
        crate::ptable::syscall_state(true);
    }
    let r = match crate::seccomp::check(c.rax, &a, c.rip) {
        Some(r) => r.unwrap_or_else(|e| -e),
        None => dispatch_nr(c, a),
    };
    if main {
        crate::ptable::syscall_state(false);
    }
    // A write to a pipe or socket nobody reads any more is EPIPE plus SIGPIPE, whose default kills the
    // writer: that's how a producer stops once its consumer quit (`yes | head -1`). A send can opt out
    // with MSG_NOSIGNAL; Python and others ignore SIGPIPE, and raise drops an ignored signal.
    const MSG_NOSIGNAL: u64 = 0x4000;
    if r == -EPIPE && match c.rax {
        1 | 18 | 20 | 296 | 328 => true, // write, pwrite64, writev, pwritev, pwritev2
        44 | 307 => a[3] & MSG_NOSIGNAL == 0, // sendto, sendmmsg
        46 => a[2] & MSG_NOSIGNAL == 0,       // sendmsg
        _ => false,
    } {
        let _ = signal::raise(13);
    }
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
        64 => crate::sysvipc::semget(a[0], a[1], a[2]),
        65 => crate::sysvipc::semtimedop(a[0], a[1], a[2], 0), // semop
        220 => crate::sysvipc::semtimedop(a[0], a[1], a[2], a[3]),
        66 => crate::sysvipc::semctl(a[0], a[1], a[2], a[3]),
        68 => crate::sysvipc::msgget(a[0], a[1]),
        69 => crate::sysvipc::msgsnd(a[0], a[1], a[2], a[3]),
        70 => crate::sysvipc::msgrcv(a[0], a[1], a[2], a[3], a[4]),
        71 => crate::sysvipc::msgctl(a[0], a[1], a[2]),
        30 => shmat(a[0], a[1], a[2]),
        67 => shmdt(a[0], c.rsp),
        31 => shmctl(a[0], a[1], a[2]),
        25 => mremap(a[0], a[1], a[2], a[3]),
        26 => msync(a[0], a[1]),
        27 => mincore(a[0], a[1], a[2]),
        12 => Ok(0),                   // brk: always "fails"; musl and glibc fall back to mmap
        13 => signal::sigaction(a[0], a[1], a[2]),
        14 => signal::sigprocmask(a[0], a[1], a[2]),
        127 => signal::sigpending(a[0], a[1]),
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
        327 | 328 if a[5] & !0x1f != 0 => Err(95), // preadv2/pwritev2: unknown RWF_* flags are EOPNOTSUPP (known ones are hints)
        295 | 327 => fs::preadv(a[0], a[1], a[2], a[3], false), // preadv, preadv2
        296 | 328 => fs::preadv(a[0], a[1], a[2], a[3], true),  // pwritev, pwritev2
        285 => fs::fallocate(a[0], a[1], a[2], a[3]),
        37 => Ok(signal::set_alarm(a[0] * 1000, 0).0.div_ceil(1000) as i64), // alarm: the seconds left of the old one
        38 => setitimer(a[0], a[1], a[2]),
        36 => getitimer(a[0], a[1]),
        // Setting the clock: a container may not (Docker's seccomp profile answers EPERM too).
        // adjtimex/clock_adjtime with modes 0 only read: the clock is in sync, nothing being adjusted.
        227 | 164 => Err(EPERM), // clock_settime, settimeofday
        159 => adjtimex_read(a[0]),
        305 => if valid_clock(a[0]) { adjtimex_read(a[1]) } else { Err(EINVAL) }, // clock_adjtime
        222 => signal::timer_create(a[0], a[1], a[2]),
        223 => signal::timer_settime(a[0], a[1], a[2], a[3]),
        224 => signal::timer_gettime(a[0], a[1]),
        225 => signal::timer_getoverrun(a[0]),
        226 => signal::timer_delete(a[0]),
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
        160 => rlimit(a[0], a[1], 0),  // setrlimit
        302 => rlimit(a[1], a[2], a[3]), // prlimit64 (self only)
        98 => { unsafe { std::ptr::write_bytes(a[1] as *mut u8, 0, 144) }; Ok(0) } // getrusage: zeros
        99 => sysinfo(a[0]),
        100 => times(a[0]),
        309 => getcpu(a[0], a[1]),
        204 => sched_getaffinity(a[0], a[1], a[2]),
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
        213 if (a[0] as i32) <= 0 => Err(EINVAL), // epoll_create: size must be positive (and is ignored)
        213 => net::sys_epoll_create(0),
        291 => net::sys_epoll_create(a[0]),
        233 => net::sys_epoll_ctl(a[0], a[1], a[2], a[3]),
        232 | 281 => net::sys_epoll_wait(a[0], a[1], a[2], a[3] as i32 as i64), // pwait: mask ignored
        441 => net::sys_epoll_wait(a[0], a[1], a[2], timespec_ms(a[3])),
        20 => fs::writev(a[0], a[1], a[2]),
        22 => fs::pipe2(a[0], 0),
        21 => fs::faccessat(CWD, a[0], a[1]),
        28 => madvise(a[0], a[1], a[2]),
        149..=152 | 325 => Ok(0), // mlock, munlock, mlockall, munlockall, mlock2. ponytail: pages may still be paged out
        140 => Ok(20), // getpriority: the raw call answers 20 - nice; everyone runs at nice 0 (rpm asks)
        141 => Ok(0),  // setpriority. ponytail: accepted, not applied
        32 => fs::dup(a[0], 0, false),
        33 => fs::dup3(a[0], a[1], 0),
        35 => nanosleep(a[0], a[1]),
        39 => proc::getpid(),
        186 => thread::gettid(),
        24 => thread::sched_yield(),
        40 => fs::sendfile(a[0], a[1], a[2], a[3]),
        // splice(in, off_in, out, off_out, len, flags) is sendfile through a buffer here. ponytail: no off_out.
        275 => if a[3] != 0 { Err(EINVAL) } else { fs::sendfile(a[2], a[0], a[1], a[4]) },
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
        247 => proc::waitid(a[0], a[1], a[2], a[3]),
        425..=427 | 434 | 326 => Err(ENOSYS),
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
        96 => gettimeofday(a[0], a[1]),
        102 | 107 => Ok(proc::UID.load(Relaxed) as i64), // getuid, geteuid
        104 | 108 => Ok(proc::GID.load(Relaxed) as i64), // getgid, getegid
        105 => proc::set_id(&proc::UID, a[0]),            // setuid
        106 => proc::set_id(&proc::GID, a[0]),            // setgid
        113 | 117 => proc::set_id(&proc::UID, a[1]),      // setreuid, setresuid: the effective id
        114 | 119 => proc::set_id(&proc::GID, a[1]),      // setregid, setresgid
        118 => proc::get_res(&proc::UID, [a[0], a[1], a[2]]), // getresuid
        120 => proc::get_res(&proc::GID, [a[0], a[1], a[2]]), // getresgid
        157 if a[0] == 21 => crate::seccomp::mode(),       // PR_GET_SECCOMP
        157 if a[0] == 22 => crate::seccomp::set(a[1], a[2]), // PR_SET_SECCOMP
        157 => prctl(a[0], a[1]),
        317 => crate::seccomp::seccomp(a[0], a[1], a[2]),
        115 => proc::getgroups(a[0], a[1]),
        116 => proc::setgroups(a[0], a[1]),
        109 => proc::setpgid(a[0] as u32, a[1] as u32),
        110 => proc::getppid(),
        111 => proc::getpgid(0), // getpgrp
        112 => proc::setsid(),
        121 => proc::getpgid(a[0] as u32),
        124 => proc::getsid(a[0] as u32),
        158 if a[0] == 0x1002 => { ts().fs = a[1]; Ok(0) } // arch_prctl(ARCH_SET_FS)
        158 if a[0] == 0x1003 => { unsafe { *(a[1] as *mut u64) = ts().fs }; Ok(0) } // ARCH_GET_FS
        158 => Err(EINVAL), // the rest (CET, AMX, CPUID faulting): not supported, as glibc's probes expect
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
        230 => clock_nanosleep(a[0], a[1], a[2], a[3]),
        228 => clock_gettime(a[0], a[1]),
        229 => clock_getres(a[0], a[1]),
        201 => time(a[0]),
        221 => fs::fadvise(a[0], a[2], a[3]), // fadvise64(fd, offset, len, advice)
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
        439 if a[3] & !0x1300 != 0 => Err(EINVAL), // faccessat2: AT_SYMLINK_NOFOLLOW, AT_EACCESS, AT_EMPTY_PATH
        269 | 439 => fs::faccessat(a[0], a[1], a[2]),
        273 => Ok(0),                  // set_robust_list
        // tkill, tgkill. ponytail: signals are process-wide; whichever thread returns from a syscall next runs it.
        200 => signal::send_thread(a[0], a[1]),        // tkill
        234 => if crate::proc::host_pid(a[0] as u32) == crate::proc::pid() { signal::send_thread(a[1], a[2]) } else { proc::kill(a[0] as i32 as i64, a[2]) }, // tgkill
        292 if a[2] & !0o2000000 != 0 || a[0] == a[1] => Err(EINVAL), // dup3: only O_CLOEXEC, and old != new
        292 => fs::dup3(a[0], a[1], a[2]),
        293 => fs::pipe2(a[0], a[1]),
        253 => crate::inotify::init(0),
        294 => crate::inotify::init(a[0]),
        254 => crate::inotify::add_watch(a[0], a[1], a[2]),
        255 => crate::inotify::rm_watch(a[0], a[1]),
        318 if a[2] & !7 != 0 => Err(EINVAL), // getrandom: GRND_NONBLOCK, GRND_RANDOM, GRND_INSECURE only
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
        dlog(format_args!("pid {} syscall {} ({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}) = {res}", unsafe { GetCurrentProcessId() }, c.rax, a[0], a[1], a[2], a[3], a[4], a[5]));
    } else if let Err(e) = r && debug() {
        eprintln!("[lx] syscall {} ({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}) -> -{e}", c.rax, a[0], a[1], a[2], a[3], a[4], a[5]);
    }
    r.unwrap_or_else(|e| -e)
}

// ---- guest memory helpers. The guest shares our address space; these trust its pointers. ----

/// ponytail: a bad guest pointer crashes lx instead of returning EFAULT; add a guarded copy when it matters.
pub unsafe fn guest_mut<'a>(addr: u64, len: usize) -> &'a mut [u8] {
    unsafe { std::slice::from_raw_parts_mut(addr as *mut u8, len) }
}

/// A path (PATH_MAX, 4096 bytes with its NUL).
pub fn cstr(addr: u64) -> Result<String, i64> {
    cstr_max(addr, 4096).map_err(|e| if e == E2BIG { ENAMETOOLONG } else { e })
}

/// A NUL-terminated guest string of at most `max` bytes, else E2BIG.
pub fn cstr_max(addr: u64, max: usize) -> Result<String, i64> {
    if addr == 0 {
        return Err(EFAULT);
    }
    // Scanned one readable region at a time: a bad pointer (LTP's EFAULT checks) is EFAULT, not a
    // fault inside lx. Usually one VirtualQuery: a path sits in one region.
    let p = addr as *const u8;
    let mut i = 0;
    loop {
        let here = addr + i as u64;
        let end = readable_end(here).ok_or(EFAULT)?;
        let stop = ((end - here) as usize).min(max - i);
        if let Some(n) = (0..stop).find(|&k| unsafe { *p.add(i + k) } == 0) {
            let len = i + n;
            return Ok(String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(p, len) }).into_owned());
        }
        i += stop;
        if i >= max {
            return Err(E2BIG);
        }
    }
}

/// Copy `bytes` to guest memory at `addr`, or EFAULT unless every page it covers is committed and
/// writable: a bad pointer from the guest is an error rather than a fault inside lx, and read-only
/// guest memory (text, .rodata, PROT_READ maps) isn't written, as on Linux. For small results the guest
/// may point anywhere (LTP's EFAULT checks); bulk copies go through ReadFile, which probes itself.
pub fn put_guest(addr: u64, bytes: &[u8]) -> R {
    let end = addr.checked_add(bytes.len() as u64).ok_or(EFAULT)?;
    // The hot callers (clock_gettime, gettimeofday: lx has no vDSO) write the same page again and again:
    // once checked, it stays writable until the map changes (MAP_GEN), so skip the VirtualQuery.
    thread_local!(static CHECKED: std::cell::Cell<(u64, u64)> = const { std::cell::Cell::new((u64::MAX, 0)) });
    let page = addr & !(PAGE - 1);
    let same_page = end > addr && (end - 1) & !(PAGE - 1) == page;
    let epoch = MAP_GEN.load(Relaxed);
    if same_page && CHECKED.get() == (page, epoch) {
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), addr as *mut u8, bytes.len()) };
        return Ok(0);
    }
    let mut p = addr;
    while p < end {
        let mut m = MemoryBasicInformation::default();
        if unsafe { VirtualQuery(p as *const _, &mut m, size_of::<MemoryBasicInformation>()) } == 0
            || m.state != MEM_COMMIT || !matches!(m.protect, 0x04 | 0x08 | 0x40 | 0x80) {
            return Err(EFAULT);
        }
        p = (m.base + m.region_size) as u64; // usually one query: the result fits one region
    }
    if same_page {
        CHECKED.set((page, epoch));
    }
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), addr as *mut u8, bytes.len()) };
    Ok(0)
}

/// Bumped by every syscall that changes the address space (see dispatch): put_guest's page cache.
static MAP_GEN: AtomicU64 = AtomicU64::new(0);

/// Read `N` bytes of guest memory at `addr`, or EFAULT unless every page is committed and readable.
pub fn get_guest<const N: usize>(addr: u64) -> Result<[u8; N], i64> {
    if !readable(addr, N) {
        return Err(EFAULT);
    }
    Ok(unsafe { std::ptr::read_unaligned(addr as *const [u8; N]) })
}

/// get_guest for a length known at run time; None: EFAULT.
pub fn get_guest_vec(addr: u64, n: usize) -> Option<Vec<u8>> {
    readable(addr, n).then(|| unsafe { std::slice::from_raw_parts(addr as *const u8, n) }.to_vec())
}

/// Whether [addr, addr+n) is committed guest memory we may read.
/// The end of the readable region holding `addr`, if it is readable.
fn readable_end(addr: u64) -> Option<u64> {
    let mut m = MemoryBasicInformation::default();
    let ok = unsafe { VirtualQuery(addr as *const _, &mut m, size_of::<MemoryBasicInformation>()) } != 0
        && m.state == MEM_COMMIT && m.protect & 0x101 == 0 && m.protect & 0xff != 0x10;
    ok.then(|| (m.base + m.region_size) as u64)
}

/// EFAULT unless [addr, addr+n) is committed and readable (`write`: and writable): for syscalls that
/// work on a guest buffer in place.
pub fn check_guest(addr: u64, n: usize, write: bool) -> Result<(), i64> {
    let Some(end) = addr.checked_add(n as u64) else { return Err(EFAULT) };
    let mut p = addr;
    while p < end {
        let mut m = MemoryBasicInformation::default();
        if unsafe { VirtualQuery(p as *const _, &mut m, size_of::<MemoryBasicInformation>()) } == 0 || m.state != MEM_COMMIT
            || if write { !matches!(m.protect, 0x04 | 0x08 | 0x40 | 0x80) } else { m.protect & 0x101 != 0 || m.protect & 0xff == 0x10 } {
            return Err(EFAULT);
        }
        p = (m.base + m.region_size) as u64;
    }
    Ok(())
}

fn readable(addr: u64, n: usize) -> bool {
    let Some(end) = addr.checked_add(n as u64) else { return false };
    let mut p = addr;
    while p < end {
        let mut m = MemoryBasicInformation::default();
        if unsafe { VirtualQuery(p as *const _, &mut m, size_of::<MemoryBasicInformation>()) } == 0
            || m.state != MEM_COMMIT || m.protect & 0x101 != 0 || m.protect & 0xff == 0x10 {
            return false; // PAGE_NOACCESS, PAGE_GUARD, execute-only
        }
        p = (m.base + m.region_size) as u64;
    }
    true
}

/// u64s as the guest's little-endian bytes, for put_guest.
pub fn as_bytes(v: &[u64]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}

// Guest buffers go straight to the NT kernel, which probes them: a bad pointer is an error, not a crash.
pub fn write_handle(h: isize, buf: u64, len: u64) -> R {
    let mut done = 0u32;
    let len = len.min(u32::MAX as u64) as u32;
    let (ok, err) = crate::signal::interruptible(|| unsafe { (WriteFile(h, buf as *const u8, len, &mut done, std::ptr::null_mut()), GetLastError()) });
    if ok != 0 {
        return Ok(done as i64);
    }
    // ERROR_NO_DATA / ERROR_BROKEN_PIPE: the reader is gone (dispatch adds the SIGPIPE).
    match err {
        232 | 109 => Err(EPIPE),
        995 => Err(EINTR), // a signal cancelled the write
        e => Err(io_errno(e)),
    }
}

/// A failed ReadFile/WriteFile's error as Linux reports it; the rest is EIO.
pub fn io_errno(err: u32) -> i64 {
    match err {
        5 => EBADF,   // ERROR_ACCESS_DENIED: the fd isn't open for this direction (write to a pipe's read end)
        998 => EFAULT, // ERROR_NOACCESS: the guest buffer isn't mapped (NT probed it)
        87 => EINVAL, // ERROR_INVALID_PARAMETER
        _ => EIO,
    }
}

pub fn read_handle(h: isize, buf: u64, len: u64) -> R {
    let mut done = 0u32;
    let len = len.min(u32::MAX as u64) as u32;
    let (ok, err) = crate::signal::interruptible(|| unsafe { (ReadFile(h, buf as *mut u8, len, &mut done, std::ptr::null_mut()), GetLastError()) });
    if ok != 0 {
        return Ok(done as i64);
    }
    match err {
        109 => Ok(0),       // ERROR_BROKEN_PIPE is EOF
        995 => Err(EINTR),  // ERROR_OPERATION_ABORTED: a signal cancelled the read
        e => Err(io_errno(e)),
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
            MEM_COMMIT => unsafe {
                // A copy-on-write file view (map_image) takes writable as WRITECOPY, not READWRITE.
                VirtualProtect(p as *mut _, n as usize, prot, &mut old) != 0
                    || matches!(prot, 0x04 | 0x40) && VirtualProtect(p as *mut _, n as usize, prot * 2, &mut old) != 0
            },
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
    // Private file mappings share the file's pages copy-on-write where they can (see mmap_cow);
    // a MAP_FIXED first cuts any copy-on-write view out of its way.
    let fixed = flags & MAP_FIXED != 0;
    let holes = if fixed { punch_views(addr, len) } else { Vec::new() };
    let cow = if flags & MAP_ANONYMOUS == 0 { mmap_cow(addr, len, prot, fixed, fd, off, &holes) } else { None };
    if cow.is_none() {
        for &(a, n) in &holes {
            place_plain(a, n, false); // ordinary reserved memory for the paths below
        }
    }
    let p = if let Some(c) = cow {
        c
    } else if fixed {
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
    if flags & MAP_ANONYMOUS == 0 && cow.is_none() {
        // Not shareable (unaligned offset, odd placement): a private copy of the file's bytes.
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
        for &(o, n) in &ranges {
            patch_code(p + (o - off), n as usize);
        }
        if cow.is_some() {
            set_view_code(p, ranges);
        }
    }
    protect(p, len, page_prot(prot));
    Ok(p as i64)
}

/// The file ranges just patched in the CoW view at `base`, for re-patching after a re-map.
/// ponytail: set after the view is listed, so another thread's MAP_FIXED cutting it in between would
/// re-map its pieces unpatched; take the views lock across mmap's patching if that ever shows up.
fn set_view_code(base: u64, ranges: Vec<(u64, u64)>) {
    if let Some(v) = COW_VIEWS.lock().unwrap().iter_mut().find(|v| v.base == base) {
        v.code = ranges;
    }
}

// ---- MAP_SHARED: views of NT sections ----
//
// A shared mapping is a view of a section: pagefile-backed for anonymous memory, the file's own for a
// file. Every process mapping it (forked children included) sees the same pages, and writes reach the
// file. Views aren't in ALLOCS, so fork doesn't copy them: the child maps the same section at the same
// address instead (`snapshot` / `restore`). Views must start on NT's 64K granularity, so an offset that
// isn't 64K-aligned maps from the aligned offset below it and returns a pointer into the view.
// ponytail: munmap of part of a view unmaps all of it; mremap of a view makes a private copy.
//
// A file mapping longer than the file (bbolt maps ahead, then writes the file longer) can't be one
// view: NT views end at the file's end. The rest stays a placeholder (`full`), and a fault there after
// the file grew maps a longer view into it (`grow_view`). ponytail: a forked child's copy doesn't grow.

struct View {
    base: u64,
    len: u64,
    section: isize,
    off: u64,
    access: u32,
    /// Address space held for the view, past `len` as a placeholder (== len when it can't grow).
    full: u64,
    /// For growing: the file (a duplicate handle, 0 if none) and the section and view protections.
    file: isize,
    prot: (u32, u32),
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
    let mut sprot = PAGE_READWRITE;
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
            sprot = rw;
            let mut s = unsafe { CreateFileMappingW(h, std::ptr::null_mut(), rw, 0, 0, std::ptr::null()) };
            if s == 0 && !write {
                // A file opened read-only can still be mapped for reading.
                sprot = if exec { 0x20 } else { 0x02 };
                s = unsafe { CreateFileMappingW(h, std::ptr::null_mut(), sprot, 0, 0, std::ptr::null()) };
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
    let full = (delta + len).next_multiple_of(PAGE);
    if let Some(fd) = file.filter(|_| !fixed && full > vlen.next_multiple_of(PAGE)) {
        return mmap_growable(section, sprot, access, fd, aoff, vlen, full, prot).map(|base| (base + delta) as i64);
    }
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
    VIEWS.lock().unwrap().push(View { base, len: vlen, section, off: aoff, access, full: vlen, file: 0, prot: (0, 0) });
    Ok((base + delta) as i64)
}

/// A shared file mapping of `full` bytes whose file holds only `vlen` of them from `off`: the view in
/// a placeholder of the whole length, the rest left a placeholder for `grow_view`.
fn mmap_growable(section: isize, sprot: u32, access: u32, fd: u64, off: u64, vlen: u64, full: u64, prot: u64) -> Result<u64, i64> {
    let vprot = match (access & FILE_MAP_WRITE != 0, prot & 4 != 0) {
        (true, true) => 0x40,
        (true, false) => PAGE_READWRITE,
        (false, true) => 0x20,
        (false, false) => 0x02,
    };
    let fail = |e| {
        unsafe { CloseHandle(section) };
        Err(e)
    };
    let base = loop {
        let a = NEXT.fetch_add(full.next_multiple_of(0x10000), Relaxed);
        if a + full > WINDOW.1 {
            return fail(ENOMEM);
        }
        if unsafe { VirtualAlloc2(0, a as *mut _, full as usize, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, 0x01, std::ptr::null_mut(), 0) } as u64 == a {
            break a;
        }
    };
    carve(base, vlen.next_multiple_of(PAGE));
    let me = unsafe { GetCurrentProcess() };
    if unsafe { MapViewOfFile3(section, me, base as *mut _, off, vlen as usize, MEM_REPLACE_PLACEHOLDER, vprot, std::ptr::null_mut(), 0) } as u64 != base {
        unsafe { VirtualFree(base as *mut _, 0, MEM_RELEASE) };
        return fail(ENOMEM);
    }
    if prot == 0 {
        let mut old = 0;
        unsafe { VirtualProtect(base as *mut _, vlen as usize, 0x01, &mut old) }; // PROT_NONE
    }
    let (h, _) = fs::file_handle(fd)?;
    let mut file = 0isize;
    unsafe { crate::win::DuplicateHandle(me, h, me, &mut file, 0, 0, 2) }; // DUPLICATE_SAME_ACCESS
    VIEWS.lock().unwrap().push(View { base, len: vlen, section, off, access, full, file, prot: (sprot, vprot) });
    Ok(base)
}

/// A fault at `addr` past the end of a growable view: if its file has grown since, map the longer view
/// (in the same placeholder, so the address range stays ours) and have the guest retry. Also true when
/// another thread just did that and the page is there now.
fn grow_view(addr: u64, write: bool) -> bool {
    // Every access violation comes through here: if lx itself faulted holding VIEWS, give up after a
    // second (and crash with the fault) rather than deadlock; another thread holds it only briefly.
    let start = std::time::Instant::now();
    let mut views = loop {
        match VIEWS.try_lock() {
            Ok(v) => break v,
            Err(_) if start.elapsed().as_secs() >= 1 => return false,
            Err(_) => std::thread::yield_now(),
        }
    };
    let Some(v) = views.iter_mut().find(|v| v.full > v.len && (v.base..v.base + v.full).contains(&addr)) else {
        return false;
    };
    if addr < v.base + v.len.next_multiple_of(PAGE) {
        // Mapped already: retry if it allows this access (it was being re-mapped), else a real fault.
        let mut m = MemoryBasicInformation::default();
        unsafe { VirtualQuery(addr as *const _, &mut m, size_of::<MemoryBasicInformation>()) };
        return m.state == 0x1000 && if write { matches!(m.protect, 0x04 | 0x40) } else { m.protect & 0xfe != 0 };
    }
    let file = std::mem::ManuallyDrop::new(unsafe { <std::fs::File as std::os::windows::io::FromRawHandle>::from_raw_handle(v.file as _) });
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let new = size.saturating_sub(v.off).min(v.full);
    if v.base + new <= addr {
        return false; // still past the end: Linux would raise SIGBUS
    }
    let section = unsafe { CreateFileMappingW(v.file, std::ptr::null_mut(), v.prot.0, 0, 0, std::ptr::null()) };
    if section == 0 {
        return false;
    }
    let me = unsafe { GetCurrentProcess() };
    const MEM_COALESCE_PLACEHOLDERS: u32 = 0x1;
    let ok = unsafe {
        UnmapViewOfFile2(me, v.base as *mut _, MEM_PRESERVE_PLACEHOLDER);
        VirtualFree(v.base as *mut _, v.full as usize, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
        carve(v.base, new.next_multiple_of(PAGE));
        MapViewOfFile3(section, me, v.base as *mut _, v.off, new as usize, MEM_REPLACE_PLACEHOLDER, v.prot.1, std::ptr::null_mut(), 0) as u64 == v.base
    };
    if debug() {
        dlog(format_args!("shared view {:#x}: grown {:#x} -> {new:#x} for {addr:#x}: {ok}", v.base, v.len));
    }
    if !ok {
        unsafe { CloseHandle(section) };
        return false;
    }
    unsafe { CloseHandle(v.section) };
    (v.section, v.len) = (section, new);
    true
}

/// Unmap every shared view overlapping [addr, addr+len). Returns whether there was one.
fn unmap_views(addr: u64, len: u64) -> bool {
    let mut views = VIEWS.lock().unwrap();
    let before = views.len();
    views.retain(|v| {
        if v.base < addr + len && addr < v.base + v.full {
            unsafe {
                UnmapViewOfFile(v.base as *mut _);
                CloseHandle(v.section);
                if v.full > v.len {
                    VirtualFree((v.base + v.len.next_multiple_of(PAGE)) as *mut _, 0, MEM_RELEASE); // the placeholder
                    CloseHandle(v.file);
                }
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
    mark_views(addr, len, prot & 2 != 0, prot & 4 != 0);
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
    for (a, n) in punch_views(addr, len) {
        place_plain(a, n, false); // a copy-on-write view's pages go; the address range stays reserved
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

/// adjtimex as a reader: struct timex with modes 0 gets "synchronized" (TIME_OK), anything else is a change
/// a container may not make. Offsets: modes 0, status 32, constant 40, precision 48, tolerance 56,
/// time (timeval) 64, tick 80.
fn adjtimex_read(tx: u64) -> R {
    let modes = u32::from_le_bytes(get_guest::<4>(tx)?);
    if modes != 0 {
        return Err(EPERM);
    }
    let (s, ns) = now(0);
    let mut t = [0u8; 208];
    t[64..72].copy_from_slice(&s.to_le_bytes());
    t[72..80].copy_from_slice(&(ns / 1000).to_le_bytes());
    t[80..88].copy_from_slice(&10_000u64.to_le_bytes()); // tick: 10000 us, as USER_HZ 100 has it
    t[48..56].copy_from_slice(&1u64.to_le_bytes()); // precision 1 us
    put_guest(tx, &t)?;
    Ok(0) // TIME_OK
}

/// The clock ids Linux knows (10 was CLOCK_SGI_CYCLE, gone). Negative ids name another process's
/// or thread's CPU clock. ponytail: those aren't supported (EINVAL).
fn valid_clock(clock: u64) -> bool {
    matches!(clock, 0..=9 | 11)
}

/// A struct timespec Linux accepts: 0 <= tv_nsec < 1e9 and tv_sec >= 0.
fn valid_timespec(ts: u64) -> bool {
    let [s, ns] = unsafe { *(ts as *const [i64; 2]) };
    s >= 0 && (0..1_000_000_000).contains(&ns)
}

/// All our clocks tick in nanoseconds (QueryPerformanceCounter is finer than that on modern hardware).
fn clock_getres(clock: u64, ts: u64) -> R {
    if !valid_clock(clock) {
        return Err(EINVAL);
    }
    if ts != 0 {
        unsafe { *(ts as *mut [u64; 2]) = [0, 1] };
    }
    Ok(0)
}

fn clock_gettime(clock: u64, ts: u64) -> R {
    if !valid_clock(clock) {
        return Err(EINVAL);
    }
    let (s, ns) = now(clock);
    let mut b = [0u8; 16]; // no allocation: this is the most frequent syscall (no vDSO)
    b[..8].copy_from_slice(&s.to_le_bytes());
    b[8..].copy_from_slice(&ns.to_le_bytes());
    put_guest(ts, &b)
}

fn gettimeofday(tv: u64, tz: u64) -> R {
    if tz != 0 {
        put_guest(tz, &[0; 8])?; // struct timezone: UTC, no DST
    }
    if tv != 0 {
        let (s, ns) = now(0);
        put_guest(tv, &as_bytes(&[s, ns / 1000]))?;
    }
    Ok(0)
}

fn nanosleep(ts: u64, rem: u64) -> R {
    if !valid_timespec(ts) {
        return Err(EINVAL);
    }
    let start = Instant::now();
    let [s, ns] = unsafe { *(ts as *const [u64; 2]) };
    let want = std::time::Duration::new(s, ns as u32);
    let r = signal::precise_sleep(want);
    if r == Err(EINTR) {
        remaining(rem, want, start);
    }
    r
}

/// Limits like a Docker container's defaults: 8 MB stack, 1024 open files (fs::nofile), the rest unlimited.
/// ponytail: only RLIMIT_NOFILE is enforced; other new limits are accepted and ignored.
fn rlimit(resource: u64, new: u64, old: u64) -> R {
    const INF: u64 = u64::MAX;
    if resource > 15 {
        return Err(EINVAL); // RLIMIT_NLIMITS is 16
    }
    let (cur, max) = match resource {
        3 => (8 << 20, INF),        // RLIMIT_STACK
        7 => fs::nofile().into(),   // RLIMIT_NOFILE
        _ => (INF, INF),
    };
    if old != 0 {
        put_guest(old, &as_bytes(&[cur, max]))?;
    }
    if new != 0 && resource == 7 {
        let [cur, max] = unsafe { *(new as *const [u64; 2]) };
        return fs::set_nofile(cur, max);
    }
    Ok(0)
}

/// All host CPUs are ours. Returns the mask size like the kernel does.
fn sched_getaffinity(pid: u64, len: u64, mask: u64) -> R {
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get()).min(64);
    if len < 8 || len % 8 != 0 {
        return Err(EINVAL);
    }
    if pid != 0 {
        proc::kill(pid as i64, 0)?; // ESRCH for a process that isn't there
    }
    let bits = if cpus == 64 { u64::MAX } else { (1u64 << cpus) - 1 };
    put_guest(mask, &bits.to_le_bytes())?;
    Ok(8)
}

/// setitimer(ITIMER_REAL, {interval, value} as timevals, old).
fn setitimer(which: u64, new: u64, old: u64) -> R {
    if which != 0 {
        return Err(EINVAL); // ITIMER_VIRTUAL / ITIMER_PROF
    }
    let [is, ius, vs, vus] = if new != 0 { unsafe { *(new as *const [u64; 4]) } } else { [0; 4] }; // NULL disarms
    let (left, iv) = signal::set_alarm(vs * 1000 + vus.div_ceil(1000), is * 1000 + ius.div_ceil(1000));
    if old != 0 {
        unsafe { *(old as *mut [u64; 4]) = [iv / 1000, iv % 1000 * 1000, left / 1000, left % 1000 * 1000] };
    }
    Ok(0)
}

fn getitimer(which: u64, cur: u64) -> R {
    let (left, iv) = match which {
        0 => signal::alarm_left(),
        1 | 2 => (0, 0), // ITIMER_VIRTUAL / ITIMER_PROF: never armed here
        _ => return Err(EINVAL),
    };
    put_guest(cur, &as_bytes(&[iv / 1000, iv % 1000 * 1000, left / 1000, left % 1000 * 1000]))
}

fn clock_nanosleep(clock: u64, flags: u64, req: u64, rem: u64) -> R {
    const TIMER_ABSTIME: u64 = 1;
    if clock == 3 {
        return Err(95); // EOPNOTSUPP: the thread CPU clock can't be slept on
    }
    if !valid_clock(clock) || flags & !TIMER_ABSTIME != 0 || !valid_timespec(req) {
        return Err(EINVAL);
    }
    let start = Instant::now();
    let [s, ns] = unsafe { *(req as *const [u64; 2]) };
    let want = std::time::Duration::new(s, ns as u32);
    let wait = if flags & TIMER_ABSTIME != 0 {
        let (s, ns) = now(clock);
        want.saturating_sub(std::time::Duration::new(s, ns as u32))
    } else {
        want
    };
    if wait < std::time::Duration::from_millis(1) {
        std::thread::sleep(wait); // too short for a signal to matter; the ms wait below would round it
        return Ok(0);
    }
    // A signal cuts it short (EINTR), as for nanosleep: Python's and glibc's sleep() come here.
    let r = signal::precise_sleep(wait);
    if r == Err(EINTR) && flags & TIMER_ABSTIME == 0 {
        remaining(rem, wait, start);
    }
    r
}

/// After an interrupted relative sleep: what was left of `wait`, into `rem` (if given).
fn remaining(rem: u64, wait: std::time::Duration, start: Instant) {
    if rem != 0 {
        let left = wait.saturating_sub(start.elapsed());
        unsafe { *(rem as *mut [u64; 2]) = [left.as_secs(), left.subsec_nanos() as u64] };
    }
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
    check_guest(buf, len as usize, true)?;
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
    fn timeEndPeriod(ms: u32) -> u32;
}

/// Linux timers are ~1 ms; NT's default tick is 15.6 ms, so a 1 ms wait took 16. This raises the timer
/// resolution for the length of one short wait (futex, poll, epoll_wait, sleeps), ended when the guard
/// drops: a server whose event loop passes short timeouts doesn't keep the fast tick while idle.
pub struct FineWait;

impl FineWait {
    pub fn for_ms(ms: i64) -> Option<FineWait> {
        (1..16).contains(&ms).then(|| {
            unsafe { timeBeginPeriod(1) };
            FineWait
        })
    }
}

impl Drop for FineWait {
    fn drop(&mut self) {
        unsafe { timeEndPeriod(1) };
    }
}

/// The interrupted guest's FP/vector state for a signal frame: on the direct path the XSAVE image
/// lx_sys_entry took (restored on the way out), on the trap path the CONTEXT's legacy 512-byte area.
pub fn fp_area(c: &mut Context) -> &'static mut [u8] {
    let t = ts();
    if t.in_direct {
        let n = (std::arch::x86_64::__cpuid_count(0xd, 0).ebx as usize).next_multiple_of(64);
        &mut t.xsave.0[..n]
    } else {
        // CONTEXT.FltSave (XSAVE_FORMAT) right after rip; only the trap path has a whole CONTEXT.
        unsafe { std::slice::from_raw_parts_mut((c as *mut Context as *mut u8).add(0x100), 512) }
    }
}

// ---- program images as shared copy-on-write file views ----
//
// Linux shares a program's pages between every process running it (page cache); copying the file in
// gave each process its own full copy (Grafana's ~20 Go plugin processes: tens of MB each). Here a
// placeholder reserves the image's span, and each PT_LOAD becomes a copy-on-write view of the file at
// its exact 4K address and offset (placeholders allow 4K granularity where plain views need 64K);
// bss becomes anonymous memory and gaps plain reservations, so the rest of lx sees ordinary regions.
// Patching syscall sites then privatizes only the pages it writes.

#[link(name = "kernelbase", kind = "raw-dylib")]
unsafe extern "system" {
    fn VirtualAlloc2(process: isize, addr: *mut std::ffi::c_void, size: usize, ty: u32, prot: u32,
                     params: *mut std::ffi::c_void, count: u32) -> *mut std::ffi::c_void;
    fn MapViewOfFile3(section: isize, process: isize, addr: *mut std::ffi::c_void, offset: u64, size: usize,
                      ty: u32, prot: u32, params: *mut std::ffi::c_void, count: u32) -> *mut std::ffi::c_void;
    fn UnmapViewOfFile2(process: isize, base: *mut std::ffi::c_void, flags: u32) -> i32;
}
const MEM_RESERVE_PLACEHOLDER: u32 = 0x40000;
const MEM_REPLACE_PLACEHOLDER: u32 = 0x4000;
const MEM_PRESERVE_PLACEHOLDER: u32 = 0x2;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

/// One PT_LOAD of an image: file offset, absolute address (bias applied), sizes.
pub struct ImageSeg {
    pub off: u64,
    pub addr: u64,
    pub filesz: u64,
    pub memsz: u64,
}

/// Map `segs` of the file at `host` over [lo, hi) (64K-aligned lo; `fixed`: exactly there, else in the
/// guest window) as copy-on-write views. Returns the base, or None to fall back to copying (a layout
/// where segments share a page, or the file can't be mapped): checked before anything is mapped.
pub fn map_image(host: &std::path::Path, segs: &[ImageSeg], fixed: bool, lo: u64, hi: u64) -> Option<u64> {
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
    if std::env::var_os("LX_NOCOW").is_some() {
        return None;
    }
    // Each segment's pages must be its own: no two segments in one page (older layouts do that).
    let page = |a: u64| a & !(PAGE - 1);
    let mut order: Vec<&ImageSeg> = segs.iter().collect();
    order.sort_by_key(|s| s.addr);
    for w in order.windows(2) {
        if (w[0].addr + w[0].memsz).next_multiple_of(PAGE) > page(w[1].addr) {
            return None;
        }
    }
    let f = std::fs::OpenOptions::new().read(true).access_mode(0x8000_0000 | 0x2000_0000).open(host).ok()?; // GENERIC_READ | GENERIC_EXECUTE
    let fsize = f.metadata().ok()?.len();
    let section = unsafe { CreateFileMappingW(f.as_raw_handle() as isize, std::ptr::null_mut(), PAGE_EXECUTE_WRITECOPY, 0, 0, std::ptr::null()) };
    if section == 0 {
        return None;
    }
    let len = hi - lo;
    let reserve = |a: u64| unsafe {
        VirtualAlloc2(0, a as *mut _, len as usize, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, 0x01, std::ptr::null_mut(), 0)
    } as u64;
    let base = if fixed {
        Some(lo).filter(|&a| reserve(a) == a)
    } else {
        loop {
            let a = NEXT.fetch_add(len.next_multiple_of(0x10000), Relaxed);
            if a + len > WINDOW.1 {
                break None;
            }
            if reserve(a) == a {
                break Some(a);
            }
        }
    };
    let Some(base) = base else {
        unsafe { CloseHandle(section) };
        return None;
    };
    let bias = base - lo;
    let me = unsafe { GetCurrentProcess() };
    // Carve [a, a+n) out of the placeholder that starts at `cursor` (it runs to the span's end).
    let carve = |cursor: u64, a: u64, n: u64| unsafe {
        if a > cursor {
            VirtualFree(cursor as *mut _, (a - cursor) as usize, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
        }
        if a + n < base + len {
            VirtualFree(a as *mut _, n as usize, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
        }
    };
    let plain = |a: u64, n: u64, commit: bool| unsafe {
        let ty = MEM_RESERVE | MEM_REPLACE_PLACEHOLDER | if commit { MEM_COMMIT } else { 0 };
        !VirtualAlloc2(0, a as *mut _, n as usize, ty, if commit { PAGE_READWRITE } else { 0x01 }, std::ptr::null_mut(), 0).is_null()
    };
    let mut cursor = base;
    let mut ok = true;
    for s in order {
        let (v0, v1) = (page(s.addr + bias), (s.addr + bias + s.filesz).next_multiple_of(PAGE));
        let mem_end = (s.addr + bias + s.memsz).next_multiple_of(PAGE);
        if v0 > cursor {
            carve(cursor, v0, 0); // the gap before: back to an ordinary reservation below
            ok &= plain(cursor, v0 - cursor, false);
            cursor = v0;
        }
        if v1 > v0 {
            carve(cursor, v0, v1 - v0);
            let v = unsafe {
                // Not past the file's end (the rest of that last page reads as zero).
                MapViewOfFile3(section, me, v0 as *mut _, page(s.off), (v1 - v0).min(fsize - page(s.off)) as usize, MEM_REPLACE_PLACEHOLDER,
                               PAGE_EXECUTE_WRITECOPY, std::ptr::null_mut(), 0)
            } as u64;
            ok &= v == v0;
            // A segment with bss: zero the rest of its last file page, to the page's end, as Linux's
            // loader does (glibc's ld.so hands that memory out as zeroed malloc memory). Without bss the
            // page keeps the file's bytes, as on Linux. Copy-on-write privatizes just that page.
            let tail = s.addr + bias + s.filesz;
            if ok && tail < v1 && s.memsz > s.filesz {
                unsafe { std::ptr::write_bytes(tail as *mut u8, 0, (v1 - tail) as usize) };
            }
            cursor = v1;
        }
        if mem_end > cursor {
            carve(cursor, cursor, mem_end - cursor);
            ok &= plain(cursor, mem_end - cursor, true); // bss: fresh zero pages
            cursor = mem_end;
        }
    }
    if cursor < base + len {
        ok &= plain(cursor, base + len - cursor, false);
    }
    unsafe { CloseHandle(section) }; // the views keep it alive
    if !ok {
        release_span(base, len);
        return None;
    }
    ALLOCS.lock().unwrap().push((base, len));
    if debug() {
        dlog(format_args!("map_image {} at {base:#x}+{len:#x}", host.display()));
    }
    Some(base)
}

/// Free [base, base+len) region by region: views are unmapped, anonymous pieces released. A span from
/// map_image is several allocations, not one.
fn release_span(base: u64, len: u64) {
    let mut p = base;
    while p < base + len {
        let mut m = MemoryBasicInformation::default();
        if unsafe { VirtualQuery(p as *const _, &mut m, size_of::<MemoryBasicInformation>()) } == 0 {
            break;
        }
        let end = m.base as u64 + m.region_size as u64;
        unsafe {
            const MEM_MAPPED: u32 = 0x40000;
            if m.state != MEM_FREE {
                if m.ty == MEM_MAPPED {
                    UnmapViewOfFile(m.allocation_base as *mut _);
                } else {
                    VirtualFree(m.allocation_base as *mut _, 0, MEM_RELEASE);
                }
            }
        }
        p = end.max(p + PAGE);
    }
}

// ---- private file mmaps as copy-on-write views (ld.so mapping shared libraries) ----
//
// ld.so maps a library's whole span from the file, then MAP_FIXEDs segments over parts of it at other
// offsets and anonymous bss over the rest. A view can't be partly replaced, so a MAP_FIXED over one
// turns it back into a placeholder, maps its untouched parts again from the file (re-patching code
// parts, which is deterministic), and leaves a placeholder hole for the new mapping. A view the guest
// made writable is turned into private memory first, so its changes survive.

struct CowView {
    base: u64,
    len: u64,
    section: isize, // kept open for re-mapping parts; ponytail: never closed
    off: u64,
    fsize: u64,     // the file's size: a view may not reach past its end
    code: Vec<(u64, u64)>, // file ranges (offset, len) whose syscall sites were patched: re-done after a
                           // re-map, and only there (lld puts .dynstr in the executable segment)
    written: bool,  // the guest may have changed it: never re-mapped from the file
}
static COW_VIEWS: Mutex<Vec<CowView>> = Mutex::new(Vec::new());

/// A copy-on-write, executable-capable section of fd's file and its size.
fn file_section(fd: u64) -> Option<(isize, u64)> {
    let (h, size) = fs::file_handle(fd).ok()?;
    let h2 = unsafe { ReOpenFile(h, 0x8000_0000 | 0x2000_0000, 7, 0) }; // GENERIC_READ | GENERIC_EXECUTE
    if h2 == -1 || h2 == 0 {
        return None;
    }
    let s = unsafe { CreateFileMappingW(h2, std::ptr::null_mut(), PAGE_EXECUTE_WRITECOPY, 0, 0, std::ptr::null()) };
    unsafe { CloseHandle(h2) };
    (s != 0).then_some((s, size))
}

/// Split the placeholder containing [a, a+n) so that range is a placeholder of its own.
fn carve(a: u64, n: u64) {
    let mut m = MemoryBasicInformation::default();
    unsafe { VirtualQuery(a as *const _, &mut m, size_of::<MemoryBasicInformation>()) };
    let (p0, p1) = (m.allocation_base as u64, m.base as u64 + m.region_size as u64);
    unsafe {
        if a > p0 {
            VirtualFree(p0 as *mut _, (a - p0) as usize, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
        }
        if a + n < p1 {
            VirtualFree(a as *mut _, n as usize, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
        }
    }
}

/// Map n bytes (page-rounded hole) of the file at `off` into the placeholder at `a`; a view may not reach past
/// the file's end, so it covers min(n, fsize - off) bytes and the rest of that page reads as zero, as on Linux.
fn place_view(section: isize, a: u64, off: u64, n: u64, fsize: u64) -> bool {
    carve(a, n);
    let me = unsafe { GetCurrentProcess() };
    let bytes = n.min(fsize.saturating_sub(off));
    (unsafe { MapViewOfFile3(section, me, a as *mut _, off, bytes as usize, MEM_REPLACE_PLACEHOLDER, PAGE_EXECUTE_WRITECOPY, std::ptr::null_mut(), 0) }) as u64 == a
}

/// Fill the placeholder [a, a+n) with ordinary memory: committed zero pages, or reserved only.
fn place_plain(a: u64, n: u64, commit: bool) -> bool {
    carve(a, n);
    let ty = MEM_RESERVE | MEM_REPLACE_PLACEHOLDER | if commit { MEM_COMMIT } else { 0 };
    !unsafe { VirtualAlloc2(0, a as *mut _, n as usize, ty, if commit { PAGE_READWRITE } else { 0x01 }, std::ptr::null_mut(), 0) }.is_null()
}

/// The protections of [a, a+n) region by region, to put back after a re-map.
fn protections(a: u64, n: u64) -> Vec<(u64, u64, u32)> {
    let mut out = Vec::new();
    let mut p = a;
    while p < a + n {
        let mut m = MemoryBasicInformation::default();
        if unsafe { VirtualQuery(p as *const _, &mut m, size_of::<MemoryBasicInformation>()) } == 0 {
            break;
        }
        let end = (m.base as u64 + m.region_size as u64).min(a + n);
        out.push((p, end - p, m.protect));
        p = end;
    }
    out
}

fn reprotect(prots: &[(u64, u64, u32)], keep: impl Fn(u64) -> bool) {
    for &(p, n, pr) in prots {
        if keep(p) && pr != 0 {
            let mut old = 0;
            unsafe { VirtualProtect(p as *mut _, n as usize, pr, &mut old) };
        }
    }
}

/// The NT name of what's mapped at `addr` (\\Device\\HarddiskVolumeN\\...), or of an open file's handle.
fn nt_name(addr: Option<u64>, h: isize) -> String {
    unsafe extern "system" {
        fn K32GetMappedFileNameW(process: isize, addr: *const std::ffi::c_void, name: *mut u16, size: u32) -> u32;
        fn GetFinalPathNameByHandleW(h: isize, name: *mut u16, size: u32, flags: u32) -> u32;
    }
    let mut name = [0u16; 1024];
    let n = match addr {
        Some(a) => unsafe { K32GetMappedFileNameW(GetCurrentProcess(), a as *const _, name.as_mut_ptr(), 1024) },
        None => unsafe { GetFinalPathNameByHandleW(h, name.as_mut_ptr(), 1024, 0x2) }, // VOLUME_NAME_NT
    };
    String::from_utf16_lossy(&name[..(n as usize).min(1024)]).to_lowercase()
}

/// ftruncate shrinking a file this process has mapped: NT refuses while any view of it exists
/// (ERROR_USER_MAPPED_FILE), Linux allows it. Copy-on-write views of the file become private copies,
/// shared ones are unmapped, `set` truncates, and the shared views come back at their addresses in a
/// placeholder of their old length: cut to the new end, the rest held (it faults, where Linux raises
/// SIGBUS) and grown into again if the file grows (grow_view).
/// ponytail: other processes' views still refuse it (EIO); re-mapped views lose their mprotect; between
/// the unmap and the placeholder the range is briefly free.
pub fn truncate_mapped(h: isize, size: u64, set: impl FnOnce() -> std::io::Result<()>) -> std::io::Result<()> {
    let file = nt_name(None, h);
    let me = unsafe { GetCurrentProcess() };
    {
        let mut cow = COW_VIEWS.lock().unwrap();
        cow.retain(|v| {
            if nt_name(Some(v.base), 0) != file {
                return true;
            }
            // The view's pages as they are now (the guest's writes, our patches), then private memory.
            let prots = protections(v.base, v.len);
            let mut old = 0;
            unsafe { VirtualProtect(v.base as *mut _, v.len as usize, 0x02, &mut old) };
            let copy = unsafe { std::slice::from_raw_parts(v.base as *const u8, v.len as usize) }.to_vec();
            unsafe {
                UnmapViewOfFile2(me, v.base as *mut _, MEM_PRESERVE_PLACEHOLDER);
                CloseHandle(v.section); // an open section holds the file's size too
            }
            place_plain(v.base, v.len, true);
            unsafe { std::ptr::copy_nonoverlapping(copy.as_ptr(), v.base as *mut u8, copy.len()) };
            let prots: Vec<_> = prots.into_iter().map(|(a, n, pr)| (a, n, match pr & 0xff { 0x08 => 0x04, 0x80 => 0x40, x => x })).collect();
            reprotect(&prots, |_| true);
            false
        });
    }
    let mut views = VIEWS.lock().unwrap();
    let mut gone = Vec::new();
    views.retain(|v| {
        if nt_name(Some(v.base), 0) != file {
            return true;
        }
        unsafe {
            UnmapViewOfFile(v.base as *mut _);
            CloseHandle(v.section);
            if v.full > v.len {
                VirtualFree((v.base + v.len.next_multiple_of(PAGE)) as *mut _, 0, MEM_RELEASE); // its growth placeholder
                CloseHandle(v.file);
            }
        }
        gone.push((v.base, v.len.max(v.full).next_multiple_of(PAGE), v.off, v.access));
        false
    });
    let r = set();
    for (base, full, off, access) in gone {
        // The whole old range stays ours, as a placeholder, before anything else can take it.
        if unsafe { VirtualAlloc2(0, base as *mut _, full as usize, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, 0x01, std::ptr::null_mut(), 0) } as u64 != base {
            continue;
        }
        let len = full.min(size.saturating_sub(off));
        let sprot = match (access & FILE_MAP_WRITE != 0, access & FILE_MAP_EXECUTE != 0) {
            (true, true) => 0x40,
            (true, false) => PAGE_READWRITE,
            (false, true) => 0x20,
            (false, false) => 0x02,
        };
        let section = if len == 0 { 0 } else { unsafe { CreateFileMappingW(h, std::ptr::null_mut(), sprot, 0, 0, std::ptr::null()) } };
        let head = len.next_multiple_of(PAGE).min(full);
        if head > 0 {
            carve(base, head);
        }
        let mapped = section != 0
            && unsafe { MapViewOfFile3(section, me, base as *mut _, off, len as usize, MEM_REPLACE_PLACEHOLDER, sprot, std::ptr::null_mut(), 0) } as u64 == base;
        if !mapped {
            // Nothing of the file left there (or it wouldn't map): plain reserved memory that faults.
            if section != 0 {
                unsafe { CloseHandle(section) };
            }
            for (a, n) in [(base, head), (base + head, full - head)] {
                if n > 0 {
                    place_plain(a, n, false);
                }
            }
            continue;
        }
        let mut file = 0isize;
        unsafe { crate::win::DuplicateHandle(me, h, me, &mut file, 0, 0, 2) }; // DUPLICATE_SAME_ACCESS, for grow_view
        views.push(View { base, len, section, off, access, full, file, prot: (sprot, sprot) });
    }
    r
}

/// Make [addr, addr+len) free of copy-on-write views. Returns the placeholder holes left inside it.
fn punch_views(addr: u64, len: u64) -> Vec<(u64, u64)> {
    let mut views = COW_VIEWS.lock().unwrap();
    let mut holes = Vec::new();
    let mut i = 0;
    while i < views.len() {
        let v = &views[i];
        let (vb, ve) = (v.base, v.base + v.len);
        if ve <= addr || vb >= addr + len {
            i += 1;
            continue;
        }
        let v = views.remove(i);
        let prots = protections(vb, v.len);
        let me = unsafe { GetCurrentProcess() };
        if v.written {
            // Changed by the guest: keep the contents as private memory instead.
            let mut copy = vec![0u8; v.len as usize];
            unsafe { std::ptr::copy_nonoverlapping(vb as *const u8, copy.as_mut_ptr(), copy.len()) };
            unsafe { UnmapViewOfFile2(me, vb as *mut _, MEM_PRESERVE_PLACEHOLDER) };
            place_plain(vb, v.len, true);
            unsafe { std::ptr::copy_nonoverlapping(copy.as_ptr(), vb as *mut u8, copy.len()) };
            reprotect(&prots, |_| true);
            continue;
        }
        unsafe { UnmapViewOfFile2(me, vb as *mut _, MEM_PRESERVE_PLACEHOLDER) };
        let (cut0, cut1) = (vb.max(addr), ve.min(addr + len));
        let mut keep = Vec::new();
        if vb < cut0 {
            keep.push((vb, cut0 - vb, v.off));
        }
        if cut1 < ve {
            keep.push((cut1, ve - cut1, v.off + (cut1 - vb)));
        }
        for &(a, n, off) in &keep {
            if place_view(v.section, a, off, n, v.fsize) {
                for &(co, cn) in &v.code {
                    let (lo, hi) = (co.max(off), (co + cn).min(off + n));
                    if lo < hi {
                        patch_code(a + (lo - off), (hi - lo) as usize);
                    }
                }
                views.insert(i, CowView { base: a, len: n, section: v.section, off, fsize: v.fsize, code: v.code.clone(), written: false });
                i += 1;
            }
        }
        reprotect(&prots, |p| p < cut0 || p >= cut1);
        holes.push((cut0, cut1 - cut0));
    }
    holes
}

/// mprotect on views: writable means their pages may now hold the guest's changes, executable means
/// syscall sites got patched in (so a re-map must patch again).
fn mark_views(addr: u64, len: u64, written: bool, exec: bool) {
    for v in COW_VIEWS.lock().unwrap().iter_mut() {
        if v.base < addr + len && addr < v.base + v.len {
            v.written |= written;
            if exec {
                // mprotect patched this part: a re-map must patch it again (overlaps rescan clean).
                let (lo, hi) = (addr.max(v.base), (addr + len).min(v.base + v.len));
                v.code.push((v.off + (lo - v.base), hi - lo));
            }
        }
    }
}

/// A private file mapping as a copy-on-write view; `holes`: the placeholders punch_views left for a
/// MAP_FIXED. Returns the address, or None for the ordinary copying path.
fn mmap_cow(addr: u64, len: u64, prot: u64, fixed: bool, fd: u64, off: u64, holes: &[(u64, u64)]) -> Option<u64> {
    if std::env::var_os("LX_NOCOW").is_some() || off % PAGE != 0 {
        return None;
    }
    if debug() {
        dlog(format_args!("mmap_cow {addr:#x}+{len:#x} off {off:#x} prot {prot} fixed {fixed} holes {holes:x?}"));
    }
    // MAP_FIXED only into one whole hole a punched view left (ld.so's segments); elsewhere copy.
    if fixed && holes != [(addr, len)] {
        return None;
    }
    let (section, size) = file_section(fd)?;
    if off >= size {
        unsafe { CloseHandle(section) };
        return None;
    }
    let flen = len.min((size - off).next_multiple_of(PAGE));
    let base = if fixed {
        addr
    } else {
        let a = loop {
            let a = NEXT.fetch_add(len.next_multiple_of(0x10000), Relaxed);
            if a + len > WINDOW.1 {
                unsafe { CloseHandle(section) };
                return None;
            }
            if unsafe { VirtualAlloc2(0, a as *mut _, len as usize, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, 0x01, std::ptr::null_mut(), 0) } as u64 == a {
                break a;
            }
        };
        ALLOCS.lock().unwrap().push((a, len));
        a
    };
    let (view_ok, tail_ok) = (place_view(section, base, off, flen, size), flen == len || place_plain(base + flen, len - flen, true));
    if debug() && !(view_ok && tail_ok) {
        dlog(format_args!("mmap_cow at {base:#x}: view {view_ok} (flen {flen:#x}) tail {tail_ok} err {}", unsafe { GetLastError() }));
    }
    if !(view_ok && tail_ok) {
        return None; // ponytail: a half-placed mapping is left as is; never seen
    }
    // Executable: mmap patches it (exec_ranges) right after and records which ranges (set_view_code).
    COW_VIEWS.lock().unwrap().push(CowView { base, len: flen, section, off, fsize: size, code: Vec::new(), written: prot & 2 != 0 });
    Some(base)
}

/// /proc/self/maps: the guest's allocations and views as NT sees them now, one line per run of pages
/// with the same state and protection. ponytail: no file names, offsets or [heap]/[stack] labels.
pub fn maps() -> String {
    let mut ranges: Vec<(u64, u64, bool)> = ALLOCS.lock().unwrap().iter().map(|&(b, l)| (b, l, false)).collect();
    ranges.extend(VIEWS.lock().unwrap().iter().map(|v| (v.base, v.len, true)));
    ranges.extend(COW_VIEWS.lock().unwrap().iter().map(|v| (v.base, v.len, false)));
    ranges.extend(SHM_AT.lock().unwrap().iter().map(|&(b, l)| (b, l, true)));
    ranges.sort();
    let (mut out, mut done) = (String::new(), 0u64);
    for (base, len, shared) in ranges {
        let mut p = base.max(done);
        while p < base + len {
            let mut m = MemoryBasicInformation::default();
            if unsafe { VirtualQuery(p as *const _, &mut m, size_of::<MemoryBasicInformation>()) } == 0 {
                break;
            }
            let end = ((m.base + m.region_size) as u64).min(base + len);
            if m.state != MEM_FREE {
                let perms = match if m.state == MEM_COMMIT { m.protect & 0xff } else { 1 } {
                    0x02 => "r--", 0x04 | 0x08 => "rw-", 0x10 => "--x", 0x20 => "r-x", 0x40 | 0x80 => "rwx", _ => "---",
                };
                out += &format!("{p:08x}-{end:08x} {perms}{} 00000000 00:00 0\n", if shared { 's' } else { 'p' });
            }
            p = end;
        }
        done = done.max(base + len);
    }
    out
}
