//! Linux signals: dispositions, the blocked mask, and delivery when a syscall returns.
//! Sources today: SIGCHLD when a child exits, and kill/tkill on ourselves.
//! ponytail: no asynchronous delivery into a running guest and no cross-process signals yet (kill() on
//! another process terminates it). Those need a per-process signal channel; see DESIGN.md §5.
use crate::proc;
use crate::syscall::{R, EINTR, EINVAL};
use crate::win::Context;
use std::sync::Mutex;

pub const SIGCHLD: u64 = 17;
const SA_NODEFER: u64 = 0x4000_0000;
const SA_RESETHAND: u64 = 0x8000_0000;
const SA_ONSTACK: u64 = 0x0800_0000;
const SS_ONSTACK: u64 = 1;
const SS_DISABLE: u64 = 2;

/// sigaltstack(ss, old_ss), per thread. Go requires it: goroutine stacks are too small for signal frames.
/// stack_t is { void *ss_sp; int ss_flags; size_t ss_size; }.
pub fn sigaltstack(ss: u64, old: u64, rsp: u64) -> R {
    let t = crate::syscall::ts();
    let on = t.altstack.is_some_and(|(b, n)| (b..b + n).contains(&rsp));
    if old != 0 {
        let (b, n) = t.altstack.unwrap_or((0, 0));
        let flags = if t.altstack.is_none() { SS_DISABLE } else if on { SS_ONSTACK } else { 0 };
        unsafe { *(old as *mut [u64; 3]) = [b, flags, n] };
    }
    if ss != 0 {
        if on {
            return Err(crate::syscall::EPERM);
        }
        let [b, flags, n] = unsafe { *(ss as *const [u64; 3]) };
        t.altstack = if flags as u32 as u64 & SS_DISABLE != 0 { None } else { Some((b, n)) };
    }
    Ok(0)
}

#[derive(Clone, Copy)]
struct Action {
    handler: u64, // 0 = SIG_DFL, 1 = SIG_IGN, else a guest function
    flags: u64,
    restorer: u64,
    mask: u64,
}
const DFL: Action = Action { handler: 0, flags: 0, restorer: 0, mask: 0 };

struct State {
    actions: [Action; 65],
    blocked: u64,
    pending: u64,
    /// While in sigsuspend: the mask to restore once the handler returns.
    suspended_mask: Option<u64>,
}
static S: Mutex<State> = Mutex::new(State { actions: [DFL; 65], blocked: 0, pending: 0, suspended_mask: None });

fn bit(sig: u64) -> u64 {
    1 << (sig - 1)
}
const UNBLOCKABLE: u64 = (1 << 8) | (1 << 18); // SIGKILL, SIGSTOP

pub fn sigaction(sig: u64, act: u64, old: u64) -> R {
    if sig == 0 || sig > 64 {
        return Err(EINVAL);
    }
    let mut s = S.lock().unwrap();
    let a = s.actions[sig as usize];
    if old != 0 {
        unsafe { *(old as *mut [u64; 4]) = [a.handler, a.flags, a.restorer, a.mask] }; // struct k_sigaction
    }
    if act != 0 {
        if sig == 9 || sig == 19 {
            return Err(EINVAL);
        }
        let [handler, flags, restorer, mask] = unsafe { *(act as *const [u64; 4]) };
        s.actions[sig as usize] = Action { handler, flags, restorer, mask };
    }
    Ok(0)
}

pub fn sigprocmask(how: u64, set: u64, old: u64) -> R {
    let mut s = S.lock().unwrap();
    if old != 0 {
        unsafe { *(old as *mut u64) = s.blocked };
    }
    if set != 0 {
        let v = unsafe { *(set as *const u64) };
        s.blocked = match how {
            0 => s.blocked | v,  // SIG_BLOCK
            1 => s.blocked & !v, // SIG_UNBLOCK
            2 => v,              // SIG_SETMASK
            _ => return Err(EINVAL),
        } & !UNBLOCKABLE;
    }
    Ok(0)
}

pub fn raise(sig: u64) -> R {
    if sig == 0 || sig > 64 {
        return Err(EINVAL);
    }
    S.lock().unwrap().pending |= bit(sig);
    Ok(0)
}

pub fn deliverable() -> bool {
    let s = S.lock().unwrap();
    s.pending & !s.blocked != 0
}

// ---- signals from other processes (kill, lx kill/stop) and from the console (Ctrl-C) ----
//
// Each lx process owns a mailbox: shared memory `Local\lx-sig-<pid>` holding a pending bitmask, plus
// the event `Local\lx-sigev-<pid>`. Senders OR their bit in and set the event. A watcher thread turns
// arrivals into raise() + wake(). ponytail: a handler can't run while the guest spins without making
// syscalls; that needs thread hijack (SuspendThread/SetThreadContext). Default "terminate" still works.

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicIsize, Ordering::SeqCst};

/// Set by the waits a signal must cut short (sleep, poll, wait4, sigsuspend). Auto-reset.
static INTR: AtomicIsize = AtomicIsize::new(0);
/// The guest's thread, so CancelSynchronousIo can break a blocked ReadFile/WriteFile.
static GUEST_THREAD: AtomicIsize = AtomicIsize::new(0);
/// While this process only waits for an exec'd successor: pass signals on to it (same Linux pid).
pub static FORWARD_TO: AtomicU32 = AtomicU32::new(0);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn mailbox(pid: u32, create: bool) -> Option<(&'static AtomicU64, isize)> {
    use crate::win::*;
    let (map_name, ev_name) = (wide(&format!("Local\\lx-sig-{pid}")), wide(&format!("Local\\lx-sigev-{pid}")));
    unsafe {
        let (map, ev) = if create {
            (CreateFileMappingW(-1, std::ptr::null_mut(), PAGE_READWRITE, 0, 8, map_name.as_ptr()),
             CreateEventW(std::ptr::null_mut(), 0, 0, ev_name.as_ptr()))
        } else {
            (OpenFileMappingW(FILE_MAP_WRITE, 0, map_name.as_ptr()), OpenEventW(EVENT_MODIFY_STATE, 0, ev_name.as_ptr()))
        };
        if map == 0 || ev == 0 {
            return None;
        }
        let view = MapViewOfFile(map, FILE_MAP_WRITE, 0, 0, 8);
        // ponytail: sender-side handles and views are never closed; senders are short-lived.
        (!view.is_null()).then(|| (&*(view as *const AtomicU64), ev))
    }
}

/// Put `sig` in another lx process's mailbox. ESRCH if it isn't a running lx guest.
pub fn send(pid: u32, sig: u64) -> R {
    if sig == 0 || sig > 64 {
        return Err(EINVAL);
    }
    let (bits, ev) = mailbox(pid, false).ok_or(crate::syscall::ESRCH)?;
    bits.fetch_or(bit(sig), SeqCst);
    unsafe { crate::win::SetEvent(ev) };
    Ok(0)
}

/// Make this process signalable: create the mailbox, start the watcher, take over Ctrl-C.
pub fn listen() {
    use crate::win::*;
    unsafe {
        let mut t = 0isize;
        DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &mut t, 0, 0, 2); // SAME_ACCESS
        GUEST_THREAD.store(t, SeqCst);
        INTR.store(CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null()), SeqCst);
        SetConsoleCtrlHandler(Some(console_ctrl), 1);
    }
    let Some((bits, ev)) = mailbox(unsafe { GetCurrentProcessId() }, true) else { return };
    std::thread::spawn(move || loop {
        unsafe { WaitForMultipleObjects(1, &ev, 0, u32::MAX) };
        let mut b = bits.swap(0, SeqCst);
        while b != 0 {
            let sig = b.trailing_zeros() as u64 + 1;
            b &= b - 1;
            arrive(sig);
        }
    });
}

/// A signal from outside: forward it (if we only wait for an exec'd successor) or raise and wake.
fn arrive(sig: u64) {
    if crate::syscall::siglog() {
        crate::syscall::dlog(format_args!("pid {} arrive {sig}", unsafe { crate::win::GetCurrentProcessId() }));
    }
    let to = FORWARD_TO.load(SeqCst);
    if to != 0 {
        let _ = send(to, sig);
        return;
    }
    if sig == 9 {
        proc::exit(128 + 9); // SIGKILL can't be caught
    }
    let _ = raise(sig);
    // Default action "terminate" needs no guest cooperation: do it now, even if the guest is spinning.
    let fatal = {
        let s = S.lock().unwrap();
        s.pending & !s.blocked & bit(sig) != 0 && s.actions[sig as usize].handler == 0 && !default_ignores(sig)
    };
    if fatal {
        proc::exit(128 + sig);
    }
    unsafe {
        crate::win::SetEvent(INTR.load(SeqCst));
        crate::win::CancelSynchronousIo(GUEST_THREAD.load(SeqCst));
    }
}

/// Ctrl-C / Ctrl-Break / console close, which every process on the console gets, like a terminal's
/// foreground group gets SIGINT. A waiting exec proxy ignores it: its successor gets its own.
unsafe extern "system" fn console_ctrl(kind: u32) -> i32 {
    if FORWARD_TO.load(SeqCst) == 0 {
        arrive(match kind {
            0 => 2,  // CTRL_C_EVENT -> SIGINT
            1 => 3,  // CTRL_BREAK_EVENT -> SIGQUIT
            _ => 1,  // close/logoff/shutdown -> SIGHUP
        });
    }
    1
}

/// The event a blocking wait should include so a signal interrupts it (0 before listen()).
pub fn intr_event() -> isize {
    INTR.load(SeqCst)
}

/// Sleep up to `ms` (u32::MAX = forever), cut short by a deliverable signal: then Err(EINTR).
pub fn interruptible_sleep(ms: u32) -> R {
    let ev = intr_event();
    let start = std::time::Instant::now();
    loop {
        if deliverable() {
            return Err(EINTR);
        }
        let left = if ms == u32::MAX { u32::MAX } else { ms.saturating_sub(start.elapsed().as_millis() as u32) };
        if left == 0 {
            return Ok(0);
        }
        if ev == 0 {
            std::thread::sleep(std::time::Duration::from_millis(left.min(3_600_000) as u64));
        } else {
            unsafe { crate::win::WaitForMultipleObjects(1, &ev, 0, left) };
        }
    }
}

/// setitimer(ITIMER_REAL) / alarm: SIGALRM after `value_ms`, then every `interval_ms` (0 = once).
/// Each call replaces the previous timer. ponytail: the old timer's remaining time reads as 0, and
/// ITIMER_VIRTUAL/PROF (CPU-time timers) aren't supported.
pub fn set_alarm(value_ms: u64, interval_ms: u64) {
    static GEN: AtomicU64 = AtomicU64::new(0);
    let id = GEN.fetch_add(1, SeqCst) + 1;
    if value_ms == 0 {
        return; // disarm
    }
    std::thread::spawn(move || {
        let mut wait = value_ms;
        loop {
            std::thread::sleep(std::time::Duration::from_millis(wait));
            if GEN.load(SeqCst) != id {
                return; // replaced or disarmed meanwhile
            }
            arrive(14); // SIGALRM
            if interval_ms == 0 {
                return;
            }
            wait = interval_ms;
        }
    });
}

/// `TERM`, `SIGTERM`, `15` -> 15.
pub fn parse(name: &str) -> Option<u64> {
    const NAMES: [&str; 31] = ["HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV", "USR2",
        "PIPE", "ALRM", "TERM", "STKFLT", "CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG", "XCPU", "XFSZ",
        "VTALRM", "PROF", "WINCH", "IO", "PWR", "SYS"];
    let n = name.trim_start_matches('-');
    let n = n.strip_prefix("SIG").unwrap_or(n).to_ascii_uppercase();
    n.parse().ok().filter(|&s| (1..=64).contains(&s))
        .or_else(|| NAMES.iter().position(|&x| x == n).map(|i| i as u64 + 1))
}

/// rt_sigsuspend (mask_ptr != 0) and pause (mask_ptr == 0): swap in the mask, sleep until a signal
/// can be delivered, return EINTR. The handler then runs on the way out of the syscall.
pub fn sigsuspend(mask_ptr: u64) -> R {
    {
        let mut s = S.lock().unwrap();
        s.suspended_mask = Some(s.blocked);
        if mask_ptr != 0 {
            s.blocked = unsafe { *(mask_ptr as *const u64) } & !UNBLOCKABLE;
        }
    }
    while !deliverable() {
        proc::wait_for_child_exit(); // returns on a child exit (raising SIGCHLD) or a signal from outside
    }
    Err(EINTR)
}

fn default_ignores(sig: u64) -> bool {
    matches!(sig, 17 | 18 | 23 | 28) // SIGCHLD, SIGCONT, SIGURG, SIGWINCH
}

// ucontext_t / siginfo_t layout (x86-64 Linux).
const UC_MCONTEXT: u64 = 40; // after uc_flags, uc_link, uc_stack
const UC_SIGMASK: u64 = UC_MCONTEXT + 256;
const UC_SIZE: u64 = 1024; // room for the full struct, fpregs pointer left NULL
const SI_SIZE: u64 = 128;

/// Order of gregs in mcontext: r8..r15, rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip, eflags.
fn gregs(c: &mut Context) -> [&mut u64; 17] {
    [&mut c.r8, &mut c.r9, &mut c.r10, &mut c.r11, &mut c.r12, &mut c.r13, &mut c.r14, &mut c.r15,
     &mut c.rdi, &mut c.rsi, &mut c.rbp, &mut c.rbx, &mut c.rdx, &mut c.rax, &mut c.rcx, &mut c.rsp, &mut c.rip]
}

/// Largest signal frame: return address + ucontext + siginfo, plus alignment slack.
pub const FRAME_MAX: usize = (8 + UC_SIZE + SI_SIZE + 32) as usize;

/// Called when a syscall returns (`c` already holds the post-syscall state). If a signal is pending and
/// unblocked, run its default action, or point `c` at its handler and return the signal frame bytes,
/// which the caller places at the new `c.rsp` once it's safe to (see syscall::resume_with_signals).
pub fn deliver(c: &mut Context) -> Option<Vec<u8>> {
    proc::notice_child_exits();
    let mut s = S.lock().unwrap();
    loop {
        let ready = s.pending & !s.blocked;
        if ready == 0 {
            return None;
        }
        let sig = ready.trailing_zeros() as u64 + 1;
        s.pending &= !bit(sig);
        let a = s.actions[sig as usize];
        match a.handler {
            0 if default_ignores(sig) => continue,
            0 => {
                drop(s);
                proc::exit(128 + sig); // default action: terminate, reported like a shell would
            }
            1 => continue, // SIG_IGN
            handler => {
                let restore_mask = s.suspended_mask.take().unwrap_or(s.blocked);
                // Below the red zone: [return address = restorer][ucontext][siginfo].
                // SA_ONSTACK handlers start at the top of the thread's alternate stack, unless already on it.
                let t = crate::syscall::ts();
                let alt = t.altstack.filter(|&(b, n)| a.flags & SA_ONSTACK != 0 && !(b..b + n).contains(&c.rsp));
                let top = alt.map(|(b, n)| b + n).unwrap_or(c.rsp - 128); // else below the red zone
                let info = (top - SI_SIZE) & !15;
                let uc = (info - UC_SIZE) & !15;
                let sp = uc - 8; // handler entry: rsp % 16 == 8, as after a call
                let mut frame = vec![0u8; (info + SI_SIZE - sp) as usize];
                let mut put = |addr: u64, v: u64| {
                    let o = (addr - sp) as usize;
                    frame[o..o + 8].copy_from_slice(&v.to_le_bytes());
                };
                put(sp, a.restorer);
                put(info, sig); // si_signo (low half), si_errno 0
                put(info + 8, if sig == SIGCHLD { 1 } else { 0 }); // si_code: CLD_EXITED / SI_USER
                let flags = c.eflags as u64;
                for (i, r) in gregs(c).into_iter().enumerate() {
                    put(uc + UC_MCONTEXT + 8 * i as u64, *r);
                }
                put(uc + UC_MCONTEXT + 8 * 17, flags);
                put(uc + UC_SIGMASK, restore_mask);
                if let Some((b, n)) = t.altstack {
                    // uc_stack describes the alternate stack (Go reads it back).
                    let on_alt = alt.is_some() || (b..b + n).contains(&c.rsp);
                    put(uc + 16, b);
                    put(uc + 24, if on_alt { SS_ONSTACK } else { 0 });
                    put(uc + 32, n);
                } else {
                    put(uc + 24, SS_DISABLE);
                }
                if crate::syscall::siglog() {
                    crate::syscall::dlog(format_args!("signal {sig}: handler {handler:#x}, frame {sp:#x}, interrupted rip {:#x} rsp {:#x}, alt {:?}", c.rip, c.rsp, alt));
                }
                (c.rsp, c.rip, c.rdi, c.rsi, c.rdx) = (sp, handler, sig, info, uc);
                s.blocked |= (a.mask | if a.flags & SA_NODEFER == 0 { bit(sig) } else { 0 }) & !UNBLOCKABLE;
                if a.flags & SA_RESETHAND != 0 {
                    s.actions[sig as usize] = DFL;
                }
                return Some(frame); // one handler at a time; the rest go when it returns via rt_sigreturn
            }
        }
    }
}

/// rt_sigreturn: the handler's restorer called it with rsp at our ucontext. Restore everything.
pub fn sigreturn(c: &mut Context) {
    let uc = c.rsp;
    let get = |i: usize| unsafe { *((uc + UC_MCONTEXT) as *const u64).add(i) };
    let saved: Vec<u64> = (0..18).map(get).collect();
    for (r, v) in gregs(c).into_iter().zip(&saved) {
        *r = *v;
    }
    c.eflags = saved[17] as u32;
    if crate::syscall::siglog() {
        crate::syscall::dlog(format_args!("sigreturn to rip {:#x} rsp {:#x}", c.rip, c.rsp));
    }
    S.lock().unwrap().blocked = unsafe { *((uc + UC_SIGMASK) as *const u64) } & !UNBLOCKABLE;
}

/// Dispositions and mask survive fork. (Fields: blocked, then 64 x [handler, flags, restorer, mask].)
pub fn snapshot() -> Vec<String> {
    let s = S.lock().unwrap();
    let mut v = vec![s.blocked];
    for a in &s.actions[1..] {
        v.extend([a.handler, a.flags, a.restorer, a.mask]);
    }
    v.into_iter().map(|n| n.to_string()).collect()
}

pub fn restore(f: &[String]) -> Result<&[String], String> {
    const N: usize = 1 + 64 * 4;
    let nums: Vec<u64> = f.get(..N).ok_or("malformed signal state")?.iter()
        .map(|x| x.parse().map_err(|_| "malformed signal state".to_string())).collect::<Result<_, _>>()?;
    let mut s = S.lock().unwrap();
    s.blocked = nums[0];
    for (i, a) in nums[1..].chunks(4).enumerate() {
        s.actions[i + 1] = Action { handler: a[0], flags: a[1], restorer: a[2], mask: a[3] };
    }
    Ok(&f[N..])
}
