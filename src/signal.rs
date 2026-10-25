//! Linux signals: dispositions, the blocked mask, and delivery when a syscall returns.
//! Sources today: SIGCHLD when a child exits, and kill/tkill on ourselves.
//! ponytail: no asynchronous delivery into a running guest and no cross-process signals yet (kill() on
//! another process terminates it). Those need a per-process signal channel; see DESIGN.md §5.
use crate::proc;
use crate::syscall::{R, EAGAIN, EINTR, EINVAL};
use crate::win::Context;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

pub const SIGCHLD: u64 = 17;
const SA_NODEFER: u64 = 0x4000_0000;
const SA_RESTART: u64 = 0x1000_0000;
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

/// Dispositions and pending signals are the process's; the blocked mask is each thread's own
/// (`ThreadState::sigmask`), so one thread's handler or sigprocmask never changes another's.
/// ponytail: pending is process-wide (no per-thread pending for tkill or faults): the first thread
/// with the signal unblocked takes it.
struct State {
    actions: [Action; 65],
    pending: u64,
}
static S: Mutex<State> = Mutex::new(State { actions: [DFL; 65], pending: 0 });

/// The main guest thread's mask, for the watcher thread's "is a fatal signal blocked?" check.
static MAIN_MASK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn mask() -> u64 {
    crate::syscall::ts().sigmask
}

fn set_mask(v: u64) {
    let v = v & !UNBLOCKABLE;
    crate::syscall::ts().sigmask = v;
    if unsafe { crate::win::GetCurrentThreadId() } == crate::thread::MAIN_TID.load(std::sync::atomic::Ordering::Relaxed) {
        MAIN_MASK.store(v, std::sync::atomic::Ordering::Relaxed);
    }
}

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
        if sig == SIGCHLD {
            const SA_NOCLDWAIT: u64 = 2;
            crate::ptable::set_nocldwait(handler == 1 || flags & SA_NOCLDWAIT != 0); // SIG_IGN: no zombies
        }
    }
    Ok(0)
}

pub fn sigprocmask(how: u64, set: u64, old: u64) -> R {
    let m = mask();
    if old != 0 {
        unsafe { *(old as *mut u64) = m };
    }
    if set != 0 {
        let v = unsafe { *(set as *const u64) };
        set_mask(match how {
            0 => m | v,  // SIG_BLOCK
            1 => m & !v, // SIG_UNBLOCK
            2 => v,      // SIG_SETMASK
            _ => return Err(EINVAL),
        });
    }
    Ok(0)
}

pub fn raise(sig: u64) -> R {
    if sig == 0 || sig > 64 {
        return Err(EINVAL);
    }
    if sig == SIGCONT {
        cont(); // whatever its handler: a stopped process goes on
    }
    let mut s = S.lock().unwrap();
    // An ignored signal (SIG_IGN, or a default action of "ignore" like SIGCHLD's) that isn't blocked is
    // discarded when it's sent, as on Linux: left pending it would make the next wait4 return EINTR.
    let handler = s.actions[sig as usize].handler;
    let blocked = MAIN_MASK.load(std::sync::atomic::Ordering::Relaxed) & bit(sig) != 0;
    // SIGSTOP, and SIGTSTP/SIGTTIN/SIGTTOU left at their default: the process stops (a blocked one waits
    // in pending, and stops when deliver finds it).
    if sig == 19 || (matches!(sig, 20..=22) && handler == 0 && !blocked) {
        drop(s);
        stop(sig);
        return Ok(0);
    }
    if !blocked && (handler == 1 || (handler == 0 && default_ignores(sig))) {
        return Ok(0);
    }
    s.pending |= bit(sig);
    Ok(0)
}

/// rt_sigpending: the signals pending for this thread or the process that its mask blocks.
pub fn sigpending(set: u64, size: u64) -> R {
    if size > 8 {
        return Err(EINVAL);
    }
    let s = S.lock().unwrap();
    let pending = (s.pending | crate::syscall::ts().tpending.load(SeqCst)) & mask();
    crate::syscall::put_guest(set, &pending.to_le_bytes())
}

pub fn deliverable() -> bool {
    let s = S.lock().unwrap();
    (s.pending | crate::syscall::ts().tpending.load(SeqCst)) & !mask() != 0
}

/// tkill/tgkill: a signal for one thread of ours (`tid` as gettid says it: the main thread is the pid).
/// It's woken if parked in a futex; Go's AllThreadsSyscall (setuid in gosu) waits for every thread.
pub fn send_thread(tid: u64, sig: u64) -> R {
    if sig > 64 {
        return Err(EINVAL);
    }
    let main = crate::thread::MAIN_TID.load(Relaxed);
    let wtid = if proc::host_pid(tid as u32) == proc::pid() { main } else { tid as u32 };
    let t = crate::syscall::ts_of(wtid).ok_or(crate::syscall::ESRCH)?;
    if sig == 0 {
        return Ok(0);
    }
    {
        let _s = S.lock().unwrap(); // deliver() takes it from under the same lock
        t.tpending.fetch_or(bit(sig), SeqCst);
    }
    let addr = t.futex_addr.load(SeqCst);
    if addr != 0 {
        unsafe { crate::win::WakeByAddressAll(addr as *const _) };
    }
    // What its sleeps and waits wait on (intr_event): INTR for the main thread, else its own.
    let ev = if wtid == main { INTR.load(SeqCst) } else { t.wake.load(SeqCst) };
    if ev != 0 {
        unsafe { crate::win::SetEvent(ev) };
    }
    // A thread spinning in guest code makes no syscall to take it at: stop it there.
    let handled = S.lock().unwrap().actions[sig as usize].handler > 1;
    if handled && t.sigmask & bit(sig) == 0 && wtid != unsafe { crate::win::GetCurrentThreadId() } {
        let h = if wtid == main { GUEST_THREAD.load(SeqCst) } else { crate::thread::handle_of(wtid) };
        kick(h, t);
    }
    Ok(0)
}

/// Make a thread that is running guest code take its pending signal now, as Linux interrupts a running
/// thread. It's suspended, and if it's in guest code (not in lx or a Windows DLL, where it takes the
/// signal as its syscall returns or its wait wakes) it is sent to lx_kick_entry: in by the direct syscall
/// path, which moves to the thread's lx stack before touching memory, saves every register and the vector
/// state, delivers, and returns where it was. Nothing is written below the guest's rsp but the signal
/// frame (Go's goroutine stacks are a few KB, packed together). Spinning loops (`while (!flag)`), Go's
/// preemption and GC suspension signals need it.
#[repr(C, align(16))]
struct Ctx([u8; 1232]); // CONTEXT: ContextFlags 0x30, Rcx 0x80, R11 0xd0, Rip 0xf8

fn kick(h: isize, t: &crate::syscall::ThreadState) {
    // LX_NOKICK=1 turns kicks off (a handled signal then waits for the thread's next syscall).
    static OFF: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *OFF.get_or_init(|| std::env::var("LX_NOKICK").is_ok_and(|v| v == "1")) {
        return;
    }
    if h == 0 || t.kicked.load(SeqCst) {
        return; // not a guest thread, or a kick on its way already
    }
    let q = |c: &Ctx, o: usize| u64::from_le_bytes(c.0[o..o + 8].try_into().unwrap());
    // Inside a stub the thread leaves it within a few instructions: let it run a moment, then look again.
    for _ in 0..20 {
        let mut c = Ctx([0; 1232]);
        c.0[0x30..0x34].copy_from_slice(&0x0010_0003u32.to_le_bytes()); // CONTEXT_AMD64 | CONTROL | INTEGER
        if !unsafe { kick_once(h, t, &mut c, q) } {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// One try of kick: false when done (kicked, or nothing to do), true to try again (it was in a stub).
unsafe fn kick_once(h: isize, t: &crate::syscall::ThreadState, c: &mut Ctx, q: impl Fn(&Ctx, usize) -> u64) -> bool {
    unsafe extern "system" {
        fn SuspendThread(h: isize) -> u32;
        fn GetThreadContext(h: isize, c: *mut u8) -> i32;
        fn SetThreadContext(h: isize, c: *const u8) -> i32;
    }
    // One kick at a time in the process: two threads signalling each other (Go's threads preempt one
    // another) each sat in SuspendThread on the other, waiting for it to stop, and neither ever did.
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let mut again = false;
    unsafe {
        if SuspendThread(h) == u32::MAX {
            return false;
        }
        if GetThreadContext(h, c.0.as_mut_ptr()) != 0 {
            let rip = q(c, 0xf8);
            let mut m = crate::win::MemoryBasicInformation::default();
            crate::win::VirtualQuery(rip as *const _, &mut m, std::mem::size_of::<crate::win::MemoryBasicInformation>());
            const MEM_IMAGE: u32 = 0x100_0000;
            let guest = m.state == 0x1000 && m.ty != MEM_IMAGE && !t.on_host();
            again = guest && crate::jump::in_stub(rip);
            if guest && !again {
                for (i, o) in [0xf8, 0x80, 0xd0].into_iter().enumerate() {
                    t.kick[i].store(q(c, o), SeqCst);
                }
                t.kicked.store(true, SeqCst);
                c.0[0xf8..0x100].copy_from_slice(&crate::syscall::kick_entry_addr().to_le_bytes());
                c.0[0x30..0x34].copy_from_slice(&0x0010_0001u32.to_le_bytes()); // set only CONTROL
                if SetThreadContext(h, c.0.as_ptr()) == 0 {
                    t.kicked.store(false, SeqCst);
                }
            }
        }
        crate::win::ResumeThread(h);
    }
    again
}

// ---- signalfd ----

/// signalfd: readable while one of `mask`'s signals is pending; a read takes it. The program keeps those
/// signals blocked (postgres 18 waits on one with epoll instead of using handlers), so ordinary delivery
/// leaves them pending for us.
pub struct SignalFd {
    pub mask: AtomicU64,
    pub nonblock: AtomicBool,
}

impl SignalFd {
    fn take(&self) -> Option<u64> {
        let mut s = S.lock().unwrap();
        let hit = s.pending & self.mask.load(Relaxed);
        let sig = (hit != 0).then(|| hit.trailing_zeros() as u64 + 1)?;
        s.pending &= !bit(sig);
        Some(sig)
    }

    /// Fills whole struct signalfd_siginfo (128 bytes): ssi_signo, and ssi_code CLD_EXITED for SIGCHLD
    /// (only a child's exit raises it; util-linux's script reaps only on such codes).
    /// ponytail: no ssi_pid or ssi_status; reapers waitpid for those.
    pub fn read(&self, buf: u64, len: u64) -> R {
        if len < 128 {
            return Err(EINVAL);
        }
        let mut n = 0;
        while n < len / 128 {
            match self.take() {
                Some(sig) => {
                    let mut info = [0u8; 128];
                    info[..4].copy_from_slice(&(sig as u32).to_le_bytes());
                    if sig == SIGCHLD {
                        info[8..12].copy_from_slice(&1i32.to_le_bytes()); // CLD_EXITED
                    }
                    unsafe { std::ptr::copy_nonoverlapping(info.as_ptr(), (buf + n * 128) as *mut u8, 128) };
                    n += 1;
                }
                None if n > 0 => break,
                None if self.nonblock.load(Relaxed) => return Err(EAGAIN),
                None if deliverable() => return Err(EINTR),
                None => std::thread::sleep(std::time::Duration::from_millis(10)), // ponytail: polled, like eventfd
            }
        }
        Ok((n * 128) as i64)
    }

    pub fn ready(&self, events: i16) -> i16 {
        let s = S.lock().unwrap();
        if s.pending & self.mask.load(Relaxed) != 0 { events & 1 } else { 0 } // POLLIN
    }
}

// ---- signals from other processes (kill, lx kill/stop) and from the console (Ctrl-C) ----
//
// Each lx process owns a mailbox: shared memory `Local\lx-sig-<pid>` holding a pending bitmask, plus
// the event `Local\lx-sigev-<pid>`. Senders OR their bit in and set the event. A watcher thread turns
// arrivals into raise() + wake(), and kick() stops a thread that is spinning in guest code for it.

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicIsize, Ordering::SeqCst};

/// Set by the waits a signal must cut short (sleep, poll, wait4, sigsuspend). Auto-reset.
static INTR: AtomicIsize = AtomicIsize::new(0);
/// The guest's thread, so CancelSynchronousIo can break a blocked ReadFile/WriteFile.
static GUEST_THREAD: AtomicIsize = AtomicIsize::new(0);
static GUEST_TID: AtomicU32 = AtomicU32::new(0);
/// Whether the guest thread is inside a ReadFile/WriteFile a signal may cancel. Only then: the cancel
/// aborts whatever host call is running, and chdir's CreateFile failing would be a bogus EINTR.
static IN_IO: std::sync::Mutex<bool> = std::sync::Mutex::new(false);

/// Run a blocking read/write that a signal may cut short (ERROR_OPERATION_ABORTED -> EINTR).
/// Clearing the flag waits for a cancel in progress, so a cancel never lands after `f`.
pub fn interruptible<T>(f: impl FnOnce() -> T) -> T {
    if unsafe { crate::win::GetCurrentThreadId() } != GUEST_TID.load(SeqCst) {
        return f(); // the cancel targets the guest thread only
    }
    *IN_IO.lock().unwrap() = true;
    let r = f();
    *IN_IO.lock().unwrap() = false;
    r
}

fn cancel_io() {
    let in_io = IN_IO.lock().unwrap();
    if *in_io {
        unsafe { crate::win::CancelSynchronousIo(GUEST_THREAD.load(SeqCst)) };
    }
}
/// While this process only waits for an exec'd successor: pass signals on to it (same Linux pid).
pub static FORWARD_TO: AtomicU32 = AtomicU32::new(0);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

/// A process's mailbox: [pending signal bits, process group | session << 32] (both as host pids), and its
/// job-control state for the parent's wait (see `stop`): a wait status, with bit 32 while unreported; then
/// for each signal its last sender, guest pid | uid << 32 (si_pid and si_uid).
type Mailbox = [AtomicU64; 3 + 65];
const MAILBOX_SIZE: u32 = (3 + 65) * 8;

/// Who sent each signal that arrived from another process (see Mailbox), until it's delivered.
static SENDER: [AtomicU64; 65] = [const { AtomicU64::new(0) }; 65];

/// The sender of a signal from this process (kill of ourselves): our pid and uid.
pub fn sent_by_self(sig: u64) {
    if let Some(s) = SENDER.get(sig as usize) {
        s.store(proc::getpid().unwrap_or(0) as u64 | (proc::UID.load(SeqCst) as u64) << 32, SeqCst);
    }
}

fn mailbox(pid: u32, create: bool) -> Option<(&'static Mailbox, isize)> {
    use crate::win::*;
    let (map_name, ev_name) = (wide(&format!("Local\\lx-sig-{pid}")), wide(&format!("Local\\lx-sigev-{pid}")));
    unsafe {
        let (map, ev) = if create {
            (CreateFileMappingW(-1, std::ptr::null_mut(), PAGE_READWRITE, 0, MAILBOX_SIZE, map_name.as_ptr()),
             CreateEventW(std::ptr::null_mut(), 0, 0, ev_name.as_ptr()))
        } else {
            (OpenFileMappingW(FILE_MAP_WRITE, 0, map_name.as_ptr()), OpenEventW(EVENT_MODIFY_STATE, 0, ev_name.as_ptr()))
        };
        if map == 0 || ev == 0 {
            return None;
        }
        let view = MapViewOfFile(map, FILE_MAP_WRITE, 0, 0, MAILBOX_SIZE as usize);
        // ponytail: sender-side handles and views are never closed; senders are short-lived.
        (!view.is_null()).then(|| (&*(view as *const Mailbox), ev))
    }
}

/// Put `sig` in another lx process's mailbox. ESRCH if it isn't a running lx guest.
pub fn send(pid: u32, sig: u64) -> R {
    if sig == 0 || sig > 64 {
        return Err(EINVAL);
    }
    let (b, ev) = mailbox(pid, false).ok_or(crate::syscall::ESRCH)?;
    b[3 + sig as usize].store(proc::getpid().unwrap_or(0) as u64 | (proc::UID.load(SeqCst) as u64) << 32, SeqCst);
    b[0].fetch_or(bit(sig), SeqCst);
    unsafe { crate::win::SetEvent(ev) };
    Ok(0)
}

/// A forked child's mailbox exists before its handlers are restored: signals wait there until then, rather
/// than meeting default dispositions (a SIGINT for Python's handler would kill the child).
pub static HELD: AtomicBool = AtomicBool::new(false);
static OWN_EV: AtomicIsize = AtomicIsize::new(0);

/// Deliver what arrived while HELD.
pub fn release() {
    HELD.store(false, SeqCst);
    unsafe { crate::win::SetEvent(OWN_EV.load(SeqCst)) };
}

/// Our own mailbox (set by listen).
static OWN: std::sync::atomic::AtomicPtr<Mailbox> = std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

/// (process group, session) of host process `pid`, or ours for None. Read from the mailbox without keeping
/// it mapped, since a group kill looks at every process on the machine.
pub fn ids(pid: Option<u32>) -> Option<(u32, u32)> {
    use crate::win::*;
    let v = match pid {
        None => match unsafe { OWN.load(SeqCst).as_ref() } {
            Some(b) => b[1].load(SeqCst),
            None => { let p = proc::pid() as u64; p | p << 32 }
        },
        Some(pid) => unsafe {
            let map = OpenFileMappingW(FILE_MAP_WRITE, 0, wide(&format!("Local\\lx-sig-{pid}")).as_ptr());
            if map == 0 {
                return None;
            }
            let view = MapViewOfFile(map, FILE_MAP_WRITE, 0, 0, 16);
            let v = view.as_ref().map(|_| (*(view as *const Mailbox))[1].load(SeqCst));
            if !view.is_null() {
                UnmapViewOfFile(view);
            }
            CloseHandle(map);
            v?
        },
    };
    Some((v as u32, (v >> 32) as u32))
}

/// Set the (process group, session) of host process `pid`, or ours for None.
pub fn set_ids(pid: Option<u32>, pgid: u32, sid: u32) -> R {
    let b = match pid {
        None => unsafe { OWN.load(SeqCst).as_ref() }.ok_or(crate::syscall::ESRCH)?,
        Some(pid) => mailbox(pid, false).ok_or(crate::syscall::ESRCH)?.0,
    };
    b[1].store(pgid as u64 | (sid as u64) << 32, SeqCst);
    Ok(0)
}

/// Every lx process in process group `pgid` (host pids, mailbox names).
pub fn group(pgid: u32) -> Vec<u32> {
    unsafe extern "system" {
        fn K32EnumProcesses(pids: *mut u32, cb: u32, needed: *mut u32) -> i32;
    }
    let mut pids = vec![0u32; 4096];
    let mut n = 0u32;
    unsafe { K32EnumProcesses(pids.as_mut_ptr(), 4 * pids.len() as u32, &mut n) };
    pids.truncate(n as usize / 4);
    pids.retain(|&p| p != 0 && ids(Some(p)).is_some_and(|(g, _)| g == pgid));
    pids
}

/// Make this process signalable: create the mailbox, start the watcher, take over Ctrl-C.
pub fn listen() {
    use crate::win::*;
    unsafe {
        let mut t = 0isize;
        DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &mut t, 0, 0, 2); // SAME_ACCESS
        GUEST_THREAD.store(t, SeqCst);
        GUEST_TID.store(GetCurrentThreadId(), SeqCst);
        INTR.store(CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null()), SeqCst);
        SetConsoleCtrlHandler(Some(console_ctrl), 1);
    }
    let me = unsafe { GetCurrentProcessId() };
    let Some((mb, ev)) = mailbox(me, true) else { return };
    // Process group and session: inherited from the parent lx (LX_PGRP, see spawn_lx), else our own.
    // An exec'd program keeps them where its pid's mailbox is: the predecessor's, which stays as a proxy.
    let own = match proc::pid() {
        p if p == me => {
            let ids = std::env::var("LX_PGRP").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(me as u64 | (me as u64) << 32);
            mb[1].store(ids, SeqCst);
            Some(mb)
        }
        p => mailbox(p, false).map(|(b, _)| b),
    };
    if let Some(b) = own {
        OWN.store(b as *const Mailbox as *mut Mailbox, SeqCst);
    }
    OWN_EV.store(ev, SeqCst);
    std::thread::spawn(move || loop {
        unsafe { WaitForMultipleObjects(1, &ev, 0, u32::MAX) };
        if HELD.load(SeqCst) {
            continue; // stays in the mailbox until release()
        }
        let mut b = mb[0].swap(0, SeqCst);
        while b != 0 {
            let sig = b.trailing_zeros() as u64 + 1;
            b &= b - 1;
            SENDER[sig as usize].store(mb[3 + sig as usize].load(SeqCst), SeqCst);
            arrive(sig);
        }
    });
}

/// A signal from outside: forward it (if we only wait for an exec'd successor) or raise and wake.
fn arrive(sig: u64) {
    if crate::syscall::siglog() {
        let s = &crate::syscall::IN_SYSCALL;
        let now = match s[0].load(SeqCst) {
            0 => "running guest code".to_string(),
            nr => format!("in syscall {} ({:#x}, {:#x}, {:#x})", nr - 1, s[1].load(SeqCst), s[2].load(SeqCst), s[3].load(SeqCst)),
        };
        crate::syscall::dlog(format_args!("pid {} arrive {sig}; guest {now}", unsafe { crate::win::GetCurrentProcessId() }));
    }
    let to = FORWARD_TO.load(SeqCst);
    if to != 0 {
        let _ = send(to, sig);
        return;
    }
    if sig == 9 {
        proc::die(9); // SIGKILL can't be caught
    }
    let _ = raise(sig);
    // Default action "terminate" needs no guest cooperation: do it now, even if the guest is spinning.
    let fatal = {
        let s = S.lock().unwrap();
        let blocked = MAIN_MASK.load(std::sync::atomic::Ordering::Relaxed);
        s.pending & !blocked & bit(sig) != 0 && s.actions[sig as usize].handler == 0 && !default_ignores(sig)
    };
    if fatal {
        proc::die(sig);
    }
    unsafe {
        crate::win::SetEvent(INTR.load(SeqCst));
    }
    crate::syscall::wake_futex_waiters();
    cancel_io();
    if S.lock().unwrap().actions[sig as usize].handler > 1 && MAIN_MASK.load(Relaxed) & bit(sig) == 0 {
        if let Some(t) = crate::syscall::ts_of(crate::thread::MAIN_TID.load(Relaxed)) {
            kick(GUEST_THREAD.load(SeqCst), t); // in case it's spinning in guest code
        }
    }
}

/// Break a blocking wait for a signal raised from another thread of ours, if the guest has a handler for
/// it (an ignored SIGCHLD needn't interrupt anything).
pub fn wake_if_handled(sig: u64) {
    if S.lock().unwrap().actions[sig as usize].handler > 1 { // not SIG_DFL (0) or SIG_IGN (1)
        unsafe {
            crate::win::SetEvent(INTR.load(SeqCst));
        }
        crate::syscall::wake_futex_waiters();
        cancel_io();
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

/// The event a blocking wait should include so a signal interrupts it (0 before listen()): INTR on the
/// main thread, which signals from outside set, and the thread's own elsewhere, which tgkill sets and
/// process-wide signals too (wake_futex_waiters). Before, other threads shared INTR: a tgkill didn't wake
/// one in nanosleep (musl's and glibc's setuid wait for every thread to take theirs: gosu, Go with cgo).
pub fn intr_event() -> isize {
    let intr = INTR.load(SeqCst);
    if intr == 0 || unsafe { crate::win::GetCurrentThreadId() } == crate::thread::MAIN_TID.load(Relaxed) {
        return intr;
    }
    let t = crate::syscall::ts();
    let ev = t.wake.load(SeqCst);
    if ev != 0 {
        return ev;
    }
    let ev = unsafe { crate::win::CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null()) };
    t.wake.store(ev, SeqCst);
    ev
}

/// Sleep up to `ms` (u32::MAX = forever), cut short by a deliverable signal: then Err(EINTR).
pub fn interruptible_sleep(ms: u32) -> R {
    let _fine = crate::syscall::FineWait::for_ms(ms as i64); // else a 1 ms sleep takes NT's 15.6 ms tick
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

/// nanosleep and clock_nanosleep: like interruptible_sleep, but on a high-resolution waitable timer, so
/// a 1 ms sleep takes about 1 ms rather than whole timer ticks (a sleep loop's latency and throughput).
pub fn precise_sleep(d: std::time::Duration) -> R {
    unsafe extern "system" {
        fn CreateWaitableTimerExW(attr: *mut std::ffi::c_void, name: *const u16, flags: u32, access: u32) -> isize;
        fn SetWaitableTimer(t: isize, due: *const i64, period: i32, f: *mut std::ffi::c_void, a: *mut std::ffi::c_void, resume: i32) -> i32;
    }
    // One per thread state, which a later thread inherits with it (see syscall::reuse_ts).
    let ts = crate::syscall::ts();
    if ts.timer == 0 {
        ts.timer = unsafe { CreateWaitableTimerExW(std::ptr::null_mut(), std::ptr::null(), 2, 0x1F_0003) }; // HIGH_RESOLUTION, TIMER_ALL_ACCESS
    }
    let t = ts.timer;
    if t == 0 || d >= std::time::Duration::from_millis(50) {
        // Long sleeps don't need it (nor older Windows, which lacks the flag).
        return interruptible_sleep(d.as_nanos().div_ceil(1_000_000).min(u32::MAX as u128 - 1) as u32);
    }
    let start = std::time::Instant::now();
    loop {
        if deliverable() {
            return Err(EINTR);
        }
        let left = d.saturating_sub(start.elapsed());
        if left.is_zero() {
            return Ok(0);
        }
        let due = -((left.as_nanos() / 100).max(1) as i64); // relative, in 100 ns
        unsafe { SetWaitableTimer(t, &due, 0, std::ptr::null_mut(), std::ptr::null_mut(), 0) };
        let hs = [t, intr_event()];
        unsafe { crate::win::WaitForMultipleObjects(if hs[1] != 0 { 2 } else { 1 }, hs.as_ptr(), 0, u32::MAX) };
    }
}

/// rt_sigtimedwait (sigwait, sigwaitinfo): take a pending signal from `set` without running its
/// handler; daemons block their signals and wait for them in one thread. `timeout_ms` < 0: forever.
pub fn sigtimedwait(set: u64, info: u64, timeout_ms: i64) -> R {
    let want = unsafe { *(set as *const u64) } & !UNBLOCKABLE;
    let start = std::time::Instant::now();
    loop {
        {
            let mut s = S.lock().unwrap();
            let mine = &crate::syscall::ts().tpending;
            let ready = (mine.load(SeqCst) | s.pending) & want;
            if ready != 0 {
                let sig = ready.trailing_zeros() as u64 + 1;
                if mine.load(SeqCst) & bit(sig) != 0 { mine.fetch_and(!bit(sig), SeqCst); } else { s.pending &= !bit(sig); }
                if info != 0 {
                    unsafe { std::ptr::write_bytes(info as *mut u8, 0, 128) };
                    unsafe { *(info as *mut u32) = sig as u32 }; // si_signo; si_code 0 = SI_USER
                }
                return Ok(sig as i64);
            }
        }
        let left = if timeout_ms < 0 { 10 } else { timeout_ms - start.elapsed().as_millis() as i64 };
        if left <= 0 {
            return Err(crate::syscall::EAGAIN);
        }
        // ponytail: re-checks every 10 ms; a signal from outside or a handled one cuts the sleep short.
        interruptible_sleep(left.min(10) as u32)?;
    }
}

/// When the armed ITIMER_REAL fires next, and its interval (ms).
static ALARM_NEXT: Mutex<Option<(std::time::Instant, u64)>> = Mutex::new(None);

fn left(next: Option<(std::time::Instant, u64)>, now: std::time::Instant) -> (u64, u64) {
    next.map_or((0, 0), |(at, iv)| (at.saturating_duration_since(now).as_millis().max(1) as u64, iv))
}

/// getitimer(ITIMER_REAL): (ms left, interval ms).
pub fn alarm_left() -> (u64, u64) {
    left(*ALARM_NEXT.lock().unwrap(), std::time::Instant::now())
}

/// setitimer(ITIMER_REAL) / alarm: SIGALRM after `value_ms`, then every `interval_ms` (0 = once).
/// Each call replaces the previous timer and returns what was left of it (ms, interval ms).
/// ponytail: ITIMER_VIRTUAL/PROF (CPU-time timers) aren't supported.
pub fn set_alarm(value_ms: u64, interval_ms: u64) -> (u64, u64) {
    static GEN: AtomicU64 = AtomicU64::new(0);
    let now = std::time::Instant::now();
    let mut next = ALARM_NEXT.lock().unwrap();
    let old = left(*next, now);
    let id = GEN.fetch_add(1, SeqCst) + 1;
    if value_ms == 0 {
        *next = None; // disarm
        return old;
    }
    *next = Some((now + std::time::Duration::from_millis(value_ms), interval_ms));
    std::thread::spawn(move || {
        let mut wait = value_ms;
        loop {
            std::thread::sleep(std::time::Duration::from_millis(wait));
            {
                let mut next = ALARM_NEXT.lock().unwrap();
                if GEN.load(SeqCst) != id {
                    return; // replaced or disarmed meanwhile
                }
                *next = (interval_ms != 0).then(|| (std::time::Instant::now() + std::time::Duration::from_millis(interval_ms), interval_ms));
            }
            arrive(14); // SIGALRM
            if interval_ms == 0 {
                return;
            }
            wait = interval_ms;
        }
    });
    old
}

// ---- POSIX timers (timer_create & co.) ----
//
// Each timer has one thread, started on its first arming, that sleeps on a Condvar until the expiry;
// timer_settime and timer_delete wake it, so re-arming (a watchdog reset every few ms) doesn't pile up
// threads. SIGEV_SIGNAL goes to the process, SIGEV_THREAD_ID (what glibc's and musl's SIGEV_THREAD use)
// to one thread, SIGEV_NONE only counts.
// ponytail: the signal carries no si_value or SI_TIMER (no siginfo payload), so several timers on one
// signal can't be told apart; CPU-time clocks run as MONOTONIC.

struct PosixTimer {
    /// Which timer_create made it: a slot reused after timer_delete is another timer to the old thread.
    serial: u64,
    signo: u64,
    notify: u32,
    tid: u64,
    clock: u64,
    /// When it fires next, and its interval (zero: once).
    next: Option<std::time::Instant>,
    interval: std::time::Duration,
    overrun: u32,
    worker: bool,
}

static PTIMERS: Mutex<Vec<Option<PosixTimer>>> = Mutex::new(Vec::new());
static PTIMER_WAKE: std::sync::Condvar = std::sync::Condvar::new();

/// timer_create(clock, sevp, timerid).
pub fn timer_create(clock: u64, sevp: u64, out: u64) -> R {
    static SERIAL: AtomicU64 = AtomicU64::new(0);
    if !matches!(clock, 0..=7 | 11) {
        return Err(EINVAL);
    }
    let (signo, notify, tid) = if sevp == 0 {
        (14, 0, 0) // NULL: SIGEV_SIGNAL with SIGALRM
    } else {
        let e = crate::syscall::get_guest::<20>(sevp)?;
        let word = |o: usize| u32::from_le_bytes(e[o..o + 4].try_into().unwrap());
        (word(8) as u64, word(12), word(16) as u64)
    };
    match notify {
        0 | 4 if signo == 0 || signo > 64 => return Err(EINVAL),
        0 | 1 | 4 => {}
        _ => return Err(EINVAL), // SIGEV_THREAD is libc's, made of SIGEV_THREAD_ID
    }
    let mut ts = PTIMERS.lock().unwrap();
    let id = ts.iter().position(Option::is_none).unwrap_or_else(|| { ts.push(None); ts.len() - 1 });
    let serial = SERIAL.fetch_add(1, SeqCst);
    ts[id] = Some(PosixTimer { serial, signo, notify, tid, clock, next: None, interval: Default::default(), overrun: 0, worker: false });
    if let Err(e) = crate::syscall::put_guest(out, &(id as u32).to_le_bytes()) {
        ts[id] = None;
        return Err(e);
    }
    Ok(0)
}

fn itimerspec_out(t: &PosixTimer, out: u64) -> R {
    let left = t.next.map_or(Default::default(), |at| at.saturating_duration_since(std::time::Instant::now()));
    let v = [t.interval.as_secs(), t.interval.subsec_nanos() as u64, left.as_secs(), left.subsec_nanos() as u64];
    crate::syscall::put_guest(out, &crate::syscall::as_bytes(&v))
}

/// timer_settime(id, flags, new, old).
pub fn timer_settime(id: u64, flags: u64, new: u64, old: u64) -> R {
    const TIMER_ABSTIME: u64 = 1;
    let mut ts = PTIMERS.lock().unwrap();
    let t = ts.get_mut(id as usize).and_then(Option::as_mut).ok_or(EINVAL)?;
    if new == 0 {
        return Err(EINVAL);
    }
    let raw = crate::syscall::get_guest::<32>(new)?;
    let [is, ins, vs, vns]: [i64; 4] = std::array::from_fn(|i| i64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap()));
    if [ins, vns].iter().any(|n| !(0..1_000_000_000).contains(n)) || is < 0 || vs < 0 {
        return Err(EINVAL);
    }
    if old != 0 {
        itimerspec_out(t, old)?;
    }
    let (interval, mut value) = (std::time::Duration::new(is as u64, ins as u32), std::time::Duration::new(vs as u64, vns as u32));
    if flags & TIMER_ABSTIME != 0 && !value.is_zero() {
        let (s, ns) = crate::syscall::now(t.clock);
        value = value.saturating_sub(std::time::Duration::new(s, ns as u32)).max(std::time::Duration::from_nanos(1));
    }
    t.overrun = 0;
    t.interval = interval;
    t.next = (!value.is_zero()).then(|| std::time::Instant::now() + value);
    if t.next.is_some() && !t.worker {
        t.worker = true;
        let serial = t.serial;
        std::thread::spawn(move || timer_worker(id as usize, serial));
    }
    PTIMER_WAKE.notify_all();
    Ok(0)
}

/// A timer's thread: fires it at each expiry, waits while it's disarmed, ends when it's deleted.
fn timer_worker(id: usize, serial: u64) {
    let mut ts = PTIMERS.lock().unwrap();
    loop {
        let Some(t) = ts.get_mut(id).and_then(Option::as_mut).filter(|t| t.serial == serial) else { return };
        let Some(at) = t.next else {
            ts = PTIMER_WAKE.wait(ts).unwrap();
            continue;
        };
        let now = std::time::Instant::now();
        if now < at {
            ts = PTIMER_WAKE.wait_timeout(ts, at - now).unwrap().0;
            continue;
        }
        if t.interval.is_zero() {
            t.next = None;
        } else {
            // Periods that went by while we weren't scheduled count as overruns.
            let missed = ((now - at).as_nanos() / t.interval.as_nanos()) as u32;
            t.overrun = missed;
            t.next = Some(at + t.interval * (missed + 1));
        }
        let (signo, notify, tid) = (t.signo, t.notify, t.tid);
        drop(ts);
        match notify {
            0 => arrive(signo),
            4 => { let _ = send_thread(tid, signo); }
            _ => {}
        }
        ts = PTIMERS.lock().unwrap();
    }
}

pub fn timer_gettime(id: u64, out: u64) -> R {
    let ts = PTIMERS.lock().unwrap();
    itimerspec_out(ts.get(id as usize).and_then(Option::as_ref).ok_or(EINVAL)?, out).map(|_| 0)
}

pub fn timer_getoverrun(id: u64) -> R {
    let ts = PTIMERS.lock().unwrap();
    Ok(ts.get(id as usize).and_then(Option::as_ref).ok_or(EINVAL)?.overrun as i64)
}

pub fn timer_delete(id: u64) -> R {
    let mut ts = PTIMERS.lock().unwrap();
    let slot = ts.get_mut(id as usize).filter(|t| t.is_some()).ok_or(EINVAL)?;
    *slot = None; // its thread sees the slot gone and ends
    PTIMER_WAKE.notify_all();
    Ok(0)
}

/// execve in place: handlers go back to the default (ignored signals stay ignored, the mask and pending
/// signals stay), POSIX timers are deleted, the alternate stack is gone.
pub fn reset_for_exec() {
    for a in S.lock().unwrap().actions.iter_mut() {
        if a.handler > 1 {
            *a = DFL;
        }
    }
    PTIMERS.lock().unwrap().clear(); // their threads see their slots gone and end
    PTIMER_WAKE.notify_all();
    crate::syscall::ts().altstack = None;
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
/// ppoll, pselect6, epoll_pwait(2): wait under the guest's sigmask (`size` bytes at `mask_ptr`; none:
/// the thread's own). A signal that ends the wait is delivered under it and the old mask comes back
/// after its handler, as with sigsuspend; otherwise it comes back right away.
pub fn with_mask(mask_ptr: u64, size: u64, wait: impl FnOnce() -> R) -> R {
    if mask_ptr == 0 {
        return wait();
    }
    if size != 8 {
        return Err(EINVAL);
    }
    let new = u64::from_le_bytes(crate::syscall::get_guest::<8>(mask_ptr)?);
    let old = mask();
    set_mask(new);
    let r = wait();
    if r == Err(EINTR) && deliverable() {
        crate::syscall::ts().suspended_mask = Some(old);
    } else {
        set_mask(old);
    }
    r
}

pub fn sigsuspend(mask_ptr: u64) -> R {
    crate::syscall::ts().suspended_mask = Some(mask());
    if mask_ptr != 0 {
        set_mask(unsafe { *(mask_ptr as *const u64) });
    }
    while !deliverable() {
        proc::wait_for_child_exit(); // returns on a child exit (raising SIGCHLD) or a signal from outside
    }
    Err(EINTR)
}

const SIGCONT: u64 = 18;

// ---- job control ----
//
// A stopped process's guest threads park at their next syscall boundary (deliver), where they hold none
// of our locks; one spinning in guest code is kicked there, and one blocked in a syscall parks when it
// returns (it does nothing meanwhile). The parent hears through SIGCHLD and reads the state from our
// mailbox (child_state). ponytail: SIGCHLD goes to the parent on every stop and continue (SA_NOCLDSTOP
// is the parent's to honor), and orphaned process groups aren't exempt from SIGTSTP.
static STOPPED: AtomicBool = AtomicBool::new(false);

fn run_event() -> isize {
    static EV: std::sync::OnceLock<isize> = std::sync::OnceLock::new();
    *EV.get_or_init(|| unsafe { crate::win::CreateEventW(std::ptr::null_mut(), 1, 1, std::ptr::null()) }) // manual, set
}

/// A guest thread of a stopped process waits here until SIGCONT.
pub fn park_if_stopped() {
    if STOPPED.load(SeqCst) {
        crate::ptable::set_stopped(true); // again: this thread's syscall may have just marked it running
        let ev = run_event();
        unsafe { crate::win::WaitForMultipleObjects(1, &ev, 0, u32::MAX) };
    }
}

fn stop(sig: u64) {
    if STOPPED.swap(true, SeqCst) {
        return;
    }
    unsafe extern "system" {
        fn ResetEvent(ev: isize) -> i32;
    }
    unsafe { ResetEvent(run_event()) };
    crate::ptable::set_stopped(true);
    report(0x7f | sig << 8); // WIFSTOPPED, WSTOPSIG
    let me = unsafe { crate::win::GetCurrentThreadId() };
    for (tid, h) in std::iter::once((crate::thread::MAIN_TID.load(SeqCst), GUEST_THREAD.load(SeqCst))).chain(crate::thread::others()) {
        if tid != me && let Some(t) = crate::syscall::ts_of(tid) {
            kick(h, t);
        }
    }
}

fn cont() {
    if !STOPPED.swap(false, SeqCst) {
        return;
    }
    crate::ptable::set_stopped(false);
    unsafe { crate::win::SetEvent(run_event()) };
    report(0xffff); // WIFCONTINUED
}

/// Our job-control state for the parent's wait, and SIGCHLD to wake it.
fn report(status: u64) {
    if let Some(b) = unsafe { OWN.load(SeqCst).as_ref() } {
        b[2].store(status | 1 << 32, SeqCst);
    }
    let parent = proc::parent_host();
    if parent != 0 {
        let _ = send(parent, 17);
    }
}

/// A child's unreported stop or continue: its wait status (0x7f | sig << 8, or 0xffff), cleared unless
/// `keep` (WNOWAIT).
pub fn child_state(pid: u32, keep: bool) -> Option<u32> {
    let (b, _) = mailbox(pid, false)?;
    let v = b[2].load(SeqCst);
    if v & 1 << 32 == 0 {
        return None;
    }
    if !keep && b[2].compare_exchange(v, v & !(1 << 32), SeqCst, SeqCst).is_err() {
        return None; // it changed meanwhile: the next look reports that
    }
    Some(v as u32 & 0xffff)
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
/// Largest signal frame: return address + FP area (an XSAVE image, 64-aligned, + magic) + ucontext +
/// siginfo, plus alignment slack.
pub const FRAME_MAX: usize = (8 + 4096 + 64 + 64 + UC_SIZE + SI_SIZE + 32) as usize;

/// Called when a syscall returns (`c` already holds the post-syscall state). If a signal is pending and
/// unblocked, run its default action, or point `c` at its handler and return the signal frame bytes,
/// which the caller places at the new `c.rsp` once it's safe to (see syscall::resume_with_signals).
pub fn deliver(c: &mut Context) -> Option<Vec<u8>> {
    park_if_stopped();
    let restart = std::mem::take(&mut crate::syscall::ts().restart);
    proc::notice_child_exits();
    let mut s = S.lock().unwrap();
    let mine = &crate::syscall::ts().tpending;
    loop {
        let own = mine.load(SeqCst) & !mask(); // this thread's own signals go first
        let ready = own | s.pending & !mask();
        if ready == 0 {
            return None;
        }
        let sig = ready.trailing_zeros() as u64 + 1;
        if own & bit(sig) != 0 {
            mine.fetch_and(!bit(sig), SeqCst);
        } else {
            s.pending &= !bit(sig);
        }
        let a = s.actions[sig as usize];
        match a.handler {
            0 if default_ignores(sig) => continue,
            0 | 1 if sig == 19 || (a.handler == 0 && matches!(sig, 20..=22)) => {
                drop(s);
                stop(sig); // tkill'd to a thread (musl's raise), or a stop signal that was blocked
                park_if_stopped();
                s = S.lock().unwrap();
            }
            0 => {
                drop(s);
                proc::die(sig); // default action: terminate (wait4 sees WIFSIGNALED)
            }
            1 => continue, // SIG_IGN
            _ => {
                // si_code: SI_TKILL with our pid and uid for tkill/tgkill (glibc's SIGSETXID handler, which
                // setuid waits on in every thread, ignores anything else), CLD_EXITED, or SI_USER.
                let (code, who) = if own & bit(sig) != 0 {
                    (-6i64 as u64, proc::getpid().unwrap_or(0) as u64 | (proc::UID.load(Relaxed) as u64) << 32)
                } else {
                    // SI_USER with the sender's pid and uid (kill), or CLD_EXITED.
                    (if sig == SIGCHLD { 1 } else { 0 }, SENDER[sig as usize].swap(0, SeqCst))
                };
                // SA_RESTART: the handler returns into the interrupted syscall, made again.
                let again = (restart != 0 && a.flags & SA_RESTART != 0).then_some(restart - 1);
                return Some(frame(&mut s, c, sig, a, code, who, again)); // one handler at a time; the rest go when it returns via rt_sigreturn
            }
        }
    }
}

/// A fault in guest code (SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTRAP) with `si_code` and `si_addr`: the frame
/// for the guest's handler, which may fix the cause or move `rip` in the ucontext (HotSpot's implicit null
/// checks and safepoint polls). None when there's no handler, it's ignored, or this thread has it
/// blocked (a fault inside its own handler): the guest dies, like Linux.
pub fn fault(c: &mut Context, sig: u64, code: u64, addr: u64) -> Option<Vec<u8>> {
    let mut s = S.lock().unwrap();
    let a = s.actions[sig as usize];
    if a.handler <= 1 || mask() & bit(sig) != 0 {
        return None;
    }
    Some(frame(&mut s, c, sig, a, code, addr, None))
}

/// Point `c` at the handler for `sig` and build its signal frame (see `deliver`).
fn frame(s: &mut State, c: &mut Context, sig: u64, a: Action, code: u64, addr: u64, restart: Option<u64>) -> Vec<u8> {
    let handler = a.handler;
    let restore_mask = crate::syscall::ts().suspended_mask.take().unwrap_or(mask());
    // Below the red zone: [return address = restorer][ucontext][siginfo].
    // SA_ONSTACK handlers start at the top of the thread's alternate stack, unless already on it.
    let t = crate::syscall::ts();
    let alt = t.altstack.filter(|&(b, n)| a.flags & SA_ONSTACK != 0 && !(b..b + n).contains(&c.rsp));
    let top = alt.map(|(b, n)| b + n).unwrap_or(c.rsp - 128); // else below the red zone
    // Top down, as Linux lays it out: the interrupted FP/vector state (uc_mcontext.fpregs points here;
    // rt_sigreturn restores it, so a handler using xmm can't clobber the code it interrupted), then
    // siginfo, the ucontext, and the return address right below it (rt_sigreturn finds uc at rsp).
    let fp = crate::syscall::fp_area(c);
    let xstate = fp.len() > 512;
    let fpa = (top - fp.len() as u64 - 64) & !63; // + room for the FP_XSTATE_MAGIC2 after it
    let info = (fpa - SI_SIZE) & !15;
    let uc = (info - UC_SIZE) & !15;
    let sp = uc - 8; // handler entry: rsp % 16 == 8, as after a call
    let mut frame = vec![0u8; (fpa + fp.len() as u64 + 64 - sp) as usize];
    let mut put = |addr: u64, v: u64| {
        let o = (addr - sp) as usize;
        frame[o..o + 8].copy_from_slice(&v.to_le_bytes());
    };
    put(sp, a.restorer);
    put(info, sig); // si_signo (low half), si_errno 0
    put(info + 8, code); // si_code (low half)
    put(info + 16, addr); // si_addr, for faults
    let flags = c.eflags as u64;
    for (i, r) in gregs(c).into_iter().enumerate() {
        put(uc + UC_MCONTEXT + 8 * i as u64, *r);
    }
    put(uc + UC_MCONTEXT + 8 * 17, flags);
    if let Some(nr) = restart {
        // Return into the syscall instead of past it: rax = its number, rip = the instruction (or, at a
        // rewritten site, its copy in the stub).
        let at = c.rip - 2;
        put(uc + UC_MCONTEXT + 8 * 13, nr); // REG_RAX
        put(uc + UC_MCONTEXT + 8 * 16, crate::jump::redirect(at).unwrap_or(at)); // REG_RIP
    }
    put(uc + UC_SIGMASK, restore_mask);
    for (i, q) in fp.chunks_exact(8).enumerate() {
        put(fpa + 8 * i as u64, u64::from_le_bytes(q.try_into().unwrap()));
    }
    if xstate {
        // fx_sw_bytes in the image's software-reserved bytes, then FP_XSTATE_MAGIC2 right after it,
        // so code that walks the extended state (as glibc's and the kernel's readers do) finds it.
        let n = fp.len() as u64;
        let features = u64::from_le_bytes(fp[512..520].try_into().unwrap()) | 3; // XSTATE_BV, x87 + SSE
        put(fpa + 464, 0x4650_5853 | (n + 4) << 32); // FP_XSTATE_MAGIC1, extended_size
        put(fpa + 472, features);
        put(fpa + 480, n); // xstate_size
        put(fpa + n, 0x4650_5845); // FP_XSTATE_MAGIC2
        put(uc, 1); // uc_flags: UC_FP_XSTATE
    }
    put(uc + UC_MCONTEXT + 8 * 23, fpa); // mcontext.fpregs
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
    set_mask(mask() | a.mask | if a.flags & SA_NODEFER == 0 { bit(sig) } else { 0 });
    if a.flags & SA_RESETHAND != 0 {
        s.actions[sig as usize] = DFL;
    }
    frame
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
    // The FP state the frame carries (the handler may have edited it) goes back too. A full XSAVE
    // image says so with FP_XSTATE_MAGIC1; otherwise only the legacy 512 bytes are trusted, so a
    // frame from the trap path never feeds xrstor a header it didn't write.
    let fpregs = get(23);
    if fpregs != 0 {
        let dst = crate::syscall::fp_area(c);
        let magic = unsafe { *((fpregs + 464) as *const u32) };
        let size = unsafe { *((fpregs + 480) as *const u32) } as usize;
        let n = if magic == 0x4650_5853 { size.min(dst.len()) } else { 512 };
        unsafe { std::ptr::copy_nonoverlapping(fpregs as *const u8, dst.as_mut_ptr(), n.min(dst.len())) };
    }
    if crate::syscall::siglog() {
        crate::syscall::dlog(format_args!("sigreturn to rip {:#x} rsp {:#x}", c.rip, c.rsp));
    }
    set_mask(unsafe { *((uc + UC_SIGMASK) as *const u64) });
}

/// Dispositions and mask survive fork. (Fields: blocked, then 64 x [handler, flags, restorer, mask].)
pub fn snapshot() -> Vec<String> {
    let s = S.lock().unwrap();
    let mut v = vec![mask()]; // the forking thread's mask becomes the child's
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
    set_mask(nums[0]);
    for (i, a) in nums[1..].chunks(4).enumerate() {
        s.actions[i + 1] = Action { handler: a[0], flags: a[1], restorer: a[2], mask: a[3] };
    }
    Ok(&f[N..])
}
