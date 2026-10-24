//! Guest threads: clone(CLONE_THREAD) is a Windows thread in this process that runs guest code, with
//! its own ThreadState (FS base, trampoline slots). futex maps onto WaitOnAddress/WakeByAddress*,
//! which compare-and-sleep atomically just like FUTEX_WAIT.
use crate::syscall::{self, R, EAGAIN, EINVAL, ENOSYS};
use crate::win::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};

const ETIMEDOUT: i64 = 110;

/// Windows id of the thread that started the guest: Linux makes the main thread's tid equal the pid.
pub static MAIN_TID: AtomicU32 = AtomicU32::new(0);
/// Running guest threads; the last one out ends the process.
static LIVE: AtomicU64 = AtomicU64::new(1);
/// Other guest threads (tid, handle), so execve can stop them like Linux does.
static THREADS: Mutex<Vec<(u32, isize)>> = Mutex::new(Vec::new());

/// The Windows handle of guest thread `tid` (0 if it isn't one of ours).
pub fn handle_of(tid: u32) -> isize {
    THREADS.lock().unwrap().iter().find(|t| t.0 == tid).map_or(0, |t| t.1)
}

/// Our guest threads' tids, the main one (the pid) first: /proc/self/task.
pub fn tids() -> Vec<u32> {
    let mut v = vec![crate::proc::getpid().unwrap_or(0) as u32];
    v.extend(THREADS.lock().unwrap().iter().map(|t| t.0));
    v
}

pub fn set_main() {
    MAIN_TID.store(unsafe { GetCurrentThreadId() }, Relaxed);
}

pub fn gettid() -> R {
    let me = unsafe { GetCurrentThreadId() };
    if me == MAIN_TID.load(Relaxed) { crate::proc::getpid() } else { Ok(me as i64) }
}

struct Init {
    regs: [u64; 18],
    fs: u64,
    clear_tid: u64,
    sigmask: u64,
}

/// clone(CLONE_VM | CLONE_THREAD | ...): run the child on a new Windows thread with the parent's
/// registers, rax = 0, and the stack (and TLS) the caller set up.
pub fn clone_thread(c: &Context, flags: u64, stack: u64, ptid: u64, ctid: u64, tls: u64) -> R {
    const CLONE_VM: u64 = 0x100;
    const CLONE_SETTLS: u64 = 0x80000;
    const CLONE_PARENT_SETTID: u64 = 0x100000;
    const CLONE_CHILD_CLEARTID: u64 = 0x200000;
    const CLONE_CHILD_SETTID: u64 = 0x1000000;
    if flags & CLONE_VM == 0 || stack == 0 {
        return Err(EINVAL);
    }
    let next = c.rip + 2;
    let regs = [0, next, c.rdx, c.rbx, stack, c.rbp, c.rsi, c.rdi, c.r8, c.r9, c.r10, c.eflags as u64,
                c.r12, c.r13, c.r14, c.r15, next, c.eflags as u64];
    let init = Box::new(Init {
        regs,
        fs: if flags & CLONE_SETTLS != 0 { tls } else { syscall::ts().fs },
        clear_tid: if flags & CLONE_CHILD_CLEARTID != 0 { ctid } else { 0 },
        sigmask: syscall::ts().sigmask, // a new thread starts with its creator's mask, like Linux
    });
    let mut tid = 0u32;
    // Small host stack: the thread switches to the guest's stack right away.
    let p = Box::into_raw(init);
    let h = unsafe { CreateThread(std::ptr::null_mut(), 64 << 10, thread_main, p as *mut _, 0x4 | 0x10000, &mut tid) };
    if h == 0 {
        drop(unsafe { Box::from_raw(p) });
        return Err(EAGAIN);
    }
    // Same address space, so the parent can write both tids before the child runs.
    if flags & CLONE_PARENT_SETTID != 0 {
        unsafe { *(ptid as *mut u32) = tid };
    }
    if flags & CLONE_CHILD_SETTID != 0 {
        unsafe { *(ctid as *mut u32) = tid };
    }
    LIVE.fetch_add(1, Relaxed);
    THREADS.lock().unwrap().push((tid, h));
    if syscall::debug() {
        syscall::dlog(format_args!("clone thread -> t{tid}: rip {next:#x} rsp {stack:#x} fs {:#x} flags {flags:#x}", unsafe { (*p).fs }));
    }
    unsafe { ResumeThread(h) }; // created CREATE_SUSPENDED (0x4), stack size is a reservation (0x10000)
    Ok(tid as i64)
}

unsafe extern "system" fn thread_main(p: *mut std::ffi::c_void) -> u32 {
    let init = unsafe { Box::from_raw(p as *mut Init) };
    let t = syscall::ts();
    t.fs = init.fs;
    t.clear_tid = init.clear_tid;
    t.sigmask = init.sigmask;
    let (lo, hi) = syscall::alloc_containing(init.regs[4] - 1).unwrap_or((init.regs[4] - (1 << 20), init.regs[4]));
    syscall::enter(init.regs, lo, hi)
}

/// SYS_exit: end this thread. Wakes pthread_join through clear_tid; the last thread ends the process.
pub fn exit(code: u64) -> ! {
    let t = syscall::ts();
    if t.clear_tid != 0 {
        unsafe {
            *(t.clear_tid as *mut u32) = 0;
            WakeByAddressAll(t.clear_tid as *const _);
        }
    }
    if LIVE.fetch_sub(1, Relaxed) == 1 {
        crate::proc::exit(code);
    }
    let me = unsafe { GetCurrentThreadId() };
    syscall::forget_ts(); // no more signals for this tid
    THREADS.lock().unwrap().retain(|&(tid, h)| {
        if tid == me {
            unsafe { CloseHandle(h) };
        }
        tid != me
    });
    // ExitThread frees the stack the TEB names: make that our host stack again, not the guest's memory
    // (which belongs to the guest: musl's pthread struct lives there and pthread_join still reads it).
    if let Some([b, l, d]) = t.host_teb {
        unsafe {
            std::arch::asm!("mov qword ptr gs:[0x08], {b}", "mov qword ptr gs:[0x10], {l}", "mov qword ptr gs:[0x1478], {d}",
                b = in(reg) b, l = in(reg) l, d = in(reg) d);
        }
    }
    unsafe { ExitThread(code as u32) }
}

/// execve replaces the whole process image: stop every other guest thread first (Linux kills them).
pub fn stop_others() {
    let me = unsafe { GetCurrentThreadId() };
    // ponytail: TerminateThread can leave a lock of ours held by the victim; execve only spawns and waits
    // afterwards, and uses try_lock where it touches shared state.
    if let Ok(threads) = THREADS.try_lock() {
        for &(tid, h) in threads.iter().filter(|(tid, _)| *tid != me) {
            let _ = tid;
            unsafe { TerminateThread(h, 0) };
        }
    }
}

/// futex(2): the subset libc and Go use. Waking reports 0 woken (callers don't rely on the count).
pub fn futex(uaddr: u64, op: u64, val: u64, timeout: u64, val3: u64) -> R {
    const FUTEX_CLOCK_REALTIME: u64 = 256;
    let cmd = op & 0x7f; // without FUTEX_PRIVATE_FLAG / CLOCK_REALTIME
    let cur = || unsafe { std::ptr::read_volatile(uaddr as *const u32) };
    match cmd {
        0 | 9 => {
            // FUTEX_WAIT (relative timeout), FUTEX_WAIT_BITSET (absolute). ponytail: bitsets ignored.
            let expect = val as u32;
            syscall::check_guest(uaddr, 4, false)?; // a bad uaddr is EFAULT (LTP), not a fault in lx
            if cur() != expect {
                return Err(EAGAIN);
            }
            let ms = if timeout == 0 {
                u32::MAX
            } else {
                let [s, ns] = unsafe { *(timeout as *const [u64; 2]) };
                let mut want = std::time::Duration::new(s, ns as u32);
                if cmd == 9 {
                    let (s, ns) = syscall::now(if op & FUTEX_CLOCK_REALTIME != 0 { 0 } else { 1 });
                    want = want.saturating_sub(std::time::Duration::new(s, ns as u32));
                }
                // Round up: a wait with 0.9 ms left must still sleep, not spin (WaitOnAddress(0) returns at once).
                want.as_nanos().div_ceil(1_000_000).min(u32::MAX as u128 - 1) as u32
            };
            let _fine = syscall::FineWait::for_ms(ms as i64);
            if syscall::in_shared_view(uaddr) {
                return shared_wait(uaddr, expect, ms);
            }
            // A signal for this thread (tkill) wakes us through futex_addr: publish it, then re-check.
            let t = syscall::ts();
            t.futex_addr.store(uaddr, std::sync::atomic::Ordering::SeqCst);
            if crate::signal::deliverable() {
                t.futex_addr.store(0, std::sync::atomic::Ordering::SeqCst);
                return Err(crate::syscall::EINTR);
            }
            let woke = unsafe { WaitOnAddress(uaddr as *const _, &expect as *const u32 as *const _, 4, ms) };
            t.futex_addr.store(0, std::sync::atomic::Ordering::SeqCst);
            if woke == 0 && unsafe { GetLastError() } == 1460 {
                Err(ETIMEDOUT) // ERROR_TIMEOUT
            } else if crate::signal::deliverable() {
                Err(crate::syscall::EINTR)
            } else {
                Ok(0)
            }
        }
        1 | 10 => {
            // FUTEX_WAKE, FUTEX_WAKE_BITSET. Waking more than asked is a spurious wakeup, which is allowed.
            if syscall::in_shared_view(uaddr) {
                return Ok(shared_wake(uaddr, val as u32) as i64);
            }
            if val == 1 {
                unsafe { WakeByAddressSingle(uaddr as *const _) };
            } else if val > 1 {
                unsafe { WakeByAddressAll(uaddr as *const _) };
            }
            Ok(0)
        }
        3 | 4 => {
            // FUTEX_REQUEUE / FUTEX_CMP_REQUEUE: wake everyone instead of moving them; they re-check.
            if cmd == 4 && cur() != val3 as u32 {
                return Err(EAGAIN);
            }
            if syscall::in_shared_view(uaddr) {
                return Ok(shared_wake(uaddr, u32::MAX) as i64);
            }
            unsafe { WakeByAddressAll(uaddr as *const _) };
            Ok(0)
        }
        _ => Err(ENOSYS),
    }
}

// ---- futexes in MAP_SHARED memory ----
//
// The waker may be another process, and WaitOnAddress only hears wakes from this one. Waiters and wakers
// meet at named objects for (container, address) instead: a semaphore to wake on and a count of waiters,
// so FUTEX_WAKE wakes and reports as many as Linux would (LTP's checkpoints wake without changing the
// value and loop until the count is right). Fork keeps shared views at the same address.
// ponytail: the same file mapped at different addresses (after exec) doesn't meet here; such waiters still
// see a changed value through the re-check every 100 ms.

unsafe extern "system" {
    fn CreateSemaphoreW(attr: *mut std::ffi::c_void, initial: i32, max: i32, name: *const u16) -> isize;
    fn OpenSemaphoreW(access: u32, inherit: i32, name: *const u16) -> isize;
    fn ReleaseSemaphore(sem: isize, n: i32, prev: *mut i32) -> i32;
}

struct SharedFutex {
    sem: isize,
    map: isize,
    waiters: *const AtomicU32,
}

impl SharedFutex {
    fn open(uaddr: u64, create: bool) -> Option<SharedFutex> {
        let root = std::env::var("LX_IN_JOB").unwrap_or_default();
        let name = |k: &str| format!("Local\\lx-fx{k}-{root}-{uaddr:x}").encode_utf16().chain([0]).collect::<Vec<u16>>();
        let (sn, mn) = (name("s"), name("n"));
        unsafe {
            let (sem, map) = if create {
                (CreateSemaphoreW(std::ptr::null_mut(), 0, i32::MAX, sn.as_ptr()),
                 CreateFileMappingW(-1, std::ptr::null_mut(), PAGE_READWRITE, 0, 4, mn.as_ptr()))
            } else {
                (OpenSemaphoreW(0x0010_0002, 0, sn.as_ptr()), OpenFileMappingW(FILE_MAP_WRITE, 0, mn.as_ptr())) // SYNCHRONIZE | MODIFY_STATE
            };
            let view = if map != 0 { MapViewOfFile(map, FILE_MAP_WRITE, 0, 0, 4) } else { std::ptr::null_mut() };
            let f = SharedFutex { sem, map, waiters: view as *const AtomicU32 };
            (sem != 0 && !view.is_null()).then_some(f)
        }
    }

    fn waiters(&self) -> &AtomicU32 {
        unsafe { &*self.waiters }
    }

    /// Take up to `n` waiters off the count: the ones this caller wakes (or, for a leaving waiter, itself).
    fn take(&self, n: u32) -> u32 {
        let mut took = 0;
        let _ = self.waiters().try_update(Relaxed, Relaxed, |w| { took = w.min(n); Some(w - took) });
        took
    }
}

impl Drop for SharedFutex {
    fn drop(&mut self) {
        unsafe {
            if !self.waiters.is_null() {
                UnmapViewOfFile(self.waiters as *mut _);
            }
            for h in [self.sem, self.map] {
                if h != 0 {
                    CloseHandle(h);
                }
            }
        }
    }
}

fn shared_wait(uaddr: u64, expect: u32, ms: u32) -> R {
    let cur = || unsafe { std::ptr::read_volatile(uaddr as *const u32) };
    let Some(f) = SharedFutex::open(uaddr, true) else { return Err(EAGAIN) };
    f.waiters().fetch_add(1, Relaxed);
    let start = std::time::Instant::now();
    let r = loop {
        if cur() != expect {
            break Err(EAGAIN);
        }
        if crate::signal::deliverable() {
            break Err(crate::syscall::EINTR);
        }
        if ms != u32::MAX && start.elapsed().as_millis() >= ms as u128 {
            break Err(ETIMEDOUT);
        }
        let hs = [f.sem, crate::signal::intr_event()];
        let n = if hs[1] != 0 { 2 } else { 1 };
        // Wakes and signals end the wait at once; the 100 ms cap only bounds how late a value change by
        // an unmatched waker (see above) is noticed, without spinning idle waiters (postgres backends).
        let left = if ms == u32::MAX { 100 } else { (ms as u128).saturating_sub(start.elapsed().as_millis()).min(100) as u32 };
        if unsafe { WaitForMultipleObjects(n, hs.as_ptr(), 0, left.max(1)) } == 0 {
            return Ok(0); // woken; the waker took us off the count
        }
    };
    if f.take(1) == 0 {
        // A waker counted us between our last look and now: its release is ours to consume.
        unsafe { WaitForMultipleObjects(1, &f.sem, 0, 1000) };
        return Ok(0);
    }
    // A changed value is a wakeup (EAGAIN is only for a mismatch before sleeping).
    if r == Err(EAGAIN) { Ok(0) } else { r }
}

fn shared_wake(uaddr: u64, n: u32) -> u32 {
    let Some(f) = SharedFutex::open(uaddr, false) else { return 0 };
    let took = f.take(n);
    if took > 0 {
        unsafe { ReleaseSemaphore(f.sem, took as i32, std::ptr::null_mut()) };
    }
    took
}

/// membarrier: FlushProcessWriteBuffers is exactly "a memory barrier on every thread of this process".
pub fn membarrier(cmd: u64) -> R {
    const QUERY: u64 = 0;
    const GLOBAL: u64 = 1;
    const PRIVATE_EXPEDITED: u64 = 8;
    const REGISTER_PRIVATE_EXPEDITED: u64 = 16;
    match cmd {
        QUERY => Ok((GLOBAL | PRIVATE_EXPEDITED | REGISTER_PRIVATE_EXPEDITED) as i64),
        GLOBAL | PRIVATE_EXPEDITED => {
            unsafe { FlushProcessWriteBuffers() };
            Ok(0)
        }
        REGISTER_PRIVATE_EXPEDITED => Ok(0),
        _ => Err(EINVAL),
    }
}

pub fn sched_yield() -> R {
    unsafe { SwitchToThread() };
    Ok(0)
}

/// Running guest threads (for /proc/self/status).
pub fn live() -> u64 {
    LIVE.load(Relaxed)
}
