//! The Linux process model on NT.
//! - fork/vfork/clone (no threads): start a fresh lx that rebuilds the guest at the same addresses,
//!   copying memory from us while we wait (like Cygwin). The child is a normal Win32 process, so it can
//!   exec. RtlCloneUserProcess was tried first: its children crash in CreateProcess (probe/clone2.c).
//! - execve: start a fresh lx for the new program with our fds/cwd/argv/env, then wait and pass its exit
//!   code on. ponytail: the waiting lx is an extra process per exec; in-place re-exec (unmap the guest,
//!   load the new image) saves it, now that every guest mapping is tracked.
//! - wait4/kill: Windows process handles of the children we created.
use crate::syscall::{self, R, cstr, debug, EAGAIN, ECHILD, ENOEXEC, ESRCH};
use crate::{fs, signal, win::*};
use std::io::{Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::process::Child;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};

struct Kid {
    pid: u32,
    process: OwnedHandle,
    /// SIGCHLD already raised for its exit.
    notified: bool,
    /// Its process group as last seen (inherited from us at fork): an exited child's mailbox is gone,
    /// and waitpid(0) / waitpid(-pgid) must still find it.
    pgid: u32,
}
static CHILDREN: Mutex<Vec<Kid>> = Mutex::new(Vec::new());
/// Children reaped in the last minute, (pid, when): fork doesn't hand their pids out again (see fork).
static REAPED: Mutex<Vec<(u32, std::time::Instant)>> = Mutex::new(Vec::new());

fn recently_reaped(pid: u32) -> bool {
    let mut r = REAPED.lock().unwrap();
    r.retain(|(_, t)| t.elapsed() < std::time::Duration::from_secs(60));
    r.iter().any(|(p, _)| *p == pid)
}
static PARENT: AtomicU32 = AtomicU32::new(0);

/// Our parent lx process (host pid), 0 for the container's first.
pub fn parent_host() -> u32 {
    PARENT.load(Relaxed)
}

/// Linux user/group ids, as the guest sees them. Containers start as root (0).
/// ponytail: tracked, not enforced (on Windows the whole container runs as the host user).
pub static UID: AtomicU32 = AtomicU32::new(0);
pub static GID: AtomicU32 = AtomicU32::new(0);

pub fn set_id(id: &AtomicU32, v: u64) -> R {
    if v as u32 != u32::MAX {
        id.store(v as u32, Relaxed); // -1 means "unchanged"
        save_ids();
    }
    Ok(0)
}

/// uid, gid and umask go to every later lx process of this one (fork and exec start new ones) in the
/// host environment, which the guest never sees: `su postgres -c pg_ctl` must exec pg_ctl as postgres.
pub fn save_ids() {
    let groups: Vec<String> = GROUPS.lock().unwrap().iter().map(u32::to_string).collect();
    let v = format!("{} {} {} {}", UID.load(Relaxed), GID.load(Relaxed), fs::UMASK.load(Relaxed), groups.join(","));
    unsafe { std::env::set_var("LX_IDS", v) };
}

pub fn load_ids() {
    let Ok(v) = std::env::var("LX_IDS") else { return };
    let mut f = v.split(' ');
    let n: Vec<u32> = f.by_ref().take(3).filter_map(|x| x.parse().ok()).collect();
    if let [uid, gid, mask] = n[..] {
        (UID.store(uid, Relaxed), GID.store(gid, Relaxed), fs::UMASK.store(mask, Relaxed));
    }
    *GROUPS.lock().unwrap() = f.next().unwrap_or("").split(',').filter_map(|g| g.parse().ok()).collect();
}

/// Supplementary groups (setgroups; su, login and initgroups set them), inherited like the ids.
/// ponytail: they ride in LX_IDS, and a Windows environment variable holds at most 32767 characters, so
/// some 5000 groups or more would make the next fork or exec fail; no real system has that many.
static GROUPS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

/// getgroups(size, list): with size 0 only the count; a list too short is EINVAL.
pub fn getgroups(size: u64, list: u64) -> R {
    let g = GROUPS.lock().unwrap().clone();
    if size as i32 == 0 {
        return Ok(g.len() as i64);
    }
    if (size as i32) < g.len() as i32 {
        return Err(syscall::EINVAL);
    }
    let bytes: Vec<u8> = g.iter().flat_map(|x| x.to_le_bytes()).collect();
    syscall::put_guest(list, &bytes)?;
    Ok(g.len() as i64)
}

/// setgroups(size, list): at most NGROUPS_MAX (65536).
/// ponytail: capabilities aren't modeled, so it isn't refused for lacking CAP_SETGID: setpriv and gosu
/// keep it across their uid switch (PR_SET_KEEPCAPS) and call setgroups after, as redis's entrypoint does.
pub fn setgroups(size: u64, list: u64) -> R {
    if size as i32 > 65536 || (size as i32) < 0 {
        return Err(syscall::EINVAL);
    }
    syscall::check_guest(list, size as usize * 4, false)?;
    let g: Vec<u32> = (0..size as usize).map(|i| unsafe { *(list as *const u32).add(i) }).collect();
    *GROUPS.lock().unwrap() = g;
    save_ids();
    Ok(0)
}

/// Our supplementary groups (for /proc/self/status).
pub fn groups() -> Vec<u32> {
    GROUPS.lock().unwrap().clone()
}

/// Whether the caller is in group `gid` (its own or a supplementary one), for permission checks.
pub fn in_group(gid: u32) -> bool {
    GID.load(Relaxed) == gid || GROUPS.lock().unwrap().contains(&gid)
}

pub fn get_res(id: &AtomicU32, out: [u64; 3]) -> R {
    for p in out.into_iter().filter(|&p| p != 0) {
        unsafe { *(p as *mut u32) = id.load(Relaxed) };
    }
    Ok(0)
}

/// The pid the guest sees. Linux keeps it across execve; here an exec'd program runs in a new lx process,
/// so that one takes its predecessor's pid (which stays behind as a proxy passing signals on, so a kill
/// of the pid still arrives). pg_ctl waits for the pid it forked to show up in postmaster.pid.
static PID: AtomicU32 = AtomicU32::new(0);

pub fn pid() -> u32 {
    match PID.load(Relaxed) {
        0 => unsafe { GetCurrentProcessId() },
        p => p,
    }
}

/// Windows exit code of an lx process a signal killed: this tag | the signal, so wait4 reports
/// WIFSIGNALED. The container's first process (what Windows and Docker see) exits 128 + signal instead.
pub const SIGNALED: u32 = 0x4C58_0000;

/// The process dies of `sig` (default action, SIGKILL, seccomp).
pub fn die(sig: u64) -> ! {
    exit(SIGNALED as u64 | (sig & 0x7f))
}

/// The container's first process (whose lx is LX_IN_JOB). The guest sees it as pid 1, as in Docker:
/// s6-overlay, tini and dumb-init insist on being pid 1. lx keeps the real pids inside (signal mailboxes
/// are named by them); `guest_pid` and `host_pid` translate at the syscall boundary.
fn root() -> u32 {
    static ROOT: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *ROOT.get_or_init(|| std::env::var("LX_IN_JOB").ok().and_then(|v| v.parse().ok()).unwrap_or(0))
}

pub fn guest_pid(p: u32) -> u32 {
    if p != 0 && p == root() { 1 } else { p }
}

pub fn host_pid(p: u32) -> u32 {
    if p == 1 && root() != 0 { root() } else { p }
}

pub fn getpid() -> R {
    Ok(guest_pid(pid()) as i64)
}

/// pid 1's parent is 0, as in a container.
pub fn getppid() -> R {
    Ok(if pid() == root() { 0 } else { guest_pid(PARENT.load(Relaxed)) as i64 })
}

fn inheritable_pipe() -> std::io::Result<(OwnedHandle, OwnedHandle)> {
    let (mut r, mut w) = (0isize, 0isize);
    if unsafe { CreatePipe(&mut r, &mut w, std::ptr::null_mut(), 0) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { (OwnedHandle::from_raw_handle(r as _), OwnedHandle::from_raw_handle(w as _)) })
}

fn raw(h: &OwnedHandle) -> String {
    let h = h.as_raw_handle() as isize;
    unsafe { SetHandleInformation(h, 1, 1) };
    h.to_string()
}

/// Start `lx <mode> <state-handle> [extra...]` and send it `state` over an inherited pipe.
/// Rust's Command passes bInheritHandles=TRUE: the child gets every handle currently inheritable.
/// Retries pipe I/O that a signal's CancelSynchronousIo (signal.rs) aborted: fork's own pipe transfers
/// must finish, and the signal is still delivered when the syscall returns.
fn uncancelled<T>(mut op: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    loop {
        match op() {
            Err(e) if e.raw_os_error() == Some(995) => {} // ERROR_OPERATION_ABORTED
            r => return r,
        }
    }
}

/// Creation flags for an lx we start: without a console of our own (lx run -d, an engine in the
/// background), Windows would give every new console process a console window of its own, one popping
/// up per fork. DETACHED_PROCESS gives it none, like us (its stdio are inherited handles anyway).
pub fn no_console_flags() -> u32 {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetConsoleWindow() -> isize;
    }
    if unsafe { GetConsoleWindow() } == 0 { 0x8 } else { 0 }
}

fn spawn_lx(mode: &str, extra: &[String], state: Vec<String>) -> std::io::Result<Child> {
    use std::os::windows::process::CommandExt;
    let (r, w) = inheritable_pipe()?;
    let (pgid, sid) = signal::ids(None).unwrap_or_default(); // the child starts in our group and session
    let mut child = std::process::Command::new(std::env::current_exe()?).arg(mode).arg(raw(&r)).args(extra)
        .env("LX_PGRP", (pgid as u64 | (sid as u64) << 32).to_string()).creation_flags(no_console_flags()).spawn()?;
    drop(r);
    let (mut w, state) = (std::fs::File::from(w), state.join("\0"));
    let mut rest = state.as_bytes();
    while !rest.is_empty() {
        let n = match uncancelled(|| w.write(rest)) {
            Ok(n) => n,
            // The new lx died before reading its state: say how (an NTSTATUS like 0xc0000005 is a crash).
            Err(e) => {
                let code = child.wait().ok().and_then(|s| s.code()).map(|c| c as u32);
                return Err(std::io::Error::other(format!("{e}; the new lx exited with {code:#x?}")));
            }
        };
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        rest = &rest[n..];
    }
    drop(w); // closing it is the child's EOF
    Ok(child)
}

/// The receiving side: the state fields a parent sent with `spawn_lx`.
fn read_state(handle: &str) -> Result<Vec<String>, String> {
    let h: usize = handle.parse().map_err(|_| "bad state handle")?;
    let mut blob = String::new();
    unsafe { std::fs::File::from_raw_handle(h as _) }.read_to_string(&mut blob).map_err(|e| e.to_string())?;
    Ok(blob.split('\0').map(String::from).collect())
}

/// fork, vfork, and clone without CLONE_THREAD. `stack` is clone's new stack pointer (0 = keep).
static SPAWN: Mutex<()> = Mutex::new(());

pub fn fork(c: &mut Context, stack: u64) -> R {
    let next = c.rip + 2;
    // What the child resumes with: the state right after the syscall, rax = 0 (kernel ABI: rcx = rip,
    // r11 = rflags). ponytail: SSE/x87 registers aren't carried; SysV makes them caller-saved anyway.
    let rsp = if stack != 0 { stack } else { c.rsp };
    let regs = [0, next, c.rdx, c.rbx, rsp, c.rbp, c.rsi, c.rdi, c.r8, c.r9, c.r10, c.eflags as u64,
                c.r12, c.r13, c.r14, c.r15, next, c.eflags as u64];
    // One spawn at a time: building the state marks handles inheritable and views_inheritable(false) takes
    // the sections back, so another thread's fork in between (Go forks from many) would hand its child
    // handles that weren't inherited ("shared mapping can't be placed in the child").
    let spawning = SPAWN.lock().unwrap_or_else(|e| e.into_inner());
    let (mut state, handles) = fs::proc_state(true); // `handles`: what the child inherits, ours until spawned
    state.extend(syscall::snapshot());
    state.extend(signal::snapshot());
    state.extend(crate::jump::snapshot());
    state.extend(regs.iter().map(|r| r.to_string()));
    state.push(pid().to_string()); // the child's parent pid

    // The child copies our memory, so it gets a read-only handle to us; it reports back on `ready`.
    let mut me = 0isize;
    let ok = unsafe { DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &mut me,
        0x0010 | 0x1000, 1, 0) }; // PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, inheritable
    if ok == 0 {
        return Err(EAGAIN);
    }
    let me = unsafe { OwnedHandle::from_raw_handle(me as _) };
    let fail = |e: String| { eprintln!("[lx] fork: {e}"); EAGAIN };
    let (ready_r, ready_w) = inheritable_pipe().map_err(|e| fail(e.to_string()))?;
    // Windows hands a freed pid out again at once; a child must not get one we just reaped, which may
    // still be a process group's id (a shell's or test runner's late `kill -9 -$pgid` would hit it). Such a
    // child is held, so the next spawn gets another pid, and killed before it ever runs guest code.
    let mut held = Vec::new();
    let child = loop {
        match spawn_lx("--fork", &[raw(&me), raw(&ready_w)], state.clone()) {
            Ok(c) if held.len() < 4 && recently_reaped(c.id()) => held.push(c),
            r => break r,
        }
    };
    for mut h in held {
        let _ = h.kill();
        let _ = h.wait();
    }
    syscall::views_inheritable(false); // the child has its copies of the shared-memory sections now
    drop((spawning, handles));
    let mut child = child.map_err(|e| fail(e.to_string()))?;
    drop((me, ready_w)); // if the child dies before reporting, `ready` hits EOF
    let mut byte = [0u8];
    let mut ready_r = std::fs::File::from(ready_r);
    if !matches!(uncancelled(|| ready_r.read(&mut byte)), Ok(1)) {
        let _ = child.kill();
        return Err(fail("child failed to rebuild the guest".into()));
    }
    let pid = child.id();
    let pgid = signal::ids(None).map_or(self::pid(), |(g, _)| g);
    CHILDREN.lock().unwrap().push(Kid { pid, process: OwnedHandle::from(child), notified: false, pgid });
    // A parent blocked in epoll_wait/poll/read hears of the exit at once, not at its next syscall return
    // (postgres's postmaster sleeps up to 60 s waiting for its startup process to exit).
    std::thread::spawn(move || {
        let h = unsafe { OpenProcess(0x0010_0000, 0, pid) }; // SYNCHRONIZE
        if h != 0 {
            unsafe { WaitForMultipleObjects(1, &h, 0, u32::MAX) };
            unsafe { CloseHandle(h) };
            notice_child_exits();
            signal::wake_if_handled(signal::SIGCHLD);
        }
    });
    Ok(pid as i64)
}

/// The forked side (`lx --fork <state> <parent> <ready>`): rebuild the guest, then hand back the
/// registers to resume with and the guest stack bounds.
pub fn receive_fork(state: &str, parent: &str, ready: &str) -> Result<([u64; 18], (u64, u64)), String> {
    let fields = read_state(state)?;
    let rest = fs::init_from(&fields)?;
    let parent: usize = parent.parse().map_err(|_| "bad parent handle")?;
    let parent = unsafe { OwnedHandle::from_raw_handle(parent as _) };
    let (stack, rest) = syscall::restore(rest, parent.as_raw_handle() as isize)?;
    let rest = signal::restore(rest)?;
    signal::release();
    let rest = crate::jump::restore(rest)?;
    let nums: Vec<u64> = rest.iter().map(|s| s.parse().map_err(|_| "malformed fork state")).collect::<Result<_, _>>()?;
    let [regs @ .., ppid] = nums.as_slice() else { return Err("malformed fork state".into()) };
    let regs: [u64; 18] = regs.try_into().map_err(|_| "malformed fork state")?;
    PARENT.store(*ppid as u32, Relaxed);
    crate::ptable::fork_child();
    let ready: usize = ready.parse().map_err(|_| "bad ready handle")?;
    if unsafe { std::fs::File::from_raw_handle(ready as _) }.write_all(b"1").is_err() {
        // The parent is gone (its container is being stopped): there's no fork to finish, nor anyone to tell.
        std::process::exit(0);
    }
    Ok((regs, stack))
}

/// clone(flags, stack, ptid, ctid, tls) (x86-64 argument order).
pub fn clone(c: &mut Context, flags: u64, stack: u64, ptid: u64, ctid: u64, tls: u64) -> R {
    const CLONE_THREAD: u64 = 0x10000;
    if flags & CLONE_THREAD != 0 {
        return crate::thread::clone_thread(c, flags, stack, ptid, ctid, tls);
    }
    // CLONE_VM|CLONE_VFORK (posix_spawn, Go's os/exec) works as a fork: the child only runs until it execs.
    // ponytail: other threads keep running while the child copies memory, so the copy can be torn;
    // harmless for a child that execs right away, which is what multithreaded programs do.
    fork(c, stack)
}

/// clone3(struct clone_args *, size): { flags, pidfd, child_tid, parent_tid, exit_signal, stack,
/// stack_size, tls, ... }. The new stack is given as base + size; the rest maps onto clone.
pub fn clone3(c: &mut Context, args: u64, size: u64) -> R {
    if size < 64 {
        return Err(crate::syscall::EINVAL);
    }
    let a = unsafe { *(args as *const [u64; 8]) };
    let [flags, _pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls] = a;
    let sp = if stack != 0 { stack + stack_size } else { 0 };
    clone(c, flags | (exit_signal & 0xff), sp, parent_tid, child_tid, tls)
}

pub fn wait4(pid: i64, status: u64, options: u64) -> R {
    const WNOHANG: u64 = 1;
    if options & !(WNOHANG | 2 | 8 | 0xe000_0000) != 0 {
        return Err(syscall::EINVAL); // WUNTRACED, WCONTINUED, __WNOTHREAD/__WALL/__WCLONE are the rest
    }
    if pid == i32::MIN as i64 {
        return Err(ESRCH); // -INT_MIN has no positive pid
    }
    let sel = match pid {
        -1 => Which::Any,
        0 => Which::Group(signal::ids(None).map_or(self::pid(), |(g, _)| g)),
        p if p < 0 => Which::Group(host_pid(-p as u32)),
        p => Which::Pid(host_pid(p as u32)),
    };
    let Some((pid, code)) = wait_child(sel, options & WNOHANG == 0, false, options & (2 | 8))? else { return Ok(0) };
    if status != 0 {
        unsafe { *(status as *mut i32) = wait_status(code) as i32 };
    }
    Ok(pid as i64)
}

/// The wait status for an lx exit code: WIFSIGNALED with the signal, or WIFEXITED with WEXITSTATUS = code.
fn wait_status(code: u32) -> u32 {
    if code & 0xFFFF_0000 == JOB {
        return code & 0xffff;
    }
    if code & 0xFFFF_0000 == SIGNALED { code & 0x7f | if dumps_core(code & 0x7f) { 0x80 } else { 0 } } else { (code & 0xff) << 8 }
}

/// wait_child's code for a stop or continue: JOB | the wait status (signal::child_state).
const JOB: u32 = 0x4A0B_0000;

/// Signals whose default action dumps core: WCOREDUMP is set for them, as in a container whose core
/// limit (unlimited here, see rlimit) lets the kernel dump. ponytail: no core file is written.
fn dumps_core(sig: u32) -> bool {
    matches!(sig, 3 | 4 | 5 | 6 | 7 | 8 | 11 | 24 | 25 | 31) // QUIT ILL TRAP ABRT BUS FPE SEGV XCPU XFSZ SYS
}

/// Which children a wait is for.
#[derive(Clone, Copy)]
enum Which {
    Any,
    Pid(u32),
    /// Children in this process group (host pid of its leader).
    Group(u32),
}

/// waitid(idtype, id, infop, options): P_ALL 0, P_PID 1, P_PGID 2; WEXITED required (stopped and
/// continued children never happen here), WNOHANG, WNOWAIT leaves the child to be waited for again.
/// infop gets a siginfo: SIGCHLD, CLD_EXITED or CLD_KILLED, the pid, uid and status.
pub fn waitid(idtype: u64, id: u64, info: u64, options: u64) -> R {
    const WNOHANG: u64 = 1;
    const WEXITED: u64 = 4;
    const WNOWAIT: u64 = 0x0100_0000;
    if options & !(WNOHANG | 2 | WEXITED | 8 | WNOWAIT | 0xe000_0000) != 0 || options & (WEXITED | 2 | 8) == 0 {
        return Err(syscall::EINVAL);
    }
    let sel = match idtype {
        0 => Which::Any,
        1 if id as i32 > 0 => Which::Pid(host_pid(id as u32)),
        2 => Which::Group(if id == 0 { signal::ids(None).map_or(self::pid(), |(g, _)| g) } else { host_pid(id as u32) }),
        _ => return Err(syscall::EINVAL),
    };
    let got = wait_child(sel, options & WNOHANG == 0, options & WNOWAIT != 0, options & (2 | 8) | if options & WEXITED != 0 { 0 } else { NO_EXIT })?;
    if info != 0 {
        let mut si = [0u8; 128];
        if let Some((pid, code)) = got {
            let killed = code & 0xFFFF_0000 == SIGNALED;
            let put = |si: &mut [u8; 128], off: usize, v: i32| si[off..off + 4].copy_from_slice(&v.to_le_bytes());
            // CLD_EXITED 1, CLD_KILLED 2, CLD_DUMPED 3, CLD_STOPPED 5, CLD_CONTINUED 6, and the status:
            // the exit code, the signal, or SIGCONT
            let (cld, status) = match code {
                c if c & 0xFFFF_0000 == JOB && c & 0xffff == 0xffff => (6, 18),
                c if c & 0xFFFF_0000 == JOB => (5, (c >> 8 & 0xff) as i32),
                c if killed => (if dumps_core(c & 0x7f) { 3 } else { 2 }, (c & 0x7f) as i32),
                c => (1, (c & 0xff) as i32),
            };
            put(&mut si, 0, signal::SIGCHLD as i32);
            put(&mut si, 8, cld);
            put(&mut si, 16, guest_pid(pid) as i32);
            put(&mut si, 20, UID.load(Relaxed) as i32);
            put(&mut si, 24, status);
        }
        crate::syscall::put_guest(info, &si)?; // under WNOHANG with none ready: zeroed, si_pid 0
    }
    Ok(0)
}

/// Wait for a child matching `sel` to exit: (its pid, its lx exit code), None under !blocking when none
/// has. `keep`: leave it waitable (WNOWAIT).
/// `job`: also report stopped (2, WUNTRACED/WSTOPPED) and continued (8, WCONTINUED) children; with
/// NO_EXIT, only those (waitid without WEXITED).
fn wait_child(sel: Which, blocking: bool, keep: bool, job: u64) -> Result<Option<(u32, u32)>, i64> {
    let matches = |k: &mut Kid| match sel {
        Which::Any => true,
        Which::Pid(p) => k.pid == p,
        Which::Group(g) => {
            if let Some((kg, _)) = signal::ids(Some(k.pid)) {
                k.pgid = kg; // it may have moved (setpgid); once it has exited, the last one seen counts
            }
            k.pgid == g
        }
    };
    loop {
        // Wait on our own duplicates with the lock released: other threads keep making syscalls,
        // and one of them may reap (and close) a child meanwhile.
        let waits: Vec<(u32, OwnedHandle)> = {
            let mut kids = CHILDREN.lock().unwrap();
            if job & (2 | 8) != 0 {
                let state = kids.iter_mut().find_map(|k| {
                    if !matches(k) {
                        return None;
                    }
                    let s = signal::child_state(k.pid, true)?;
                    let want = if s == 0xffff { job & 8 != 0 } else { job & 2 != 0 };
                    (want && (keep || signal::child_state(k.pid, false) == Some(s))).then_some((k.pid, JOB | s))
                });
                if let Some(got) = state {
                    return Ok(Some(got));
                }
            }
            kids.iter_mut().filter_map(|k| if matches(k) { k.process.try_clone().ok().map(|h| (k.pid, h)) } else { None })
                .take(63).collect()
        };
        if waits.is_empty() {
            return Err(ECHILD);
        }
        let mut hs: Vec<isize> = waits.iter().map(|(_, h)| h.as_raw_handle() as isize).collect();
        let n = hs.len();
        if blocking && signal::intr_event() != 0 {
            hs.push(signal::intr_event()); // a signal cuts the wait short
        }
        let r = unsafe { WaitForMultipleObjects(hs.len() as u32, hs.as_ptr(), 0, if blocking { u32::MAX } else { 0 }) } as usize;
        if job & NO_EXIT != 0 && r < n {
            // Waiting for stops only: an exit isn't ours to report (nor to reap); wait for the next change.
            if !blocking {
                return Ok(None);
            }
            let intr = signal::intr_event();
            if intr == 0 || unsafe { WaitForMultipleObjects(1, &intr, 0, u32::MAX) } != 0 || signal::deliverable() {
                return Err(crate::syscall::EINTR);
            }
            continue;
        }
        if r == n && blocking {
            if signal::deliverable() {
                return Err(crate::syscall::EINTR);
            }
            continue;
        }
        if r >= n {
            return Ok(None); // WAIT_TIMEOUT under WNOHANG
        }
        let mut kids = CHILDREN.lock().unwrap();
        let Some(i) = kids.iter().position(|k| k.pid == waits[r].0) else { continue }; // reaped elsewhere
        let mut code = 0u32;
        unsafe { GetExitCodeProcess(kids[i].process.as_raw_handle() as isize, &mut code) };
        let pid = kids[i].pid;
        if !keep {
            REAPED.lock().unwrap().push((pid, std::time::Instant::now()));
            kids.remove(i);
            crate::ptable::reap(guest_pid(pid)); // its zombie leaves /proc
        }
        return Ok(Some((pid, code)));
    }
}

/// wait_child's `job` flag: waitid without WEXITED.
const NO_EXIT: u64 = 1 << 32;

/// Raise SIGCHLD for children that exited since we last looked (cheap: a zero-timeout wait each).
pub fn notice_child_exits() {
    let mut kids = CHILDREN.lock().unwrap();
    for k in kids.iter_mut().filter(|k| !k.notified) {
        let h = k.process.as_raw_handle() as isize;
        if unsafe { WaitForMultipleObjects(1, &h, 0, 0) } == 0 {
            k.notified = true;
            let _ = signal::raise(signal::SIGCHLD);
        }
    }
}

/// Block until some child exits (raising SIGCHLD). With no running children nothing can wake us,
/// which is also what Linux would do without other signal sources.
pub fn wait_for_child_exit() {
    let mut hs: Vec<isize> = CHILDREN.lock().unwrap().iter().filter(|k| !k.notified).take(63)
        .map(|k| k.process.as_raw_handle() as isize).collect();
    if signal::intr_event() != 0 {
        hs.push(signal::intr_event()); // or a signal from outside
    }
    if hs.is_empty() {
        std::thread::sleep(std::time::Duration::from_secs(3600));
        return;
    }
    unsafe { WaitForMultipleObjects(hs.len() as u32, hs.as_ptr(), 0, u32::MAX) };
    notice_child_exits();
}

pub fn kill(pid: i64, sig: u64) -> R {
    let pid = if pid > 0 { host_pid(pid as u32) as i64 } else { pid };
    let me = self::pid() as i64;
    if pid == me {
        if sig != 0 {
            signal::sent_by_self(sig);
        }
        return if sig == 0 { Ok(0) } else { signal::raise(sig) }; // delivered when this syscall returns
    }
    if pid == -1 {
        // ponytail: "everyone" means our children.
        let pids: Vec<u32> = CHILDREN.lock().unwrap().iter().map(|k| k.pid).collect();
        for p in pids {
            let _ = kill(p as i64, sig);
        }
        return Ok(0);
    }
    if pid <= 0 {
        let pgid = if pid == 0 { signal::ids(None).ok_or(ESRCH)?.0 } else { host_pid(-pid as u32) };
        let members = signal::group(pgid);
        if members.is_empty() {
            return Err(ESRCH);
        }
        let mine = members.contains(&unsafe { GetCurrentProcessId() }) || members.contains(&self::pid());
        for p in members.into_iter().filter(|&p| p != unsafe { GetCurrentProcessId() } && p != self::pid()) {
            let _ = send(p, sig);
        }
        return if mine && sig != 0 { signal::raise(sig) } else { Ok(0) }; // ourselves last, as we may die of it
    }
    send(pid as u32, sig)
}

/// setpgid(pid, pgid): 0 means the caller / the target's own pid.
pub fn setpgid(pid: u32, pgid: u32) -> R {
    let target = if pid == 0 || host_pid(pid) == self::pid() { None } else { Some(host_pid(pid)) };
    let me = target.unwrap_or(self::pid());
    let pgid = if pgid == 0 { me } else { host_pid(pgid) };
    let (_, sid) = signal::ids(target).ok_or(ESRCH)?;
    signal::set_ids(target, pgid, sid)
}

pub fn getpgid(pid: u32) -> R {
    let target = if pid == 0 || host_pid(pid) == self::pid() { None } else { Some(host_pid(pid)) };
    Ok(guest_pid(signal::ids(target).ok_or(ESRCH)?.0) as i64)
}

pub fn getsid(pid: u32) -> R {
    let target = if pid == 0 || host_pid(pid) == self::pid() { None } else { Some(host_pid(pid)) };
    Ok(guest_pid(signal::ids(target).ok_or(ESRCH)?.1) as i64)
}

/// setsid: a new session and group led by us; EPERM if we already lead a group (like the container's pid 1).
pub fn setsid() -> R {
    let me = self::pid();
    if signal::ids(None).is_some_and(|(g, _)| g == me) {
        return Err(syscall::EPERM);
    }
    signal::set_ids(None, me, me)?;
    Ok(guest_pid(me) as i64)
}

/// Signal any lx guest process by pid (the mailbox). SIGKILL goes the same way (the watcher thread exits,
/// or passes it on to an exec'd successor); a process without a mailbox is terminated outright.
pub fn send(pid: u32, sig: u64) -> R {
    if sig == 9 && signal::send(pid, 9).is_err() {
        let h = unsafe { OpenProcess(0x0001 | 0x0010_0000, 0, pid) }; // PROCESS_TERMINATE | SYNCHRONIZE
        if h == 0 {
            return Err(ESRCH);
        }
        unsafe { TerminateProcess(h, 128 + 9) };
        unsafe { CloseHandle(h) };
        return Ok(0);
    }
    if sig == 9 {
        return Ok(0);
    }
    if sig == 0 {
        let h = unsafe { OpenProcess(0x1000, 0, pid) }; // PROCESS_QUERY_LIMITED_INFORMATION
        if h == 0 {
            return Err(ESRCH);
        }
        unsafe { CloseHandle(h) };
        return Ok(0);
    }
    signal::send(pid, sig)
}

/// `lx stop <pid>`: SIGTERM, then SIGKILL if it's still running after `grace`, like `docker stop`.
pub fn stop(pid: u32, grace: std::time::Duration) -> Result<(), String> {
    let h = unsafe { OpenProcess(0x0010_0000, 0, pid) }; // SYNCHRONIZE
    if h == 0 {
        return Err(format!("no process {pid}"));
    }
    send(pid, 15).map_err(|_| format!("{pid} is not an lx container process"))?;
    let gone = unsafe { WaitForMultipleObjects(1, &h, 0, grace.as_millis() as u32) } == 0;
    if !gone {
        eprintln!("[lx] {pid} ignored SIGTERM for {}s, sending SIGKILL", grace.as_secs());
        let _ = send(pid, 9);
        unsafe { WaitForMultipleObjects(1, &h, 0, 5000) };
    }
    unsafe { CloseHandle(h) };
    Ok(())
}

// ---- running containers, for `lx ps` ----

const RUNNING: &str = "rootfs/containers";

/// Record this top-level `lx run` so `lx ps` can list it (removed again on exit; stale entries,
/// e.g. after a hard kill, are filtered out by checking the pid is still alive).
/// `config` (JSON) is what `lx exec` needs to step in, kept beside it as `<pid>.json`.
pub fn register_container(desc: &str, config: &str) {
    let _ = std::fs::create_dir_all(RUNNING);
    let pid = unsafe { GetCurrentProcessId() };
    let _ = std::fs::write(format!("{RUNNING}/{pid}.json"), config);
    let _ = std::fs::write(format!("{RUNNING}/{pid}"), desc);
    CONTAINER.store(true, Relaxed);
}

/// `lx run -d`: where container `pid`'s output goes (`lx logs`). Kept after it exits, like Docker's logs.
pub fn set_log(pid: u32, path: &str) {
    let _ = std::fs::create_dir_all(RUNNING);
    let _ = std::fs::write(format!("{RUNNING}/{pid}.log"), path);
}

pub fn log_of(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("{RUNNING}/{pid}.log")).ok()
}

/// A running container's config (see register_container).
pub fn container_config(pid: u32) -> Option<String> {
    send(pid, 0).ok()?;
    std::fs::read_to_string(format!("{RUNNING}/{pid}.json")).ok()
}

/// A running container's `--name`.
pub fn name_of(pid: u32) -> Option<String> {
    let cfg: serde_json::Value = serde_json::from_str(&container_config(pid)?).ok()?;
    cfg["name"].as_str().map(String::from)
}

/// A running container by `--name`, or by the pid of its first lx process.
pub fn container_pid(id: &str) -> Option<u32> {
    if let Ok(pid) = id.parse::<u32>() {
        return Some(pid);
    }
    ps().into_iter().map(|(pid, _)| pid).find(|&pid| name_of(pid).as_deref() == Some(id))
}
static CONTAINER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// ---- per-container writable layers ----

const LAYERS: &str = "rootfs/layers";
static LAYER: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

/// A fresh layer directory for this container, named after our pid (so `gc_layers` can tell whether
/// its container still runs). Removed when the container exits.
pub fn new_layer() -> std::io::Result<std::path::PathBuf> {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    let dir = std::path::Path::new(LAYERS).join(format!("{}-{nanos}", unsafe { GetCurrentProcessId() }));
    std::fs::create_dir_all(dir.join("upper"))?;
    fs::case_sensitive(&dir.join("upper")); // the container's own files: case-sensitive like the image
    let dir = std::fs::canonicalize(dir)?; // same verbatim form as the image root
    *LAYER.lock().unwrap() = Some(dir.clone());
    Ok(dir)
}

/// Remove layers whose container is gone (killed before it could clean up).
pub fn gc_layers() {
    for e in std::fs::read_dir(LAYERS).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let pid = name.split('-').next().and_then(|p| p.parse::<u32>().ok());
        if pid.is_some_and(|p| send(p, 0).is_err()) {
            let _ = std::fs::remove_dir_all(e.path());
            let _ = std::fs::remove_dir_all(std::path::Path::new(SOCKETS).join(&name));
        }
    }
}

/// Where AF_UNIX socket files live, one folder per container (see net.rs).
const SOCKETS: &str = "rootfs/s";

pub fn ps() -> Vec<(u32, String)> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(RUNNING).into_iter().flatten().flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
        if send(pid, 0).is_ok() {
            v.push((pid, std::fs::read_to_string(e.path()).unwrap_or_default()));
        } else {
            let _ = std::fs::remove_file(e.path());
            let _ = std::fs::remove_file(format!("{RUNNING}/{pid}.json"));
        }
    }
    v
}

/// Exit immediately, without DLL teardown: the guest owns the process; nothing of ours needs flushing.
pub fn exit(code: u64) -> ! {
    crate::ptable::unregister();
    if crate::syscall::patchlog() {
        use std::sync::atomic::Ordering::Relaxed;
        crate::syscall::dlog(format_args!(
            "pid {} exit: syscall sites {} rewritten ({} forward) / {} fallback, {} fallback traps; fs sites {} rewritten / {} left, {} FS-base faults",
            unsafe { GetCurrentProcessId() }, crate::jump::REWRITTEN.load(Relaxed), crate::jump::FORWARD.load(Relaxed), crate::jump::FALLBACK_SITES.load(Relaxed),
            crate::syscall::FALLBACK_TRAPS.load(Relaxed), crate::jump::FS_REWRITTEN.load(Relaxed), crate::jump::FS_LEFT.load(Relaxed),
            crate::syscall::FS_FAULTS.load(Relaxed)));
    }
    if crate::syscall::siglog() {
        crate::syscall::dlog(format_args!("pid {} exit {}", unsafe { GetCurrentProcessId() }, code as u8));
    }
    if CONTAINER.load(Relaxed) {
        let pid = unsafe { GetCurrentProcessId() };
        let _ = std::fs::remove_file(format!("{RUNNING}/{pid}"));
        let _ = std::fs::remove_file(format!("{RUNNING}/{pid}.json"));
    }
    if let Ok(g) = LAYER.try_lock() && let Some(dir) = g.as_ref() {
        let _ = std::fs::remove_dir_all(dir); // the container's changes go with it (docker run --rm)
        if let Some(name) = dir.file_name() {
            let _ = std::fs::remove_dir_all(std::path::Path::new(SOCKETS).join(name)); // its AF_UNIX socket files
        }
    }
    if debug() {
        eprintln!("[lx] pid {} exit {}", unsafe { GetCurrentProcessId() }, code as u8);
    }
    crate::sysvipc::undo_all(); // SEM_UNDO: what this process took, given back
    // Close the guest's fds first: TerminateProcess drops sockets abortively, and a peer of an AF_UNIX
    // pair then reads ECONNRESET where Linux gives EOF (erts and its erl_child_setup).
    fs::close_all();
    let code = code as u32;
    let code = match code & 0xFFFF_0000 == SIGNALED {
        true if root() == 0 || root() == unsafe { GetCurrentProcessId() } => 128 + (code & 0x7f), // like a shell
        true => code,
        false => code & 0xff,
    };
    unsafe {
        TerminateProcess(GetCurrentProcess(), code);
    }
    unreachable!()
}

fn strv(p: u64) -> Result<Vec<String>, i64> {
    let mut v = Vec::new();
    for i in 0..4096 {
        let s = unsafe { *((p + i * 8) as *const u64) };
        if s == 0 {
            return Ok(v);
        }
        // An argument or environment string may be up to MAX_ARG_STRLEN (32 pages), not just a path's
        // 4096: aclocal hands sh -c a 4.7 KB command line.
        v.push(crate::syscall::cstr_max(s, 32 * 4096)?);
    }
    Err(crate::syscall::E2BIG)
}

pub fn execve(path: u64, argv: u64, envp: u64) -> R {
    let path = cstr(path)?;
    let argv = if argv == 0 { vec![] } else { strv(argv)? };
    let env = if envp == 0 { vec![] } else { strv(envp)? };
    // execve takes the path literally (relative to cwd), never a PATH search.
    let lookup = if path.contains('/') { path.clone() } else { format!("./{path}") };
    let (_, bytes) = fs::find_exe(&lookup, "")?;
    if !bytes.starts_with(b"\x7fELF") && !bytes.starts_with(b"#!") {
        return Err(ENOEXEC); // the shell then runs it as a script itself
    }
    drop(bytes); // we only wait from here on: don't keep the whole program (traefik: 176 MB) while it runs
    // A single-threaded process (shells, entrypoint scripts, `exec nginx`) replaces its program in place,
    // as Linux does: no new Windows process to start (~20 ms) and none left behind waiting. With other
    // threads it goes the old way: stopping them could leave one of our locks held (stop_others).
    if crate::thread::live() == 1 && unsafe { GetCurrentThreadId() } == crate::thread::MAIN_TID.load(Relaxed)
        && std::env::var("LX_NOINPLACE").map_or(true, |v| v != "1") {
        return exec_in_place(&lookup, argv, env);
    }
    let spawning = SPAWN.lock().unwrap_or_else(|e| e.into_inner()); // see fork
    let (mut state, handles) = fs::proc_state(false);
    state.push(PARENT.load(Relaxed).to_string()); // exec keeps the pid relationship
    state.push(pid().to_string()); // and the pid itself
    state.push(lookup); // as called, not resolved: a #! script sees the name it was run by (start)
    state.push(argv.len().to_string());
    state.extend(argv);
    state.extend(env);
    let child = spawn_lx("--exec", &[], state);
    drop((spawning, handles)); // before waiting: holding pipe ends would keep readers from EOF
    let mut child = child.map_err(|e| {
        eprintln!("[lx] execve: {e}");
        EAGAIN
    })?;
    crate::thread::stop_others(); // exec replaces the whole image: no other threads survive it
    fs::close_all(); // we only wait from here on; don't hold pipe ends open
    signal::FORWARD_TO.store(child.id(), Relaxed); // our pid is its pid: pass signals on
    syscall::release_guest_memory();
    let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(1);
    exit(code as u64)
}

/// execve within this process. Everything that can fail is checked first (crate::prepare), so a bad
/// program is still an error for the caller; past that point the old program is gone, as on Linux.
/// Kept: the pid, children, ids, the signal mask and pending signals, ignored signals, fds without
/// FD_CLOEXEC, alarm, seccomp filters. Reset: memory, code patches, handlers, POSIX timers, sigaltstack.
fn exec_in_place(lookup: &str, argv: Vec<String>, env: Vec<String>) -> R {
    let p = crate::prepare(lookup, argv, "").map_err(|(e, _)| e)?;
    fs::close_cloexec();
    signal::reset_for_exec();
    syscall::reset_for_exec();
    let e = crate::launch(p, env);
    eprintln!("[lx] execve: {e}");
    die(9) // too late for an error return, as on Linux
}

/// The exec'd side (`lx --exec <state>`): rebuild the fd table; returns (exe, argv, env).
pub fn receive_exec(state: &str) -> Result<(String, Vec<String>, Vec<String>), String> {
    let fields = read_state(state)?;
    let rest = fs::init_from(&fields)?;
    let [ppid, pid, exe, argc, rest @ ..] = rest else { return Err("malformed exec state".into()) };
    PARENT.store(ppid.parse().map_err(|_| "malformed exec state")?, Relaxed);
    PID.store(pid.parse().map_err(|_| "malformed exec state")?, Relaxed);
    let argc: usize = argc.parse().map_err(|_| "malformed exec state")?;
    if rest.len() < argc {
        return Err("malformed exec state".into());
    }
    Ok((exe.clone(), rest[..argc].to_vec(), rest[argc..].to_vec()))
}
