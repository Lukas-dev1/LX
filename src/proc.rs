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
}
static CHILDREN: Mutex<Vec<Kid>> = Mutex::new(Vec::new());
static PARENT: AtomicU32 = AtomicU32::new(0);

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
    let v = format!("{} {} {}", UID.load(Relaxed), GID.load(Relaxed), fs::UMASK.load(Relaxed));
    unsafe { std::env::set_var("LX_IDS", v) };
}

pub fn load_ids() {
    let Ok(v) = std::env::var("LX_IDS") else { return };
    let n: Vec<u32> = v.split(' ').filter_map(|x| x.parse().ok()).collect();
    if let [uid, gid, mask] = n[..] {
        (UID.store(uid, Relaxed), GID.store(gid, Relaxed), fs::UMASK.store(mask, Relaxed));
    }
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

pub fn getpid() -> R {
    Ok(pid() as i64)
}

pub fn getppid() -> R {
    Ok(PARENT.load(Relaxed) as i64)
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

fn spawn_lx(mode: &str, extra: &[String], state: Vec<String>) -> std::io::Result<Child> {
    let (r, w) = inheritable_pipe()?;
    let child = std::process::Command::new(std::env::current_exe()?).arg(mode).arg(raw(&r)).args(extra).spawn()?;
    drop(r);
    let (mut w, state) = (std::fs::File::from(w), state.join("\0"));
    let mut rest = state.as_bytes();
    while !rest.is_empty() {
        let n = uncancelled(|| w.write(rest))?;
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
pub fn fork(c: &mut Context, stack: u64) -> R {
    let next = c.rip + 2;
    // What the child resumes with: the state right after the syscall, rax = 0 (kernel ABI: rcx = rip,
    // r11 = rflags). ponytail: SSE/x87 registers aren't carried; SysV makes them caller-saved anyway.
    let rsp = if stack != 0 { stack } else { c.rsp };
    let regs = [0, next, c.rdx, c.rbx, rsp, c.rbp, c.rsi, c.rdi, c.r8, c.r9, c.r10, c.eflags as u64,
                c.r12, c.r13, c.r14, c.r15, next, c.eflags as u64];
    let mut state = fs::proc_state(true);
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
    let child = spawn_lx("--fork", &[raw(&me), raw(&ready_w)], state);
    syscall::views_inheritable(false); // the child has its copies of the shared-memory sections now
    let mut child = child.map_err(|e| fail(e.to_string()))?;
    drop((me, ready_w)); // if the child dies before reporting, `ready` hits EOF
    let mut byte = [0u8];
    let mut ready_r = std::fs::File::from(ready_r);
    if !matches!(uncancelled(|| ready_r.read(&mut byte)), Ok(1)) {
        let _ = child.kill();
        return Err(fail("child failed to rebuild the guest".into()));
    }
    let pid = child.id();
    CHILDREN.lock().unwrap().push(Kid { pid, process: OwnedHandle::from(child), notified: false });
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
    let rest = crate::jump::restore(rest)?;
    let nums: Vec<u64> = rest.iter().map(|s| s.parse().map_err(|_| "malformed fork state")).collect::<Result<_, _>>()?;
    let [regs @ .., ppid] = nums.as_slice() else { return Err("malformed fork state".into()) };
    let regs: [u64; 18] = regs.try_into().map_err(|_| "malformed fork state")?;
    PARENT.store(*ppid as u32, Relaxed);
    let ready: usize = ready.parse().map_err(|_| "bad ready handle")?;
    unsafe { std::fs::File::from_raw_handle(ready as _) }.write_all(b"1").map_err(|e| e.to_string())?;
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
    let blocking = options & WNOHANG == 0;
    loop {
        // Wait on our own duplicates with the lock released: other threads keep making syscalls,
        // and one of them may reap (and close) a child meanwhile.
        let waits: Vec<(u32, OwnedHandle)> = {
            let kids = CHILDREN.lock().unwrap();
            // ponytail: process groups (pid 0 or < -1) are treated as "any child".
            kids.iter().filter(|k| pid <= 0 || k.pid as i64 == pid).take(63)
                .filter_map(|k| k.process.try_clone().ok().map(|h| (k.pid, h))).collect()
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
        if r == n && blocking {
            if signal::deliverable() {
                return Err(crate::syscall::EINTR);
            }
            continue;
        }
        if r >= n {
            return Ok(0); // WAIT_TIMEOUT under WNOHANG
        }
        let mut kids = CHILDREN.lock().unwrap();
        let Some(i) = kids.iter().position(|k| k.pid == waits[r].0) else { continue }; // reaped elsewhere
        let kid = kids.remove(i);
        let mut code = 0u32;
        unsafe { GetExitCodeProcess(kid.process.as_raw_handle() as isize, &mut code) };
        if status != 0 {
            unsafe { *(status as *mut i32) = ((code & 0xff) << 8) as i32 }; // WIFEXITED, WEXITSTATUS = code
        }
        return Ok(kid.pid as i64);
    }
}

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
    let me = self::pid() as i64;
    if pid == me {
        return if sig == 0 { Ok(0) } else { signal::raise(sig) }; // delivered when this syscall returns
    }
    if pid <= 0 {
        // ponytail: no process groups; "my group" / "everyone" means our children.
        let pids: Vec<u32> = CHILDREN.lock().unwrap().iter().map(|k| k.pid).collect();
        for p in pids {
            let _ = kill(p as i64, sig);
        }
        return Ok(0);
    }
    send(pid as u32, sig)
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
pub fn register_container(desc: &str) {
    let _ = std::fs::create_dir_all(RUNNING);
    let _ = std::fs::write(format!("{RUNNING}/{}", unsafe { GetCurrentProcessId() }), desc);
    CONTAINER.store(true, Relaxed);
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
        }
    }
    v
}

/// Exit immediately, without DLL teardown: the guest owns the process; nothing of ours needs flushing.
pub fn exit(code: u64) -> ! {
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
        let _ = std::fs::remove_file(format!("{RUNNING}/{}", unsafe { GetCurrentProcessId() }));
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
    unsafe {
        TerminateProcess(GetCurrentProcess(), code as u32 & 0xff);
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
        v.push(cstr(s)?);
    }
    Err(crate::syscall::E2BIG)
}

pub fn execve(path: u64, argv: u64, envp: u64) -> R {
    let path = cstr(path)?;
    let argv = if argv == 0 { vec![] } else { strv(argv)? };
    let env = if envp == 0 { vec![] } else { strv(envp)? };
    // execve takes the path literally (relative to cwd), never a PATH search.
    let lookup = if path.contains('/') { path.clone() } else { format!("./{path}") };
    let (exe, bytes) = fs::find_exe(&lookup, "")?;
    if !bytes.starts_with(b"\x7fELF") && !bytes.starts_with(b"#!") {
        return Err(ENOEXEC); // the shell then runs it as a script itself
    }
    let mut state = fs::proc_state(false);
    state.push(PARENT.load(Relaxed).to_string()); // exec keeps the pid relationship
    state.push(pid().to_string()); // and the pid itself
    state.push(exe);
    state.push(argv.len().to_string());
    state.extend(argv);
    state.extend(env);
    let mut child = spawn_lx("--exec", &[], state).map_err(|e| {
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
