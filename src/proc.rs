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

pub fn getpid() -> R {
    Ok(unsafe { GetCurrentProcessId() } as i64)
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
fn spawn_lx(mode: &str, extra: &[String], state: Vec<String>) -> std::io::Result<Child> {
    let (r, w) = inheritable_pipe()?;
    let child = std::process::Command::new(std::env::current_exe()?).arg(mode).arg(raw(&r)).args(extra).spawn()?;
    drop(r);
    std::fs::File::from(w).write_all(state.join("\0").as_bytes())?; // closing it is the child's EOF
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
    state.extend(regs.iter().map(|r| r.to_string()));
    state.push(unsafe { GetCurrentProcessId() }.to_string());

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
    let mut child = spawn_lx("--fork", &[raw(&me), raw(&ready_w)], state).map_err(|e| fail(e.to_string()))?;
    drop((me, ready_w)); // if the child dies before reporting, `ready` hits EOF
    let mut byte = [0u8];
    if !matches!(std::fs::File::from(ready_r).read(&mut byte), Ok(1)) {
        let _ = child.kill();
        return Err(fail("child failed to rebuild the guest".into()));
    }
    let pid = child.id();
    CHILDREN.lock().unwrap().push(Kid { pid, process: OwnedHandle::from(child), notified: false });
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

pub fn wait4(pid: i64, status: u64, options: u64) -> R {
    const WNOHANG: u64 = 1;
    loop {
        // Wait on our own duplicates with the lock released: other threads keep making syscalls,
        // and one of them may reap (and close) a child meanwhile.
        let waits: Vec<(u32, OwnedHandle)> = {
            let kids = CHILDREN.lock().unwrap();
            // ponytail: process groups (pid 0 or < -1) are treated as "any child".
            kids.iter().filter(|k| pid <= 0 || k.pid as i64 == pid).take(64)
                .filter_map(|k| k.process.try_clone().ok().map(|h| (k.pid, h))).collect()
        };
        if waits.is_empty() {
            return Err(ECHILD);
        }
        let hs: Vec<isize> = waits.iter().map(|(_, h)| h.as_raw_handle() as isize).collect();
        let timeout = if options & WNOHANG != 0 { 0 } else { u32::MAX };
        let r = unsafe { WaitForMultipleObjects(hs.len() as u32, hs.as_ptr(), 0, timeout) } as usize;
        if r >= hs.len() {
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
    let hs: Vec<isize> = CHILDREN.lock().unwrap().iter().filter(|k| !k.notified).take(64)
        .map(|k| k.process.as_raw_handle() as isize).collect();
    if hs.is_empty() {
        std::thread::sleep(std::time::Duration::from_secs(3600));
        return;
    }
    unsafe { WaitForMultipleObjects(hs.len() as u32, hs.as_ptr(), 0, u32::MAX) };
    notice_child_exits();
}

pub fn kill(pid: i64, sig: u64) -> R {
    if pid == unsafe { GetCurrentProcessId() } as i64 {
        return if sig == 0 { Ok(0) } else { signal::raise(sig) }; // delivered when this syscall returns
    }
    let kids = CHILDREN.lock().unwrap();
    // ponytail: only our own children are addressable, and they get the default "terminate".
    let Some(k) = kids.iter().find(|k| k.pid as i64 == pid) else { return Err(ESRCH) };
    if sig != 0 {
        unsafe { TerminateProcess(k.process.as_raw_handle() as isize, 128 + sig as u32) };
    }
    Ok(0)
}

/// Exit immediately, without DLL teardown: the guest owns the process; nothing of ours needs flushing.
pub fn exit(code: u64) -> ! {
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
    let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(1);
    exit(code as u64)
}

/// The exec'd side (`lx --exec <state>`): rebuild the fd table; returns (exe, argv, env).
pub fn receive_exec(state: &str) -> Result<(String, Vec<String>, Vec<String>), String> {
    let fields = read_state(state)?;
    let rest = fs::init_from(&fields)?;
    let [ppid, exe, argc, rest @ ..] = rest else { return Err("malformed exec state".into()) };
    PARENT.store(ppid.parse().map_err(|_| "malformed exec state")?, Relaxed);
    let argc: usize = argc.parse().map_err(|_| "malformed exec state")?;
    if rest.len() < argc {
        return Err("malformed exec state".into());
    }
    Ok((exe.clone(), rest[..argc].to_vec(), rest[argc..].to_vec()))
}
