//! The container's process table, for /proc/<pid> of the other processes (ps, pgrep, pidof,
//! healthchecks): a named shared memory section per container, one slot per guest process, claimed when
//! its program starts (an exec keeps its pid's slot, a fork child copies its parent's) and freed at exit.
//! Slots of processes that died without freeing theirs are skipped (and freed) by readers.
//! ponytail: 1024 slots; no locking (a reader may see a slot's names mid-write); no CPU or memory
//! figures; a dead process whose Windows pid is reused at once looks alive (creation times would tell);
//! a process killed between claiming a slot and storing its Windows pid leaks that slot.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering::{Relaxed, SeqCst}};

const SLOTS: usize = 1024;
const SLOT: usize = 512;
const COMM: usize = 16;
const EXE: usize = 128;
const CMDLINE: usize = SLOT - 40 - COMM - EXE;

#[repr(C)]
struct Slot {
    pid: AtomicU32, // as getpid says it (1: the container's first process); 0: free
    // The Windows pid running it now. 0 with a pid set: being claimed or freed (readers skip it). Claiming
    // sets pid then win; freeing clears win (one freer wins the swap) then pid.
    win: AtomicU32,
    ppid: u32,
    uid: u32,
    gid: u32,
    /// While its main thread is in a syscall, the tick (ms, | 1) it entered at; 0 in guest code.
    sys_ms: AtomicU32,
    /// 1: it ignores SIGCHLD (or set SA_NOCLDWAIT), so its children leave no zombies.
    nocldwait: AtomicU32,
    _pad: u32,
    start_ms: u64, // GetTickCount64 at its start
    comm: [u8; COMM],
    exe: [u8; EXE],
    cmdline: [u8; CMDLINE],
}

const _: () = assert!(size_of::<Slot>() == SLOT);

/// One process, as /proc shows it.
pub struct Info {
    /// R running; S its main thread has been in one syscall for a while (blocked); Z exited, not yet
    /// reaped by its parent.
    pub state: char,
    /// Its children are reaped as they exit (SIGCHLD ignored, SA_NOCLDWAIT).
    pub nocldwait: bool,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub start_ms: u64,
    pub comm: String,
    pub exe: String,
    pub cmdline: Vec<u8>,
}

/// The slots, as raw pointers: the section is shared memory other processes write too.
fn table() -> Option<impl Iterator<Item = *mut Slot>> {
    static BASE: OnceLock<usize> = OnceLock::new();
    let base = *BASE.get_or_init(|| {
        let root = std::env::var("LX_IN_JOB").unwrap_or_else(|_| std::process::id().to_string());
        let name: Vec<u16> = format!("Local\\lx-procs-{root}").encode_utf16().chain([0]).collect();
        // Paging-file backed, PAGE_READWRITE; FILE_MAP_ALL_ACCESS. Kept for the process's life.
        let h = unsafe { crate::win::CreateFileMappingW(-1, std::ptr::null_mut(), 0x04, 0, (SLOTS * SLOT) as u32, name.as_ptr()) };
        if h == 0 {
            return 0;
        }
        unsafe { crate::win::MapViewOfFile(h, 0xF001F, 0, 0, SLOTS * SLOT) as usize }
    });
    (base != 0).then(|| (0..SLOTS).map(move |i| unsafe { (base as *mut Slot).add(i) }))
}

fn alive(win: u32) -> bool {
    use crate::win::*;
    let h = unsafe { OpenProcess(0x1000, 0, win) }; // PROCESS_QUERY_LIMITED_INFORMATION
    if h == 0 {
        return false;
    }
    let mut code = 0u32;
    let ok = unsafe { GetExitCodeProcess(h, &mut code) } != 0;
    unsafe { CloseHandle(h) };
    ok && code == 259 // STILL_ACTIVE
}

fn put(dst: &mut [u8], src: &[u8]) {
    let n = src.len().min(dst.len() - 1);
    dst.fill(0);
    dst[..n].copy_from_slice(&src[..n]);
}

/// A slot for `pid`: its own (an exec keeps it), else a free or dead one.
fn claim(pid: u32) -> Option<&'static mut Slot> {
    if let Some(p) = table()?.find(|&p| unsafe { (*p).pid.load(SeqCst) } == pid) {
        return Some(unsafe { &mut *p });
    }
    // A free slot; if none is, free the slots of processes that died without freeing theirs, and retry.
    for _ in 0..2 {
        for p in table()? {
            let s = unsafe { &*p };
            if s.pid.compare_exchange(0, pid, SeqCst, SeqCst).is_ok() {
                s.win.store(std::process::id(), SeqCst);
                let m = unsafe { &mut *p };
                m.start_ms = unsafe { crate::win::GetTickCount64() };
                return Some(m);
            }
        }
        all(); // frees dead slots
    }
    // Still full: zombies of a parent that never waits. The oldest one gives up its slot, rather than a
    // new process going unseen in /proc (Linux would just list many Z).
    let oldest = table()?.filter(|&p| unsafe { (*p).pid.load(SeqCst) != 0 && !alive((*p).win.load(SeqCst)) })
        .min_by_key(|&p| unsafe { (*p).start_ms })?;
    let s = unsafe { &*oldest };
    free(s, s.win.load(SeqCst));
    claim(pid)
}

/// Free slot `s` whose process ran as `win` (unless someone else freed or reclaimed it meanwhile).
fn free(s: &Slot, win: u32) {
    if win != 0 && s.win.compare_exchange(win, 0, SeqCst, SeqCst).is_ok() {
        s.pid.store(0, SeqCst);
    }
}

/// This process's slot, for syscall_state.
static OWN: AtomicPtr<Slot> = AtomicPtr::new(std::ptr::null_mut());

/// The main thread enters (true) or leaves (false) a syscall: what /proc/<pid>/stat's state is made of
/// (LTP waits for a child to show S before it signals it, so S must mean blocked, not just in lx).
pub fn syscall_state(entering: bool) {
    let p = OWN.load(Relaxed);
    if !p.is_null() {
        let v = if entering { (unsafe { crate::win::GetTickCount64() } as u32) | 1 } else { 0 };
        unsafe { (*p).sys_ms.store(v, Relaxed) };
    }
}

/// This process starts a program (run, exec): record it.
pub fn register(exe: &str, argv: &[String]) {
    let pid = crate::proc::getpid().unwrap_or(0) as u32;
    let Some(s) = claim(pid) else { return };
    s.sys_ms.store(0, Relaxed);
    OWN.store(s as *mut Slot, Relaxed);
    s.win.store(std::process::id(), SeqCst);
    s.ppid = crate::proc::getppid().unwrap_or(0) as u32;
    s.uid = crate::proc::UID.load(SeqCst);
    s.gid = crate::proc::GID.load(SeqCst);
    // comm is the name it was started under (`sleep`), not the file the link led to (busybox): argv[0].
    let started = argv.first().map(String::as_str).filter(|a| !a.is_empty()).unwrap_or(exe);
    put(&mut s.comm, started.rsplit('/').next().unwrap_or(started).as_bytes());
    put(&mut s.exe, exe.as_bytes());
    let cmd: Vec<u8> = argv.iter().flat_map(|a| a.bytes().chain([0])).collect();
    put(&mut s.cmdline, &cmd);
}

/// A forked child: the parent's program, under its own pid.
pub fn fork_child() {
    let Some(parent) = get(crate::proc::getppid().unwrap_or(0) as u32) else { return };
    let pid = crate::proc::getpid().unwrap_or(0) as u32;
    let Some(s) = claim(pid) else { return };
    s.sys_ms.store(0, Relaxed);
    s.nocldwait.store(parent.nocldwait as u32, Relaxed); // dispositions survive fork
    OWN.store(s as *mut Slot, Relaxed);
    s.win.store(std::process::id(), SeqCst);
    s.ppid = parent.pid;
    (s.uid, s.gid) = (crate::proc::UID.load(SeqCst), crate::proc::GID.load(SeqCst));
    put(&mut s.comm, parent.comm.as_bytes());
    put(&mut s.exe, parent.exe.as_bytes());
    put(&mut s.cmdline, &parent.cmdline);
}

/// At exit: our slot stays as a zombie for our parent to reap (wait4 frees it, see reap), as on Linux;
/// with no parent in the container to do that, it's freed now. An exec proxy's slot was taken over by
/// its successor.
pub fn unregister() {
    let me = std::process::id();
    let mine = table().and_then(|mut t| t.find(|&p| unsafe { (*p).win.load(SeqCst) == me && (*p).pid.load(SeqCst) != 0 }));
    if let Some(p) = mine {
        let s = unsafe { &*p };
        if get(s.ppid).is_none_or(|parent| parent.state == 'Z' || parent.nocldwait) {
            free(s, me);
        }
    }
}

/// Our SIGCHLD disposition changed: whether our children are reaped at once (no zombies).
pub fn set_nocldwait(on: bool) {
    let p = OWN.load(Relaxed);
    if !p.is_null() {
        unsafe { (*p).nocldwait.store(on as u32, Relaxed) };
    }
}

/// wait4 collected child `pid`: its zombie slot goes.
pub fn reap(pid: u32) {
    let Some(t) = table() else { return };
    for p in t {
        let s = unsafe { &*p };
        if s.pid.load(SeqCst) == pid {
            free(s, s.win.load(SeqCst));
        }
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]).into_owned()
}

fn info(s: &Slot) -> Info {
    let end = s.cmdline.windows(2).position(|w| w == [0, 0]).map_or(s.cmdline.len(), |i| i + 1);
    // In one syscall for 16 ms or more (a tick or two): blocked there, as far as a reader can tell.
    let sys = s.sys_ms.load(Relaxed);
    let sleeping = sys != 0 && (unsafe { crate::win::GetTickCount64() } as u32).wrapping_sub(sys) >= 16;
    Info { state: if sleeping { 'S' } else { 'R' }, nocldwait: s.nocldwait.load(Relaxed) != 0, pid: s.pid.load(SeqCst), ppid: s.ppid, uid: s.uid, gid: s.gid, start_ms: s.start_ms,
           comm: text(&s.comm), exe: text(&s.exe), cmdline: s.cmdline[..end].to_vec() }
}

/// The container's processes: the live ones, and the zombies of live parents.
pub fn all() -> Vec<Info> {
    let Some(t) = table() else { return Vec::new() };
    let slots: Vec<(*mut Slot, bool)> = t
        .filter(|&p| unsafe { (*p).pid.load(SeqCst) != 0 && (*p).win.load(SeqCst) != 0 }) // else free, or being claimed or freed
        .map(|p| (p, alive(unsafe { (*p).win.load(SeqCst) })))
        .collect();
    // A live parent that will reap: its exited children are zombies until then.
    let reaper = |pid: u32| slots.iter().any(|&(p, a)| a && unsafe { (*p).pid.load(SeqCst) == pid && (*p).nocldwait.load(Relaxed) == 0 });
    slots.iter().filter_map(|&(p, a)| {
        let s = unsafe { &*p };
        if a {
            return Some(info(s));
        }
        if reaper(s.ppid) {
            return Some(Info { state: 'Z', ..info(s) }); // exited (or was killed); its parent hasn't reaped it
        }
        free(s, s.win.load(SeqCst)); // nobody left to reap it
        None
    }).collect()
}

pub fn get(pid: u32) -> Option<Info> {
    all().into_iter().find(|i| i.pid == pid)
}
