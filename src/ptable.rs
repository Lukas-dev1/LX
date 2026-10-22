//! The container's process table, for /proc/<pid> of the other processes (ps, pgrep, pidof,
//! healthchecks): a named shared memory section per container, one slot per guest process, claimed when
//! its program starts (an exec keeps its pid's slot, a fork child copies its parent's) and freed at exit.
//! Slots of processes that died without freeing theirs are skipped (and freed) by readers.
//! ponytail: 1024 slots; no locking (a reader may see a slot mid-write); no CPU or memory figures.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};

const SLOTS: usize = 1024;
const SLOT: usize = 512;
const COMM: usize = 16;
const EXE: usize = 128;
const CMDLINE: usize = SLOT - 32 - COMM - EXE;

#[repr(C)]
struct Slot {
    pid: AtomicU32, // as getpid says it (1: the container's first process); 0: free
    win: u32,       // the Windows pid running it now
    ppid: u32,
    uid: u32,
    gid: u32,
    _pad: u32,
    start_ms: u64, // GetTickCount64 at its start
    comm: [u8; COMM],
    exe: [u8; EXE],
    cmdline: [u8; CMDLINE],
}

const _: () = assert!(size_of::<Slot>() == SLOT);

/// One process, as /proc shows it.
pub struct Info {
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
    // A free slot, else (rarely) one whose process died without freeing it.
    for dead_ok in [false, true] {
        for p in table()? {
            let s = unsafe { &*p };
            let cur = s.pid.load(SeqCst);
            if (cur == 0 || (dead_ok && !alive(s.win))) && s.pid.compare_exchange(cur, pid, SeqCst, SeqCst).is_ok() {
                let m = unsafe { &mut *p };
                m.start_ms = unsafe { crate::win::GetTickCount64() };
                return Some(m);
            }
        }
    }
    None
}

/// This process starts a program (run, exec): record it.
pub fn register(exe: &str, argv: &[String]) {
    let pid = crate::proc::getpid().unwrap_or(0) as u32;
    let Some(s) = claim(pid) else { return };
    s.win = std::process::id();
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
    s.win = std::process::id();
    s.ppid = parent.pid;
    (s.uid, s.gid) = (crate::proc::UID.load(SeqCst), crate::proc::GID.load(SeqCst));
    put(&mut s.comm, parent.comm.as_bytes());
    put(&mut s.exe, parent.exe.as_bytes());
    put(&mut s.cmdline, &parent.cmdline);
}

/// At exit: free our slot (an exec proxy's was taken over by its successor).
pub fn unregister() {
    let me = std::process::id();
    let mine = table().and_then(|mut t| t.find(|&p| unsafe { (*p).win == me && (*p).pid.load(SeqCst) != 0 }));
    if let Some(p) = mine {
        unsafe { (*p).pid.store(0, SeqCst) };
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]).into_owned()
}

fn info(s: &Slot) -> Info {
    let end = s.cmdline.windows(2).position(|w| w == [0, 0]).map_or(s.cmdline.len(), |i| i + 1);
    Info { pid: s.pid.load(SeqCst), ppid: s.ppid, uid: s.uid, gid: s.gid, start_ms: s.start_ms,
           comm: text(&s.comm), exe: text(&s.exe), cmdline: s.cmdline[..end].to_vec() }
}

/// The container's live processes.
pub fn all() -> Vec<Info> {
    let Some(t) = table() else { return Vec::new() };
    t.filter_map(|p| {
        let s = unsafe { &*p };
        let pid = s.pid.load(SeqCst);
        if pid == 0 {
            return None;
        }
        if !alive(s.win) {
            let _ = s.pid.compare_exchange(pid, 0, SeqCst, SeqCst); // died without freeing it
            return None;
        }
        Some(info(s))
    }).collect()
}

pub fn get(pid: u32) -> Option<Info> {
    all().into_iter().find(|i| i.pid == pid)
}
