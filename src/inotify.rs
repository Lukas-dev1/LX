//! inotify: the fd reads an internal pipe; each watch is a thread waiting in ReadDirectoryChangesW on
//! the host directory where the container's changes land, writing struct inotify_event records into the
//! pipe. read, poll, epoll and fork work as on any pipe.
//! ponytail: changes the image had all along aren't events (only the container's own, in its writable
//! layer or a volume); IN_ACCESS/IN_OPEN/IN_CLOSE_NOWRITE never come; IN_CLOSE_WRITE comes with every
//! IN_MODIFY (NT doesn't tell writes from closes); the watching threads live in the process that added
//! them.

use crate::fs::{self, WHITEOUT};
use crate::syscall::{EINVAL, R};
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

const IN_MODIFY: u32 = 0x2;
const IN_ATTRIB: u32 = 0x4;
const IN_CLOSE_WRITE: u32 = 0x8;
const IN_MOVED_FROM: u32 = 0x40;
const IN_MOVED_TO: u32 = 0x80;
const IN_CREATE: u32 = 0x100;
const IN_DELETE: u32 = 0x200;
const IN_IGNORED: u32 = 0x8000;
const IN_ONLYDIR: u32 = 0x0100_0000;
const IN_ISDIR: u32 = 0x4000_0000;

struct Watch {
    wd: i32,
    dir: isize, // its directory handle, for cancelling the wait
    stop: Arc<AtomicBool>,
}

struct Instance {
    pipe: isize, // the fd's pipe handle
    sink: Arc<Mutex<OwnedHandle>>,
    watches: Vec<Watch>,
}

static INSTANCES: Mutex<Vec<Instance>> = Mutex::new(Vec::new());
static NEXT_WD: AtomicU32 = AtomicU32::new(1);
static COOKIE: AtomicU32 = AtomicU32::new(1);

/// inotify_init1(flags): IN_NONBLOCK and IN_CLOEXEC are O_NONBLOCK and O_CLOEXEC.
pub fn init(flags: u64) -> R {
    let (fd, sink) = fs::internal_pipe(flags)?;
    INSTANCES.lock().unwrap().push(Instance { pipe: fs::pipe_raw(fd as u64)?, sink: Arc::new(Mutex::new(sink)), watches: Vec::new() });
    Ok(fd)
}

/// One event record: struct inotify_event { int wd; u32 mask, cookie, len; char name[len]; }.
fn record(wd: i32, mask: u32, cookie: u32, name: &str) -> Vec<u8> {
    let len = if name.is_empty() { 0 } else { (name.len() + 1).next_multiple_of(4) };
    let mut r = Vec::with_capacity(16 + len);
    for v in [wd as u32, mask, cookie, len as u32] {
        r.extend(v.to_le_bytes());
    }
    r.extend(name.as_bytes());
    r.resize(16 + len, 0);
    r
}

fn send(sink: &Mutex<OwnedHandle>, bytes: &[u8]) -> bool {
    let w = sink.lock().unwrap();
    unsafe { crate::win::WriteFile(w.as_raw_handle() as isize, bytes.as_ptr(), bytes.len() as u32, &mut 0, std::ptr::null_mut()) != 0 }
}

/// inotify_add_watch(fd, path, mask): a new watch descriptor (a path watched again gets a new one).
pub fn add_watch(fd: u64, path: u64, mask: u64) -> R {
    let mask = mask as u32;
    let pipe = fs::pipe_raw(fd)?;
    let sink = INSTANCES.lock().unwrap().iter().find(|i| i.pipe == pipe).map(|i| i.sink.clone()).ok_or(EINVAL)?;
    let (dir, only) = fs::watch_target(path)?;
    if mask & IN_ONLYDIR != 0 && only.is_some() {
        return Err(crate::syscall::ENOTDIR);
    }
    let w: Vec<u16> = std::os::windows::ffi::OsStrExt::encode_wide(dir.as_os_str()).chain([0]).collect();
    // FILE_LIST_DIRECTORY, share all, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS (a directory)
    let h = unsafe { crate::win::CreateFileW(w.as_ptr(), 1, 7, std::ptr::null_mut(), 3, 0x0200_0000, 0) };
    if h == -1 {
        return Err(crate::syscall::ENOENT);
    }
    let wd = NEXT_WD.fetch_add(1, Relaxed) as i32;
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    std::thread::spawn(move || watch(h, wd, mask, only, &dir, &sink, &stopped));
    let mut all = INSTANCES.lock().unwrap();
    if let Some(i) = all.iter_mut().find(|i| i.pipe == pipe) {
        i.watches.push(Watch { wd, dir: h, stop });
    }
    Ok(wd as i64)
}

/// inotify_rm_watch(fd, wd): the watch ends with IN_IGNORED.
pub fn rm_watch(fd: u64, wd: u64) -> R {
    let pipe = fs::pipe_raw(fd)?;
    let mut all = INSTANCES.lock().unwrap();
    let inst = all.iter_mut().find(|i| i.pipe == pipe).ok_or(EINVAL)?;
    let at = inst.watches.iter().position(|w| w.wd == wd as i32).ok_or(EINVAL)?;
    let w = inst.watches.swap_remove(at);
    w.stop.store(true, Relaxed);
    unsafe { crate::win::CancelIoEx(w.dir, std::ptr::null_mut()) };
    send(&inst.sink, &record(w.wd, IN_IGNORED, 0, ""));
    Ok(0)
}

fn watch(h: isize, wd: i32, mask: u32, only: Option<String>, dir: &std::path::Path, sink: &Mutex<OwnedHandle>, stop: &AtomicBool) {
    // FILE_NOTIFY_CHANGE_FILE_NAME | DIR_NAME | ATTRIBUTES | SIZE | LAST_WRITE
    const FILTER: u32 = 0x1 | 0x2 | 0x4 | 0x8 | 0x10;
    let mut buf = vec![0u32; 16384]; // DWORD-aligned, as ReadDirectoryChangesW wants
    let mut moving = 0u32;
    while !stop.load(Relaxed) {
        let mut n = 0u32;
        let ok = unsafe { crate::win::ReadDirectoryChangesW(h, buf.as_mut_ptr().cast(), (buf.len() * 4) as u32, 0, FILTER, &mut n,
            std::ptr::null_mut(), std::ptr::null_mut()) };
        if ok == 0 || stop.load(Relaxed) {
            break;
        }
        let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n as usize) };
        let mut at = 0usize;
        let mut out = Vec::new();
        while at + 12 <= bytes.len() {
            let word = |o: usize| u32::from_le_bytes(bytes[at + o..at + o + 4].try_into().unwrap());
            let (next, action, len) = (word(0), word(4), word(8) as usize);
            let wide: Vec<u16> = bytes[at + 12..at + 12 + len].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            let name = fs::dec_name(&String::from_utf16_lossy(&wide));
            // A whiteout appearing is the image's entry being deleted; our other bookkeeping is no event.
            let (name, action) = match name.strip_prefix(WHITEOUT) {
                Some(n) if !n.starts_with(".wh.") && !n.starts_with("lx") => (n.to_string(), 2),
                Some(_) => (String::new(), 0),
                None => (name, action),
            };
            let isdir = fs::attrs(&dir.join(&name)).is_some_and(|m| m.dir);
            let events: &[u32] = match action {
                1 => &[IN_CREATE],                    // FILE_ACTION_ADDED
                2 => &[IN_DELETE],                    // REMOVED
                3 => &[IN_MODIFY, IN_CLOSE_WRITE],    // MODIFIED (size, time or attributes)
                4 => { moving = COOKIE.fetch_add(1, Relaxed); &[IN_MOVED_FROM] } // RENAMED_OLD_NAME
                5 => &[IN_MOVED_TO],                  // RENAMED_NEW_NAME
                _ => &[],
            };
            let ours = only.as_ref().is_none_or(|o| *o == name);
            for &e in events.iter().filter(|&&e| ours && mask & e != 0 && !name.is_empty()) {
                let cookie = if e & (IN_MOVED_FROM | IN_MOVED_TO) != 0 { moving } else { 0 };
                // A watched file's own events carry no name; a directory's name its entry.
                let shown = if only.is_some() { "" } else { name.as_str() };
                out.extend(record(wd, e | if isdir { IN_ISDIR } else { 0 }, cookie, shown));
            }
            if action == 3 && mask & IN_ATTRIB != 0 && ours && !name.is_empty() {
                out.extend(record(wd, IN_ATTRIB, 0, if only.is_some() { "" } else { name.as_str() }));
            }
            if next == 0 {
                break;
            }
            at += next as usize;
        }
        if !out.is_empty() && !send(sink, &out) {
            break; // the inotify fd is closed
        }
    }
    unsafe { crate::win::CloseHandle(h) };
}
