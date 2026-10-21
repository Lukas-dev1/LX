//! The guest's filesystem: path resolution confined to the rootfs, the fd table, file syscalls,
//! and unpacking image layers onto NTFS.
//!
//! Linux symlinks are stored as small marker files (LINK_MAGIC + target) and resolved here, never by
//! Windows: creating NTFS symlinks needs admin/Developer Mode, and resolving ourselves means `..` and
//! absolute targets can't leave the rootfs.
use crate::syscall::{R, cstr, guest_mut, read_handle, write_handle};
use crate::syscall::{EBADF, EEXIST, EINVAL, EISDIR, ELOOP, ENOENT, ENOTDIR, ERANGE, ESPIPE, ENOTEMPTY, EACCES, EBUSY, EIO};
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;
use crate::net::{Epoll, Sock};

const LINK_MAGIC: &[u8] = b"\0lxlink\0";
pub const AT_FDCWD: u64 = -100i64 as u64;
pub const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_EMPTY_PATH: u64 = 0x1000;
const AT_REMOVEDIR: u64 = 0x200;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
const O_DIRECTORY: u64 = 0o200000;
const O_NOFOLLOW: u64 = 0o400000;
const O_CLOEXEC: u64 = 0o2000000;
pub const O_NONBLOCK: u64 = 0o4000;

pub enum Fd {
    /// Console or pipe: plain read/write on a Windows handle.
    Handle(OwnedHandle),
    File { f: File, host: PathBuf },
    // ponytail: dup'd dir fds don't share the read position like Linux does.
    Dir { guest: String, pos: usize },
    /// Emulated character devices; image /dev directories are empty.
    Dev(Dev),
    /// Shared like a Linux open file description: dup and fork share the socket and its O_NONBLOCK.
    Socket(Arc<Sock>),
    Epoll(Arc<Mutex<Epoll>>),
    /// eventfd: a counter (Go's netpoller and nginx use it to wake their epoll waits).
    Event(Arc<EventFd>),
}

pub struct EventFd {
    count: Mutex<u64>,
    changed: std::sync::Condvar,
    semaphore: bool,
    nonblock: std::sync::atomic::AtomicBool,
}

impl EventFd {
    pub fn new(init: u64, flags: u64) -> Self {
        const EFD_SEMAPHORE: u64 = 1;
        EventFd {
            count: Mutex::new(init),
            changed: std::sync::Condvar::new(),
            semaphore: flags & EFD_SEMAPHORE != 0,
            nonblock: std::sync::atomic::AtomicBool::new(flags & O_NONBLOCK != 0),
        }
    }

    fn read(&self, buf: u64, len: u64) -> R {
        if len < 8 {
            return Err(EINVAL);
        }
        let mut c = self.count.lock().unwrap();
        while *c == 0 {
            if self.nonblock.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(crate::syscall::EAGAIN);
            }
            if crate::signal::deliverable() {
                return Err(crate::syscall::EINTR);
            }
            // Short timed waits so a signal still interrupts the read.
            c = self.changed.wait_timeout(c, std::time::Duration::from_millis(20)).unwrap().0;
        }
        let v = if self.semaphore { 1 } else { *c };
        *c -= v;
        unsafe { *(buf as *mut u64) = v };
        Ok(8)
    }

    fn write(&self, buf: u64, len: u64) -> R {
        if len < 8 {
            return Err(EINVAL);
        }
        let v = unsafe { *(buf as *const u64) };
        let mut c = self.count.lock().unwrap();
        if v == u64::MAX || *c > u64::MAX - 1 - v {
            return Err(crate::syscall::EAGAIN); // ponytail: a blocking writer would wait; nobody fills it that far
        }
        *c += v;
        self.changed.notify_all();
        Ok(8)
    }

    fn ready(&self, events: i16) -> i16 {
        let readable = *self.count.lock().unwrap() > 0;
        (if readable { events & POLLIN } else { 0 }) | (events & POLLOUT)
    }
}

pub fn eventfd(init: u64, flags: u64) -> R {
    const EFD_CLOEXEC: u64 = 0o2000000;
    Ok(add_fd(Fd::Event(Arc::new(EventFd::new(init, flags))), flags & EFD_CLOEXEC != 0))
}

#[derive(Clone, Copy)]
pub enum Dev {
    Null,
    Zero,
    Random,
}

impl Dev {
    fn of(guest: &str) -> Option<Dev> {
        match guest {
            "/dev/null" => Some(Dev::Null),
            "/dev/zero" => Some(Dev::Zero),
            "/dev/random" | "/dev/urandom" => Some(Dev::Random),
            _ => None,
        }
    }
    fn tag(self) -> &'static str {
        match self { Dev::Null => "null", Dev::Zero => "zero", Dev::Random => "random" }
    }
    fn stat(self) -> [u64; 18] {
        let mut s = [0u64; 18];
        let minor = match self { Dev::Null => 3, Dev::Zero => 5, Dev::Random => 9 };
        (s[1], s[2], s[3], s[5], s[7]) = (minor, 1, 0o020666, 0x100 | minor, 4096); // char device 1:minor
        s
    }
}

/// `/dev/stdin|stdout|stderr`, `/dev/fd/N`, `/proc/self/fd/N`: opening one dups that fd.
fn fd_alias(guest: &str) -> Option<u64> {
    match guest {
        "/dev/stdin" => Some(0),
        "/dev/stdout" => Some(1),
        "/dev/stderr" => Some(2),
        _ => guest.strip_prefix("/dev/fd/").or_else(|| guest.strip_prefix("/proc/self/fd/"))?.parse().ok(),
    }
}

pub struct Fs {
    /// The image (read-only when `upper` is set).
    root: PathBuf,
    /// The container's writable layer: every change lands here, the image is never modified.
    /// None for a plain `lx <rootfs> cmd`, which writes the rootfs directly.
    upper: Option<PathBuf>,
    cwd: String,
    fds: Vec<Option<Slot>>,
}

// Whiteouts in the upper layer use the OCI layer format, so a container layer is a valid image layer.
const WHITEOUT: &str = ".wh.";
const OPAQUE: &str = ".wh..wh..opq";

fn exists(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok()
}

/// An fd owns its Windows handle (dup duplicates it), so closing the last fd of a pipe end really
/// closes it and the reader sees EOF.
pub struct Slot {
    fd: Fd,
    cloexec: bool,
}
static FS: Mutex<Option<Fs>> = Mutex::new(None);

pub fn init(root: PathBuf) {
    let std = |n: i32| {
        let h = unsafe { crate::win::GetStdHandle(n as u32) };
        let owned = (h != 0 && h != -1).then(|| unsafe { BorrowedHandle::borrow_raw(h as _) }.try_clone_to_owned().ok());
        owned.flatten().map(|h| Slot { fd: Fd::Handle(h), cloexec: false })
    };
    *FS.lock().unwrap() = Some(Fs { root, upper: None, cwd: "/".into(), fds: vec![std(-10), std(-11), std(-12)] });
}

/// Give the container a writable layer on top of the image (call right after init).
pub fn set_upper(upper: PathBuf) {
    with(|fs| fs.upper = Some(upper));
}

/// Write a file into the container (through the writable layer), e.g. /etc/resolv.conf.
pub fn write_guest_file(guest: &str, data: &[u8]) -> Result<(), i64> {
    let host = with(|fs| fs.writable(&split(guest).into_iter().collect::<Vec<_>>(), false))?;
    if read_link(&host).is_some() {
        let _ = fs::remove_file(&host); // replace a symlink, as Docker's bind-mounted files do
    }
    fs::write(host, data).map_err(errno)
}

fn with<T>(f: impl FnOnce(&mut Fs) -> T) -> T {
    f(FS.lock().unwrap().as_mut().expect("fs::init not called"))
}

fn errno(e: io::Error) -> i64 {
    match e.raw_os_error() {
        Some(2 | 3) => ENOENT,
        Some(5) => EACCES,
        Some(32) => EBUSY,
        Some(80 | 183) => EEXIST,
        Some(145) => ENOTEMPTY,
        Some(267) => ENOTDIR,
        Some(123 | 87) => EINVAL,
        _ => EIO,
    }
}

fn split(p: &str) -> VecDeque<String> {
    p.split('/').filter(|s| !s.is_empty()).map(String::from).collect()
}

pub fn read_link(host: &Path) -> Option<String> {
    let m = fs::symlink_metadata(host).ok()?;
    if !m.is_file() || m.len() > 4096 || m.len() < LINK_MAGIC.len() as u64 {
        return None;
    }
    let d = fs::read(host).ok()?;
    d.strip_prefix(LINK_MAGIC).map(|t| String::from_utf8_lossy(t).into_owned())
}

fn write_link(host: &Path, target: &str) -> io::Result<()> {
    fs::write(host, [LINK_MAGIC, target.as_bytes()].concat())
}

fn ino(host: &Path) -> u64 {
    let mut h = DefaultHasher::new();
    host.hash(&mut h);
    h.finish() | 1
}

impl Fs {
    /// Where `comps` lives now: the upper layer if it's there, else the image unless a whiteout or an
    /// opaque directory hides it. A path that exists nowhere maps into the upper layer.
    fn host(&self, comps: &[String]) -> PathBuf {
        let mut lower = self.root.clone();
        lower.extend(comps);
        let Some(up) = &self.upper else { return lower };
        let mut upper = up.clone();
        upper.extend(comps);
        if exists(&upper) || self.hidden(comps) || !exists(&lower) {
            upper
        } else {
            lower
        }
    }

    /// Is the image's copy of `comps` deleted in the upper layer?
    fn hidden(&self, comps: &[String]) -> bool {
        let Some(up) = &self.upper else { return false };
        let mut dir = up.clone();
        for (i, c) in comps.iter().enumerate() {
            if exists(&dir.join(format!("{WHITEOUT}{c}"))) || (i > 0 && exists(&dir.join(OPAQUE))) {
                return true;
            }
            dir.push(c);
        }
        false
    }

    fn in_lower(&self, comps: &[String]) -> bool {
        let mut lower = self.root.clone();
        lower.extend(comps);
        self.upper.is_some() && !self.hidden(comps) && exists(&lower)
    }

    /// The upper-layer path for changing `comps`: parent directories are created in the upper layer, a
    /// whiteout for the name is cleared, and with `copy` an image file is copied up first.
    fn writable(&self, comps: &[String], copy: bool) -> Result<PathBuf, i64> {
        let Some(up) = &self.upper else { return Ok(self.host(comps)) };
        let mut upper = up.clone();
        upper.extend(comps);
        if exists(&upper) {
            return Ok(upper);
        }
        let parent = upper.parent().unwrap_or(up);
        fs::create_dir_all(parent).map_err(errno)?;
        if let Some(name) = comps.last() {
            let _ = fs::remove_file(parent.join(format!("{WHITEOUT}{name}")));
        }
        if copy && self.in_lower(comps) {
            let mut lower = self.root.clone();
            lower.extend(comps);
            copy_up(&lower, &upper).map_err(errno)?;
        }
        Ok(upper)
    }

    /// Delete `comps` from the container: remove the upper copy, and whiteout the image's copy.
    fn remove(&self, comps: &[String], dir: bool) -> Result<(), i64> {
        let lower = self.in_lower(comps);
        if let Some(up) = &self.upper {
            let mut upper = up.clone();
            upper.extend(comps);
            if exists(&upper) {
                if dir { fs::remove_dir_all(&upper) } else { fs::remove_file(&upper) }.map_err(errno)?;
            }
            if lower {
                let parent = upper.parent().unwrap_or(up);
                fs::create_dir_all(parent).map_err(errno)?;
                fs::write(parent.join(format!("{WHITEOUT}{}", comps.last().unwrap())), b"").map_err(errno)?;
            }
            return Ok(());
        }
        let host = self.host(comps);
        if dir { fs::remove_dir(host) } else { fs::remove_file(host) }.map_err(errno)
    }

    /// Directory entries of `comps` across both layers (names, is-dir), whiteouts applied.
    fn list(&self, comps: &[String]) -> Result<Vec<(String, bool)>, i64> {
        let mut out: Vec<(String, bool)> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut hide = std::collections::HashSet::new();
        let mut found = false;
        let mut opaque = false;
        if let Some(up) = &self.upper {
            let mut upper = up.clone();
            upper.extend(comps);
            if let Ok(rd) = fs::read_dir(&upper) {
                found = true;
                for e in rd.flatten() {
                    let name = e.file_name().to_string_lossy().into_owned();
                    if name == OPAQUE {
                        opaque = true;
                    } else if let Some(h) = name.strip_prefix(WHITEOUT) {
                        hide.insert(h.to_string());
                    } else if seen.insert(name.clone()) {
                        out.push((name, e.file_type().is_ok_and(|t| t.is_dir())));
                    }
                }
            }
        }
        if !opaque && (self.upper.is_none() || self.in_lower(comps)) {
            let mut lower = self.root.clone();
            lower.extend(comps);
            if let Ok(rd) = fs::read_dir(&lower) {
                found = true;
                for e in rd.flatten() {
                    let name = e.file_name().to_string_lossy().into_owned();
                    if !hide.contains(&name) && seen.insert(name.clone()) {
                        out.push((name, e.file_type().is_ok_and(|t| t.is_dir())));
                    }
                }
            }
        }
        if found { Ok(out) } else { Err(ENOENT) }
    }

    /// Guest path -> (normalized guest path, host path). Symlinks are followed by us, `..` stops at the
    /// root, and components can't smuggle Windows syntax, so the result is always inside the rootfs.
    /// ponytail: an NTFS reparse point placed inside the rootfs by someone else would still be followed by
    /// Windows; the AppContainer boundary (DESIGN.md §7) covers that.
    pub fn resolve(&self, dir: &str, path: &str, follow: bool) -> Result<(String, PathBuf), i64> {
        if path.is_empty() {
            return Err(ENOENT);
        }
        let mut todo = split(path);
        let mut comps: Vec<String> = if path.starts_with('/') { vec![] } else { split(dir).into() };
        let mut hops = 0;
        while let Some(c) = todo.pop_front() {
            match c.as_str() {
                "." => continue,
                ".." => { comps.pop(); continue }
                _ if c.contains(['\\', ':', '\0']) => return Err(ENOENT),
                // Layer bookkeeping names are ours; the guest can't see or forge whiteouts.
                _ if c.starts_with(WHITEOUT) && self.upper.is_some() => return Err(ENOENT),
                _ => comps.push(c),
            }
            if !todo.is_empty() || follow {
                if let Some(target) = read_link(&self.host(&comps)) {
                    hops += 1;
                    if hops > 40 {
                        return Err(ELOOP);
                    }
                    comps.pop();
                    if target.starts_with('/') {
                        comps.clear();
                    }
                    let mut next = split(&target);
                    next.extend(todo.drain(..));
                    todo = next;
                }
            }
        }
        Ok((format!("/{}", comps.join("/")), self.host(&comps)))
    }

    fn dir_of(&self, dirfd: u64) -> Result<String, i64> {
        if dirfd as i32 == AT_FDCWD as i32 { // int argument: only the low 32 bits count (Go zero-extends)
            return Ok(self.cwd.clone());
        }
        match self.fds.get(dirfd as usize) {
            Some(Some(Slot { fd: Fd::Dir { guest, .. }, .. })) => Ok(guest.clone()),
            Some(Some(_)) => Err(ENOTDIR),
            _ => Err(EBADF),
        }
    }

    fn at(&self, dirfd: u64, path: u64, follow: bool) -> Result<(String, PathBuf), i64> {
        self.resolve(&self.dir_of(dirfd)?, &cstr(path)?, follow)
    }

    fn fd(&mut self, fd: u64) -> Result<&mut Fd, i64> {
        self.fds.get_mut(fd as usize).and_then(|f| f.as_mut()).map(|s| &mut s.fd).ok_or(EBADF)
    }

    fn add(&mut self, fd: Fd, min: usize, cloexec: bool) -> i64 {
        while self.fds.len() <= min {
            self.fds.push(None);
        }
        let i = (min..self.fds.len()).find(|&i| self.fds[i].is_none()).unwrap_or_else(|| {
            self.fds.push(None);
            self.fds.len() - 1
        });
        self.fds[i] = Some(Slot { fd, cloexec });
        i as i64
    }
}

/// Resolve an executable: relative to cwd when it has a slash, else a PATH search like a shell.
/// Returns the guest path and the file contents.
pub fn find_exe(cmd: &str, path_var: &str) -> Result<(String, Vec<u8>), i64> {
    with(|fs| {
        let dirs: Vec<&str> = if cmd.contains('/') { vec![fs.cwd.as_str()] } else { path_var.split(':').collect() };
        let found = dirs.iter().filter_map(|d| fs.resolve(d, cmd, true).ok());
        let mut err = ENOENT;
        for (guest, host) in found {
            match fs::metadata(&host) {
                Ok(m) if m.is_dir() => err = EACCES,
                Ok(_) => return fs::read(&host).map(|b| (guest, b)).map_err(errno),
                Err(_) => {}
            }
        }
        Err(err)
    })
}

// ---- process support: what fork and exec need from the fd table ----

fn handle_any(fd: &Fd) -> Result<isize, i64> {
    match fd {
        Fd::Dir { .. } | Fd::Epoll(_) | Fd::Event(_) => Err(EISDIR),
        Fd::Socket(s) => Ok(s.s as isize), // Winsock sockets are kernel handles and inherit like them
        _ => handle(fd),
    }
}

/// Everything a new lx needs to rebuild this process's view: root, cwd, and the fds. A fork keeps
/// every fd; an exec drops CLOEXEC ones. Handles are passed by value (inherited at the same value).
pub fn proc_state(fork: bool) -> Vec<String> {
    with(|fs| {
        // Only handles the new process keeps may reach it; a leaked pipe end would block EOF forever.
        for s in fs.fds.iter().flatten() {
            if let Ok(h) = handle_any(&s.fd) {
                unsafe { crate::win::SetHandleInformation(h, 1, (fork || !s.cloexec) as u32) };
            }
        }
        let upper = fs.upper.as_ref().map(|u| u.to_string_lossy().into_owned()).unwrap_or_default();
        let mut v = vec![fs.root.to_string_lossy().into_owned(), upper, fs.cwd.clone(), String::new()];
        let mut n = 0;
        for (i, s) in fs.fds.iter().enumerate() {
            let Some(s) = s.as_ref().filter(|s| fork || !s.cloexec) else { continue };
            let (kind, h, path) = match &s.fd {
                Fd::Handle(h) => ("h", h.as_raw_handle() as usize, String::new()),
                Fd::File { f, host } => ("f", f.as_raw_handle() as usize, host.to_string_lossy().into_owned()),
                Fd::Dir { guest, .. } => ("d", 0, guest.clone()),
                Fd::Dev(d) => (d.tag(), 0, String::new()),
                Fd::Socket(k) => ("s", k.s, (k.nonblocking() as u8).to_string()),
                // ponytail: epoll instances aren't carried across fork/exec (servers make one per worker).
                Fd::Epoll(_) => continue,
                // ponytail: an eventfd shared across fork isn't carried either; each process starts without it.
                Fd::Event(_) => continue,
            };
            v.extend([i.to_string(), kind.into(), h.to_string(), path, (s.cloexec as u8).to_string()]);
            n += 1;
        }
        v[3] = n.to_string();
        v
    })
}

/// Rebuild the fd table from `proc_state` fields (in the new lx). Returns the unparsed rest.
pub fn init_from(fields: &[String]) -> Result<&[String], String> {
    let bad = || "malformed process state".to_string();
    let [root, upper, cwd, n, rest @ ..] = fields else { return Err(bad()) };
    let mut fds: Vec<Option<Slot>> = Vec::new();
    let mut rest = rest;
    for _ in 0..n.parse::<usize>().map_err(|_| bad())? {
        let [fd, kind, h, path, cloexec, more @ ..] = rest else { return Err(bad()) };
        let fd: usize = fd.parse().map_err(|_| bad())?;
        let h: usize = h.parse().map_err(|_| bad())?;
        let fd_ = match kind.as_str() {
            "h" => Fd::Handle(unsafe { OwnedHandle::from_raw_handle(h as _) }),
            "f" => Fd::File { f: unsafe { File::from_raw_handle(h as _) }, host: PathBuf::from(path) },
            "d" => Fd::Dir { guest: path.clone(), pos: 0 },
            "null" => Fd::Dev(Dev::Null),
            "zero" => Fd::Dev(Dev::Zero),
            "random" => Fd::Dev(Dev::Random),
            "s" => Fd::Socket(Arc::new(Sock::inherited(h, path == "1"))),
            _ => return Err(bad()),
        };
        while fds.len() <= fd {
            fds.push(None);
        }
        fds[fd] = Some(Slot { fd: fd_, cloexec: cloexec == "1" });
        rest = more;
    }
    let upper = (!upper.is_empty()).then(|| PathBuf::from(upper));
    *FS.lock().unwrap() = Some(Fs { root: PathBuf::from(root), upper, cwd: cwd.clone(), fds });
    Ok(rest)
}

/// Drop every fd (closing the handles). Used by a process that has exec'd and only waits now,
/// so it doesn't hold pipe ends open.
pub fn close_all() {
    // try_lock: after execve stopped the other threads, one of them may have died holding this lock.
    if let Ok(mut g) = FS.try_lock() && let Some(fs) = g.as_mut() {
        fs.fds.clear();
    }
}

pub fn pipe2(fds: u64, flags: u64) -> R {
    let (mut r, mut w) = (0isize, 0isize);
    if unsafe { crate::win::CreatePipe(&mut r, &mut w, std::ptr::null_mut(), 65536) } == 0 {
        return Err(EIO);
    }
    let own = |h: isize| Fd::Handle(unsafe { OwnedHandle::from_raw_handle(h as _) });
    let cloexec = flags & O_CLOEXEC != 0;
    let (a, b) = with(|fs| (fs.add(own(r), 0, cloexec), fs.add(own(w), 0, cloexec)));
    unsafe { *(fds as *mut [i32; 2]) = [a as i32, b as i32] };
    Ok(0)
}

// ---- syscalls ----

fn handle(fd: &Fd) -> Result<isize, i64> {
    match fd {
        Fd::Handle(h) => Ok(h.as_raw_handle() as isize),
        Fd::File { f, .. } => Ok(f.as_raw_handle() as isize),
        Fd::Dir { .. } => Err(EISDIR),
        Fd::Dev(_) | Fd::Socket(_) | Fd::Epoll(_) | Fd::Event(_) => Err(EINVAL),
    }
}

/// What a read/write/poll on an fd talks to. Taken out of the fd table so blocking I/O runs unlocked.
enum Io {
    Handle(isize),
    Dev(Dev),
    Sock(Arc<Sock>),
    Event(Arc<EventFd>),
}

fn io_target(fd: u64) -> Result<Io, i64> {
    with(|fs| match fs.fd(fd)? {
        Fd::Dev(d) => Ok(Io::Dev(*d)),
        Fd::Socket(s) => Ok(Io::Sock(s.clone())),
        Fd::Event(e) => Ok(Io::Event(e.clone())),
        other => handle(other).map(Io::Handle),
    })
}

pub fn read(fd: u64, buf: u64, len: u64) -> R {
    match io_target(fd)? {
        Io::Handle(h) => read_handle(h, buf, len),
        Io::Sock(s) => s.recv(buf, len, 0),
        Io::Event(e) => e.read(buf, len),
        Io::Dev(Dev::Null) => Ok(0),
        Io::Dev(Dev::Zero) => {
            unsafe { guest_mut(buf, len as usize) }.fill(0);
            Ok(len as i64)
        }
        Io::Dev(Dev::Random) => crate::syscall::getrandom(buf, len),
    }
}

pub fn write(fd: u64, buf: u64, len: u64) -> R {
    match io_target(fd)? {
        Io::Handle(h) => write_handle(h, buf, len),
        Io::Sock(s) => s.send(buf, len, 0),
        Io::Dev(_) => Ok(len as i64), // devices swallow writes
        Io::Event(e) => e.write(buf, len),
    }
}

pub fn sock(fd: u64) -> Result<Arc<Sock>, i64> {
    with(|fs| match fs.fd(fd)? {
        Fd::Socket(s) => Ok(s.clone()),
        _ => Err(crate::syscall::ENOTSOCK),
    })
}

pub fn epoll(fd: u64) -> Result<Arc<Mutex<Epoll>>, i64> {
    with(|fs| match fs.fd(fd)? {
        Fd::Epoll(e) => Ok(e.clone()),
        _ => Err(EINVAL),
    })
}

pub fn add_fd(fd: Fd, cloexec: bool) -> i64 {
    with(|fs| fs.add(fd, 0, cloexec))
}

/// The socket behind an fd, if it is one (epoll uses it for an efficient wait).
pub fn socket_of(fd: i32) -> Option<usize> {
    with(|fs| match fs.fd(fd as u64) {
        Ok(Fd::Socket(s)) => Some(s.s),
        _ => None,
    })
}

const POLLIN: i16 = 1;
const POLLOUT: i16 = 4;
const POLLHUP: i16 = 0x10;
const POLLNVAL: i16 = 0x20;

/// Which of `events` (poll bits) are ready on `fd` right now, plus POLLERR/POLLHUP/POLLNVAL.
pub fn readiness(fd: i32, events: i16) -> i16 {
    if fd < 0 {
        return 0;
    }
    match io_target(fd as u64) {
        Err(_) => POLLNVAL,
        Ok(Io::Dev(_)) => events & (POLLIN | POLLOUT),
        Ok(Io::Sock(s)) => s.ready(events),
        Ok(Io::Event(e)) => e.ready(events),
        Ok(Io::Handle(h)) => match unsafe { crate::win::GetFileType(h) } {
            3 => {
                // FILE_TYPE_PIPE. ponytail: write ends always report POLLOUT.
                let mut avail = 0u32;
                let ok = unsafe { crate::win::PeekNamedPipe(h, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut avail, std::ptr::null_mut()) };
                match (ok, avail) {
                    (0, _) => POLLHUP | (events & POLLIN),
                    (_, 0) => events & POLLOUT,
                    _ => events & (POLLIN | POLLOUT),
                }
            }
            2 => {
                // FILE_TYPE_CHAR (console): input is ready when the handle is signaled.
                let r = unsafe { crate::win::WaitForMultipleObjects(1, &h, 0, 0) } == 0;
                (if r { events & POLLIN } else { 0 }) | (events & POLLOUT)
            }
            _ => events & (POLLIN | POLLOUT),
        },
    }
}

/// ioctl: just what works without a tty.
pub fn ioctl(fd: u64, req: u64, arg: u64) -> R {
    const FIONREAD: u64 = 0x541B;
    const FIONBIO: u64 = 0x5421;
    const FIONCLEX: u64 = 0x5450;
    const FIOCLEX: u64 = 0x5451;
    const FIOASYNC: u64 = 0x5452;
    if req == FIOCLEX || req == FIONCLEX {
        return fcntl(fd, 2, (req == FIOCLEX) as u64); // F_SETFD
    }
    match (req, io_target(fd)?) {
        (FIOASYNC, _) => Ok(0), // ponytail: no SIGIO; nginx's channels work without it
        (FIONBIO, Io::Sock(s)) => {
            s.set_nonblocking(unsafe { *(arg as *const i32) } != 0);
            Ok(0)
        }
        (FIONBIO, _) => Ok(0),
        (FIONREAD, Io::Sock(s)) => {
            unsafe { *(arg as *mut i32) = s.available() as i32 };
            Ok(0)
        }
        (FIONREAD, Io::Handle(h)) => {
            let mut avail = 0u32;
            unsafe { crate::win::PeekNamedPipe(h, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut avail, std::ptr::null_mut()) };
            unsafe { *(arg as *mut i32) = avail as i32 };
            Ok(0)
        }
        _ => Err(crate::syscall::ENOTTY), // no terminals yet
    }
}

/// poll/ppoll: pipes are checked with PeekNamedPipe, console input by waiting on it, sockets with
/// WSAPoll, files and devices are always ready. ponytail: re-checks in 1ms steps while nothing is ready.
pub fn poll(fds: u64, n: u64, timeout_ms: i64) -> R {
    if n > 1024 {
        return Err(EINVAL);
    }
    let start = std::time::Instant::now();
    loop {
        let mut ready = 0;
        for i in 0..n {
            let p = (fds + i * 8) as *mut [i16; 4]; // struct pollfd { int fd; short events, revents; }
            let entry = unsafe { &mut *p };
            let fd = (entry[0] as u16 as u32 | (entry[1] as u16 as u32) << 16) as i32;
            let revents = readiness(fd, entry[2]);
            entry[3] = revents;
            if revents != 0 {
                ready += 1;
            }
        }
        let expired = timeout_ms >= 0 && start.elapsed().as_millis() as i64 >= timeout_ms;
        if ready > 0 || expired {
            return Ok(ready);
        }
        if crate::signal::deliverable() {
            return Err(crate::syscall::EINTR);
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// sendfile: from the file position (cat), or from `*off` leaving the position alone and advancing
/// `*off` instead (nginx). ponytail: a bounce buffer, up to 64K per call; TransmitFile would be zero-copy.
pub fn sendfile(out: u64, inp: u64, off: u64, count: u64) -> R {
    let mut buf = vec![0u8; count.min(1 << 16) as usize];
    let n = if off != 0 {
        pread(inp, buf.as_mut_ptr() as u64, buf.len() as u64, unsafe { *(off as *const u64) }, false)?
    } else {
        read(inp, buf.as_mut_ptr() as u64, buf.len() as u64)?
    };
    if n == 0 {
        return Ok(0);
    }
    let sent = write(out, buf.as_ptr() as u64, n as u64)?;
    if off != 0 {
        unsafe { *(off as *mut u64) += sent as u64 };
    } else if sent < n {
        lseek(inp, sent - n, 1)?; // give back what the socket didn't take
    }
    Ok(sent)
}

/// pread64/pwrite64: I/O at an offset without moving the file position. NT's positioned I/O does
/// move it on synchronous handles, so put it back.
pub fn pread(fd: u64, buf: u64, len: u64, off: u64, write: bool) -> R {
    use std::os::windows::fs::FileExt;
    with(|fs| {
        let Fd::File { f, .. } = fs.fd(fd)? else { return Err(ESPIPE) };
        let keep = f.stream_position().map_err(errno)?;
        let len = len.min(u32::MAX as u64) as usize;
        let r = if write {
            f.seek_write(unsafe { std::slice::from_raw_parts(buf as *const u8, len) }, off)
        } else {
            f.seek_read(unsafe { guest_mut(buf, len) }, off)
        };
        f.seek(SeekFrom::Start(keep)).map_err(errno)?;
        match r {
            Ok(n) => Ok(n as i64),
            Err(e) if e.raw_os_error() == Some(38) => Ok(0), // ERROR_HANDLE_EOF: read past the end
            Err(e) => Err(errno(e)),
        }
    })
}

pub fn readv(fd: u64, iov: u64, cnt: u64) -> R {
    if cnt > 1024 {
        return Err(EINVAL);
    }
    let mut total = 0;
    for i in 0..cnt {
        let [base, len] = unsafe { *((iov + i * 16) as *const [u64; 2]) };
        match read(fd, base, len) {
            Ok(n) => {
                total += n;
                if (n as u64) < len { break } // short read: don't block for more
            }
            Err(e) => return if total > 0 { Ok(total) } else { Err(e) },
        }
    }
    Ok(total)
}

pub fn writev(fd: u64, iov: u64, cnt: u64) -> R {
    if cnt > 1024 {
        return Err(EINVAL);
    }
    let mut total = 0;
    for i in 0..cnt {
        // ponytail: the iovec array is read directly; a bad pointer crashes us instead of returning EFAULT.
        let [base, len] = unsafe { *((iov + i * 16) as *const [u64; 2]) };
        match write(fd, base, len) {
            Ok(n) => {
                total += n;
                if (n as u64) < len { break }
            }
            Err(e) => return if total > 0 { Ok(total) } else { Err(e) },
        }
    }
    Ok(total)
}

pub fn openat(dirfd: u64, path: u64, flags: u64) -> R {
    let cloexec = flags & O_CLOEXEC != 0;
    let guest = with(|fs| fs.at(dirfd, path, flags & O_NOFOLLOW == 0))?.0;
    if let Some(n) = fd_alias(&guest) {
        return dup(n, 0, cloexec);
    }
    if guest == "/dev/tty" {
        return Err(crate::syscall::ENXIO); // no controlling terminal, like `docker run` without -t
    }
    with(|fs| {
        if let Some(d) = Dev::of(&guest) {
            return Ok(fs.add(Fd::Dev(d), 0, cloexec));
        }
        let (guest, mut host) = fs.at(dirfd, path, flags & O_NOFOLLOW == 0)?;
        let meta = fs::metadata(&host);
        let acc = flags & 3;
        let changes = acc != 0 || flags & (O_CREAT | O_TRUNC) != 0;
        if changes && !meta.as_ref().is_ok_and(|m| m.is_dir()) {
            // Copy the image's file up unless it's about to be truncated anyway.
            host = fs.writable(&split(&guest).into_iter().collect::<Vec<_>>(), flags & O_TRUNC == 0)?;
        }
        let fd = if meta.as_ref().is_ok_and(|m| m.is_dir()) {
            if acc != 0 { return Err(EISDIR) }
            Fd::Dir { guest, pos: 0 }
        } else {
            if flags & O_DIRECTORY != 0 {
                return Err(if meta.is_ok() { ENOTDIR } else { ENOENT });
            }
            let f = OpenOptions::new()
                .read(acc != 1)
                .write(acc != 0)
                .append(flags & O_APPEND != 0)
                .truncate(flags & O_TRUNC != 0 && acc != 0)
                .create(flags & O_CREAT != 0)
                .create_new(flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL)
                .open(&host)
                .map_err(errno)?;
            Fd::File { f, host }
        };
        Ok(fs.add(fd, 0, cloexec))
    })
}

pub fn close(fd: u64) -> R {
    with(|fs| {
        let slot = fs.fds.get_mut(fd as usize).ok_or(EBADF)?;
        slot.take().map(|_| 0).ok_or(EBADF)
    })
}

fn dup_fd(fd: &Fd) -> Result<Fd, i64> {
    Ok(match fd {
        Fd::Handle(h) => Fd::Handle(h.try_clone().map_err(errno)?),
        Fd::File { f, host } => Fd::File { f: f.try_clone().map_err(errno)?, host: host.clone() },
        Fd::Dir { guest, pos } => Fd::Dir { guest: guest.clone(), pos: *pos },
        Fd::Dev(d) => Fd::Dev(*d),
        Fd::Socket(s) => Fd::Socket(s.clone()),
        Fd::Epoll(e) => Fd::Epoll(e.clone()),
        Fd::Event(e) => Fd::Event(e.clone()),
    })
}

pub fn dup(fd: u64, min: u64, cloexec: bool) -> R {
    with(|fs| {
        let new = dup_fd(fs.fd(fd)?)?;
        Ok(fs.add(new, min as usize, cloexec))
    })
}

pub fn dup3(old: u64, new: u64, flags: u64) -> R {
    with(|fs| {
        if old == new {
            return fs.fd(old).map(|_| new as i64); // dup2(fd, fd) is a no-op
        }
        let d = dup_fd(fs.fd(old)?)?;
        if new > 65535 { return Err(EBADF) }
        while fs.fds.len() <= new as usize {
            fs.fds.push(None);
        }
        fs.fds[new as usize] = Some(Slot { fd: d, cloexec: flags & O_CLOEXEC != 0 });
        Ok(new as i64)
    })
}

pub fn fcntl(fd: u64, cmd: u64, arg: u64) -> R {
    match cmd {
        0 => dup(fd, arg, false),    // F_DUPFD
        1030 => dup(fd, arg, true),  // F_DUPFD_CLOEXEC
        1 | 2 => with(|fs| {
            fs.fd(fd)?;
            let slot = fs.fds[fd as usize].as_mut().unwrap();
            if cmd == 2 {
                slot.cloexec = arg & 1 != 0;
                return Ok(0); // F_SETFD returns 0, not the flags (Python treats anything else as failure)
            }
            Ok(slot.cloexec as i64) // F_GETFD
        }),
        // F_SETFL / F_GETFL: O_NONBLOCK matters for sockets. ponytail: ignored on pipes and files.
        8 => with(|fs| fs.fd(fd).map(|_| 0)), // F_SETOWN: only matters for SIGIO, which we don't send
        4 => with(|fs| match fs.fd(fd)? {
            Fd::Socket(s) => { s.set_nonblocking(arg & O_NONBLOCK != 0); Ok(0) }
            Fd::Event(e) => { e.nonblock.store(arg & O_NONBLOCK != 0, std::sync::atomic::Ordering::Relaxed); Ok(0) }
            _ => Ok(0),
        }),
        3 => with(|fs| match fs.fd(fd)? {
            Fd::Socket(s) if s.nonblocking() => Ok(2 | O_NONBLOCK as i64),
            _ => Ok(2), // O_RDWR
        }),
        _ => Err(EINVAL),
    }
}

pub fn lseek(fd: u64, off: i64, whence: u64) -> R {
    with(|fs| match fs.fd(fd)? {
        Fd::File { f, .. } => {
            let pos = match whence {
                0 => SeekFrom::Start(off as u64),
                1 => SeekFrom::Current(off),
                2 => SeekFrom::End(off),
                _ => return Err(EINVAL),
            };
            f.seek(pos).map(|p| p as i64).map_err(|_| EINVAL)
        }
        Fd::Dir { pos, .. } if off == 0 && whence == 0 => { *pos = 0; Ok(0) }
        Fd::Dir { .. } => Err(EINVAL),
        Fd::Handle(_) | Fd::Socket(_) | Fd::Epoll(_) | Fd::Event(_) => Err(ESPIPE),
        Fd::Dev(_) => Ok(0),
    })
}

/// `struct stat` for x86-64 (144 bytes).
fn stat_of(host: &Path) -> Result<[u64; 18], i64> {
    let m = fs::symlink_metadata(host).map_err(errno)?;
    let link = if m.is_file() { read_link(host) } else { None };
    // ponytail: no stored modes/owners yet, so files are 0755 root:root. Keep real modes in an ADS (DESIGN.md §6).
    let (mode, size, nlink) = match &link {
        _ if m.is_dir() => (0o040755, 4096, 2),
        Some(t) => (0o120777, t.len() as u64, 1),
        None => (0o100755, m.len(), 1),
    };
    let t = m.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).unwrap_or_default();
    let mut s = [0u64; 18];
    s[0] = 0x803;
    s[1] = ino(host);
    s[2] = nlink;
    s[3] = mode;
    s[6] = size;
    s[7] = 4096;
    s[8] = size.div_ceil(512);
    for i in [9, 11, 13] {
        (s[i], s[i + 1]) = (t.as_secs(), t.subsec_nanos() as u64);
    }
    Ok(s)
}

fn put_stat(buf: u64, s: [u64; 18]) -> R {
    unsafe { *(buf as *mut [u64; 18]) = s };
    Ok(0)
}

pub fn fstat(fd: u64, buf: u64) -> R {
    let s = with(|fs| match fs.fd(fd)? {
        Fd::File { host, .. } => stat_of(host),
        Fd::Dir { guest, .. } => {
            let guest = guest.clone();
            stat_of(&fs.resolve("/", &guest, true)?.1)
        }
        Fd::Handle(h) => {
            let mut s = [0u64; 18];
            let pipe = unsafe { crate::win::GetFileType(h.as_raw_handle() as isize) } == 3; // FILE_TYPE_PIPE
            let mode = if pipe { 0o010600 } else { 0o020620 }; // fifo, or a character device like a tty
            (s[1], s[2], s[3], s[7]) = (h.as_raw_handle() as u64, 1, mode, 4096);
            Ok(s)
        }
        Fd::Dev(d) => Ok(d.stat()),
        Fd::Socket(k) => {
            let mut s = [0u64; 18];
            (s[1], s[2], s[3], s[7]) = (k.s as u64, 1, 0o140777, 4096); // S_IFSOCK
            Ok(s)
        }
        Fd::Epoll(_) | Fd::Event(_) => {
            let mut s = [0u64; 18];
            (s[2], s[3], s[7]) = (1, 0o600, 4096); // anon inode
            Ok(s)
        }
    })?;
    put_stat(buf, s)
}

pub fn fstatat(dirfd: u64, path: u64, buf: u64, flags: u64) -> R {
    if flags & AT_EMPTY_PATH != 0 && cstr(path)?.is_empty() {
        return fstat(dirfd, buf);
    }
    let (guest, host) = with(|fs| fs.at(dirfd, path, flags & AT_SYMLINK_NOFOLLOW == 0))?;
    if let Some(d) = Dev::of(&guest) {
        return put_stat(buf, d.stat());
    }
    put_stat(buf, stat_of(&host)?)
}


pub fn faccessat(dirfd: u64, path: u64) -> R {
    let (guest, host) = with(|fs| fs.at(dirfd, path, true))?;
    if Dev::of(&guest).is_some() || fd_alias(&guest).is_some() {
        return Ok(0);
    }
    fs::symlink_metadata(host).map(|_| 0).map_err(errno)
}

/// The guest path of the running ELF, for /proc/self/exe (ld.so resolves $ORIGIN with it).
static EXE: Mutex<String> = Mutex::new(String::new());

pub fn set_exe(guest: &str) {
    *EXE.lock().unwrap() = guest.to_string();
}

/// The few /proc links programs actually read. ponytail: no /proc filesystem otherwise (DESIGN.md §5).
fn proc_link(guest: &str) -> Option<String> {
    let rest = guest.strip_prefix("/proc/self/").or_else(|| {
        let r = guest.strip_prefix("/proc/")?;
        let (pid, rest) = r.split_once('/')?;
        (pid.parse::<u32>().ok()? == unsafe { crate::win::GetCurrentProcessId() }).then_some(rest)
    })?;
    match rest {
        "exe" => Some(EXE.lock().unwrap().clone()),
        "cwd" => Some(with(|fs| fs.cwd.clone())),
        "root" => Some("/".into()),
        _ => {
            let fd: usize = rest.strip_prefix("fd/")?.parse().ok()?;
            with(|fs| match &fs.fds.get(fd)?.as_ref()?.fd {
                Fd::Dir { guest, .. } => Some(guest.clone()),
                Fd::Dev(d) => Some(format!("/dev/{}", d.tag())),
                Fd::File { host, .. } => {
                    let rel = fs.upper.as_ref().and_then(|u| host.strip_prefix(u).ok()).or_else(|| host.strip_prefix(&fs.root).ok())?;
                    Some(format!("/{}", rel.to_string_lossy().replace('\\', "/")))
                }
                Fd::Handle(_) => Some("pipe:[0]".into()),
                Fd::Socket(k) => Some(format!("socket:[{}]", k.s)),
                Fd::Epoll(_) => Some("anon_inode:[eventpoll]".into()),
                Fd::Event(_) => Some("anon_inode:[eventfd]".into()),
            })
        }
    }
}

pub fn readlinkat(dirfd: u64, path: u64, buf: u64, size: u64) -> R {
    let (guest, host) = with(|fs| fs.at(dirfd, path, false))?;
    let t = proc_link(&guest).or_else(|| read_link(&host)).ok_or(EINVAL)?;
    let n = t.len().min(size as usize);
    unsafe { guest_mut(buf, n) }.copy_from_slice(&t.as_bytes()[..n]);
    Ok(n as i64)
}

fn comps_of(guest: &str) -> Vec<String> {
    split(guest).into_iter().collect()
}

pub fn mkdirat(dirfd: u64, path: u64) -> R {
    with(|fs| {
        let (guest, host) = fs.at(dirfd, path, false)?;
        if exists(&host) {
            return Err(EEXIST);
        }
        let c = comps_of(&guest);
        let was_hidden = fs.upper.is_some() && fs.hidden(&c);
        let up = fs.writable(&c, false)?;
        fs::create_dir(&up).map_err(errno)?;
        if was_hidden {
            // Recreated over a deleted image dir: it must not show the old contents (overlayfs: opaque).
            fs::write(up.join(OPAQUE), b"").map_err(errno)?;
        }
        Ok(0)
    })
}

pub fn unlinkat(dirfd: u64, path: u64, flags: u64) -> R {
    with(|fs| {
        let (guest, host) = fs.at(dirfd, path, false)?;
        let c = comps_of(&guest);
        let is_dir = fs::symlink_metadata(&host).map_err(errno)?.is_dir();
        match (flags & AT_REMOVEDIR != 0, is_dir) {
            (true, true) if !fs.list(&c)?.is_empty() => Err(ENOTEMPTY),
            (true, true) => fs.remove(&c, true).map(|_| 0),
            (true, false) => Err(ENOTDIR),
            (false, true) => Err(EISDIR),
            // ponytail: NT refuses to delete open files; POSIX-delete via FILE_DISPOSITION_POSIX_SEMANTICS later.
            (false, false) => fs.remove(&c, false).map(|_| 0),
        }
    })
}

pub fn renameat(olddir: u64, old: u64, newdir: u64, new: u64) -> R {
    with(|fs| {
        let (from_guest, from) = fs.at(olddir, old, false)?;
        let (to_guest, _) = fs.at(newdir, new, false)?;
        let (fc, tc) = (comps_of(&from_guest), comps_of(&to_guest));
        let is_dir = fs::symlink_metadata(&from).map_err(errno)?.is_dir();
        // Bring the source into the upper layer (whole tree for an image directory), then move it there.
        let src = fs.writable(&fc, true)?;
        let dst = fs.writable(&tc, false)?;
        if exists(&dst) && !is_dir {
            let _ = fs::remove_file(&dst);
        }
        fs::rename(&src, &dst).map_err(errno)?;
        if fs.upper.is_some() && fs.in_lower(&fc) {
            fs.remove(&fc, is_dir)?; // the image's copy must stay hidden at the old name
        }
        Ok(0)
    })
}

pub fn symlinkat(target: u64, dirfd: u64, path: u64) -> R {
    let target = cstr(target)?;
    with(|fs| {
        let (guest, host) = fs.at(dirfd, path, false)?;
        if exists(&host) {
            return Err(EEXIST);
        }
        let up = fs.writable(&comps_of(&guest), false)?;
        write_link(&up, &target).map(|_| 0).map_err(errno)
    })
}

/// truncate(path) / ftruncate(fd).
pub fn truncate(dirfd: u64, path: u64, fd: Option<u64>, len: u64) -> R {
    with(|fs| {
        let f = match fd {
            Some(fd) => match fs.fd(fd)? {
                Fd::File { f, .. } => return f.set_len(len).map(|_| 0).map_err(errno),
                _ => return Err(EINVAL),
            },
            None => {
                let (guest, _) = fs.at(dirfd, path, true)?;
                fs.writable(&comps_of(&guest), true)?
            }
        };
        OpenOptions::new().write(true).open(f).and_then(|f| f.set_len(len)).map(|_| 0).map_err(errno)
    })
}

pub fn getcwd(buf: u64, size: u64) -> R {
    with(|fs| {
        let n = fs.cwd.len() + 1;
        if (size as usize) < n { return Err(ERANGE) }
        let out = unsafe { guest_mut(buf, n) };
        out[..n - 1].copy_from_slice(fs.cwd.as_bytes());
        out[n - 1] = 0;
        Ok(n as i64)
    })
}

/// Set the starting directory (an image's WorkingDir). It must exist in the rootfs.
pub fn set_cwd(dir: &str) -> Result<(), i64> {
    with(|fs| {
        let (guest, host) = fs.resolve("/", dir, true)?;
        if !fs::metadata(&host).map_err(errno)?.is_dir() {
            return Err(ENOTDIR);
        }
        fs.cwd = guest;
        Ok(())
    })
}

pub fn chdir(path: u64) -> R {
    with(|fs| {
        let (guest, host) = fs.at(AT_FDCWD, path, true)?;
        if !fs::metadata(&host).map_err(errno)?.is_dir() { return Err(ENOTDIR) }
        fs.cwd = guest;
        Ok(0)
    })
}

pub fn fchdir(fd: u64) -> R {
    with(|fs| {
        let dir = fs.dir_of(fd)?;
        fs.cwd = dir;
        Ok(0)
    })
}

/// linux_dirent64 records: u64 ino, i64 off, u16 reclen, u8 type, name, NUL, padded to 8.
pub fn getdents64(fd: u64, buf: u64, count: u64) -> R {
    with(|fs| {
        let Fd::Dir { guest, pos } = fs.fd(fd)? else { return Err(ENOTDIR) };
        let (guest, start) = (guest.clone(), *pos);
        let (guest, host) = fs.resolve("/", &guest, true)?;
        let mut names: Vec<(String, u8)> = vec![(".".into(), 4), ("..".into(), 4)];
        for (name, dir) in fs.list(&comps_of(&guest))? {
            names.push((name, if dir { 4 } else { 0 })); // DT_DIR / DT_UNKNOWN
        }
        let out = unsafe { guest_mut(buf, count as usize) };
        let (mut n, mut i) = (0, start);
        while let Some((name, dt)) = names.get(i) {
            let rec = (19 + name.len() + 1).next_multiple_of(8);
            if n + rec > out.len() { break }
            let r = &mut out[n..n + rec];
            r.fill(0);
            r[0..8].copy_from_slice(&ino(&host.join(name)).to_le_bytes());
            r[8..16].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            r[16..18].copy_from_slice(&(rec as u16).to_le_bytes());
            r[18] = *dt;
            r[19..19 + name.len()].copy_from_slice(name.as_bytes());
            n += rec;
            i += 1;
        }
        if n == 0 && i < names.len() { return Err(EINVAL) }
        if let Fd::Dir { pos, .. } = fs.fd(fd)? { *pos = i }
        Ok(n as i64)
    })
}

/// Copy file bytes into guest memory for a file-backed mmap. Returns bytes read.
pub fn read_at(fd: u64, dst: &mut [u8], off: u64) -> R {
    with(|fs| {
        let Fd::File { f, .. } = fs.fd(fd)? else { return Err(EBADF) };
        let keep = f.stream_position().map_err(errno)?;
        f.seek(SeekFrom::Start(off)).map_err(errno)?;
        let mut n = 0;
        while n < dst.len() {
            match f.read(&mut dst[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(e) => return Err(errno(e)),
            }
        }
        f.seek(SeekFrom::Start(keep)).map_err(errno)?;
        Ok(n as i64)
    })
}

// ---- image layers ----

/// Unpack an OCI/Docker layer (tar, gzipped or not) into `dest`, on top of earlier layers.
/// Entry paths are untrusted: absolute paths and `..` are rejected, never joined. Our symlinks are plain
/// marker files on the host, so an entry can't be written "through" a symlink either.
/// Whiteouts: `.wh.NAME` deletes NAME from lower layers, `.wh..wh..opq` empties its directory.
pub fn unpack(layer: &Path, dest: &Path) -> Result<(u32, u32), String> {
    let mut f = io::BufReader::new(File::open(layer).map_err(|e| format!("{}: {e}", layer.display()))?);
    let gz = io::BufRead::fill_buf(&mut f).map_err(|e| e.to_string())?.starts_with(&[0x1f, 0x8b]);
    let input: Box<dyn Read> = if gz { Box::new(flate2::read::GzDecoder::new(f)) } else { Box::new(f) };
    let mut ar = tar::Archive::new(input);
    fs::create_dir_all(dest).map_err(|e| e.to_string())?;
    let (mut done, mut skipped) = (0, 0);
    let clean = |p: &Path| -> Option<PathBuf> {
        let mut out = PathBuf::new();
        for c in p.components() {
            match c {
                Component::Normal(n) if !n.to_string_lossy().contains([':', '\\']) => out.push(n),
                Component::CurDir | Component::RootDir => {}
                _ => return None,
            }
        }
        Some(out)
    };
    for e in ar.entries().map_err(|e| e.to_string())? {
        let mut e = e.map_err(|e| e.to_string())?;
        let path = e.path().map_err(|e| e.to_string())?.into_owned();
        let Some(rel) = clean(&path).filter(|r| !r.as_os_str().is_empty()) else { skipped += 1; continue };
        let host = dest.join(&rel);
        if let Some(p) = host.parent() {
            fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        let name = rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if let Some(target) = name.strip_prefix(".wh.") {
            let dir = host.parent().unwrap_or(dest);
            if target == ".wh..opq" {
                for e in fs::read_dir(dir).into_iter().flatten().flatten() {
                    remove_any(&e.path());
                }
            } else {
                remove_any(&dir.join(target));
            }
            done += 1;
            continue;
        }
        let ty = e.header().entry_type();
        // A later layer may replace a path with a different kind of entry.
        if let Ok(m) = fs::symlink_metadata(&host) {
            if !(ty.is_dir() && m.is_dir()) {
                remove_any(&host);
            }
        }
        let r = if ty.is_dir() {
            fs::create_dir_all(&host)
        } else if ty.is_symlink() {
            let t = e.link_name().ok().flatten().map(|t| t.to_string_lossy().into_owned()).unwrap_or_default();
            write_link(&host, &t)
        } else if ty.is_hard_link() {
            match e.link_name().ok().flatten().and_then(|t| clean(&t)) {
                Some(t) => fs::copy(dest.join(t), &host).map(|_| ()),
                None => { skipped += 1; continue }
            }
        } else if ty.is_file() {
            File::create(&host).and_then(|mut out| io::copy(&mut e, &mut out)).map(|_| ())
        } else {
            skipped += 1; // device nodes, fifos
            continue;
        };
        match r {
            Ok(()) => done += 1,
            Err(err) => { eprintln!("[lx] unpack {}: {err}", path.display()); skipped += 1 }
        }
    }
    Ok((done, skipped))
}

/// Copy an image entry into the upper layer: a file, a symlink marker, or a whole directory tree.
fn copy_up(from: &Path, to: &Path) -> io::Result<()> {
    if fs::symlink_metadata(from)?.is_dir() {
        fs::create_dir_all(to)?;
        for e in fs::read_dir(from)? {
            let e = e?;
            copy_up(&e.path(), &to.join(e.file_name()))?;
        }
        Ok(())
    } else {
        fs::copy(from, to).map(|_| ())
    }
}

fn remove_any(p: &Path) {
    let _ = if p.is_dir() { fs::remove_dir_all(p) } else { fs::remove_file(p) };
}

#[test]
fn resolve_stays_inside_rootfs() {
    let root = std::env::temp_dir().join(format!("lx-test-{}", std::process::id()));
    fs::create_dir_all(root.join("bin")).unwrap();
    write_link(&root.join("bin/sh"), "busybox").unwrap();
    write_link(&root.join("up"), "../../../..").unwrap();
    write_link(&root.join("loop"), "loop").unwrap();
    let fs_ = Fs { root: root.clone(), upper: None, cwd: "/".into(), fds: vec![] };
    let r = |p: &str| fs_.resolve("/bin", p, true).map(|x| x.0);
    assert_eq!(r("sh"), Ok("/bin/busybox".into()));
    assert_eq!(r("/up/etc/passwd"), Ok("/etc/passwd".into()));
    assert_eq!(r("../../../x"), Ok("/x".into()));
    assert_eq!(r("/loop"), Err(ELOOP));
    assert_eq!(r("..\\..\\x"), Err(ENOENT));
    assert_eq!(fs_.resolve("/", "/bin/sh", false).unwrap().0, "/bin/sh");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn layer_never_touches_the_image() {
    let base = std::env::temp_dir().join(format!("lx-layer-{}", std::process::id()));
    let (lower, upper) = (base.join("lower"), base.join("upper"));
    fs::create_dir_all(lower.join("etc/conf.d")).unwrap();
    fs::write(lower.join("etc/a.conf"), "image").unwrap();
    fs::write(lower.join("etc/conf.d/x"), "x").unwrap();
    fs::create_dir_all(&upper).unwrap();
    let f = Fs { root: lower.clone(), upper: Some(upper.clone()), cwd: "/".into(), fds: vec![] };
    let c = |p: &str| comps_of(p);
    let names = |p: &str| { let mut v: Vec<String> = f.list(&c(p)).unwrap().into_iter().map(|e| e.0).collect(); v.sort(); v };

    // Reads come from the image; a write copies up and leaves the image alone.
    assert_eq!(f.host(&c("/etc/a.conf")), lower.join("etc/a.conf"));
    let w = f.writable(&c("/etc/a.conf"), true).unwrap();
    fs::write(&w, "container").unwrap();
    assert_eq!(fs::read_to_string(f.host(&c("/etc/a.conf"))).unwrap(), "container");
    assert_eq!(fs::read_to_string(lower.join("etc/a.conf")).unwrap(), "image");

    // New files land in the upper layer; listings merge both layers.
    fs::write(f.writable(&c("/etc/new"), false).unwrap(), "n").unwrap();
    assert_eq!(names("/etc"), ["a.conf", "conf.d", "new"]);
    assert!(!lower.join("etc/new").exists());

    // Deleting an image entry is a whiteout: hidden in the container, still in the image.
    f.remove(&c("/etc/conf.d"), true).unwrap();
    assert!(!exists(&f.host(&c("/etc/conf.d/x"))));
    assert_eq!(names("/etc"), ["a.conf", "new"]);
    assert!(lower.join("etc/conf.d/x").exists());

    // Recreating the deleted directory starts empty (opaque), not with the image's old contents.
    let d = f.writable(&c("/etc/conf.d"), false).unwrap();
    fs::create_dir(&d).unwrap();
    fs::write(d.join(OPAQUE), b"").unwrap();
    assert_eq!(names("/etc/conf.d"), Vec::<String>::new());
    assert!(!exists(&f.host(&c("/etc/conf.d/x"))));

    fs::remove_dir_all(base).unwrap();
}
