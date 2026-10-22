//! The guest's filesystem: path resolution confined to the rootfs, the fd table, file syscalls,
//! and unpacking image layers onto NTFS.
//!
//! Linux symlinks are stored as small marker files (LINK_MAGIC + target) and resolved here, never by
//! Windows: creating NTFS symlinks needs admin/Developer Mode, and resolving ourselves means `..` and
//! absolute targets can't leave the rootfs.
use crate::syscall::{R, cstr, guest_mut, read_handle, write_handle};
use crate::syscall::{EROFS, EBADF, EEXIST, EINVAL, EISDIR, ELOOP, ENOENT, ENOTDIR, ERANGE, ESPIPE, ENOTEMPTY, EACCES, EBUSY, EIO};
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};
use std::time::UNIX_EPOCH;
use crate::net::{Epoll, Sock};

const LINK_MAGIC: &[u8] = b"\0lxlink\0";
/// Marker at a bound AF_UNIX path (the real socket file lives at a short hashed host path, see net.rs).
const SOCK_MAGIC: &[u8] = b"\0lxsock\0";
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
    /// A guest pipe end (pipe2): an overlapped NT named pipe, see `Pipe`.
    Pipe(Arc<Pipe>),
    /// Shared like a Linux open file description: dup and fork share the socket and its O_NONBLOCK.
    Socket(Arc<Sock>),
    Epoll(Arc<Mutex<Epoll>>),
    /// eventfd: a counter (Go's netpoller and nginx use it to wake their epoll waits).
    Event(Arc<EventFd>),
    Signal(Arc<crate::signal::SignalFd>),
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

/// memfd_create(name, flags): an anonymous file, here a scratch file Windows deletes with its last handle,
/// so it reads, writes, truncates and maps (MAP_SHARED included) like any file. PHP and Chromium use it.
/// ponytail: sealing (MFD_ALLOW_SEALING, F_ADD_SEALS) is accepted and not enforced.
pub fn memfd_create(_name: u64, flags: u64) -> R {
    const MFD_CLOEXEC: u64 = 1;
    with(|fs| {
        let (f, host) = scratch_file(fs, b"").map_err(errno)?;
        Ok(fs.add(Fd::File { f, host }, 0, flags & MFD_CLOEXEC != 0))
    })
}

/// signalfd4(fd, mask, sizemask, flags): fd -1 makes a new one, else changes that one's mask.
pub fn signalfd(fd: u64, mask: u64, _size: u64, flags: u64) -> R {
    const SFD_CLOEXEC: u64 = 0o2000000;
    let mask = unsafe { *(mask as *const u64) } & !((1 << 8) | (1 << 18)); // never SIGKILL, SIGSTOP
    if fd as i64 != -1 {
        return with(|fs| match fs.fd(fd)? {
            Fd::Signal(s) => { s.mask.store(mask, std::sync::atomic::Ordering::Relaxed); Ok(fd as i64) }
            _ => Err(EINVAL),
        });
    }
    let s = crate::signal::SignalFd { mask: mask.into(), nonblock: (flags & O_NONBLOCK != 0).into() };
    Ok(add_fd(Fd::Signal(Arc::new(s)), flags & SFD_CLOEXEC != 0))
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

/// A guest pipe end. NT serializes every operation on a synchronous pipe handle, so with CreatePipe a
/// read pending in one process (a forked worker waiting for work) made even PeekNamedPipe/GetFileType
/// from another process wait behind it: poll() hung. Overlapped pipes aren't serialized, so readiness
/// checks never block; reads and writes wait on their own event plus the signal event (EINTR), and
/// O_NONBLOCK works. Shared by dup and fork like an open file description.
pub struct Pipe {
    h: OwnedHandle,
    nonblock: std::sync::atomic::AtomicBool,
}

impl Pipe {
    fn raw(&self) -> isize {
        self.h.as_raw_handle() as isize
    }

    fn nonblocking(&self) -> bool {
        self.nonblock.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn available(&self) -> Option<u32> {
        let mut avail = 0u32;
        let ok = unsafe { crate::win::PeekNamedPipe(self.raw(), std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut avail, std::ptr::null_mut()) };
        (ok != 0).then_some(avail) // None: the other end is gone
    }

    /// One overlapped ReadFile/WriteFile, waited for (or EAGAIN when non-blocking and it would wait).
    fn io(&self, buf: u64, len: u64, write: bool) -> R {
        use crate::win::*;
        const ERROR_IO_PENDING: u32 = 997;
        const ERROR_BROKEN_PIPE: u32 = 109;
        const ERROR_NO_DATA: u32 = 232;
        let len = len.min(u32::MAX as u64) as u32;
        if !write && self.nonblocking() {
            match self.available() {
                Some(0) => return Err(crate::syscall::EAGAIN),
                None => return Ok(0), // EOF
                _ => {}
            }
        }
        let ev = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
        let mut o = Overlapped { internal: [0; 2], offset: 0, offset_high: 0, event: ev };
        let op = (&mut o as *mut Overlapped).cast();
        let mut done = 0u32;
        let ok = unsafe {
            if write { WriteFile(self.raw(), buf as *const u8, len, &mut done, op) } else { ReadFile(self.raw(), buf as *mut u8, len, &mut done, op) }
        };
        let mut err = if ok != 0 { 0 } else { unsafe { GetLastError() } };
        if err == ERROR_IO_PENDING {
            let intr = crate::signal::intr_event();
            let waits = if intr != 0 { vec![ev, intr] } else { vec![ev] };
            loop {
                let r = unsafe { WaitForMultipleObjects(waits.len() as u32, waits.as_ptr(), 0, u32::MAX) };
                if r == 0 || crate::signal::deliverable() {
                    break;
                }
            }
            unsafe {
                if WaitForMultipleObjects(1, &ev, 0, 0) != 0 {
                    CancelIoEx(self.raw(), op); // a signal arrived first
                }
                err = if GetOverlappedResult(self.raw(), op, &mut done, 1) != 0 { 0 } else { GetLastError() };
            }
            if err == 995 && done == 0 {
                unsafe { CloseHandle(ev) };
                return Err(crate::syscall::EINTR); // ERROR_OPERATION_ABORTED
            }
        }
        unsafe { CloseHandle(ev) };
        match err {
            0 | 995 => Ok(done as i64),
            ERROR_BROKEN_PIPE if !write => Ok(0), // EOF
            ERROR_BROKEN_PIPE | ERROR_NO_DATA => Err(crate::syscall::EPIPE),
            e => {
                if crate::syscall::debug() {
                    crate::syscall::dlog(format_args!("pipe {} on handle {:#x} failed: Windows error {e}", if write { "write" } else { "read" }, self.raw()));
                }
                Err(EIO)
            }
        }
    }

    fn ready(&self, events: i16) -> i16 {
        // ponytail: write ends always report POLLOUT (a full pipe makes the write wait instead).
        match self.available() {
            // A write end has no read access, so PeekNamedPipe is denied there: it's writable.
            None if unsafe { crate::win::GetLastError() } == 5 => events & POLLOUT,
            None => POLLHUP | (events & POLLIN),
            Some(0) => events & POLLOUT,
            Some(_) => events & (POLLIN | POLLOUT),
        }
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
    /// Volumes (`lx run -v host:guest`): host folders mounted over guest paths, bypassing the layers.
    mounts: Vec<Mount>,
    cwd: String,
    fds: Vec<Option<Slot>>,
}

pub struct Mount {
    guest: Vec<String>,
    host: PathBuf,
    ro: bool,
}

impl Mount {
    /// A named volume (lx's own folder under rootfs/volumes, made by `lx compose`) keeps Linux modes and
    /// owners like the container layer (postgres wants its data dir 0700, owned by postgres); any other
    /// volume holds the host's own files, whose modes aren't ours to set.
    fn keeps_meta(&self) -> bool {
        static DIR: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
        DIR.get_or_init(|| fs::canonicalize("rootfs/volumes").ok()).as_ref().is_some_and(|d| self.host.starts_with(d))
    }
}

// Whiteouts in the upper layer use the OCI layer format, so a container layer is a valid image layer.
pub const WHITEOUT: &str = ".wh.";
pub const OPAQUE: &str = ".wh..wh..opq";

/// Without opening the file: std's metadata calls open a handle, which costs several times as much
/// (more with a virus scanner looking at every open), and path lookups ask this for every layer.
fn exists(p: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    let w: Vec<u16> = p.as_os_str().encode_wide().chain([0]).collect();
    let attrs = unsafe { crate::win::GetFileAttributesW(w.as_ptr()) };
    attrs != u32::MAX // INVALID_FILE_ATTRIBUTES
}

/// What path lookups and stat need of an entry, read without opening it (see exists()).
#[derive(Clone, Copy)]
pub struct Attrs {
    pub dir: bool,
    pub len: u64,
    /// Last write time, ns since the Unix epoch.
    pub mtime: u64,
}

pub fn attrs(p: &Path) -> Option<Attrs> {
    use std::os::windows::ffi::OsStrExt;
    let w: Vec<u16> = p.as_os_str().encode_wide().chain([0]).collect();
    let mut d = [0u32; 9]; // WIN32_FILE_ATTRIBUTE_DATA: attributes, 3 FILETIMEs, size high, size low
    if unsafe { crate::win::GetFileAttributesExW(w.as_ptr(), 0, &mut d) } == 0 {
        return None;
    }
    let write = (d[6] as u64) << 32 | d[5] as u64; // 100 ns ticks since 1601
    Some(Attrs {
        dir: d[0] & 0x10 != 0, // FILE_ATTRIBUTE_DIRECTORY
        len: (d[7] as u64) << 32 | d[8] as u64,
        mtime: write.saturating_sub(116_444_736_000_000_000).saturating_mul(100),
    })
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
    *FS.lock().unwrap() = Some(Fs { root, upper: None, mounts: Vec::new(), cwd: "/".into(), fds: vec![std(-10), std(-11), std(-12)] });
}

/// Mount host folder `host` (canonical) at guest path `guest`. The mount point is created in the
/// container layer if the image doesn't have it, so it shows up in its parent's listing.
pub fn add_mount(guest: &str, host: PathBuf, ro: bool) -> Result<(), i64> {
    with(|fs| {
        let comps = comps_of(guest);
        if comps.is_empty() {
            return Err(EINVAL); // mounting over / would hide the whole image
        }
        if !exists(&fs.host(&comps)) {
            fs::create_dir_all(fs.writable(&comps, false)?).map_err(errno)?;
        }
        fs.mounts.push(Mount { guest: comps, host, ro });
        fs.mounts.sort_by_key(|m| std::cmp::Reverse(m.guest.len())); // longest prefix wins
        Ok(())
    })
}

/// Give the container a writable layer on top of the image (call right after init).
pub fn set_upper(upper: PathBuf) {
    with(|fs| fs.upper = Some(upper));
}

/// An AF_UNIX socket path as the container sees it: (normalized guest path, does it exist, the
/// container's name for its socket folder: its layer's directory name, so the sockets go with the layer).
pub fn unix_path(path: &str) -> Result<(String, bool, String), i64> {
    with(|fs| {
        let (guest, host) = fs.resolve(&fs.cwd.clone(), path, true)?;
        Ok((guest, exists(&host), container_name(fs)))
    })
}

fn container_name(fs: &Fs) -> String {
    match fs.upper.as_ref().and_then(|u| u.parent()).and_then(|l| l.file_name()) {
        Some(n) => n.to_string_lossy().into_owned(),
        None => format!("root-{:08x}", ino(&fs.root) as u32), // plain `lx <rootfs> cmd`: one per rootfs
    }
}

/// The container's name for abstract AF_UNIX sockets (no path).
pub fn container() -> String {
    with(|fs| container_name(fs))
}

/// Leave the socket marker at a bound AF_UNIX path, so ls/stat show a socket there.
pub fn mark_socket(guest: &str) -> Result<(), i64> {
    write_guest_file(guest, SOCK_MAGIC)
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
        Some(17) => 18, // ERROR_NOT_SAME_DEVICE -> EXDEV: rename across a volume boundary
        Some(123 | 87) => EINVAL,
        // ERROR_OPERATION_ABORTED: a signal's CancelSynchronousIo cut a blocking read/write short.
        // Callers retry EINTR (and the signal is delivered as the syscall returns).
        Some(995) => crate::syscall::EINTR,
        _ => {
            if crate::syscall::debug() {
                crate::syscall::dlog(format_args!("Windows error {e} -> EIO"));
            }
            EIO
        }
    }
}

fn split(p: &str) -> VecDeque<String> {
    p.split('/').filter(|s| !s.is_empty()).map(String::from).collect()
}

pub fn read_link(host: &Path) -> Option<String> {
    link_target(host, &attrs(host)?)
}

/// read_link with the metadata already in hand: only a small file can be a symlink marker, so most
/// entries cost nothing more.
fn link_target(host: &Path, m: &Attrs) -> Option<String> {
    if m.dir || m.len > 4096 || m.len < LINK_MAGIC.len() as u64 {
        return None;
    }
    let stamp = m.mtime ^ m.len.rotate_left(48);
    cached(&LINKS, host, stamp, || {
        let d = fs::read(host).ok()?;
        d.strip_prefix(LINK_MAGIC).map(|t| String::from_utf8_lossy(t).into_owned())
    })
}

/// Facts that cost an open to learn (is this small file a symlink marker, its :lx stream), remembered per
/// (path, mtime): a write to the file or to its stream bumps its LastWriteTime, so a change made by another
/// process misses. The clock behind file times ticks only every 1-15 ms, so our own writes (set_meta,
/// write_link) also forget the path. Each fact costs ~60 us, most of a stat.
/// ponytail: 64k entries, then all forgotten.
type FileFacts<T> = Mutex<Option<HashMap<PathBuf, (u64, T)>>>;
static LINKS: FileFacts<Option<String>> = Mutex::new(None);
static METAS: FileFacts<Option<[u32; 3]>> = Mutex::new(None);

fn forget<T>(facts: &FileFacts<T>, host: &Path) {
    if let Some(m) = facts.lock().unwrap().as_mut() {
        m.remove(host);
    }
}

fn cached<T: Clone>(facts: &FileFacts<T>, host: &Path, stamp: u64, learn: impl FnOnce() -> T) -> T {
    if let Some((s, v)) = facts.lock().unwrap().as_ref().and_then(|m| m.get(host)) && *s == stamp {
        return v.clone();
    }
    let v = learn();
    let mut g = facts.lock().unwrap();
    let m = g.get_or_insert_with(HashMap::new);
    if m.len() >= 1 << 16 {
        m.clear();
    }
    m.insert(host.to_path_buf(), (stamp, v.clone()));
    v
}

fn write_link(host: &Path, target: &str) -> io::Result<()> {
    forget(&LINKS, host);
    fs::write(host, [LINK_MAGIC, target.as_bytes()].concat())
}

fn ino(host: &Path) -> u64 {
    let mut h = DefaultHasher::new();
    host.hash(&mut h);
    h.finish() | 1
}

/// Guest characters NTFS can't store in a name live at U+F000+c on the host (like Cygwin), so
/// `libc6:amd64.list` round-trips. ponytail: trailing dots/spaces aren't encoded.
fn ntfs_bad(c: char) -> bool {
    c < ' ' || ":\\*?\"<>|".contains(c)
}

pub fn enc(name: &str) -> String {
    name.chars().map(|c| if ntfs_bad(c) { char::from_u32(0xF000 + c as u32).unwrap() } else { c }).collect()
}

fn dec(name: &str) -> String {
    let back = |c: char| char::from_u32((c as u32).wrapping_sub(0xF000)).filter(|&o| ntfs_bad(o));
    name.chars().map(|c| back(c).unwrap_or(c)).collect()
}

impl Fs {
    /// Where `comps` lives now: the upper layer if it's there, else the image unless a whiteout or an
    /// opaque directory hides it. A path that exists nowhere maps into the upper layer.
    fn host(&self, comps: &[String]) -> PathBuf {
        self.host_meta(comps).0
    }

    /// host(), plus the metadata of the entry there if it exists: resolve() needs both for every
    /// component, and stat-ing once instead of twice is most of a path lookup's cost.
    fn host_meta(&self, comps: &[String]) -> (PathBuf, Option<Attrs>) {
        if let Some((m, rest)) = self.mount_of(comps) {
            let mut p = m.host.clone();
            p.extend(rest.iter().map(|c| enc(c)));
            let meta = attrs(&p);
            return (p, meta);
        }
        let mut lower = self.root.clone();
        lower.extend(comps.iter().map(|c| enc(c)));
        let Some(up) = &self.upper else {
            let meta = attrs(&lower);
            return (lower, meta);
        };
        let mut upper = up.clone();
        upper.extend(comps.iter().map(|c| enc(c)));
        if let Some(m) = attrs(&upper) {
            return (upper, Some(m));
        }
        if self.hidden(comps) {
            return (upper, None);
        }
        match attrs(&lower) {
            Some(m) => (lower, Some(m)),
            None => (upper, None),
        }
    }

    /// The volume `comps` is in (the innermost one), and the path inside it.
    fn mount_of<'a>(&self, comps: &'a [String]) -> Option<(&Mount, &'a [String])> {
        self.mounts.iter().find(|m| comps.starts_with(&m.guest)).map(|m| (m, &comps[m.guest.len()..]))
    }

    /// Whether `comps` may get Linux modes and owners: anywhere but in a volume of the host's files.
    fn keeps_meta(&self, comps: &[String]) -> bool {
        self.mount_of(comps).is_none_or(|(m, _)| m.keeps_meta())
    }

    /// Is the image's copy of `comps` deleted in the upper layer?
    fn hidden(&self, comps: &[String]) -> bool {
        let Some(up) = &self.upper else { return false };
        let mut dir = up.clone();
        for (i, c) in comps.iter().enumerate() {
            // A directory the upper layer doesn't have holds no whiteouts, nor does anything below it.
            if i > 0 && !exists(&dir) {
                return false;
            }
            if exists(&dir.join(format!("{WHITEOUT}{}", enc(c)))) || (i > 0 && exists(&dir.join(OPAQUE))) {
                return true;
            }
            dir.push(enc(c));
        }
        false
    }

    fn in_lower(&self, comps: &[String]) -> bool {
        if self.mount_of(comps).is_some() {
            return false; // a volume hides what the image had there
        }
        let mut lower = self.root.clone();
        lower.extend(comps.iter().map(|c| enc(c)));
        self.upper.is_some() && !self.hidden(comps) && exists(&lower)
    }

    /// The upper-layer path for changing `comps`: parent directories are created in the upper layer, a
    /// whiteout for the name is cleared, and with `copy` an image file is copied up first.
    fn writable(&self, comps: &[String], copy: bool) -> Result<PathBuf, i64> {
        if let Some((m, _)) = self.mount_of(comps) {
            return if m.ro { Err(EROFS) } else { Ok(self.host(comps)) }; // straight to the host folder
        }
        let Some(up) = &self.upper else { return Ok(self.host(comps)) };
        let mut upper = up.clone();
        upper.extend(comps.iter().map(|c| enc(c)));
        if exists(&upper) {
            return Ok(upper);
        }
        // Ask before clearing the whiteout: a deleted image file must not come back as a copy.
        let copy = copy && self.in_lower(comps);
        let parent = upper.parent().unwrap_or(up);
        if !exists(parent) {
            fs::create_dir_all(parent).map_err(errno)?;
            // Directories made here stand for the image's: give them its modes and owners.
            let (mut u, mut l) = (up.clone(), self.root.clone());
            for name in &comps[..comps.len().saturating_sub(1)] {
                (u.push(enc(name)), l.push(enc(name)));
                if get_meta(&u).is_none() && let Some(m) = get_meta(&l) {
                    let _ = set_meta(&u, m);
                }
            }
        }
        if let Some(name) = comps.last() {
            let _ = fs::remove_file(parent.join(format!("{WHITEOUT}{}", enc(name))));
        }
        if copy {
            let mut lower = self.root.clone();
            lower.extend(comps.iter().map(|c| enc(c)));
            copy_up(&lower, &upper).map_err(errno)?;
        }
        Ok(upper)
    }

    /// Delete `comps` from the container: remove the upper copy, and whiteout the image's copy.
    fn remove(&self, comps: &[String], dir: bool) -> Result<(), i64> {
        if let Some((m, rest)) = self.mount_of(comps) {
            if m.ro {
                return Err(EROFS);
            }
            if rest.is_empty() {
                return Err(EBUSY); // the mount point itself
            }
            let host = self.host(comps);
            return if dir { fs::remove_dir(host) } else { fs::remove_file(host) }.map_err(errno);
        }
        let lower = self.in_lower(comps);
        if let Some(up) = &self.upper {
            let mut upper = up.clone();
            upper.extend(comps.iter().map(|c| enc(c)));
            if exists(&upper) {
                if dir { fs::remove_dir_all(&upper) } else { fs::remove_file(&upper) }.map_err(errno)?;
            }
            if lower {
                let parent = upper.parent().unwrap_or(up);
                fs::create_dir_all(parent).map_err(errno)?;
                fs::write(parent.join(format!("{WHITEOUT}{}", enc(comps.last().unwrap()))), b"").map_err(errno)?;
            }
            return Ok(());
        }
        let host = self.host(comps);
        if dir { fs::remove_dir(host) } else { fs::remove_file(host) }.map_err(errno)
    }

    /// Directory entries of `comps` across both layers (names, is-dir), whiteouts applied.
    fn list(&self, comps: &[String]) -> Result<Vec<(String, bool)>, i64> {
        if self.mount_of(comps).is_some() {
            let rd = fs::read_dir(self.host(comps)).map_err(errno)?;
            return Ok(rd.flatten().map(|e| (dec(&e.file_name().to_string_lossy()), e.file_type().is_ok_and(|t| t.is_dir()))).collect());
        }
        let mut out: Vec<(String, bool)> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut hide = std::collections::HashSet::new();
        let mut found = false;
        let mut opaque = false;
        if let Some(up) = &self.upper {
            let mut upper = up.clone();
            upper.extend(comps.iter().map(|c| enc(c)));
            if let Ok(rd) = fs::read_dir(&upper) {
                found = true;
                for e in rd.flatten() {
                    let name = dec(&e.file_name().to_string_lossy());
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
            lower.extend(comps.iter().map(|c| enc(c)));
            if let Ok(rd) = fs::read_dir(&lower) {
                found = true;
                for e in rd.flatten() {
                    let name = dec(&e.file_name().to_string_lossy());
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
        let mut last: Option<PathBuf> = None; // host(comps), when the loop already worked it out
        while let Some(c) = todo.pop_front() {
            last = None;
            match c.as_str() {
                "." => continue,
                ".." => { comps.pop(); continue }
                _ if c.contains('\0') => return Err(ENOENT), // `:` and `\` are fine: enc() maps them
                // Layer bookkeeping names are ours; the guest can't see or forge whiteouts.
                _ if c.starts_with(WHITEOUT) && self.upper.is_some() => return Err(ENOENT),
                _ => comps.push(c),
            }
            if !todo.is_empty() || follow {
                let (host, meta) = self.host_meta(&comps);
                let target = self.proc_self_link(&comps).or_else(|| meta.and_then(|m| link_target(&host, &m)));
                if let Some(target) = target {
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
                } else {
                    last = Some(host);
                }
            }
        }
        let host = last.unwrap_or_else(|| self.host(&comps));
        Ok((format!("/{}", comps.join("/")), host))
    }

    /// `/proc/{self,<pid>}/{exe,cwd,root}` as symlinks while resolving, so stat and open follow them
    /// (gosu stats /proc/self/exe). Only paths of exactly those three components are looked at.
    fn proc_self_link(&self, comps: &[String]) -> Option<String> {
        let [p, who, what] = comps else { return None };
        if p != "proc" || (who != "self" && who.parse::<u32>().ok()? != crate::proc::pid()) {
            return None;
        }
        match what.as_str() {
            "exe" => Some(EXE.lock().unwrap().clone()),
            "cwd" => Some(self.cwd.clone()),
            "root" => Some("/".into()),
            _ => None,
        }
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
        let path = cstr(path)?;
        // An absolute path ignores dirfd, even an invalid one (mariadb passes -1).
        let dir = if path.starts_with('/') { String::new() } else { self.dir_of(dirfd)? };
        self.resolve(&dir, &path, follow)
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
        Fd::Dir { .. } | Fd::Epoll(_) | Fd::Event(_) | Fd::Signal(_) => Err(EISDIR),
        Fd::Socket(s) => Ok(s.s as isize), // Winsock sockets are kernel handles and inherit like them
        _ => handle(fd),
    }
}

/// Everything a new lx needs to rebuild this process's view: root, cwd, and the fds. A fork keeps
/// every fd; an exec drops CLOEXEC ones. Handles are passed by value (inherited at the same value).
/// The state carries handle values the new process inherits. They're private inheritable duplicates (in
/// the returned list; drop them once the process is spawned), not the fds' own handles: another thread
/// can close an fd between this and CreateProcess (Go closes fds on other threads all the time), and the
/// child would get a value that was never inherited, which something else then reuses. One duplicate
/// per distinct handle, so fds sharing one (dup'd pipes and sockets) still share it over there. The
/// fds' own handles are never inheritable: only what the new process keeps may reach it (a leaked pipe
/// end would block EOF forever).
pub fn proc_state(fork: bool) -> (Vec<String>, Vec<OwnedHandle>) {
    with(|fs| {
        let mut dups: std::collections::HashMap<usize, OwnedHandle> = std::collections::HashMap::new();
        let mut dup = |h: usize| -> usize {
            if let Some(d) = dups.get(&h) {
                return d.as_raw_handle() as usize;
            }
            let me = unsafe { crate::win::GetCurrentProcess() };
            let mut d = 0isize;
            // DUPLICATE_SAME_ACCESS, inheritable. A handle that's gone (closed meanwhile) stays 0: the new
            // process sees an fd it can't use, not someone else's handle.
            if unsafe { crate::win::DuplicateHandle(me, h as isize, me, &mut d, 0, 1, 2) } == 0 {
                return 0;
            }
            dups.insert(h, unsafe { OwnedHandle::from_raw_handle(d as _) });
            d as usize
        };
        for s in fs.fds.iter().flatten() {
            if let Ok(h) = handle_any(&s.fd) {
                unsafe { crate::win::SetHandleInformation(h, 1, 0) };
            }
        }
        let upper = fs.upper.as_ref().map(|u| u.to_string_lossy().into_owned()).unwrap_or_default();
        let mounts: Vec<String> = fs.mounts.iter()
            .map(|m| format!("/{}\x1f{}\x1f{}", m.guest.join("/"), m.host.to_string_lossy(), m.ro as u8)).collect();
        let mut v = vec![fs.root.to_string_lossy().into_owned(), upper, mounts.join("\x1e"), fs.cwd.clone(), String::new()];
        let mut n = 0;
        for (i, s) in fs.fds.iter().enumerate() {
            let Some(s) = s.as_ref().filter(|s| fork || !s.cloexec) else { continue };
            let Some((kind, h, path)) = entry(&s.fd) else { continue };
            let h = if h == 0 { 0 } else { dup(h) };
            v.extend([i.to_string(), kind.into(), h.to_string(), path, (s.cloexec as u8).to_string()]);
            n += 1;
        }
        v[4] = n.to_string();
        (v, dups.into_values().collect())
    })
}

/// How an fd travels to another lx process: (kind, handle, extra), the handle still ours.
fn entry(fd: &Fd) -> Option<(&'static str, usize, String)> {
    Some(match fd {
        Fd::Handle(h) => ("h", h.as_raw_handle() as usize, String::new()),
        Fd::Pipe(p) => ("p", p.raw() as usize, (p.nonblocking() as u8).to_string()),
        Fd::File { f, host } => ("f", f.as_raw_handle() as usize, host.to_string_lossy().into_owned()),
        Fd::Dir { guest, .. } => ("d", 0, guest.clone()),
        Fd::Dev(d) => (d.tag(), 0, String::new()),
        Fd::Socket(k) => ("s", k.s, k.inherit_tag()),
        // ponytail: epoll instances aren't carried across fork/exec (servers make one per worker).
        Fd::Epoll(_) => return None,
        // ponytail: an eventfd shared across fork isn't carried either; each process starts without it.
        Fd::Event(_) | Fd::Signal(_) => return None,
    })
}

/// SCM_RIGHTS, sending side: fd's (kind, handle, extra); the handle stays ours (the caller duplicates it).
pub fn export_fd(fd: u64) -> Result<(&'static str, usize, String), i64> {
    with(|fs| fs.fds.get(fd as usize).and_then(|s| s.as_ref()).ok_or(EBADF).and_then(|s| entry(&s.fd).ok_or(EINVAL)))
}

/// SCM_RIGHTS, receiving side: a new fd for an `export_fd` record whose handle is now ours.
pub fn import_fd(kind: &str, h: usize, extra: &str, cloexec: bool) -> R {
    let fd = match kind {
        "h" => Fd::Handle(unsafe { OwnedHandle::from_raw_handle(h as _) }),
        "p" => Fd::Pipe(Arc::new(Pipe { h: unsafe { OwnedHandle::from_raw_handle(h as _) }, nonblock: (extra == "1").into() })),
        "f" => Fd::File { f: unsafe { File::from_raw_handle(h as _) }, host: PathBuf::from(extra) },
        "d" => Fd::Dir { guest: extra.to_string(), pos: 0 },
        "null" => Fd::Dev(Dev::Null),
        "zero" => Fd::Dev(Dev::Zero),
        "random" => Fd::Dev(Dev::Random),
        "s" => Fd::Socket(Arc::new(Sock::inherited(h, extra))),
        _ => return Err(EINVAL),
    };
    Ok(add_fd(fd, cloexec))
}

/// Rebuild the fd table from `proc_state` fields (in the new lx). Returns the unparsed rest.
pub fn init_from(fields: &[String]) -> Result<&[String], String> {
    let bad = || "malformed process state".to_string();
    let [root, upper, mounts, cwd, n, rest @ ..] = fields else { return Err(bad()) };
    let mounts = mounts.split('\x1e').filter(|m| !m.is_empty()).map(|m| {
        let f: Vec<&str> = m.split('\x1f').collect();
        match f.as_slice() {
            [g, h, ro] => Ok(Mount { guest: comps_of(g), host: PathBuf::from(h), ro: *ro == "1" }),
            _ => Err(bad()),
        }
    }).collect::<Result<Vec<_>, _>>()?;
    let mut fds: Vec<Option<Slot>> = Vec::new();
    let mut rest = rest;
    // dup'd fds arrive with the same handle: they must share it again, or closing one closes the
    // handle under the others (erl_child_setup closes its pair end's dup, killing the connection).
    // Pipes and sockets share their Arc; files and plain handles get a duplicate handle each.
    let mut pipes: std::collections::HashMap<usize, Arc<Pipe>> = Default::default();
    let mut socks: std::collections::HashMap<usize, Arc<Sock>> = Default::default();
    let mut seen = std::collections::HashSet::new();
    let own = |h: usize, seen: &mut std::collections::HashSet<usize>| -> usize {
        if seen.insert(h) {
            return h;
        }
        use crate::win::*;
        let mut d = 0isize;
        unsafe { DuplicateHandle(GetCurrentProcess(), h as isize, GetCurrentProcess(), &mut d, 0, 0, 2) }; // SAME_ACCESS
        d as usize
    };
    for _ in 0..n.parse::<usize>().map_err(|_| bad())? {
        let [fd, kind, h, path, cloexec, more @ ..] = rest else { return Err(bad()) };
        let fd: usize = fd.parse().map_err(|_| bad())?;
        let h: usize = h.parse().map_err(|_| bad())?;
        let fd_ = match kind.as_str() {
            "h" => Fd::Handle(unsafe { OwnedHandle::from_raw_handle(own(h, &mut seen) as _) }),
            "p" => Fd::Pipe(pipes.entry(h).or_insert_with(|| {
                Arc::new(Pipe { h: unsafe { OwnedHandle::from_raw_handle(h as _) }, nonblock: (path == "1").into() })
            }).clone()),
            "f" => Fd::File { f: unsafe { File::from_raw_handle(own(h, &mut seen) as _) }, host: PathBuf::from(path) },
            "d" => Fd::Dir { guest: path.clone(), pos: 0 },
            "null" => Fd::Dev(Dev::Null),
            "zero" => Fd::Dev(Dev::Zero),
            "random" => Fd::Dev(Dev::Random),
            "s" => Fd::Socket(socks.entry(h).or_insert_with(|| Arc::new(Sock::inherited(h, path))).clone()),
            _ => return Err(bad()),
        };
        while fds.len() <= fd {
            fds.push(None);
        }
        fds[fd] = Some(Slot { fd: fd_, cloexec: cloexec == "1" });
        rest = more;
    }
    let upper = (!upper.is_empty()).then(|| PathBuf::from(upper));
    *FS.lock().unwrap() = Some(Fs { root: PathBuf::from(root), upper, mounts, cwd: cwd.clone(), fds });
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
    use crate::win::*;
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    const PIPE_ACCESS_INBOUND: u32 = 0x1;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const OPEN_EXISTING: u32 = 3;
    // An anonymous pipe with overlapped ends: a uniquely named pipe, used by name only for this open.
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name: Vec<u16> = format!("\\\\.\\pipe\\lx-{}-{n}", unsafe { GetCurrentProcessId() }).encode_utf16().chain([0]).collect();
    let r = unsafe {
        CreateNamedPipeW(name.as_ptr(), PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            0, 1, 65536, 65536, 0, std::ptr::null_mut()) // PIPE_TYPE_BYTE | PIPE_WAIT, one instance
    };
    if r == -1 {
        return Err(EIO);
    }
    let w = unsafe { CreateFileW(name.as_ptr(), GENERIC_WRITE, 0, std::ptr::null_mut(), OPEN_EXISTING, FILE_FLAG_OVERLAPPED, 0) };
    if w == -1 {
        unsafe { CloseHandle(r) };
        return Err(EIO);
    }
    let nonblock = flags & O_NONBLOCK != 0;
    let own = |h: isize| Fd::Pipe(Arc::new(Pipe { h: unsafe { OwnedHandle::from_raw_handle(h as _) }, nonblock: nonblock.into() }));
    let cloexec = flags & O_CLOEXEC != 0;
    let (a, b) = with(|fs| (fs.add(own(r), 0, cloexec), fs.add(own(w), 0, cloexec)));
    unsafe { *(fds as *mut [i32; 2]) = [a as i32, b as i32] };
    Ok(0)
}

// ---- syscalls ----

fn handle(fd: &Fd) -> Result<isize, i64> {
    match fd {
        Fd::Handle(h) => Ok(h.as_raw_handle() as isize),
        Fd::Pipe(p) => Ok(p.raw()),
        Fd::File { f, .. } => Ok(f.as_raw_handle() as isize),
        Fd::Dir { .. } => Err(EISDIR),
        Fd::Dev(_) | Fd::Socket(_) | Fd::Epoll(_) | Fd::Event(_) | Fd::Signal(_) => Err(EINVAL),
    }
}

/// What a read/write/poll on an fd talks to. Taken out of the fd table so blocking I/O runs unlocked.
enum Io {
    Handle(isize),
    Pipe(Arc<Pipe>),
    Dev(Dev),
    Sock(Arc<Sock>),
    Event(Arc<EventFd>),
    Signal(Arc<crate::signal::SignalFd>),
}

fn io_target(fd: u64) -> Result<Io, i64> {
    with(|fs| match fs.fd(fd)? {
        Fd::Dev(d) => Ok(Io::Dev(*d)),
        Fd::Socket(s) => Ok(Io::Sock(s.clone())),
        Fd::Event(e) => Ok(Io::Event(e.clone())),
        Fd::Signal(s) => Ok(Io::Signal(s.clone())),
        Fd::Pipe(p) => Ok(Io::Pipe(p.clone())),
        other => handle(other).map(Io::Handle),
    })
}

pub fn read(fd: u64, buf: u64, len: u64) -> R {
    match io_target(fd)? {
        Io::Handle(h) => read_handle(h, buf, len),
        Io::Pipe(p) => p.io(buf, len, false),
        Io::Sock(s) => s.recv(buf, len, 0),
        Io::Event(e) => e.read(buf, len),
        Io::Signal(s) => s.read(buf, len),
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
        Io::Pipe(p) => p.io(buf, len, true),
        Io::Sock(s) => s.send(buf, len, 0),
        Io::Dev(_) => Ok(len as i64), // devices swallow writes
        Io::Event(e) => e.write(buf, len),
        Io::Signal(_) => Err(EINVAL),
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
        Ok(Io::Signal(s)) => s.ready(events),
        Ok(Io::Pipe(p)) => p.ready(events),
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
        (FIONREAD, Io::Pipe(p)) => {
            unsafe { *(arg as *mut i32) = p.available().unwrap_or(0) as i32 };
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

/// select / pselect6 on top of poll: fd_sets (bit arrays of u64) in, pollfds through `poll`, fd_sets out.
/// Returns the number of set bits, like Linux.
pub fn select(n: u64, rd: u64, wr: u64, ex: u64, timeout_ms: i64) -> R {
    const POLLPRI: i16 = 2;
    const POLLERR: i16 = 8;
    if n > 1024 {
        return Err(EINVAL);
    }
    let bit = |set: u64, fd: u64| set != 0 && (unsafe { *((set + fd / 64 * 8) as *const u64) } >> (fd % 64)) & 1 != 0;
    let (mut fds, mut pfds) = (Vec::new(), Vec::<[i16; 4]>::new()); // struct pollfd { int fd; short events, revents }
    for fd in 0..n {
        let ev = if bit(rd, fd) { POLLIN } else { 0 } | if bit(wr, fd) { POLLOUT } else { 0 } | if bit(ex, fd) { POLLPRI } else { 0 };
        if ev != 0 {
            fds.push(fd);
            pfds.push([fd as i16, (fd >> 16) as i16, ev, 0]);
        }
    }
    poll(pfds.as_mut_ptr() as u64, pfds.len() as u64, timeout_ms)?;
    for set in [rd, wr, ex].into_iter().filter(|&s| s != 0) {
        unsafe { std::ptr::write_bytes(set as *mut u64, 0, n.div_ceil(64) as usize) };
    }
    let mut count = 0;
    let mut mark = |set: u64, fd: u64| {
        unsafe { *((set + fd / 64 * 8) as *mut u64) |= 1 << (fd % 64) };
        count += 1;
    };
    for (fd, p) in fds.into_iter().zip(&pfds) {
        let r = p[3];
        if r & POLLNVAL != 0 {
            return Err(EBADF);
        }
        if rd != 0 && p[2] & POLLIN != 0 && r & (POLLIN | POLLHUP | POLLERR) != 0 { mark(rd, fd) }
        if wr != 0 && p[2] & POLLOUT != 0 && r & (POLLOUT | POLLERR) != 0 { mark(wr, fd) }
        if ex != 0 && p[2] & POLLPRI != 0 && r & POLLPRI != 0 { mark(ex, fd) }
    }
    Ok(count)
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

/// preadv/pwritev (and the -v2 forms, flags ignored): readv/writev at `off`, or at the file position
/// when `off` is -1 (only the -v2 forms allow that).
pub fn preadv(fd: u64, iov: u64, cnt: u64, off: u64, write: bool) -> R {
    if off == u64::MAX {
        return if write { writev(fd, iov, cnt) } else { readv(fd, iov, cnt) };
    }
    if cnt > 1024 {
        return Err(EINVAL);
    }
    let mut total = 0;
    for i in 0..cnt {
        let [base, len] = unsafe { *((iov + i * 16) as *const [u64; 2]) };
        match pread(fd, base, len, off + total as u64, write) {
            Ok(n) => {
                total += n;
                if (n as u64) < len { break }
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

/// A file holding `bytes` that Windows deletes when its last handle closes (forks inherit the handle):
/// how synthetic /proc files become ordinary fds that read, seek, fstat and mmap.
fn scratch_file(fs: &Fs, bytes: &[u8]) -> io::Result<(File, PathBuf)> {
    use std::io::Write;
    use std::os::windows::fs::OpenOptionsExt;
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = fs.upper.as_ref().and_then(|u| u.parent()).map(Path::to_path_buf).unwrap_or_else(std::env::temp_dir);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let host = dir.join(format!("proc-{}-{n}", unsafe { crate::win::GetCurrentProcessId() }));
    const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
    const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x100;
    let mut f = OpenOptions::new().read(true).write(true).create_new(true)
        .custom_flags(FILE_FLAG_DELETE_ON_CLOSE).attributes(FILE_ATTRIBUTE_TEMPORARY).open(&host)?;
    f.write_all(bytes)?;
    f.rewind()?;
    Ok((f, host))
}

pub fn openat(dirfd: u64, path: u64, flags: u64, mode: u64) -> R {
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
        if let Some(text) = crate::procfs::file(&guest) {
            if flags & 3 != 0 { return Err(EACCES) } // ponytail: /proc/sys is read-only here
            let (f, host) = scratch_file(fs, text.as_bytes()).map_err(errno)?;
            return Ok(fs.add(Fd::File { f, host }, 0, cloexec));
        }
        let (guest, mut host) = fs.at(dirfd, path, flags & O_NOFOLLOW == 0)?;
        if proc_dir(&guest).is_some() {
            if flags & 3 != 0 { return Err(EISDIR) }
            return Ok(fs.add(Fd::Dir { guest, pos: 0 }, 0, cloexec));
        }
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
            let excl = flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL;
            if acc == 0 && flags & O_CREAT != 0 {
                // O_RDONLY|O_CREAT is fine on Linux (Go's telemetry token); std only creates with write
                // access, so create it first, then open it read-only below.
                OpenOptions::new().write(true).create(true).create_new(excl).open(&host).map_err(errno)?;
            }
            let f = OpenOptions::new()
                .read(acc != 1)
                .write(acc != 0)
                .append(flags & O_APPEND != 0)
                .truncate(flags & O_TRUNC != 0 && acc != 0)
                .create(flags & O_CREAT != 0 && acc != 0)
                .create_new(excl && acc != 0)
                .open(&host)
                .map_err(errno)?;
            if flags & O_CREAT != 0 && meta.is_err() && fs.keeps_meta(&comps_of(&guest)) {
                let _ = set_meta(&host, new_meta(mode));
            }
            Fd::File { f, host }
        };
        Ok(fs.add(fd, 0, cloexec))
    })
}

/// close_range(first, last, flags): close every fd in the range, or with CLOSE_RANGE_CLOEXEC just mark them.
pub fn close_range(first: u64, last: u64, flags: u64) -> R {
    const CLOSE_RANGE_CLOEXEC: u64 = 4;
    if first > last {
        return Err(EINVAL); // an empty range is an error, not "close `first`" (Python passes these)
    }
    with(|fs| {
        let Some(top) = fs.fds.len().checked_sub(1) else { return Ok(0) };
        for i in first as usize..=last.min(top as u64) as usize { // empty when first is past the last fd
            if flags & CLOSE_RANGE_CLOEXEC != 0 {
                if let Some(s) = fs.fds[i].as_mut() {
                    s.cloexec = true;
                }
            } else {
                fs.fds[i] = None;
            }
        }
        Ok(0)
    })
}

/// link/linkat. In the upper layer or a volume this is a real NTFS hard link; a file that only exists
/// in the image is copied up first (the image must not gain links into a container).
pub fn linkat(olddir: u64, old: u64, newdir: u64, new: u64, flags: u64) -> R {
    const AT_SYMLINK_FOLLOW: u64 = 0x400;
    with(|fs| {
        let (og, oh) = fs.at(olddir, old, flags & AT_SYMLINK_FOLLOW != 0)?;
        let (ng, nh) = fs.at(newdir, new, false)?;
        if fs::symlink_metadata(&oh).map_err(errno)?.is_dir() {
            return Err(crate::syscall::EPERM);
        }
        if exists(&nh) {
            return Err(EEXIST);
        }
        let src = fs.writable(&comps_of(&og), true)?;
        let dst = fs.writable(&comps_of(&ng), false)?;
        fs::hard_link(&src, &dst).or_else(|_| fs::copy(&src, &dst).map(|_| ())).map(|_| 0).map_err(errno)
    })
}

/// utimensat / futimens: set access and modification times (timespec pairs; UTIME_NOW / UTIME_OMIT).
pub fn utimensat(dirfd: u64, path: u64, times: u64, flags: u64) -> R {
    const UTIME_NOW: u64 = (1 << 30) - 1;
    const UTIME_OMIT: u64 = (1 << 30) - 2;
    let when = |i: u64| -> Option<std::time::SystemTime> {
        let [s, ns] = if times == 0 { [0, UTIME_NOW] } else { unsafe { *((times + i * 16) as *const [u64; 2]) } };
        match ns {
            UTIME_OMIT => None,
            UTIME_NOW => Some(std::time::SystemTime::now()),
            _ => Some(UNIX_EPOCH + std::time::Duration::new(s, ns as u32)),
        }
    };
    let mut t = fs::FileTimes::new();
    if let Some(a) = when(0) { t = t.set_accessed(a) }
    if let Some(m) = when(1) { t = t.set_modified(m) }
    with(|fs| {
        if path == 0 {
            // futimens(fd)
            return match fs.fd(dirfd)? {
                Fd::File { f, .. } => f.set_times(t).map(|_| 0).map_err(errno),
                _ => Ok(0),
            };
        }
        let (guest, host) = fs.at(dirfd, path, flags & AT_SYMLINK_NOFOLLOW == 0)?;
        if fs::metadata(&host).map_err(errno)?.is_dir() {
            return Ok(0); // ponytail: directory times aren't settable through std; nothing relies on them
        }
        let target = fs.writable(&comps_of(&guest), true)?;
        OpenOptions::new().write(true).open(target).and_then(|f| f.set_times(t)).map(|_| 0).map_err(errno)
    })
}

/// statfs/fstatfs: the host volume's real sizes (df), reported as ext4, or tmpfs under /dev/shm.
pub fn statfs(path: Option<u64>, fd: Option<u64>, buf: u64) -> R {
    let (host, guest) = with(|fs| match (path, fd) {
        (Some(p), _) => fs.at(AT_FDCWD, p, true).map(|(g, h)| (h, g)),
        (_, Some(fd)) => match fs.fd(fd)? {
            Fd::File { host, .. } => Ok((host.clone(), String::new())),
            _ => Ok((fs.root.clone(), String::new())),
        },
        _ => Err(EINVAL),
    })?;
    let dir = if host.is_dir() { host.clone() } else { host.parent().map(Path::to_path_buf).unwrap_or(host.clone()) };
    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain([0]).collect();
    let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
    unsafe { crate::win::GetDiskFreeSpaceExW(wide.as_ptr(), &mut avail, &mut total, &mut free) };
    const BS: u64 = 4096;
    let ty: u64 = if guest.starts_with("/dev/shm") { 0x0102_1994 } else { 0xEF53 }; // TMPFS_MAGIC / EXT4
    // struct statfs: type, bsize, blocks, bfree, bavail, files, ffree, fsid[2 x i32], namelen, frsize, flags, spare[4]
    let s: [u64; 15] = [ty, BS, total / BS, free / BS, avail / BS, 1 << 24, 1 << 23, 0, 255, BS, 0, 0, 0, 0, 0];
    unsafe { *(buf as *mut [u64; 15]) = s };
    Ok(0)
}

/// The NT handle and size of a regular file's fd (for MAP_SHARED file mappings).
pub fn file_handle(fd: u64) -> Result<(isize, u64), i64> {
    with(|fs| match fs.fd(fd)? {
        Fd::File { f, .. } => Ok((f.as_raw_handle() as isize, f.metadata().map(|m| m.len()).unwrap_or(0))),
        _ => Err(crate::syscall::ENODEV),
    })
}

/// Make a directory in the container (through the layer), e.g. /dev/shm.
pub fn mkdir_guest(guest: &str) -> Result<(), i64> {
    with(|fs| {
        let c = comps_of(guest);
        if exists(&fs.host(&c)) {
            return Ok(());
        }
        fs::create_dir_all(fs.writable(&c, false)?).map_err(errno)
    })
}

pub fn close(fd: u64) -> R {
    with(|fs| {
        let slot = fs.fds.get_mut(fd as usize).ok_or(EBADF)?;
        let s = slot.take().ok_or(EBADF)?;
        if let Fd::File { f, .. } = &s.fd {
            let h = f.as_raw_handle() as isize;
            LOCKS.lock().unwrap().retain(|l| l.0 != h); // NT drops the handle's locks with it
        }
        Ok(0)
    })
}

// ---- POSIX advisory locks (fcntl, flock) on NT byte-range locks ----
//
// NT locks are mandatory: a locked range can't be read or written through other handles. POSIX locks
// are advisory. So a POSIX range [start, start+len) is locked at SHADOW + start, far beyond any real
// file data: lockers conflict exactly as on Linux, while plain reads and writes never notice. flock()
// uses a byte of its own, independent of fcntl locks as on Linux. NT can't split or convert a lock, so
// held ranges are tracked: unlocking part of one re-locks the remainder, and changing a lock's type is
// unlock + lock (restoring the old lock if the new one can't be had).
// ponytail: locks belong to the fd's handle, not the whole process (Linux: per process / per open file
// description); dup'd fds don't share them. SQLite and most lock users hold them on one fd.

const SHADOW: u64 = 1 << 62;
const FLOCK_AT: u64 = 1 << 63;

/// Locks this process holds: (handle, start, len, exclusive), in shadow coordinates.
static LOCKS: Mutex<Vec<(isize, u64, u64, bool)>> = Mutex::new(Vec::new());

#[repr(C)]
struct Overlapped {
    internal: [usize; 2],
    offset: u32,
    offset_high: u32,
    event: isize,
}

fn ov(at: u64) -> Overlapped {
    Overlapped { internal: [0; 2], offset: at as u32, offset_high: (at >> 32) as u32, event: 0 }
}

fn nt_try_lock(h: isize, start: u64, len: u64, excl: bool) -> bool {
    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 1;
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 2;
    let flags = LOCKFILE_FAIL_IMMEDIATELY | if excl { LOCKFILE_EXCLUSIVE_LOCK } else { 0 };
    let mut o = ov(start);
    unsafe { crate::win::LockFileEx(h, flags, 0, len as u32, (len >> 32) as u32, (&mut o as *mut Overlapped).cast()) != 0 }
}

fn nt_unlock(h: isize, start: u64, len: u64) {
    let mut o = ov(start);
    unsafe { crate::win::UnlockFileEx(h, 0, len as u32, (len >> 32) as u32, (&mut o as *mut Overlapped).cast()) };
}

/// Take a lock; with `wait`, retry until it's free or a signal arrives (F_SETLKW / flock without LOCK_NB).
fn take_lock(h: isize, start: u64, len: u64, excl: bool, wait: bool) -> Result<(), i64> {
    loop {
        if nt_try_lock(h, start, len, excl) {
            LOCKS.lock().unwrap().push((h, start, len, excl));
            return Ok(());
        }
        if !wait {
            return Err(crate::syscall::EAGAIN);
        }
        if crate::signal::deliverable() {
            return Err(crate::syscall::EINTR);
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Drop [start, start+len) from our locks on `h`, keeping (re-locking) the parts outside it.
/// Returns the pieces that were inside, so a failed type change can put them back.
fn release(h: isize, start: u64, len: u64) -> Vec<(u64, u64, bool)> {
    let end = start + len;
    let mut locks = LOCKS.lock().unwrap();
    let (mut keep, mut removed) = (Vec::new(), Vec::new());
    for (lh, s, l, x) in locks.drain(..) {
        if lh != h || s + l <= start || end <= s {
            keep.push((lh, s, l, x));
            continue;
        }
        nt_unlock(h, s, l);
        removed.push((s.max(start), (s + l).min(end) - s.max(start), x));
        if s < start && nt_try_lock(h, s, start - s, x) {
            keep.push((h, s, start - s, x));
        }
        if s + l > end && nt_try_lock(h, end, s + l - end, x) {
            keep.push((h, end, s + l - end, x));
        }
    }
    *locks = keep;
    removed
}

fn holds(h: isize, start: u64, len: u64) -> bool {
    LOCKS.lock().unwrap().iter().any(|&(lh, s, l, _)| lh == h && s < start + len && start < s + l)
}

/// struct flock { short l_type, l_whence; off_t l_start, l_len; pid_t l_pid; }
fn posix_lock(fd: u64, cmd: u64, arg: u64) -> R {
    const F_RDLCK: i16 = 0;
    const F_WRLCK: i16 = 1;
    const F_UNLCK: i16 = 2;
    let (h, pos, size) = with(|fs| match fs.fd(fd)? {
        Fd::File { f, .. } => {
            let pos = f.stream_position().unwrap_or(0);
            let size = f.metadata().map(|m| m.len()).unwrap_or(0);
            Ok((f.as_raw_handle() as isize, pos, size))
        }
        _ => Err(EBADF),
    })?;
    let p = arg as *mut u8;
    let (ty, whence) = unsafe { (*(p as *const i16), *(p.add(2) as *const i16)) };
    let (l_start, l_len) = unsafe { (*(p.add(8) as *const i64), *(p.add(16) as *const i64)) };
    let base = match whence { 0 => 0, 1 => pos as i64, 2 => size as i64, _ => return Err(EINVAL) };
    let (mut start, mut len) = (base + l_start, l_len);
    if len < 0 {
        start += len;
        len = -len;
    }
    if start < 0 || start as u64 >= SHADOW || !(F_RDLCK..=F_UNLCK).contains(&ty) {
        return Err(EINVAL);
    }
    let start = start as u64;
    let len = if len == 0 { SHADOW - start } else { (len as u64).min(SHADOW - start) }; // 0 = to the end
    let s = SHADOW + start;
    match cmd {
        5 | 36 => {
            // F_GETLK: our own locks never conflict; otherwise probe the range.
            if ty == F_UNLCK {
                return Err(EINVAL);
            }
            let free = holds(h, s, len) || {
                let ok = nt_try_lock(h, s, len, ty == F_WRLCK);
                if ok {
                    nt_unlock(h, s, len);
                }
                ok
            };
            unsafe {
                if free {
                    *(p as *mut i16) = F_UNLCK;
                } else {
                    *(p as *mut i16) = F_WRLCK; // ponytail: the holder's type and pid aren't known
                    *(p.add(2) as *mut i16) = 0;
                    *(p.add(8) as *mut i64) = start as i64;
                    *(p.add(16) as *mut i64) = len as i64;
                    *(p.add(24) as *mut i32) = -1;
                }
            }
            Ok(0)
        }
        _ => {
            let old = release(h, s, len);
            if ty == F_UNLCK {
                return Ok(0);
            }
            let r = take_lock(h, s, len, ty == F_WRLCK, cmd == 7 || cmd == 38);
            if r.is_err() {
                for (os, ol, ox) in old {
                    let _ = take_lock(h, os, ol, ox, false); // keep what we had, as POSIX does
                }
            }
            r.map(|_| 0)
        }
    }
}

/// fsync / fdatasync: flush the file to disk (databases rely on it for durability).
pub fn fsync(fd: u64) -> R {
    with(|fs| match fs.fd(fd)? {
        Fd::File { f, .. } => f.sync_all().map(|_| 0).map_err(errno),
        _ => Ok(0), // pipes, sockets, devices, directories: nothing to flush
    })
}

/// flock(fd, LOCK_SH | LOCK_EX | LOCK_UN [| LOCK_NB]).
pub fn flock(fd: u64, op: u64) -> R {
    const LOCK_SH: u64 = 1;
    const LOCK_EX: u64 = 2;
    const LOCK_NB: u64 = 4;
    const LOCK_UN: u64 = 8;
    let h = with(|fs| match fs.fd(fd)? {
        Fd::File { f, .. } => Ok(f.as_raw_handle() as isize),
        Fd::Dir { .. } => Ok(-1), // directories: nothing to lock on NT here; succeed like an uncontended lock
        _ => Err(EINVAL),
    })?;
    if h == -1 {
        return Ok(0);
    }
    let old = release(h, FLOCK_AT, 1);
    if op & LOCK_UN != 0 {
        return Ok(0);
    }
    if op & (LOCK_SH | LOCK_EX) == 0 {
        return Err(EINVAL);
    }
    let r = take_lock(h, FLOCK_AT, 1, op & LOCK_EX != 0, op & LOCK_NB == 0);
    if r.is_err() {
        for (os, ol, ox) in old {
            let _ = take_lock(h, os, ol, ox, false);
        }
    }
    r.map(|_| 0)
}

fn dup_fd(fd: &Fd) -> Result<Fd, i64> {
    Ok(match fd {
        Fd::Handle(h) => Fd::Handle(h.try_clone().map_err(errno)?),
        Fd::Pipe(p) => Fd::Pipe(p.clone()),
        Fd::File { f, host } => Fd::File { f: f.try_clone().map_err(errno)?, host: host.clone() },
        Fd::Dir { guest, pos } => Fd::Dir { guest: guest.clone(), pos: *pos },
        Fd::Dev(d) => Fd::Dev(*d),
        Fd::Socket(s) => Fd::Socket(s.clone()),
        Fd::Epoll(e) => Fd::Epoll(e.clone()),
        Fd::Event(e) => Fd::Event(e.clone()),
        Fd::Signal(s) => Fd::Signal(s.clone()),
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
        5 | 6 | 7 | 36 | 37 | 38 => posix_lock(fd, cmd, arg), // F_GETLK/SETLK/SETLKW and the OFD variants
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
            Fd::Signal(s) => { s.nonblock.store(arg & O_NONBLOCK != 0, std::sync::atomic::Ordering::Relaxed); Ok(0) }
            Fd::Pipe(p) => { p.nonblock.store(arg & O_NONBLOCK != 0, std::sync::atomic::Ordering::Relaxed); Ok(0) }
            _ => Ok(0),
        }),
        3 => with(|fs| match fs.fd(fd)? {
            Fd::Socket(s) if s.nonblocking() => Ok(2 | O_NONBLOCK as i64),
            Fd::Pipe(p) if p.nonblocking() => Ok(2 | O_NONBLOCK as i64),
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
        Fd::Handle(_) | Fd::Pipe(_) | Fd::Socket(_) | Fd::Epoll(_) | Fd::Event(_) | Fd::Signal(_) => Err(ESPIPE),
        Fd::Dev(_) => Ok(0),
    })
}

/// `struct stat` for x86-64 (144 bytes).
// ---- modes and owners ----
//
// NTFS has no Linux mode bits or owners, so they live in an alternate data stream of each file and
// directory, "<host>:lx": permission bits, uid, gid as three little-endian u32s. Unpack writes them
// from the tar headers, chmod/chown and creation update them; without one, an entry reads as
// 0755 root:root (images pulled before this, files lx didn't create). Volumes' host files never get one.

pub static UMASK: AtomicU32 = AtomicU32::new(0o022);

fn meta_stream(host: &Path) -> PathBuf {
    let mut p = host.as_os_str().to_owned();
    p.push(":lx");
    p.into()
}

pub fn get_meta(host: &Path) -> Option<[u32; 3]> {
    let b = fs::read(meta_stream(host)).ok()?;
    let v = |i: usize| Some(u32::from_le_bytes(b.get(i * 4..i * 4 + 4)?.try_into().ok()?));
    Some([v(0)?, v(1)?, v(2)?])
}

pub fn set_meta(host: &Path, m: [u32; 3]) -> io::Result<()> {
    forget(&METAS, host);
    fs::write(meta_stream(host), m.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>())
}

/// What a newly created file or directory gets: `mode` less the umask, owned by the effective ids.
fn new_meta(mode: u64) -> [u32; 3] {
    [mode as u32 & 0o7777 & !UMASK.load(Relaxed), crate::proc::UID.load(Relaxed), crate::proc::GID.load(Relaxed)]
}

/// umask(mask): returns the old one; later lx processes (fork, exec) get the new one (proc::save_ids).
pub fn umask(mask: u64) -> R {
    let old = UMASK.swap(mask as u32 & 0o777, Relaxed);
    crate::proc::save_ids();
    Ok(old as i64)
}

/// Fill st_mode's permission bits, st_uid and st_gid from the stored metadata.
fn with_meta(s: &mut [u64; 18], host: &Path) {
    let stamp = s[11].wrapping_mul(1_000_000_000).wrapping_add(s[12]); // mtime
    let meta = cached(&METAS, host, stamp, || get_meta(host));
    let [perm, uid, gid] = meta.unwrap_or([s[3] as u32 & 0o7777, 0, 0]);
    s[3] = (s[3] & !0o7777) | (perm & 0o7777) as u64 | (uid as u64) << 32;
    s[4] = gid as u64;
}

/// chmod/chown of the entry at `c` (guest path components; `host` is where it is now): through the
/// writable layer, so the image keeps its own. `mode`/`owner` None: keep; an id of -1 keeps that id.
fn chmeta(fs: &Fs, c: &[String], host: &Path, mode: Option<u64>, owner: Option<(u64, u64)>) -> R {
    if !fs.keeps_meta(c) {
        return Ok(0); // ponytail: a volume's files are the host's: their modes and owners aren't ours to set
    }
    let dir = host.is_dir();
    let up = fs.writable(c, !dir)?; // a directory is created in the upper layer, not copied whole
    if dir {
        fs::create_dir_all(&up).map_err(errno)?;
    }
    let mut m = get_meta(&up).or_else(|| get_meta(host)).unwrap_or([0o755, 0, 0]);
    if let Some(mode) = mode {
        m[0] = mode as u32 & 0o7777;
    }
    if let Some((uid, gid)) = owner {
        for (slot, id) in [(1, uid as u32), (2, gid as u32)] {
            if id != u32::MAX {
                m[slot] = id;
            }
        }
    }
    set_meta(&up, m).map_err(errno)?;
    Ok(0)
}

/// chmod, fchmodat, chown, lchown, fchownat.
pub fn chmeta_at(dirfd: u64, path: u64, follow: bool, mode: Option<u64>, owner: Option<(u64, u64)>) -> R {
    with(|fs| {
        let (guest, host) = fs.at(dirfd, path, follow)?;
        if fs::symlink_metadata(&host).is_err() {
            return Err(ENOENT);
        }
        chmeta(fs, &comps_of(&guest), &host, mode, owner)
    })
}

/// fchmod, fchown: by the file's path in the container. Pipes, sockets and the like: accepted.
pub fn fchmeta(fd: u64, mode: Option<u64>, owner: Option<(u64, u64)>) -> R {
    with(|fs| {
        let guest = match fs.fd(fd)? {
            Fd::Dir { guest, .. } => guest.clone(),
            Fd::File { host, .. } => {
                let host = host.clone();
                let rel = fs.upper.as_ref().and_then(|u| host.strip_prefix(u).ok()).or_else(|| host.strip_prefix(&fs.root).ok());
                let Some(rel) = rel else { return Ok(0) }; // in a volume
                format!("/{}", rel.to_string_lossy().replace('\\', "/"))
            }
            _ => return Ok(0),
        };
        let host = fs.resolve("/", &guest, false)?.1;
        chmeta(fs, &comps_of(&guest), &host, mode, owner)
    })
}

fn stat_of(host: &Path) -> Result<[u64; 18], i64> {
    let m = attrs(host).ok_or(ENOENT)?;
    let link = link_target(host, &m);
    let sock = !m.dir && m.len == SOCK_MAGIC.len() as u64 && fs::read(host).is_ok_and(|d| d == SOCK_MAGIC);
    let (mode, size, nlink) = match &link {
        _ if m.dir => (0o040755, 4096, 2),
        _ if sock => (0o140755, 0, 1), // S_IFSOCK
        Some(t) => (0o120777, t.len() as u64, 1),
        None => (0o100755, m.len, 1),
    };
    let t = std::time::Duration::from_nanos(m.mtime);
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
    if link.is_none() {
        with_meta(&mut s, host);
    }
    Ok(s)
}

fn put_stat(buf: u64, s: [u64; 18]) -> R {
    unsafe { *(buf as *mut [u64; 18]) = s };
    Ok(0)
}

pub fn fstat(fd: u64, buf: u64) -> R {
    let s = with(|fs| match fs.fd(fd)? {
        // From the open handle, not the path: the file may have been renamed or deleted since (apt does
        // both to its temp files), and Linux's fstat still answers.
        Fd::File { f, host } => {
            let m = f.metadata().map_err(errno)?;
            let t = m.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).unwrap_or_default();
            let mut s = [0u64; 18];
            (s[0], s[1], s[2], s[3], s[6], s[7], s[8]) = (0x803, ino(host), 1, 0o100755, m.len(), 4096, m.len().div_ceil(512));
            for i in [9, 11, 13] {
                (s[i], s[i + 1]) = (t.as_secs(), t.subsec_nanos() as u64);
            }
            with_meta(&mut s, host);
            Ok(s)
        }
        Fd::Dir { guest, .. } => {
            let guest = guest.clone();
            let guest = if proc_dir(&guest).is_some() { "/".into() } else { guest }; // synthetic: like the root
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
        Fd::Pipe(p) => {
            let mut s = [0u64; 18];
            (s[1], s[2], s[3], s[7]) = (p.raw() as u64, 1, 0o010600, 4096); // fifo
            Ok(s)
        }
        Fd::Socket(k) => {
            let mut s = [0u64; 18];
            (s[1], s[2], s[3], s[7]) = (k.s as u64, 1, 0o140777, 4096); // S_IFSOCK
            Ok(s)
        }
        Fd::Epoll(_) | Fd::Event(_) | Fd::Signal(_) => {
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
    if crate::procfs::file(&guest).is_some() {
        let mut s = [0u64; 18];
        (s[1], s[2], s[3], s[7]) = (ino(&host), 1, 0o100444, 4096); // a regular file of size 0, like procfs
        return put_stat(buf, s);
    }
    if proc_dir(&guest).is_some() {
        return put_stat(buf, stat_of(&with(|fs| fs.resolve("/", "/", true))?.1)?); // a directory like the root
    }
    if flags & AT_SYMLINK_NOFOLLOW == 0 && let Some(n) = fd_alias(&guest) {
        return fstat(n, buf);
    }
    if flags & AT_SYMLINK_NOFOLLOW != 0 && let Some(t) = proc_link(&guest) {
        let mut s = [0u64; 18];
        (s[1], s[2], s[3], s[6], s[7]) = (ino(&host), 1, 0o120777, t.len() as u64, 4096); // a symlink
        return put_stat(buf, s);
    }
    put_stat(buf, stat_of(&host)?)
}

/// statx(dirfd, path, flags, mask, buf): newer coreutils and glibc's stat use it. Filled from the same
/// struct stat as fstatat (flags: AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW; the sync bits don't matter here).
pub fn statx(dirfd: u64, path: u64, flags: u64, buf: u64) -> R {
    let mut s = [0u64; 18];
    fstatat(dirfd, path, s.as_mut_ptr() as u64, flags & (AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW))?;
    let mut x = [0u8; 256];
    let mut put = |off: usize, v: &[u8]| x[off..off + v.len()].copy_from_slice(v);
    put(0, &0x7ffu32.to_le_bytes()); // STATX_BASIC_STATS
    put(4, &(s[7] as u32).to_le_bytes()); // blksize
    put(16, &(s[2] as u32).to_le_bytes()); // nlink
    put(20, &((s[3] >> 32) as u32).to_le_bytes()); // uid
    put(24, &(s[4] as u32).to_le_bytes()); // gid
    put(28, &(s[3] as u16).to_le_bytes()); // mode
    put(32, &s[1].to_le_bytes()); // ino
    put(40, &s[6].to_le_bytes()); // size
    put(48, &s[8].to_le_bytes()); // blocks
    for (off, i) in [(64, 9), (96, 13), (112, 11)] { // atime, ctime, mtime: { i64 sec; u32 nsec; }
        put(off, &s[i].to_le_bytes());
        put(off + 8, &(s[i + 1] as u32).to_le_bytes());
    }
    put(128, &((s[5] >> 8) as u32 & 0xfff).to_le_bytes()); // rdev major, minor
    put(132, &(s[5] as u32 & 0xff).to_le_bytes());
    put(136, &((s[0] >> 8) as u32 & 0xfff).to_le_bytes()); // dev major, minor
    put(140, &(s[0] as u32 & 0xff).to_le_bytes());
    unsafe { std::ptr::copy_nonoverlapping(x.as_ptr(), buf as *mut u8, 256) };
    Ok(0)
}


pub fn faccessat(dirfd: u64, path: u64) -> R {
    let (guest, host) = with(|fs| fs.at(dirfd, path, true))?;
    if Dev::of(&guest).is_some() || fd_alias(&guest).is_some() || proc_dir(&guest).is_some() || crate::procfs::file(&guest).is_some() {
        return Ok(0);
    }
    fs::symlink_metadata(host).map(|_| 0).map_err(errno)
}

/// The guest path of the running ELF, for /proc/self/exe (ld.so resolves $ORIGIN with it).
static EXE: Mutex<String> = Mutex::new(String::new());

/// The running program's file name, for /proc/self/status.
pub fn exe_name() -> String {
    EXE.lock().unwrap().rsplit('/').next().unwrap_or("").chars().take(15).collect()
}

pub fn set_exe(guest: &str) {
    *EXE.lock().unwrap() = guest.to_string();
}

/// `/proc/self` and `/proc/self/fd` (or our pid) as synthetic directories: Some(true) for the fd one.
/// httpd stats `/proc/self/fd/` for `ErrorLog /proc/self/fd/2`; fd-closing loops list it.
fn proc_dir(guest: &str) -> Option<bool> {
    let r = guest.strip_prefix("/proc/")?;
    let (pid, rest) = r.split_once('/').unwrap_or((r, ""));
    if pid != "self" && pid.parse::<u32>().ok()? != unsafe { crate::win::GetCurrentProcessId() } {
        return None;
    }
    match rest {
        "" => Some(false),
        "fd" => Some(true),
        _ => None,
    }
}

/// What getdents lists in a `proc_dir`: (name, d_type).
fn proc_entries(fd_dir: bool, fds: &[Option<Slot>]) -> Vec<(String, u8)> {
    const DT_DIR: u8 = 4;
    const DT_LNK: u8 = 10;
    if !fd_dir {
        return vec![("fd".into(), DT_DIR), ("exe".into(), DT_LNK), ("cwd".into(), DT_LNK), ("root".into(), DT_LNK)];
    }
    fds.iter().enumerate().filter(|(_, s)| s.is_some()).map(|(i, _)| (i.to_string(), DT_LNK)).collect()
}

/// The few /proc links programs actually read. ponytail: no /proc filesystem otherwise (DESIGN.md §5).
fn proc_link(guest: &str) -> Option<String> {
    let rest = guest.strip_prefix("/proc/self/").or_else(|| {
        let r = guest.strip_prefix("/proc/")?;
        let (pid, rest) = r.split_once('/')?;
        (pid.parse::<u32>().ok()? == crate::proc::pid()).then_some(rest)
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
                    Some(rel.iter().map(|c| format!("/{}", dec(&c.to_string_lossy()))).collect())
                }
                Fd::Handle(_) => Some("pipe:[0]".into()),
                Fd::Pipe(p) => Some(format!("pipe:[{}]", p.raw())),
                Fd::Socket(k) => Some(format!("socket:[{}]", k.s)),
                Fd::Epoll(_) => Some("anon_inode:[eventpoll]".into()),
                Fd::Event(_) => Some("anon_inode:[eventfd]".into()),
                Fd::Signal(_) => Some("anon_inode:[signalfd]".into()),
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

pub fn mkdirat(dirfd: u64, path: u64, mode: u64) -> R {
    with(|fs| {
        let (guest, host) = fs.at(dirfd, path, false)?;
        if exists(&host) {
            return Err(EEXIST);
        }
        let c = comps_of(&guest);
        let was_hidden = fs.upper.is_some() && fs.hidden(&c);
        let up = fs.writable(&c, false)?;
        fs::create_dir(&up).map_err(errno)?;
        if fs.keeps_meta(&c) {
            let _ = set_meta(&up, new_meta(mode));
        }
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

/// fallocate(fd, mode, off, len): mode 0 grows the file to cover [off, off+len) (posix_fallocate; postgres
/// sizes its /dev/shm segments so); FALLOC_FL_KEEP_SIZE alone has nothing to do. Hole punching etc.: EOPNOTSUPP.
pub fn fallocate(fd: u64, mode: u64, off: u64, len: u64) -> R {
    const FALLOC_FL_KEEP_SIZE: u64 = 1;
    with(|fs| {
        let Fd::File { f, .. } = fs.fd(fd)? else { return Err(crate::syscall::ENODEV) };
        match mode {
            0 => {
                let end = off.checked_add(len).ok_or(EINVAL)?;
                if f.metadata().map_err(errno)?.len() < end {
                    f.set_len(end).map_err(errno)?;
                }
                Ok(0)
            }
            FALLOC_FL_KEEP_SIZE => Ok(0),
            _ => Err(95), // EOPNOTSUPP
        }
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
        if let Some(fd_dir) = proc_dir(&guest) {
            names.extend(proc_entries(fd_dir, &fs.fds));
        } else {
            for (name, dir) in fs.list(&comps_of(&guest))? {
                names.push((name, if dir { 4 } else { 0 })); // DT_DIR / DT_UNKNOWN
            }
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
                Component::Normal(n) => out.push(enc(&n.to_string_lossy())),
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
        if r.is_ok() && !ty.is_symlink() {
            let h = e.header();
            let id = |v: io::Result<u64>| v.unwrap_or(0) as u32;
            let _ = set_meta(&host, [h.mode().unwrap_or(0o755) & 0o7777, id(h.uid()), id(h.gid())]);
        }
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
        if let Some(m) = get_meta(from) {
            set_meta(to, m)?;
        }
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
    let fs_ = Fs { root: root.clone(), upper: None, mounts: vec![], cwd: "/".into(), fds: vec![] };
    let r = |p: &str| fs_.resolve("/bin", p, true).map(|x| x.0);
    assert_eq!(r("sh"), Ok("/bin/busybox".into()));
    assert_eq!(r("/up/etc/passwd"), Ok("/etc/passwd".into()));
    assert_eq!(r("../../../x"), Ok("/x".into()));
    assert_eq!(r("/loop"), Err(ELOOP));
    // `\` and `:` are plain name characters: one encoded host name, never a separator or a stream.
    let (g, h) = fs_.resolve("/", "/..\\..\\x:y", true).unwrap();
    assert_eq!(g, "/..\\..\\x:y");
    assert_eq!(h, root.join("..\u{f05c}..\u{f05c}x\u{f03a}y"));
    assert_eq!(dec("..\u{f05c}..\u{f05c}x\u{f03a}y\u{f041}"), "..\\..\\x:y\u{f041}");
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
    let f = Fs { root: lower.clone(), upper: Some(upper.clone()), mounts: vec![], cwd: "/".into(), fds: vec![] };
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

    // A deleted image file opened for writing again (copy-up asked) is new, not the image's copy.
    f.remove(&c("/etc/a.conf"), false).unwrap();
    assert!(!exists(&f.writable(&c("/etc/a.conf"), true).unwrap()));

    fs::remove_dir_all(base).unwrap();
}
