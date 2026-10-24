//! The guest's filesystem: path resolution confined to the rootfs, the fd table, file syscalls,
//! and unpacking image layers onto NTFS.
//!
//! Linux symlinks are stored as small marker files (LINK_MAGIC + target) and resolved here, never by
//! Windows: creating NTFS symlinks needs admin/Developer Mode, and resolving ourselves means `..` and
//! absolute targets can't leave the rootfs.
use crate::syscall::{R, cstr, guest_mut, read_handle, write_handle};
use crate::syscall::{EROFS, EBADF, EEXIST, EINVAL, EISDIR, ELOOP, ENOENT, ENOTDIR, ERANGE, ESPIPE, ENOTEMPTY, EACCES, EBUSY, EIO, ENAMETOOLONG};
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
/// A FIFO's marker is this and an 8-byte id, which names its pipe: the FIFO stays itself when renamed
/// (s6's ftrig makes one under a temporary name, opens it, then renames it into place).
const FIFO_MAGIC: &[u8] = b"\0lxfifo\0";
const FIFO_LEN: u64 = 16;

fn fifo_id(host: &Path, m: &Attrs) -> Option<u64> {
    if m.dir || m.len != FIFO_LEN || !may_be_marker(host, m) {
        return None;
    }
    let d = fs::read(host).ok()?;
    Some(u64::from_le_bytes(d.strip_prefix(FIFO_MAGIC)?.try_into().ok()?))
}

// ---- marker files ----
// Our marker files (symlinks, sockets, FIFOs) carry FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, so a lookup knows
// which small files to read: Defender scans a file's contents the first time anything reads them (~30-50
// ms), and reading every small file to ask "a symlink?" made a cold `find` over 19,000 files take
// minutes. The attribute only says "may be one": the content still decides, so a stray one costs a read.
// Areas made before it (image stores without a MARKED stamp beside their rootfs, volumes) are still read.

const MARKER_ATTR: u32 = 0x2000; // FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: no side effects on opens or renames
/// Beside an image's rootfs: every marker in it carries MARKER_ATTR (pulled or built by this lx).
pub const MARKED: &str = "marked";
/// Host trees whose markers all carry it: this container's upper layer, and a stamped image.
static MARKED_ROOTS: std::sync::RwLock<Vec<PathBuf>> = std::sync::RwLock::new(Vec::new());

fn mark(p: &Path) {
    let w: Vec<u16> = p.as_os_str().encode_wide().chain([0]).collect();
    let a = unsafe { crate::win::GetFileAttributesW(w.as_ptr()) };
    if a != u32::MAX {
        unsafe { crate::win::SetFileAttributesW(w.as_ptr(), a | MARKER_ATTR) };
    }
}

/// A copied file that is one of our markers gets the attribute (its source may predate it).
pub fn mark_if_marker(p: &Path) {
    let Some(m) = attrs(p) else { return };
    if m.dir || m.marker || m.len > 4096 || m.len < 8 {
        return;
    }
    if fs::read(p).is_ok_and(|d| [LINK_MAGIC, SOCK_MAGIC, FIFO_MAGIC].iter().any(|g| d.starts_with(g))) {
        mark(p);
    }
}

fn note_marked_roots(root: &Path, upper: Option<&Path>) {
    *LAYER_ROOTS.write().unwrap() = upper.into_iter().chain([root]).map(Path::to_path_buf).collect();
    let mut roots = MARKED_ROOTS.write().unwrap();
    roots.clear();
    roots.extend(upper.map(Path::to_path_buf));
    if root.parent().is_some_and(|d| d.join(MARKED).exists()) {
        roots.push(root.to_path_buf());
    }
}

fn may_be_marker(host: &Path, m: &Attrs) -> bool {
    m.marker || !MARKED_ROOTS.read().unwrap().iter().any(|r| host.starts_with(r))
}

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
    /// Read since epoll last looked: its edge re-arms (see Pipe::rearm).
    pub rearm: AtomicU32,
}

impl EventFd {
    pub fn new(init: u64, flags: u64) -> Self {
        const EFD_SEMAPHORE: u64 = 1;
        EventFd {
            count: Mutex::new(init),
            changed: std::sync::Condvar::new(),
            semaphore: flags & EFD_SEMAPHORE != 0,
            nonblock: std::sync::atomic::AtomicBool::new(flags & O_NONBLOCK != 0),
            rearm: AtomicU32::new(0),
        }
    }

    /// For a fork/exec child: "count:semaphore:nonblock".
    fn export(&self) -> String {
        let nb = self.nonblock.load(std::sync::atomic::Ordering::Relaxed);
        format!("{}:{}:{}", *self.count.lock().unwrap(), self.semaphore as u8, nb as u8)
    }

    fn import(s: &str) -> Option<Self> {
        let mut f = s.split(':');
        let count: u64 = f.next()?.parse().ok()?;
        let (sem, nb) = (f.next()? == "1", f.next()? == "1");
        Some(EventFd::new(count, if sem { 1 } else { 0 } | if nb { O_NONBLOCK } else { 0 }))
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
    if flags & !(EFD_CLOEXEC | 0o4000 | 1) != 0 {
        return Err(EINVAL); // EFD_NONBLOCK, EFD_SEMAPHORE
    }
    add_fd(Fd::Event(Arc::new(EventFd::new(init, flags))), flags & EFD_CLOEXEC != 0)
}

/// timerfd: an eventfd whose count a timer thread raises by the expirations since the last read, which
/// is exactly what reading a timerfd returns; poll/epoll readiness comes with it.
/// ponytail: one thread per armed timer; CLOCK_BOOTTIME/ALARM count as MONOTONIC.
static TIMERS: Mutex<Vec<(usize, u64, Option<std::time::Instant>, std::time::Duration)>> = Mutex::new(Vec::new());

pub fn timerfd_create(_clock: u64, flags: u64) -> R {
    eventfd(0, flags) // TFD_NONBLOCK/TFD_CLOEXEC are O_NONBLOCK/O_CLOEXEC, like eventfd's
}

fn event_of(fd: u64) -> Result<Arc<EventFd>, i64> {
    with(|fs| match fs.fd(fd)? {
        Fd::Event(e) => Ok(e.clone()),
        _ => Err(EINVAL),
    })
}

/// The armed state of timerfd `e`: (epoch: bumped by every settime, next expiry, interval).
fn timer_of(e: &Arc<EventFd>) -> (u64, Option<std::time::Instant>, std::time::Duration) {
    let key = Arc::as_ptr(e) as usize;
    TIMERS.lock().unwrap().iter().find(|t| t.0 == key).map_or((0, None, Default::default()), |t| (t.1, t.2, t.3))
}

fn put_itimerspec(p: u64, next: Option<std::time::Instant>, interval: std::time::Duration) {
    if p == 0 {
        return;
    }
    let left = next.map_or(Default::default(), |n| n.saturating_duration_since(std::time::Instant::now()));
    unsafe { *(p as *mut [u64; 4]) = [interval.as_secs(), interval.subsec_nanos() as u64, left.as_secs(), left.subsec_nanos() as u64] };
}

pub fn timerfd_gettime(fd: u64, cur: u64) -> R {
    let (_, next, interval) = timer_of(&event_of(fd)?);
    put_itimerspec(cur, next, interval);
    Ok(0)
}

/// timerfd_settime(fd, flags, new, old): arm (or with a zero value disarm) the timer.
pub fn timerfd_settime(fd: u64, flags: u64, new: u64, old: u64) -> R {
    const TFD_TIMER_ABSTIME: u64 = 1;
    let e = event_of(fd)?;
    let (epoch, next, interval) = timer_of(&e);
    put_itimerspec(old, next, interval);
    let [is, ins, vs, vns] = unsafe { *(new as *const [u64; 4]) };
    let interval = std::time::Duration::new(is, ins as u32);
    let mut value = std::time::Duration::new(vs, vns as u32);
    let armed = !value.is_zero();
    if armed && flags & TFD_TIMER_ABSTIME != 0 {
        let (s, ns) = crate::syscall::now(1); // ponytail: absolute REALTIME deadlines are taken as monotonic
        value = value.saturating_sub(std::time::Duration::new(s, ns as u32));
    }
    let epoch = epoch + 1;
    let first = armed.then(|| std::time::Instant::now() + value);
    let key = Arc::as_ptr(&e) as usize;
    {
        let mut t = TIMERS.lock().unwrap();
        t.retain(|t| t.0 != key);
        t.push((key, epoch, first, interval));
    }
    *e.count.lock().unwrap() = 0; // re-arming discards expirations not read yet, like Linux
    if let Some(mut at) = first {
        let weak = Arc::downgrade(&e);
        std::thread::spawn(move || loop {
            std::thread::sleep(at.saturating_duration_since(std::time::Instant::now()));
            let Some(e) = weak.upgrade() else { return }; // the fd was closed
            if timer_of(&e).0 != epoch {
                return; // re-armed or disarmed since
            }
            let late = std::time::Instant::now().saturating_duration_since(at);
            let n = if interval.is_zero() { 1 } else { 1 + (late.as_nanos() / interval.as_nanos()) as u64 };
            *e.count.lock().unwrap() += n;
            e.changed.notify_all();
            if interval.is_zero() {
                TIMERS.lock().unwrap().iter_mut().filter(|t| t.0 == key && t.1 == epoch).for_each(|t| t.2 = None);
                return;
            }
            at += interval * n as u32;
            TIMERS.lock().unwrap().iter_mut().filter(|t| t.0 == key && t.1 == epoch).for_each(|t| t.2 = Some(at));
        });
    }
    Ok(0)
}

/// memfd_create(name, flags): an anonymous file, here a scratch file Windows deletes with its last handle,
/// so it reads, writes, truncates and maps (MAP_SHARED included) like any file. PHP and Chromium use it.
/// ponytail: sealing (MFD_ALLOW_SEALING, F_ADD_SEALS) is accepted and not enforced.
pub fn memfd_create(_name: u64, flags: u64) -> R {
    const MFD_CLOEXEC: u64 = 1;
    with(|fs| {
        let (f, host) = scratch_file(fs, b"").map_err(errno)?;
        fs.add(Fd::File { f, host }, 0, flags & MFD_CLOEXEC != 0)
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
    add_fd(Fd::Signal(Arc::new(s)), flags & SFD_CLOEXEC != 0)
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
    /// A pseudo terminal's end: (its number, whether it's the master).
    pty: Option<(u32, bool)>,
    /// Read since epoll last looked: an edge-triggered registration reports it again if data is there.
    /// Linux signals an edge on each arrival; we only see states, and a reader that drained it to EAGAIN
    /// while more came in before our next look would wait forever (cgo under go build: 6903 bytes unread).
    pub rearm: AtomicU32,
    /// A non-blocking write found no room: POLLOUT waits for room again (see write_room for why a bare
    /// zero quota doesn't mean full).
    full: std::sync::atomic::AtomicBool,
}

impl Pipe {
    /// A pipe end from another lx process, `extra` as `extra()` made it.
    fn inherited(h: usize, extra: &str) -> Pipe {
        let pty = extra.get(2..).and_then(|n| n.parse().ok()).map(|n| (n, extra.as_bytes()[1] == b'm'));
        Pipe { h: unsafe { OwnedHandle::from_raw_handle(h as _) }, nonblock: extra.starts_with('1').into(), pty, rearm: AtomicU32::new(0), full: false.into() }
    }

    fn extra(&self) -> String {
        let pty = self.pty.map(|(n, master)| format!("{}{n}", if master { 'm' } else { 's' }));
        format!("{}{}", self.nonblocking() as u8, pty.unwrap_or_default())
    }

    fn is_pts(&self) -> bool {
        self.pty.is_some_and(|(_, master)| !master)
    }

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

    /// Free room in what this end writes into (FilePipeLocalInformation's WriteQuotaAvailable), if NT
    /// says. A pending read counts against it too: a reader blocked in read(>= the quota) shows 0 room in
    /// an empty pipe, so 0 alone doesn't mean full (pipes get 1 MiB quotas to keep that rare).
    fn write_room(&self) -> Option<u32> {
        unsafe extern "system" {
            fn NtQueryInformationFile(h: isize, iosb: *mut [usize; 2], info: *mut u32, len: u32, class: u32) -> i32;
        }
        let (mut iosb, mut info) = ([0usize; 2], [0u32; 10]);
        // FILE_PIPE_LOCAL_INFORMATION (class 24): ten ULONGs, WriteQuotaAvailable the eighth.
        (unsafe { NtQueryInformationFile(self.raw(), &mut iosb, info.as_mut_ptr(), 40, 24) } == 0).then_some(info[7])
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
        // Non-blocking, a write takes what fits rather than waiting for the reader (Go's netpoller writes
        // its pipes so, then waits for POLLOUT): one that would wait is cancelled, EAGAIN if nothing went.
        // ponytail: a write up to PIPE_BUF may go in part (Linux: all or nothing).
        if err == ERROR_IO_PENDING && write && self.nonblocking() {
            unsafe { CancelIoEx(self.raw(), op) };
            err = if unsafe { GetOverlappedResult(self.raw(), op, &mut done, 1) } != 0 { 0 } else { unsafe { GetLastError() } };
            if done == 0 && err == 995 {
                unsafe { CloseHandle(ev) };
                self.full.store(true, Relaxed);
                self.rearm.fetch_or(4, Relaxed); // POLLOUT: an edge-triggered waiter hears when there's room
                return Err(crate::syscall::EAGAIN);
            }
        }
        if write {
            self.full.store(false, Relaxed);
        }
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
                Err(crate::syscall::io_errno(e))
            }
        }
    }

    fn ready(&self, events: i16) -> i16 {
        match self.available() {
            // A write end has no read access, so PeekNamedPipe is denied there: writable if there's room.
            None => match unsafe { crate::win::GetLastError() } {
                5 => match self.write_room() {
                    Some(0) if self.full.load(Relaxed) => 0,
                    Some(1..) => { self.full.store(false, Relaxed); events & POLLOUT }
                    _ => events & POLLOUT,
                },
                230 | 536 => 0, // ERROR_BAD_PIPE, ERROR_PIPE_LISTENING: a FIFO reader whose writer hasn't come yet
                _ => POLLHUP | (events & POLLIN),
            },
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
    /// Carries MARKER_ATTR: may be one of our marker files.
    pub marker: bool,
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
        marker: d[0] & MARKER_ATTR != 0,
    })
}

/// attrs() of a path in the image, which stays as it is while an upper layer takes the writes: from a
/// listing of its directory, made once per process. Path searches (Erlang's code path, Python's
/// imports, $PATH) probe many names per directory, mostly missing ones, and every host call costs
/// tens of microseconds.
/// ponytail: a directory is listed whole on first use, however big, and stays cached for the process.
fn lower_attrs(p: &Path) -> Option<Attrs> {
    use std::os::windows::fs::MetadataExt;
    type Listing = Arc<HashMap<std::ffi::OsString, Attrs>>;
    static DIRS: Mutex<Option<HashMap<PathBuf, Listing>>> = Mutex::new(None);
    let (dir, name) = (p.parent()?, p.file_name()?);
    let cached = DIRS.lock().unwrap().get_or_insert_with(HashMap::new).get(dir).cloned();
    let listing = cached.unwrap_or_else(|| {
        let entry = |e: fs::DirEntry| {
            let m = e.metadata().ok()?;
            let mtime = m.last_write_time().saturating_sub(116_444_736_000_000_000).saturating_mul(100);
            Some((e.file_name(), Attrs { dir: m.is_dir(), len: m.file_size(), mtime, marker: m.file_attributes() & MARKER_ATTR != 0 }))
        };
        let l: Listing = Arc::new(fs::read_dir(dir).map(|rd| rd.flatten().filter_map(entry).collect()).unwrap_or_default());
        DIRS.lock().unwrap().get_or_insert_with(HashMap::new).insert(dir.to_path_buf(), l.clone());
        l
    });
    listing.get(name).copied()
}

/// getdents' d_type for a directory entry, from what the listing already returned (no extra call):
/// DT_DIR, DT_REG for a file that can't be one of our markers (empty, or larger than any: symlinks
/// are at most 4096 bytes), else DT_UNKNOWN so the reader stats it (find over a big tree otherwise
/// stats every file).
fn d_type(e: &fs::DirEntry) -> u8 {
    match e.metadata() {
        Ok(m) if m.is_dir() => 4,
        Ok(m) if m.len() == 0 || m.len() > 4096 => 8,
        _ => 0,
    }
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
    note_marked_roots(&root, None);
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
    with(|fs| {
        note_marked_roots(&fs.root, Some(&upper));
        fs.upper = Some(upper);
    });
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
        None => {
            let mut h = DefaultHasher::new();
            fs.root.hash(&mut h);
            format!("root-{:08x}", h.finish() as u32) // plain `lx <rootfs> cmd`: one per rootfs
        }
    }
}

/// The container's name for abstract AF_UNIX sockets (no path).
pub fn container() -> String {
    with(|fs| container_name(fs))
}

/// Leave the socket marker at a bound AF_UNIX path, so ls/stat show a socket there.
pub fn mark_socket(guest: &str) -> Result<(), i64> {
    write_guest_file(guest, SOCK_MAGIC)?;
    mark(&with(|fs| fs.writable(&split(guest).into_iter().collect::<Vec<_>>(), false))?);
    Ok(())
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
        Some(206) => ENAMETOOLONG, // ERROR_FILENAME_EXCED_RANGE
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
    if m.dir || m.len > 4096 || m.len < LINK_MAGIC.len() as u64 || !may_be_marker(host, m) {
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
    fs::write(host, [LINK_MAGIC, target.as_bytes()].concat())?;
    mark(host);
    Ok(())
}

/// The container's layer roots (upper, then image), for ino().
static LAYER_ROOTS: std::sync::RwLock<Vec<PathBuf>> = std::sync::RwLock::new(Vec::new());

/// Is `host` in the image under a container layer (read-only, its files shared between image copies)?
fn in_image(host: &Path) -> bool {
    let roots = LAYER_ROOTS.read().unwrap();
    roots.len() == 2 && host.starts_with(&roots[1])
}

/// An inode number for a host path: a hash of its path inside its layer, so copying an image entry up
/// into the container's layer keeps its number (GNU tar compares a directory's dev/ino before and after
/// extracting into it: "Directory renamed before its status could be extracted", wordpress).
fn ino(host: &Path) -> u64 {
    let roots = LAYER_ROOTS.read().unwrap();
    let p = roots.iter().find_map(|r| host.strip_prefix(r).ok()).unwrap_or(host);
    let mut h = DefaultHasher::new();
    p.hash(&mut h);
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

/// A host name as the guest sees it (inotify's event names).
pub fn dec_name(name: &str) -> String {
    dec(name)
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
        self.host_meta_seen(comps, None)
    }

    /// host_meta, knowing what resolve just found of the parent: Some(true) it's there, so only the last
    /// level can hide this entry; Some(false) it isn't, so neither is this (outside a volume).
    fn host_meta_seen(&self, comps: &[String], parent: Option<bool>) -> (PathBuf, Option<Attrs>) {
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
        if parent == Some(false) {
            return (upper, None);
        }
        if let Some(m) = attrs(&upper) {
            return (upper, Some(m));
        }
        if if parent == Some(true) { self.hidden_here(comps) } else { self.hidden(comps) } {
            return (upper, None);
        }
        match lower_attrs(&lower) {
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

    /// hidden() for an entry whose parent is visible: a whiteout for it, or its parent made opaque.
    fn hidden_here(&self, comps: &[String]) -> bool {
        let (Some(up), Some((last, parent))) = (&self.upper, comps.split_last()) else { return false };
        let mut dir = up.clone();
        dir.extend(parent.iter().map(|c| enc(c)));
        exists(&dir.join(format!("{WHITEOUT}{}", enc(last)))) || (!parent.is_empty() && exists(&dir.join(OPAQUE)))
    }

    fn in_lower(&self, comps: &[String]) -> bool {
        if self.mount_of(comps).is_some() {
            return false; // a volume hides what the image had there
        }
        let mut lower = self.root.clone();
        lower.extend(comps.iter().map(|c| enc(c)));
        // The image's listing first (cached, and most entries a container removes are its own): only an
        // entry the image has needs the whiteout walk.
        self.upper.is_some() && lower_attrs(&lower).is_some() && !self.hidden(comps)
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
            match if dir { fs::remove_dir_all(&upper) } else { fs::remove_file(&upper) } {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {} // only the image has it
                r => r.map_err(errno)?,
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
    fn list(&self, comps: &[String]) -> Result<Vec<(String, u8)>, i64> {
        if self.mount_of(comps).is_some() {
            let rd = fs::read_dir(self.host(comps)).map_err(errno)?;
            return Ok(rd.flatten().map(|e| (dec(&e.file_name().to_string_lossy()), d_type(&e))).collect());
        }
        let mut out: Vec<(String, u8)> = Vec::new();
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
                        out.push((name, d_type(&e)));
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
                        out.push((name, d_type(&e)));
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
        self.resolve_attrs(dir, path, follow).map(|(g, h, _)| (g, h))
    }

    /// resolve, also giving the result's attributes (None: it doesn't exist), as the lookup found them.
    fn resolve_attrs(&self, dir: &str, path: &str, follow: bool) -> Result<(String, PathBuf, Option<Attrs>), i64> {
        if path.is_empty() {
            return Err(ENOENT);
        }
        if path.len() >= 4096 || path.split('/').any(|c| c.len() > 255) {
            return Err(ENAMETOOLONG); // PATH_MAX, NAME_MAX
        }
        // A trailing slash names a directory: a symlink there is followed, and a file is ENOTDIR.
        let want_dir = path.ends_with('/') && path.trim_end_matches('/') != "" && path.trim_end_matches('/') != ".";
        let follow = follow || want_dir;
        let mut todo = split(path);
        let mut comps: Vec<String> = if path.starts_with('/') { vec![] } else { split(dir).into() };
        let mut hops = 0;
        let mut last: Option<(PathBuf, Option<Attrs>)> = None; // host_meta(comps), when the loop already worked it out
        // Whether the upper layer has no directory at comps (the parent of the next component): then it
        // holds nothing below it either, no entries and no whiteouts, and only the image needs asking.
        // Most lookups are of image files, and this saves ~3 of ~4 host calls per component.
        let mut not_in_upper = false;
        // Whether comps (the next component's parent) was just found: then only that last level can
        // hide the next one, and hidden() needn't walk the whole path again (~3 host calls per level);
        // and if it wasn't, nothing below it exists either.
        let mut seen = true;
        while let Some(c) = todo.pop_front() {
            last = None;
            match c.as_str() {
                "." => continue,
                ".." => { comps.pop(); not_in_upper = false; seen = true; continue }
                _ if c.contains('\0') => return Err(ENOENT), // `:` and `\` are fine: enc() maps them
                // Layer bookkeeping names are ours; the guest can't see or forge whiteouts.
                _ if c.starts_with(WHITEOUT) && self.upper.is_some() => return Err(ENOENT),
                _ => comps.push(c),
            }
            if !todo.is_empty() || follow {
                let (host, meta) = self.host_meta_below(&comps, not_in_upper, Some(seen));
                seen = meta.is_some();
                not_in_upper = self.upper.as_ref().is_some_and(|u| !host.starts_with(u)) && self.mount_of(&comps).is_none();
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
                    not_in_upper = false; // the link's parent may well be in the upper layer
                    seen = true; // and it was seen: it holds the link
                    let mut next = split(&target);
                    next.extend(todo.drain(..));
                    todo = next;
                } else {
                    // A path goes on only through a directory (or a mount, or /proc, /sys and /dev, which
                    // are made up after this): else creating /a/b would quietly make /a in the upper layer.
                    if !todo.is_empty() && !matches!(comps[0].as_str(), "proc" | "sys" | "dev") && self.mount_of(&comps).is_none() {
                        match &meta {
                            None => return Err(ENOENT),
                            Some(m) if !m.dir => return Err(ENOTDIR),
                            _ => {}
                        }
                    }
                    last = Some((host, meta));
                }
            }
        }
        let (host, meta) = last.unwrap_or_else(|| self.host_meta_below(&comps, not_in_upper, Some(seen)));
        if want_dir && meta.as_ref().is_some_and(|m| !m.dir) && self.mount_of(&comps).is_none() {
            return Err(ENOTDIR);
        }
        Ok((format!("/{}", comps.join("/")), host, meta))
    }

    /// host_meta(), knowing whether the upper layer lacks the parent directory: then only the image is
    /// asked (and a path in neither still maps into the upper layer, for creating it).
    fn host_meta_below(&self, comps: &[String], parent_not_in_upper: bool, parent: Option<bool>) -> (PathBuf, Option<Attrs>) {
        let Some(up) = self.upper.as_ref().filter(|_| parent_not_in_upper && self.mount_of(comps).is_none()) else {
            return self.host_meta_seen(comps, parent);
        };
        let mut lower = self.root.clone();
        lower.extend(comps.iter().map(|c| enc(c)));
        if let Some(m) = lower_attrs(&lower) {
            return (lower, Some(m));
        }
        let mut upper = up.clone();
        upper.extend(comps.iter().map(|c| enc(c)));
        (upper, None)
    }

    /// `/proc/{self,<pid>}/{exe,cwd,root}` as symlinks while resolving, so stat and open follow them
    /// (gosu stats /proc/self/exe). Only paths of exactly those three components are looked at.
    fn proc_self_link(&self, comps: &[String]) -> Option<String> {
        let [p, who, what] = comps else { return None };
        if p != "proc" || (who != "self" && crate::proc::host_pid(who.parse().ok()?) != crate::proc::pid()) {
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
        self.at_attrs(dirfd, path, follow).map(|(g, h, _)| (g, h))
    }

    fn at_attrs(&self, dirfd: u64, path: u64, follow: bool) -> Result<(String, PathBuf, Option<Attrs>), i64> {
        let path = cstr(path)?;
        // An absolute path ignores dirfd, even an invalid one (mariadb passes -1).
        let dir = if path.starts_with('/') { String::new() } else { self.dir_of(dirfd)? };
        self.resolve_attrs(&dir, &path, follow)
    }

    fn fd(&mut self, fd: u64) -> Result<&mut Fd, i64> {
        self.fds.get_mut(fd as usize).and_then(|f| f.as_mut()).map(|s| &mut s.fd).ok_or(EBADF)
    }

    /// The lowest free fd from `min` on; EMFILE past the open-file limit.
    fn add(&mut self, fd: Fd, min: usize, cloexec: bool) -> R {
        let i = (min..self.fds.len()).find(|&i| self.fds[i].is_none()).unwrap_or(self.fds.len().max(min));
        if i as u64 >= nofile()[0] {
            return Err(crate::syscall::EMFILE);
        }
        if self.fds.len() <= i {
            self.fds.resize_with(i + 1, || None);
        }
        self.fds[i] = Some(Slot { fd, cloexec });
        Ok(i as i64)
    }
}

/// Where a guest path lives on the host (symlinks followed): the ELF loader maps program files from it.
pub fn host_of(guest: &str) -> Option<PathBuf> {
    with(|fs| fs.resolve("/", guest, true).ok().map(|(_, h)| h))
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
            // Only epolls that would survive exec travel: php-fpm's workers share the master's (no CLOEXEC);
            // copying Go's CLOEXEC netpoller epoll into its fork children made `go run` hang.
            // ponytail: why the copy hangs Go is not understood yet.
            if s.cloexec && matches!(s.fd, Fd::Epoll(_)) { continue }
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
        Fd::Pipe(p) => ("p", p.raw() as usize, p.extra()),
        Fd::File { f, host } => ("f", f.as_raw_handle() as usize, host.to_string_lossy().into_owned()),
        Fd::Dir { guest, .. } => ("d", 0, guest.clone()),
        Fd::Dev(d) => (d.tag(), 0, String::new()),
        Fd::Socket(k) => ("s", k.s, k.inherit_tag()),
        // An equal epoll over the same fd numbers (Linux shares the instance; see net::epoll_export).
        Fd::Epoll(e) => ("e", 0, crate::net::epoll_export(e)),
        // An eventfd or signalfd goes over as a copy of its state, not shared (Linux shares it): the fd
        // number stays taken, or the child's next file would get it and receive the eventfd's writes
        // (curl's wakeups landed in pacman's download). ponytail: no wakeups across the processes.
        Fd::Event(e) => ("v", 0, e.export()),
        Fd::Signal(s) => ("g", 0, format!("{}:{}", s.mask.load(Relaxed), s.nonblock.load(Relaxed) as u8)),
    })
}

fn import_counter(kind: &str, extra: &str) -> Option<Fd> {
    Some(match kind {
        "v" => Fd::Event(Arc::new(EventFd::import(extra)?)),
        _ => {
            let (mask, nb) = extra.split_once(':')?;
            let s = crate::signal::SignalFd { mask: mask.parse::<u64>().ok()?.into(), nonblock: (nb == "1").into() };
            Fd::Signal(Arc::new(s))
        }
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
        "p" => Fd::Pipe(Arc::new(Pipe::inherited(h, extra))),
        "f" => Fd::File { f: unsafe { File::from_raw_handle(h as _) }, host: PathBuf::from(extra) },
        "d" => Fd::Dir { guest: extra.to_string(), pos: 0 },
        "null" => Fd::Dev(Dev::Null),
        "zero" => Fd::Dev(Dev::Zero),
        "random" => Fd::Dev(Dev::Random),
        "e" => Fd::Epoll(Arc::new(Mutex::new(crate::net::epoll_import(extra)))),
        "s" => Fd::Socket(Arc::new(Sock::inherited(h, extra))),
        "v" | "g" => import_counter(kind, extra).ok_or(EINVAL)?,
        _ => return Err(EINVAL),
    };
    add_fd(fd, cloexec)
}

/// Rebuild the fd table from `proc_state` fields (in the new lx). Returns the unparsed rest.
pub fn init_from(fields: &[String]) -> Result<&[String], String> {
    // Seen once and not again: say what was off, so a recurrence can be pinned down.
    let total = fields.len();
    let bad = || format!("malformed process state ({total} fields)");
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
    for _ in 0..n.parse::<usize>().map_err(|_| format!("{}: fd count {n:?}", bad()))? {
        let at = total - rest.len();
        let [fd, kind, h, path, cloexec, more @ ..] = rest else { return Err(format!("{}: fd entry at field {at} cut short", bad())) };
        let fd: usize = fd.parse().map_err(|_| format!("{}: fd number {fd:?} at field {at}", bad()))?;
        let h: usize = h.parse().map_err(|_| format!("{}: handle {h:?} at field {}", bad(), at + 2))?;
        let fd_ = match kind.as_str() {
            "h" => Fd::Handle(unsafe { OwnedHandle::from_raw_handle(own(h, &mut seen) as _) }),
            "p" => Fd::Pipe(pipes.entry(h).or_insert_with(|| Arc::new(Pipe::inherited(h, path))).clone()),
            "f" => Fd::File { f: unsafe { File::from_raw_handle(own(h, &mut seen) as _) }, host: PathBuf::from(path) },
            "d" => Fd::Dir { guest: path.clone(), pos: 0 },
            "null" => Fd::Dev(Dev::Null),
            "zero" => Fd::Dev(Dev::Zero),
            "random" => Fd::Dev(Dev::Random),
            "e" => Fd::Epoll(Arc::new(Mutex::new(crate::net::epoll_import(path)))),
            "v" | "g" => import_counter(kind, path).ok_or_else(bad)?,
            "s" => Fd::Socket(socks.entry(h).or_insert_with(|| Arc::new(Sock::inherited(h, path))).clone()),
            _ => return Err(format!("{}: fd kind {kind:?} at field {}", bad(), at + 1)),
        };
        while fds.len() <= fd {
            fds.push(None);
        }
        fds[fd] = Some(Slot { fd: fd_, cloexec: cloexec == "1" });
        rest = more;
    }
    let upper = (!upper.is_empty()).then(|| PathBuf::from(upper));
    note_marked_roots(Path::new(root), upper.as_deref());
    *FS.lock().unwrap() = Some(Fs { root: PathBuf::from(root), upper, mounts, cwd: cwd.clone(), fds });
    Ok(rest)
}

/// Drop every fd (closing the handles). Used by a process that has exec'd and only waits now,
/// so it doesn't hold pipe ends open.
/// execve: fds marked FD_CLOEXEC go, the rest stay.
pub fn close_cloexec() {
    with(|fs| {
        for slot in fs.fds.iter_mut() {
            if slot.as_ref().is_some_and(|s| s.cloexec) {
                *slot = None;
            }
        }
    })
}

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
            0, 1, 65536, 1 << 20, 0, std::ptr::null_mut()) // PIPE_TYPE_BYTE | PIPE_WAIT, one instance; see write_room
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
    let own = |h: isize| Fd::Pipe(Arc::new(Pipe { h: unsafe { OwnedHandle::from_raw_handle(h as _) }, nonblock: nonblock.into(), pty: None, rearm: AtomicU32::new(0), full: false.into() }));
    let cloexec = flags & O_CLOEXEC != 0;
    let (r, w) = (own(r), own(w));
    let (a, b) = with(|fs| {
        let a = fs.add(r, 0, cloexec)?;
        fs.add(w, 0, cloexec).inspect_err(|_| fs.fds[a as usize] = None).map(|b| (a, b))
    })?;
    unsafe { *(fds as *mut [i32; 2]) = [a as i32, b as i32] };
    Ok(0)
}

/// An fd reading an internal pipe whose write end the caller keeps (inotify's events). Returns the fd
/// and the write end.
pub fn internal_pipe(flags: u64) -> Result<(i64, OwnedHandle), i64> {
    use crate::win::*;
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name: Vec<u16> = format!("\\\\.\\pipe\\lx-int-{}-{n}", unsafe { GetCurrentProcessId() }).encode_utf16().chain([0]).collect();
    // Overlapped inbound end for the fd (like pipe2's), synchronous write end for the writer.
    let r = unsafe { CreateNamedPipeW(name.as_ptr(), 0x1 | 0x4000_0000 | 0x0008_0000, 0, 1, 65536, 65536, 0, std::ptr::null_mut()) };
    if r == -1 {
        return Err(EIO);
    }
    let w = unsafe { CreateFileW(name.as_ptr(), 0x4000_0000, 0, std::ptr::null_mut(), 3, 0, 0) };
    if w == -1 {
        unsafe { CloseHandle(r) };
        return Err(EIO);
    }
    let p = Pipe { h: unsafe { OwnedHandle::from_raw_handle(r as _) }, nonblock: (flags & O_NONBLOCK != 0).into(), pty: None, rearm: AtomicU32::new(0), full: false.into() };
    let w = unsafe { OwnedHandle::from_raw_handle(w as _) };
    Ok((add_fd(Fd::Pipe(Arc::new(p)), flags & O_CLOEXEC != 0)?, w))
}

/// The pipe handle behind `fd` (inotify finds its instance by it).
pub fn pipe_raw(fd: u64) -> Result<isize, i64> {
    with(|fs| match fs.fd(fd)? {
        Fd::Pipe(p) => Ok(p.raw()),
        _ => Err(EINVAL),
    })
}

/// What an inotify watch on guest `path` watches: the host directory where changes made in the container
/// land (its upper-layer copy, made if needed, or the volume's), and for a file, its name in there.
pub fn watch_target(path: u64) -> Result<(PathBuf, Option<String>), i64> {
    with(|fs| {
        let (guest, host) = fs.resolve(&fs.cwd.clone(), &cstr(path)?, true)?;
        let m = attrs(&host).ok_or(ENOENT)?;
        let comps = comps_of(&guest);
        let (dir, name) = if m.dir { (comps.as_slice(), None) } else { (&comps[..comps.len().saturating_sub(1)], comps.last().cloned()) };
        let host_dir = fs.writable(dir, false)?;
        fs::create_dir_all(&host_dir).map_err(errno)?; // an image directory gets its (empty) upper copy
        Ok((host_dir, name))
    })
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
    Epoll(Arc<Mutex<crate::net::Epoll>>),
}

fn io_target(fd: u64) -> Result<Io, i64> {
    with(|fs| match fs.fd(fd)? {
        Fd::Dev(d) => Ok(Io::Dev(*d)),
        Fd::Socket(s) => Ok(Io::Sock(s.clone())),
        Fd::Event(e) => Ok(Io::Event(e.clone())),
        Fd::Signal(s) => Ok(Io::Signal(s.clone())),
        Fd::Pipe(p) => Ok(Io::Pipe(p.clone())),
        Fd::Epoll(e) => Ok(Io::Epoll(e.clone())),
        other => handle(other).map(Io::Handle),
    })
}

pub fn read(fd: u64, buf: u64, len: u64) -> R {
    let target = io_target(fd)?;
    if let Io::Pipe(p) = &target {
        p.rearm.fetch_or(1, Relaxed); // POLLIN: see Pipe::rearm
    }
    match target {
        Io::Handle(h) if is_console(h) => read_console(h, buf, len),
        Io::Handle(h) => read_handle(h, buf, len),
        Io::Pipe(p) if p.is_pts() => pts_read(&p, buf, len),
        // A master whose slave has hung up: EIO, as Linux has it (script and sshd wait for that).
        Io::Pipe(p) if p.pty.is_some() => p.io(buf, len, false).and_then(|n| if n == 0 && len > 0 { Err(EIO) } else { Ok(n) }),
        Io::Pipe(p) => p.io(buf, len, false),
        Io::Sock(s) => s.recv(buf, len, 0),
        Io::Event(e) => {
            e.rearm.store(1, Relaxed);
            e.read(buf, len)
        }
        Io::Signal(s) => s.read(buf, len),
        Io::Dev(Dev::Null) => Ok(0),
        Io::Dev(Dev::Zero) => {
            unsafe { guest_mut(buf, len as usize) }.fill(0);
            Ok(len as i64)
        }
        Io::Dev(Dev::Random) => crate::syscall::getrandom(buf, len),
        Io::Epoll(_) => Err(EINVAL),
    }
}

pub fn write(fd: u64, buf: u64, len: u64) -> R {
    match io_target(fd)? {
        Io::Handle(h) => write_handle(h, buf, len),
        Io::Pipe(p) if p.is_pts() => pts_write(&p, buf, len),
        Io::Pipe(p) => p.io(buf, len, true),
        Io::Sock(s) => s.send(buf, len, 0),
        Io::Dev(_) => Ok(len as i64), // devices swallow writes
        Io::Event(e) => e.write(buf, len),
        Io::Signal(_) | Io::Epoll(_) => Err(EINVAL),
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

/// Whether fd is a regular file or directory (never "not ready", so epoll refuses it).
pub fn is_file(fd: u64) -> bool {
    with(|fs| matches!(fs.fd(fd), Ok(Fd::File { .. } | Fd::Dir { .. })))
}

/// The poll bits whose edge re-arms on fd (a pipe or eventfd) since the last call: POLLIN after a read,
/// POLLOUT after a write that found no room.
pub fn take_rearm(fd: i32) -> u32 {
    with(|fs| match fs.fd(fd as u64) {
        Ok(Fd::Pipe(p)) => p.rearm.swap(0, Relaxed),
        Ok(Fd::Event(e)) => e.rearm.swap(0, Relaxed),
        _ => 0,
    })
}

/// RLIMIT_NOFILE as [soft, hard]. The default is Docker's 1024 soft limit (apt and others fcntl every fd
/// number up to it); what setrlimit sets goes to later lx processes (fork, exec) in LX_NOFILE.
static NOFILE: Mutex<Option<[u64; 2]>> = Mutex::new(None);

pub fn nofile() -> [u64; 2] {
    *NOFILE.lock().unwrap().get_or_insert_with(|| {
        let v = std::env::var("LX_NOFILE").unwrap_or_default();
        match v.split(' ').filter_map(|x| x.parse().ok()).collect::<Vec<u64>>()[..] {
            [cur, max] => [cur, max],
            _ => [1024, 1 << 20],
        }
    })
}

pub fn set_nofile(cur: u64, max: u64) -> R {
    if cur > max {
        return Err(EINVAL);
    }
    if max > nofile()[1] {
        return Err(crate::syscall::EPERM); // raising the hard limit takes CAP_SYS_RESOURCE, which Docker doesn't give
    }
    *NOFILE.lock().unwrap() = Some([cur, max]);
    unsafe { std::env::set_var("LX_NOFILE", format!("{cur} {max}")) };
    Ok(0)
}

pub fn add_fd(fd: Fd, cloexec: bool) -> R {
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
        Ok(Io::Epoll(e)) => if crate::net::epoll_ready(&e) { events & POLLIN } else { 0 },
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
    let req = req as u32 as u64; // an int: musl's sign-extends requests with the top bit set (TIOCGPTN)
    if req == FIOCLEX || req == FIONCLEX {
        return fcntl(fd, 2, (req == FIOCLEX) as u64); // F_SETFD
    }
    match (req, io_target(fd)?) {
        (FIOASYNC, _) => Ok(0), // ponytail: no SIGIO; nginx's channels work without it
        (FIONBIO, Io::Sock(s)) => {
            s.set_nonblocking(unsafe { *(arg as *const i32) } != 0);
            Ok(0)
        }
        // Python's os.set_blocking uses FIONBIO, not F_SETFL: pipes and eventfds take it the same way.
        (FIONBIO, Io::Pipe(p)) => {
            p.nonblock.store(unsafe { *(arg as *const i32) } != 0, std::sync::atomic::Ordering::Relaxed);
            Ok(0)
        }
        (FIONBIO, Io::Event(e)) => {
            e.nonblock.store(unsafe { *(arg as *const i32) } != 0, std::sync::atomic::Ordering::Relaxed);
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
        (0x8910..=0x89ff, Io::Sock(_)) => crate::net::if_ioctl(req, arg), // SIOCGIF*
        (_, Io::Handle(h)) if is_console(h) => tty_ioctl(h, req, arg),
        (_, Io::Pipe(p)) if p.pty.is_some() => pty_ioctl(&p, req, arg),
        _ => Err(crate::syscall::ENOTTY),
    }
}

// ---- the console as the container's terminal ----
// The guest's termios is kept here and mapped onto the console's modes: ICANON is line input, ECHO is
// echo, ISIG is Ctrl-C as a signal, and raw mode reads VT sequences (arrows, ...) like a Linux tty.
// ponytail: one termios per lx process (an exec starts from the defaults again), and the console's mode
// isn't restored if the guest dies in raw mode; no /dev/tty or ttyname.

const ICRNL: u32 = 0o400;
const ISIG: u32 = 1;
const ICANON: u32 = 2;
const ECHO: u32 = 0o10;

/// struct termios as TCGETS has it: iflag, oflag, cflag, lflag, c_line, c_cc[19]. Starts as a fresh
/// Linux tty: ICRNL|IXON, OPOST|ONLCR, B38400|CS8|CREAD, ISIG|ICANON|ECHO|ECHOE|ECHOK|ECHOCTL|ECHOKE|IEXTEN.
const DEFAULT_TERMIOS: [u32; 9] = [
    ICRNL | 0o2000, 0o5, 0o277, 0o105073,
    // c_line 0; ^C ^\ DEL ^U ^D, VTIME 0, VMIN 1; VSWTC 0, ^Q ^S ^Z, VEOL 0; ^R ^O ^W ^V, VEOL2 0.
    0x7f1c_0300, 0x0100_0415, 0x1a13_1100, 0x170f_1200, 0x0000_0016,
];
static TERMIOS: Mutex<[u32; 9]> = Mutex::new(DEFAULT_TERMIOS);

/// Let the console interpret the escape sequences a Linux terminal does (colors, cursor moves), on
/// stdout and stderr; the console keeps this mode for every process of the container.
pub fn console_vt() {
    for std in [-11i32, -12] {
        let (h, mut mode) = (unsafe { crate::win::GetStdHandle(std as u32) }, 0);
        if unsafe { crate::win::GetConsoleMode(h, &mut mode) } != 0 {
            unsafe { crate::win::SetConsoleMode(h, mode | 4) }; // ENABLE_VIRTUAL_TERMINAL_PROCESSING
        }
    }
}

fn is_console(h: isize) -> bool {
    let mut mode = 0;
    unsafe { crate::win::GetConsoleMode(h, &mut mode) != 0 }
}

/// This process's termios, with ISIG/ICANON/ECHO as the console has them now: the console's mode is
/// what the container's processes share (`stty raw` runs in a process of its own).
fn termios() -> [u32; 9] {
    let mut t = *TERMIOS.lock().unwrap();
    let mut mode = 0;
    if unsafe { crate::win::GetConsoleMode(crate::win::GetStdHandle(-10i32 as u32), &mut mode) } != 0 {
        t[3] &= !(ISIG | ICANON | ECHO);
        t[3] |= [(1, ISIG), (2, ICANON), (4, ECHO)].iter().filter(|(m, _)| mode & m != 0).fold(0, |f, (_, b)| f | b);
    }
    t
}

fn tty_ioctl(h: isize, req: u64, arg: u64) -> R {
    const TCGETS: u64 = 0x5401;
    const TCSETS: u64 = 0x5402; // TCSETSW and TCSETSF follow: the console has nothing to drain or flush
    const TIOCSCTTY: u64 = 0x540E;
    const TIOCGPGRP: u64 = 0x540F;
    const TIOCSPGRP: u64 = 0x5410;
    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCSWINSZ: u64 = 0x5414;
    match req {
        TCGETS => {
            unsafe { *(arg as *mut [u32; 9]) = termios() };
            Ok(0)
        }
        TCSETS..=0x5404 => {
            let t = unsafe { *(arg as *const [u32; 9]) };
            *TERMIOS.lock().unwrap() = t;
            let input = unsafe { crate::win::GetStdHandle(-10i32 as u32) };
            let (lflag, mut mode) = (t[3], 0u32);
            if lflag & ISIG != 0 {
                mode |= 1; // ENABLE_PROCESSED_INPUT
            }
            if lflag & ICANON != 0 {
                mode |= 2 | if lflag & ECHO != 0 { 4 } else { 0 }; // ENABLE_LINE_INPUT, ENABLE_ECHO_INPUT
            } else {
                mode |= 0x200; // ENABLE_VIRTUAL_TERMINAL_INPUT
            }
            if is_console(input) {
                unsafe { crate::win::SetConsoleMode(input, mode) };
            }
            Ok(0)
        }
        TIOCGWINSZ => {
            let mut info = [0i16; 11];
            let out = [h, unsafe { crate::win::GetStdHandle(-11i32 as u32) }];
            if !out.iter().any(|&o| unsafe { crate::win::GetConsoleScreenBufferInfo(o, &mut info) } != 0) {
                info[5..9].copy_from_slice(&[0, 0, 79, 23]); // only an input console: say 80x24
            }
            let (rows, cols) = (info[8] - info[6] + 1, info[7] - info[5] + 1); // srWindow
            unsafe { *(arg as *mut [u16; 4]) = [rows as u16, cols as u16, 0, 0] };
            Ok(0)
        }
        TIOCGPGRP => {
            unsafe { *(arg as *mut i32) = crate::proc::getpgid(0).unwrap_or(0) as i32 };
            Ok(0)
        }
        TIOCSCTTY | TIOCSPGRP | TIOCSWINSZ => Ok(0),
        _ => Err(EINVAL),
    }
}

// ---- pseudo terminals: /dev/ptmx and /dev/pts/N ----
// A pty is one duplex named pipe, named after the container and the pty's number: the master holds the
// server end, and opening /dev/pts/N connects to it from any of the container's processes.
// ponytail: the line discipline is ONLCR on the slave's output, ICRNL, ECHO and ^C on its input: no line
// editing or buffering until a newline. A slave opens once; termios and the window size are per process.

static PTY_TERMIOS: Mutex<[u32; 9]> = Mutex::new(DEFAULT_TERMIOS);
static PTY_WINSZ: Mutex<[u16; 4]> = Mutex::new([24, 80, 0, 0]);

fn pts_pipe(n: u32) -> Vec<u16> {
    let root = std::env::var("LX_IN_JOB").unwrap_or_else(|_| std::process::id().to_string());
    format!("\\\\.\\pipe\\lx-pts-{root}-{n}").encode_utf16().chain([0]).collect()
}

/// A pty as stat shows it: /dev/pts/N is char device 136:N, the master (or None) /dev/ptmx, 5:2. The same
/// for a path and an open fd, so ttyname's check that the two match holds.
/// ponytail: /dev/pts/N stats as present whether or not that pty exists.
fn pty_stat(pty: Option<(u32, bool)>) -> [u64; 18] {
    let mut s = [0u64; 18];
    let (rdev, mode) = match pty {
        Some((n, false)) => ((136 << 8) | n as u64, 0o020620),
        _ => ((5 << 8) | 2, 0o020666),
    };
    (s[1], s[2], s[3], s[5], s[7]) = (0x10000 + rdev, 1, mode, rdev, 4096);
    s
}

fn add_pty(h: isize, n: u32, master: bool, flags: u64) -> R {
    let p = Pipe { h: unsafe { OwnedHandle::from_raw_handle(h as _) }, nonblock: (flags & O_NONBLOCK != 0).into(), pty: Some((n, master)), rearm: AtomicU32::new(0), full: false.into() };
    add_fd(Fd::Pipe(Arc::new(p)), flags & O_CLOEXEC != 0)
}

fn open_ptmx(flags: u64) -> R {
    use crate::win::*;
    for n in 0..256 {
        // PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE; byte mode, one instance.
        let h = unsafe { CreateNamedPipeW(pts_pipe(n).as_ptr(), 0x3 | 0x4000_0000 | 0x0008_0000, 0, 1, 65536, 65536, 0, std::ptr::null_mut()) };
        if h != -1 {
            return add_pty(h, n, true, flags);
        }
    }
    Err(crate::syscall::EAGAIN)
}

fn open_pts(n: u32, flags: u64) -> R {
    use crate::win::*;
    // GENERIC_READ | GENERIC_WRITE, OPEN_EXISTING, FILE_FLAG_OVERLAPPED
    let h = unsafe { CreateFileW(pts_pipe(n).as_ptr(), 0xC000_0000, 0, std::ptr::null_mut(), 3, 0x4000_0000, 0) };
    if h == -1 {
        let err = unsafe { GetLastError() };
        // The one slave connection is taken. If it's ours (apt opens the slave, forks, and the child
        // opens it again to make it its terminal), the new fd shares it.
        return with(|fs| {
            let mine = fs.fds.iter().flatten().find(|s| matches!(&s.fd, Fd::Pipe(p) if p.pty == Some((n, false))));
            let new = dup_fd(&mine.ok_or(if err == 2 { ENOENT } else { EIO })?.fd)?;
            fs.add(new, 0, flags & O_CLOEXEC != 0)
        });
    }
    add_pty(h, n, false, flags)
}

// ---- FIFOs ----
// mknod S_IFIFO leaves a marker file (stat shows a FIFO). Opening one is a named pipe named after the
// marker: a reader listens there (see fifo_reader) and, unless O_NONBLOCK, waits for a writer, as on
// Linux; a writer connects to a reader, waiting for one (O_NONBLOCK: ENXIO). O_RDWR reads, without waiting.

/// mknod/mknodat: regular files and FIFOs; device nodes and sockets: EPERM.
pub fn mknodat(dirfd: u64, path: u64, mode: u64) -> R {
    match mode & 0o170000 {
        0 | 0o100000 => close(openat(dirfd, path, O_CREAT | O_EXCL | 1 | O_CLOEXEC, mode)? as u64),
        0o010000 => with(|fs| {
            let (guest, host) = fs.at(dirfd, path, false)?;
            if exists(&host) {
                return Err(EEXIST);
            }
            let host = fs.writable(&comps_of(&guest), false)?;
            let mut id = DefaultHasher::new();
            (&host, std::process::id(), std::time::SystemTime::now()).hash(&mut id);
            fs::write(&host, [FIFO_MAGIC, &id.finish().to_le_bytes()].concat()).map_err(errno)?;
            mark(&host);
            if fs.keeps_meta(&comps_of(&guest)) {
                let _ = set_meta(&host, new_meta_in(&host, mode, false));
            }
            Ok(0)
        }),
        _ => Err(crate::syscall::EPERM),
    }
}

fn open_fifo(id: u64, flags: u64) -> R {
    use crate::win::*;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    let name: Vec<u16> = format!("\\\\.\\pipe\\lx-fifo-{id:x}").encode_utf16().chain([0]).collect();
    let nonblock = flags & O_NONBLOCK != 0;
    let wait = || {
        if crate::signal::deliverable() {
            return Err(crate::syscall::EINTR);
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
        Ok(())
    };
    let h = if flags & 3 == 1 {
        loop {
            // GENERIC_WRITE, OPEN_EXISTING: not found or busy until a reader waits.
            let h = unsafe { CreateFileW(name.as_ptr(), 0x4000_0000, 0, std::ptr::null_mut(), 3, FILE_FLAG_OVERLAPPED, 0) };
            if h != -1 {
                break h;
            }
            // ERROR_PIPE_BUSY: a reader is there, its broker is between two writers.
            if nonblock && unsafe { GetLastError() } != 231 {
                return Err(crate::syscall::ENXIO);
            }
            wait()?;
        }
    } else {
        return fifo_reader(name, flags);
    };
    let p = Pipe { h: unsafe { OwnedHandle::from_raw_handle(h as _) }, nonblock: nonblock.into(), pty: None, rearm: AtomicU32::new(0), full: false.into() };
    add_fd(Fd::Pipe(Arc::new(p)), flags & O_CLOEXEC != 0)
}

/// A FIFO's reader. Writers connect to its named pipe, any number of them: a broker thread keeps an
/// instance listening and copies each writer's bytes into one internal pipe, which the reader's fd reads.
/// When the last writer has gone the reader gets EOF, unless it's O_RDWR (a writer itself), as on Linux.
/// ponytail: the broker lives in the opening process (a child inheriting the fd still reads what comes
/// while that process lives); writers that come after EOF get EPIPE instead of a new reader.
fn fifo_reader(name: Vec<u16>, flags: u64) -> R {
    use crate::win::*;
    use std::sync::atomic::AtomicUsize;
    static N: AtomicU32 = AtomicU32::new(0);
    let int: Vec<u16> = format!("\\\\.\\pipe\\lx-fifo-in-{}-{}", unsafe { GetCurrentProcessId() }, N.fetch_add(1, Relaxed))
        .encode_utf16().chain([0]).collect();
    // The internal pipe: an overlapped inbound end for the fd (like pipe2's), a synchronous write end.
    let r = unsafe { CreateNamedPipeW(int.as_ptr(), 0x1 | 0x4000_0000 | 0x0008_0000, 0, 1, 65536, 65536, 0, std::ptr::null_mut()) };
    if r == -1 {
        return Err(EIO);
    }
    let w = unsafe { CreateFileW(int.as_ptr(), 0x4000_0000, 0, std::ptr::null_mut(), 3, 0, 0) }; // GENERIC_WRITE, OPEN_EXISTING
    if w == -1 {
        unsafe { CloseHandle(r) };
        return Err(EIO);
    }
    let sink = Arc::new(Mutex::new(Some(unsafe { OwnedHandle::from_raw_handle(w as _) })));
    let writers = Arc::new(AtomicUsize::new(0));
    let rdwr = flags & 3 == 2;
    let (came, first) = std::sync::mpsc::channel::<()>();
    // Set once no writer may come any more (EOF given, or the reader closed): the broker stops listening.
    // ponytail: never closed (a copier may still set it), one handle per FIFO reader.
    let stop = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
    let end = move |sink: &mut Option<OwnedHandle>| {
        *sink = None;
        unsafe { SetEvent(stop) };
    };
    // One overlapped operation on `h`, waited for; with `stop`, given up when that's set (or the reader closed).
    let wait_io = move |h: isize, op: &mut Overlapped, started: bool, sink: Option<&Mutex<Option<OwnedHandle>>>| -> Option<u32> {
        if !started {
            match unsafe { GetLastError() } {
                997 => {}               // ERROR_IO_PENDING
                535 => return Some(0),  // ERROR_PIPE_CONNECTED: the writer came before we listened
                _ => return None,       // failed: a writer that left
            }
        }
        loop {
            let hs = [op.event, stop];
            match unsafe { WaitForMultipleObjects(if sink.is_some() { 2 } else { 1 }, hs.as_ptr(), 0, 100) } {
                0 => break,
                1 => {
                    unsafe { CancelIoEx(h, (op as *mut Overlapped).cast()) };
                    unsafe { GetOverlappedResult(h, (op as *mut Overlapped).cast(), &mut 0, 1) };
                    return None;
                }
                _ => {
                    // Has the reader closed? A zero-byte write to it fails then.
                    let Some(sink) = sink else { continue };
                    let mut g = sink.lock().unwrap();
                    let gone = g.as_ref().is_none_or(|w| unsafe { WriteFile(w.as_raw_handle() as isize, [0u8].as_ptr(), 0, &mut 0, std::ptr::null_mut()) } == 0);
                    if gone {
                        end(&mut g);
                    }
                }
            }
        }
        let mut n = 0u32;
        (unsafe { GetOverlappedResult(h, (op as *mut Overlapped).cast(), &mut n, 1) } != 0).then_some(n)
    };
    // Inbound, overlapped, byte mode, unlimited instances: the broker waits for one writer at a time. The
    // first one listens before open returns (s6-supervise opens its control FIFO for writing right after).
    let listen = move || unsafe { CreateNamedPipeW(name.as_ptr(), 0x1 | 0x4000_0000, 0, 255, 65536, 1 << 20, 0, std::ptr::null_mut()) };
    let mut next = listen();
    std::thread::spawn(move || loop {
        let inst = std::mem::replace(&mut next, -1);
        let inst = if inst == -1 { listen() } else { inst };
        if inst == -1 {
            return;
        }
        let mut o = Overlapped { internal: [0; 2], offset: 0, offset_high: 0, event: unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) } };
        let started = unsafe { ConnectNamedPipe(inst, (&mut o as *mut Overlapped).cast()) } != 0;
        let connected = wait_io(inst, &mut o, started, Some(&sink)).is_some();
        unsafe { CloseHandle(o.event) };
        if !connected || sink.lock().unwrap().is_none() {
            unsafe { CloseHandle(inst) };
            if sink.lock().unwrap().is_none() { return } else { continue }
        }
        writers.fetch_add(1, Relaxed);
        let _ = came.send(());
        let (sink, writers) = (sink.clone(), writers.clone());
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            let mut o = Overlapped { internal: [0; 2], offset: 0, offset_high: 0, event: unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) } };
            loop {
                let started = unsafe { ReadFile(inst, buf.as_mut_ptr(), buf.len() as u32, std::ptr::null_mut(), (&mut o as *mut Overlapped).cast()) } != 0;
                let Some(n) = wait_io(inst, &mut o, started, None).filter(|&n| n > 0) else { break }; // this writer closed
                let mut g = sink.lock().unwrap();
                let Some(w) = g.as_ref() else { break };
                if unsafe { WriteFile(w.as_raw_handle() as isize, buf.as_ptr(), n, &mut 0, std::ptr::null_mut()) } == 0 {
                    end(&mut g); // the reader is gone
                    break;
                }
            }
            unsafe { CloseHandle(o.event) };
            unsafe { CloseHandle(inst) };
            if writers.fetch_sub(1, Relaxed) == 1 && !rdwr {
                end(&mut sink.lock().unwrap()); // the last writer left: EOF
            }
        });
    });
    let fd = Pipe { h: unsafe { OwnedHandle::from_raw_handle(r as _) }, nonblock: (flags & O_NONBLOCK != 0).into(), pty: None, rearm: AtomicU32::new(0), full: false.into() };
    if flags & 3 == 0 && flags & O_NONBLOCK == 0 {
        // Linux's open waits for a writer.
        while first.recv_timeout(std::time::Duration::from_millis(5)).is_err() {
            if crate::signal::deliverable() {
                return Err(crate::syscall::EINTR); // dropping `fd` makes the broker stop at its next writer
            }
        }
    }
    add_fd(Fd::Pipe(Arc::new(fd)), flags & O_CLOEXEC != 0)
}

fn pty_ioctl(p: &Pipe, req: u64, arg: u64) -> R {
    const TCGETS: u64 = 0x5401;
    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCSWINSZ: u64 = 0x5414;
    const TIOCGPTPEER: u64 = 0x5441;
    const TIOCGPTN: u64 = 0x8004_5430;
    const TIOCSPTLCK: u64 = 0x4004_5431;
    let Some((n, master)) = p.pty else { return Err(crate::syscall::ENOTTY) };
    match req {
        TIOCGPTN if master => {
            unsafe { *(arg as *mut u32) = n };
            Ok(0)
        }
        TIOCSPTLCK => Ok(0),
        TIOCGPTPEER if master => open_pts(n, arg),
        TCGETS => {
            unsafe { *(arg as *mut [u32; 9]) = *PTY_TERMIOS.lock().unwrap() };
            Ok(0)
        }
        0x5402..=0x5404 => {
            *PTY_TERMIOS.lock().unwrap() = unsafe { *(arg as *const [u32; 9]) };
            Ok(0)
        }
        TIOCGWINSZ => {
            unsafe { *(arg as *mut [u16; 4]) = *PTY_WINSZ.lock().unwrap() };
            Ok(0)
        }
        TIOCSWINSZ => {
            *PTY_WINSZ.lock().unwrap() = unsafe { *(arg as *const [u16; 4]) };
            Ok(0)
        }
        _ => tty_ioctl(0, req, arg), // the process group calls
    }
}

/// The slave's input: with ICRNL, Enter's CR becomes LF; with ISIG, ^C is SIGINT to the reader; with
/// ECHO, what's read goes back out to the master.
fn pts_read(p: &Pipe, buf: u64, len: u64) -> R {
    let n = p.io(buf, len, false)?;
    let t = *PTY_TERMIOS.lock().unwrap();
    let data = unsafe { guest_mut(buf, n as usize) };
    if t[0] & ICRNL != 0 {
        data.iter_mut().filter(|b| **b == b'\r').for_each(|b| *b = b'\n');
    }
    let mut n = n as usize;
    let vintr = (t[4] >> 8) as u8; // c_cc[VINTR], after c_line
    if t[3] & ISIG != 0 && data.contains(&vintr) {
        // ponytail: to the reader's process group, taken to be the foreground one (TIOCSPGRP isn't kept).
        n = 0;
        for i in 0..data.len() {
            if data[i] != vintr {
                data[n] = data[i];
                n += 1;
            }
        }
        let _ = crate::proc::kill(0, 2);
        if n == 0 {
            return Err(crate::syscall::EINTR); // not EOF: a handler (SA_RESTART) reads on
        }
    }
    if t[3] & ECHO != 0 && n > 0 {
        // ponytail: echoed as is, no ECHOE erase or ECHOCTL ^X forms.
        let _ = pts_write(p, buf, n as u64);
    }
    Ok(n as i64)
}

/// The slave's output: with OPOST|ONLCR, LF goes out as CRLF.
fn pts_write(p: &Pipe, buf: u64, len: u64) -> R {
    const OPOST_ONLCR: u32 = 1 | 4;
    if PTY_TERMIOS.lock().unwrap()[1] & OPOST_ONLCR != OPOST_ONLCR {
        return p.io(buf, len, true);
    }
    let data = unsafe { std::slice::from_raw_parts(buf as *const u8, len as usize) };
    let mut out = Vec::with_capacity(data.len() * 2);
    for &b in data {
        if b == b'\n' {
            out.push(b'\r');
        }
        out.push(b);
    }
    // ponytail: a short write of the converted bytes counts as all of them.
    p.io(out.as_ptr() as u64, out.len() as u64, true).map(|_| len as i64)
}

/// A console read, the way a tty delivers it: with ICRNL, Enter's CR (and the console's CRLF in line
/// mode) becomes LF; a line holding just ^D is end of file, as on Linux.
fn read_console(h: isize, buf: u64, len: u64) -> R {
    let n = read_handle(h, buf, len)? as usize;
    let data = unsafe { guest_mut(buf, n) };
    let t = termios();
    if t[3] & ICANON != 0 && data.first() == Some(&4) {
        return Ok(0);
    }
    if t[0] & ICRNL == 0 {
        return Ok(n as i64);
    }
    let mut out = 0;
    for i in 0..n {
        if data[i] == b'\r' && data.get(i + 1) == Some(&b'\n') {
            continue;
        }
        data[out] = if data[i] == b'\r' { b'\n' } else { data[i] };
        out += 1;
    }
    Ok(out as i64)
}

/// poll/ppoll: pipes are checked with PeekNamedPipe, console input by waiting on it, sockets with
/// WSAPoll, files and devices are always ready. ponytail: re-checks in 1ms steps while nothing is ready.
pub fn poll(fds: u64, n: u64, timeout_ms: i64) -> R {
    if n > 1024 {
        return Err(EINVAL);
    }
    let _fine = crate::syscall::FineWait::for_ms(timeout_ms);
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
/// What a file mapping of fd may do, as the fd was opened: (read, write). EBADF without an fd, ENODEV
/// for one that can't be mapped (pipes, sockets, directories).
pub fn map_access(fd: u64) -> Result<(bool, bool), i64> {
    with(|fs| match fs.fd(fd)? {
        Fd::File { f, .. } => Ok(granted_access(f.as_raw_handle() as isize).map_or((true, true), |g| (g & 1 != 0, g & 2 != 0))),
        Fd::Dev(_) | Fd::Handle(_) => Ok((true, true)),
        _ => Err(crate::syscall::ENODEV),
    })
}

pub fn sendfile(out: u64, inp: u64, off: u64, count: u64) -> R {
    // The output must be open for writing even when there's nothing to send.
    if with(|fs| fs.fd(out).map(|d| matches!(d, Fd::File { f, .. } if !writable_handle(f))))? {
        return Err(EBADF);
    }
    if off != 0 {
        crate::syscall::check_guest(off, 8, true)?; // EFAULT for a bad offset pointer, not a fault
    }
    // Copy in 1 MB pieces until `count` is done, the input ends, the output takes less (a full socket)
    // or a signal comes; an error after some went is that much sent, as on Linux.
    let mut buf = vec![0u8; count.min(1 << 20) as usize];
    let start = if off != 0 { unsafe { *(off as *const u64) } } else { 0 };
    // What was read from a pipe or socket can't be given back, so it all goes out (below); reading no
    // more than an output pipe has room for keeps that from waiting (splice: socket -> pipe -> socket).
    let seekable = off != 0 || with(|fs| matches!(fs.fd(inp), Ok(Fd::File { .. })));
    let room = with(|fs| match fs.fd(out) {
        Ok(Fd::Pipe(p)) => p.write_room().filter(|&r| r > 0).map(u64::from),
        _ => None,
    });
    let mut total = 0u64;
    while total < count {
        let want = (count - total).min(buf.len() as u64).min(if seekable { u64::MAX } else { room.unwrap_or(u64::MAX) });
        let got = if off != 0 {
            pread(inp, buf.as_mut_ptr() as u64, want, start + total, false)
        } else {
            read(inp, buf.as_mut_ptr() as u64, want)
        };
        let n = match got {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if total == 0 => return Err(e),
            Err(_) => break,
        };
        let mut sent = 0i64;
        let err = loop {
            match write(out, buf.as_ptr() as u64 + sent as u64, (n - sent) as u64) {
                Ok(k) => {
                    sent += k;
                    if sent == n || seekable {
                        break None;
                    }
                }
                // ponytail: a full non-blocking output briefly blocks this call rather than lose the bytes.
                Err(crate::syscall::EAGAIN) if !seekable => std::thread::sleep(std::time::Duration::from_millis(1)),
                Err(e) => break Some(e),
            }
        };
        if let Some(e) = err {
            if off == 0 && seekable {
                let _ = lseek(inp, sent - n, 1); // give back what was read for nothing
            }
            if total == 0 && sent == 0 { return Err(e) }
            total += sent as u64;
            break;
        }
        total += sent as u64;
        if sent < n {
            if off == 0 {
                lseek(inp, sent - n, 1)?; // give back what the socket didn't take
            }
            break;
        }
        // A pipe or socket gives what it has; reading on would wait for more (Linux returns instead).
        if !seekable || crate::signal::deliverable() {
            break;
        }
    }
    if off != 0 {
        unsafe { *(off as *mut u64) = start + total };
    }
    Ok(total as i64)
}

/// pread64/pwrite64: I/O at an offset without moving the file position. NT's positioned I/O does
/// move it on synchronous handles, so put it back.
pub fn pread(fd: u64, buf: u64, len: u64, off: u64, write: bool) -> R {
    use std::os::windows::fs::FileExt;
    if (off as i64) < 0 {
        return Err(EINVAL);
    }
    with(|fs| {
        let f = match fs.fd(fd)? {
            Fd::File { f, .. } => f,
            Fd::Dir { .. } => return Err(EISDIR),
            _ => return Err(ESPIPE),
        };
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
            // Wrong direction for the fd (EBADF), or an unmapped guest buffer (EFAULT): as read/write report them.
            Err(e) if matches!(e.raw_os_error(), Some(5 | 998)) => Err(crate::syscall::io_errno(e.raw_os_error().unwrap() as u32)),
            Err(e) => Err(errno(e)),
        }
    })
}

/// An iovec array Linux accepts: at most IOV_MAX entries, and lengths that sum to no more than SSIZE_MAX.
fn check_iov(iov: u64, cnt: u64) -> Result<(), i64> {
    if cnt > 1024 {
        return Err(EINVAL);
    }
    let mut sum = 0u64;
    for i in 0..cnt {
        let [_, len] = unsafe { *((iov + i * 16) as *const [u64; 2]) };
        sum = sum.checked_add(len).filter(|&s| s <= i64::MAX as u64).ok_or(EINVAL)?;
    }
    Ok(())
}

pub fn readv(fd: u64, iov: u64, cnt: u64) -> R {
    check_iov(iov, cnt)?;
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
    check_iov(iov, cnt)?;
    if (off as i64) < 0 {
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
    check_iov(iov, cnt)?;
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

/// Make `f` sparse, so growing it with ftruncate leaves a hole, as on Linux, instead of NTFS allocating
/// the new size on disk. Best effort: a volume without sparse files just allocates.
fn set_sparse(f: &File) {
    unsafe extern "system" {
        fn DeviceIoControl(h: isize, code: u32, inb: *mut u8, inn: u32, outb: *mut u8, outn: u32, got: *mut u32, ov: *mut u8) -> i32;
    }
    const FSCTL_SET_SPARSE: u32 = 0x900C4;
    let mut got = 0u32;
    unsafe { DeviceIoControl(f.as_raw_handle() as isize, FSCTL_SET_SPARSE, std::ptr::null_mut(), 0, std::ptr::null_mut(), 0, &mut got, std::ptr::null_mut()) };
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
    set_sparse(&f); // CoreCLR ftruncates its memfd to 16 GB
    f.write_all(bytes)?;
    f.rewind()?;
    Ok((f, host))
}

pub fn openat(dirfd: u64, path: u64, flags: u64, mode: u64) -> R {
    const O_PATH: u64 = 0o10000000;
    // O_PATH ignores everything but these: no creating, truncating or access mode.
    let flags = if flags & O_PATH != 0 { flags & (O_PATH | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW) } else { flags };
    let cloexec = flags & O_CLOEXEC != 0;
    let (guest, host, meta) = with(|fs| fs.at_attrs(dirfd, path, flags & O_NOFOLLOW == 0))?;
    if let Some(n) = fd_alias(&guest) {
        return dup(n, 0, cloexec);
    }
    // O_NOFOLLOW on a symlink is ELOOP, not the link itself opened as a file (O_PATH may name it).
    if flags & O_NOFOLLOW != 0 && flags & 0o10000000 == 0 && meta.as_ref().is_some_and(|m| link_target(&host, m).is_some()) {
        return Err(ELOOP);
    }
    if let Some(id) = meta.and_then(|m| fifo_id(&host, &m)) {
        return open_fifo(id, flags); // outside the fs lock: it may wait for the other end
    }
    if guest == "/dev/tty" {
        return Err(crate::syscall::ENXIO); // no controlling terminal, like `docker run` without -t
    }
    if guest == "/dev/ptmx" {
        return open_ptmx(flags);
    }
    if let Some(n) = guest.strip_prefix("/dev/pts/").and_then(|n| n.parse().ok()) {
        return open_pts(n, flags);
    }
    with(|fs| {
        if let Some(d) = Dev::of(&guest) {
            return fs.add(Fd::Dev(d), 0, cloexec);
        }
        if let Some(text) = crate::procfs::file(&guest) {
            if flags & 3 != 0 { return Err(EACCES) } // ponytail: /proc/sys is read-only here
            let (f, host) = scratch_file(fs, text.as_bytes()).map_err(errno)?;
            return fs.add(Fd::File { f, host }, 0, cloexec);
        }
        let mut host = host;
        if proc_dir(&guest).is_some() {
            if flags & 3 != 0 { return Err(EISDIR) }
            return fs.add(Fd::Dir { guest, pos: 0 }, 0, cloexec);
        }
        if meta.is_none() && flags & O_CREAT == 0 {
            return Err(ENOENT); // the lookup just found nothing: no host open to fail
        }
        // An existing entry opens only as its mode allows the caller (O_TRUNC needs write too); O_PATH
        // only names it and needs nothing (fchdir, AT_EMPTY_PATH, a dirfd: Go's os.Root, find -execdir).
        if let Some(m) = &meta && flags & O_PATH == 0 && fs.keeps_meta(&comps_of(&guest)) {
            let want = match flags & 3 { 0 => 4, 1 => 2, _ => 6 } | if flags & O_TRUNC != 0 { 2 } else { 0 };
            if !may_access(&host, m, want) {
                return Err(EACCES);
            }
        }
        let is_dir = meta.is_some_and(|m| m.dir);
        let acc = flags & 3;
        let changes = acc != 0 || flags & (O_CREAT | O_TRUNC) != 0;
        if changes && !is_dir {
            // Copy the image's file up unless it's about to be truncated anyway.
            host = fs.writable(&split(&guest).into_iter().collect::<Vec<_>>(), flags & O_TRUNC == 0)?;
        }
        let fd = if is_dir {
            if acc != 0 { return Err(EISDIR) }
            Fd::Dir { guest, pos: 0 }
        } else {
            if flags & O_DIRECTORY != 0 {
                return Err(if meta.is_some() { ENOTDIR } else { ENOENT });
            }
            let excl = flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL;
            if acc == 0 && flags & O_CREAT != 0 {
                // O_RDONLY|O_CREAT is fine on Linux (Go's telemetry token); std only creates with write
                // access, so create it first, then open it read-only below.
                OpenOptions::new().write(true).create(true).create_new(excl).open(&host).map_err(errno)?;
            }
            let mut o = OpenOptions::new();
            if flags & O_PATH != 0 {
                // Only attributes (fstat), so read and write fail with EBADF as on Linux.
                use std::os::windows::fs::OpenOptionsExt;
                o.access_mode(0x80 | 0x8 | 0x10_0000); // FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE
            }
            let f = o
                .read(acc != 1)
                .write(acc != 0)
                .append(flags & O_APPEND != 0)
                .truncate(flags & O_TRUNC != 0 && acc != 0)
                .create(flags & O_CREAT != 0 && acc != 0)
                .create_new(excl && acc != 0)
                .open(&host)
                .map_err(errno)?;
            if flags & O_CREAT != 0 && meta.is_none() && fs.keeps_meta(&comps_of(&guest)) {
                let m = new_meta_in(&host, mode, false);
                forget(&METAS, &host);
                if !set_meta_on(f.as_raw_handle() as isize, m) {
                    let _ = set_meta(&host, m); // opened without FILE_WRITE_EA (read-only): by path
                }
            }
            Fd::File { f, host }
        };
        fs.add(fd, 0, cloexec)
    })
}

/// close_range(first, last, flags): close every fd in the range, or with CLOSE_RANGE_CLOEXEC just mark them.
pub fn close_range(first: u64, last: u64, flags: u64) -> R {
    const CLOSE_RANGE_UNSHARE: u64 = 2;
    const CLOSE_RANGE_CLOEXEC: u64 = 4;
    if first > last || flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 {
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
        if let Fd::File { f, host } = &s.fd {
            let h = f.as_raw_handle() as isize;
            LOCKS.lock().unwrap().retain(|l| l.0 != h); // NT drops the handle's locks with it
            forget_lock_via(h);
            drop_posix_locks(host);
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
// fcntl locks are the process's, per file: NT's belong to an open file, so they're all taken through one
// handle per file (a duplicate of the first locking fd's). SQLite's connections in one process share
// their locks this way, as on Linux (else one's SHARED lock blocks another's EXCLUSIVE: SQLITE_BUSY).
// Closing any fd of the file drops them, as on Linux. flock locks stay with the fd's open file.
// ponytail: the file is known by its host path (a hard link elsewhere is another file).

const SHADOW: u64 = 1 << 62;
const FLOCK_AT: u64 = 1 << 63;

/// Locks this process holds: (handle, start, len, exclusive), in shadow coordinates.
static LOCKS: Mutex<Vec<(isize, u64, u64, bool)>> = Mutex::new(Vec::new());

/// The handle each file's fcntl locks are taken through.
static LOCK_HANDLES: Mutex<Vec<(PathBuf, isize)>> = Mutex::new(Vec::new());

fn lock_handle(host: &Path, h: isize) -> isize {
    use crate::win::*;
    let mut handles = LOCK_HANDLES.lock().unwrap();
    if let Some(&(_, lh)) = handles.iter().find(|(p, _)| p == host) {
        return lh;
    }
    let mut lh = 0isize;
    unsafe { DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &mut lh, 0, 0, 2) }; // SAME_ACCESS
    handles.push((host.to_path_buf(), lh));
    lh
}

/// An fd of `host` was closed: the process's fcntl locks on it go.
fn drop_posix_locks(host: &Path) {
    let mut handles = LOCK_HANDLES.lock().unwrap();
    let Some(i) = handles.iter().position(|(p, _)| p == host) else { return };
    let (_, lh) = handles.swap_remove(i);
    LOCKS.lock().unwrap().retain(|&(h, s, l, _)| h != lh || {
        nt_unlock(lh, s, l);
        false
    });
    forget_lock_via(lh);
    unsafe { crate::win::CloseHandle(lh) };
}

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

/// LockFileEx wants read or write data access, which an append-only handle (O_WRONLY|O_APPEND, like
/// dnf's log) lacks: such a handle's locks are taken through a read handle on the same file instead,
/// (handle, read handle), until the handle is closed.
static LOCK_VIA: Mutex<Vec<(isize, isize)>> = Mutex::new(Vec::new());

fn lock_via(h: isize) -> isize {
    LOCK_VIA.lock().unwrap().iter().find(|v| v.0 == h).map_or(h, |v| v.1)
}

/// `h` is being closed: close its read handle too (which drops the locks held through it).
fn forget_lock_via(h: isize) {
    let mut via = LOCK_VIA.lock().unwrap();
    if let Some(i) = via.iter().position(|v| v.0 == h) {
        unsafe { crate::win::CloseHandle(via.swap_remove(i).1) };
    }
}

fn nt_try_lock(h: isize, start: u64, len: u64, excl: bool) -> bool {
    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 1;
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 2;
    let flags = LOCKFILE_FAIL_IMMEDIATELY | if excl { LOCKFILE_EXCLUSIVE_LOCK } else { 0 };
    let lock = |via: isize| {
        let mut o = ov(start);
        unsafe { crate::win::LockFileEx(via, flags, 0, len as u32, (len >> 32) as u32, (&mut o as *mut Overlapped).cast()) != 0 }
    };
    let via = lock_via(h);
    if lock(via) {
        return true;
    }
    if via != h || unsafe { crate::win::GetLastError() } != 5 {
        return false; // ERROR_LOCK_VIOLATION: someone holds it
    }
    // ERROR_ACCESS_DENIED: GENERIC_READ, sharing everything.
    let r = unsafe { crate::win::ReOpenFile(h, 0x8000_0000, 7, 0) };
    if r == -1 {
        return false;
    }
    LOCK_VIA.lock().unwrap().push((h, r));
    lock(r)
}

fn nt_unlock(h: isize, start: u64, len: u64) {
    let mut o = ov(start);
    unsafe { crate::win::UnlockFileEx(lock_via(h), 0, len as u32, (len >> 32) as u32, (&mut o as *mut Overlapped).cast()) };
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

// ---- who holds a POSIX lock (F_GETLK) ----
//
// NT's byte-range locks don't say who holds them, and F_GETLK must report the holder's type, range and
// pid (lslocks, "already running as pid N" checks, LTP fcntl11-21). Each process publishes its locks on
// a file in a small shared table named after it, rewritten after each change; readers skip entries of
// processes that have exited. ponytail: 64 entries per file (a lock past them goes unreported); keyed by
// path, so hard links to one file get separate tables.

const LOCK_SLOTS: usize = 64;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Published {
    start: u64,
    len: u64,
    /// Windows pid (0: free slot), for "still alive"; and the pid the guest sees.
    win: u32,
    pid: u32,
    excl: u32,
    _pad: u32,
}

/// The shared table for the file at `host` and the mutex guarding it (both kept open for the process).
fn lock_table(host: &Path) -> Option<(isize, &'static mut [Published; LOCK_SLOTS])> {
    use crate::win::*;
    unsafe extern "system" {
        fn CreateMutexW(attr: *mut std::ffi::c_void, owner: i32, name: *const u16) -> isize;
    }
    static TABLES: Mutex<Vec<(PathBuf, isize, usize)>> = Mutex::new(Vec::new());
    let mut tables = TABLES.lock().unwrap();
    if let Some(&(_, m, view)) = tables.iter().find(|(p, ..)| p == host) {
        return Some((m, unsafe { &mut *(view as *mut [Published; LOCK_SLOTS]) }));
    }
    let mut hasher = DefaultHasher::new();
    host.to_string_lossy().to_lowercase().hash(&mut hasher);
    let key = hasher.finish();
    let name = |k: &str| format!("Local\\lx-locks{k}-{key:016x}").encode_utf16().chain([0]).collect::<Vec<u16>>();
    let size = (LOCK_SLOTS * std::mem::size_of::<Published>()) as u32;
    unsafe {
        let map = CreateFileMappingW(-1, std::ptr::null_mut(), PAGE_READWRITE, 0, size, name("").as_ptr());
        let mutex = CreateMutexW(std::ptr::null_mut(), 0, name("-m").as_ptr());
        let view = if map != 0 { MapViewOfFile(map, FILE_MAP_WRITE, 0, 0, size as usize) } else { std::ptr::null_mut() };
        if view.is_null() || mutex == 0 {
            return None;
        }
        tables.push((host.to_path_buf(), mutex, view as usize));
        Some((mutex, &mut *(view as *mut [Published; LOCK_SLOTS])))
    }
}

/// Run `f` on the file's table with its mutex held.
fn with_lock_table<T>(host: &Path, f: impl FnOnce(&mut [Published; LOCK_SLOTS]) -> T) -> Option<T> {
    unsafe extern "system" {
        fn ReleaseMutex(m: isize) -> i32;
    }
    let (m, table) = lock_table(host)?;
    let w = unsafe { crate::win::WaitForMultipleObjects(1, &m, 0, 2000) };
    if w != 0 && w != 0x80 { // WAIT_OBJECT_0, or WAIT_ABANDONED: its last holder died, the table is still ours to use
        return None;
    }
    let r = f(table);
    unsafe { ReleaseMutex(m) };
    Some(r)
}

/// Publish this process's current locks on the file at `host` (taken through lock handle `h`).
fn publish_locks(host: &Path, h: isize) {
    let me = std::process::id();
    let pid = crate::proc::getpid().unwrap_or(0) as u32;
    let mine: Vec<(u64, u64, bool)> = LOCKS.lock().unwrap().iter().filter(|l| l.0 == h).map(|&(_, s, l, x)| (s, l, x)).collect();
    // A hot path (SQLite locks and unlocks several times per transaction): only our own entries are
    // rewritten, with no kernel calls; dead processes' entries are swept only when the table is full.
    with_lock_table(host, |t| {
        for e in t.iter_mut().filter(|e| e.win == me) {
            *e = Published::default();
        }
        if t.iter().filter(|e| e.win == 0).count() < mine.len() {
            for e in t.iter_mut().filter(|e| e.win != 0 && !alive(e.win)) {
                *e = Published::default();
            }
        }
        let mut free = t.iter_mut().filter(|e| e.win == 0);
        for (s, l, x) in mine {
            let Some(e) = free.next() else { break };
            *e = Published { start: s - SHADOW, len: l, win: me, pid, excl: x as u32, _pad: 0 };
        }
    });
}

/// Another live process's published lock on `host` that conflicts with [start, start+len) (`excl`: we
/// want a write lock): (start, len, pid, its excl).
fn lock_holder(host: &Path, start: u64, len: u64, excl: bool) -> Option<(u64, u64, u32, bool)> {
    let me = std::process::id();
    with_lock_table(host, |t| {
        // The first conflicting one by start, as Linux reports it.
        t.iter().filter(|e| e.win != 0 && e.win != me && e.start < start + len && start < e.start + e.len
                && (excl || e.excl != 0) && alive(e.win))
            .min_by_key(|e| e.start)
            .map(|e| (e.start, e.len, e.pid, e.excl != 0))
    }).flatten()
}

fn alive(win: u32) -> bool {
    use crate::win::*;
    let h = unsafe { OpenProcess(0x0010_0000, 0, win) }; // SYNCHRONIZE
    if h == 0 {
        return false;
    }
    let running = unsafe { WaitForMultipleObjects(1, &h, 0, 0) } != 0;
    unsafe { CloseHandle(h) };
    running
}

fn holds(h: isize, start: u64, len: u64) -> bool {
    LOCKS.lock().unwrap().iter().any(|&(lh, s, l, _)| lh == h && s < start + len && start < s + l)
}

/// struct flock { short l_type, l_whence; off_t l_start, l_len; pid_t l_pid; }
fn posix_lock(fd: u64, cmd: u64, arg: u64) -> R {
    const F_RDLCK: i16 = 0;
    const F_WRLCK: i16 = 1;
    const F_UNLCK: i16 = 2;
    crate::syscall::check_guest(arg, 32, true)?; // struct flock, before the fd, as Linux copies it in first
    let (h, pos, size, host) = with(|fs| match fs.fd(fd)? {
        Fd::File { f, host } => {
            let pos = f.stream_position().unwrap_or(0);
            let size = f.metadata().map(|m| m.len()).unwrap_or(0);
            Ok((lock_handle(host, f.as_raw_handle() as isize), pos, size, host.clone()))
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
                } else if let Some((hs, hl, pid, hx)) = lock_holder(&host, start, len, ty == F_WRLCK) {
                    // The holder as it published itself: its type, range (to the end of file: 0) and pid.
                    *(p as *mut i16) = if hx { F_WRLCK } else { F_RDLCK };
                    *(p.add(2) as *mut i16) = 0;
                    *(p.add(8) as *mut i64) = hs as i64;
                    *(p.add(16) as *mut i64) = if hs + hl >= SHADOW { 0 } else { hl as i64 };
                    *(p.add(24) as *mut i32) = crate::proc::guest_pid(pid) as i32;
                } else {
                    *(p as *mut i16) = F_WRLCK; // a holder that published nothing (yet): type and pid unknown
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
                publish_locks(&host, h);
                return Ok(0);
            }
            let r = take_lock(h, s, len, ty == F_WRLCK, cmd == 7 || cmd == 38);
            if r.is_err() {
                for (os, ol, ox) in old {
                    let _ = take_lock(h, os, ol, ox, false); // keep what we had, as POSIX does
                }
            }
            publish_locks(&host, h);
            r.map(|_| 0)
        }
    }
}

/// fsync / fdatasync: flush the file to disk (databases rely on it for durability).
pub fn fsync(fd: u64) -> R {
    with(|fs| match fs.fd(fd)? {
        // NT flushes only through a handle with write access; Linux fsyncs a read-only fd too (dnf does,
        // after downloading through another): flush through a writable open of the file, or there's
        // nothing of ours to flush.
        Fd::File { f, host } => match f.sync_all() {
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                Ok(OpenOptions::new().write(true).open(host).and_then(|w| w.sync_all()).map_or(0, |_| 0))
            }
            r => r.map(|_| 0).map_err(errno),
        },
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
        if min >= nofile()[0] {
            return Err(EINVAL); // F_DUPFD past the limit
        }
        fs.add(new, min as usize, cloexec)
    })
}

pub fn dup3(old: u64, new: u64, flags: u64) -> R {
    with(|fs| {
        if old == new {
            return fs.fd(old).map(|_| new as i64); // dup2(fd, fd) is a no-op
        }
        let d = dup_fd(fs.fd(old)?)?;
        if new >= nofile()[0] { return Err(EBADF) }
        while fs.fds.len() <= new as usize {
            fs.fds.push(None);
        }
        fs.fds[new as usize] = Some(Slot { fd: d, cloexec: flags & O_CLOEXEC != 0 });
        Ok(new as i64)
    })
}

/// F_GETPIPE_SZ / F_SETPIPE_SZ: a pipe's capacity as the guest set it (64 KB until then). Linux rounds a
/// request up to a power-of-two number of pages; more than /proc/sys/fs/pipe-max-size (1 MB) is EPERM
/// without CAP_SYS_RESOURCE.
/// ponytail: only remembered (NT's own pipe buffer doesn't change), per pipe end rather than per pipe,
/// keyed by the end's handle and never forgotten, so a reused handle value starts with the old size;
/// no EBUSY for shrinking below the queued data.
fn pipe_size(fd: u64, set: Option<u64>) -> R {
    static SIZES: Mutex<Option<HashMap<usize, u64>>> = Mutex::new(None);
    let key = with(|fs| match fs.fd(fd)? {
        Fd::Pipe(p) if p.pty.is_none() => Ok(p.raw() as usize),
        _ => Err(EBADF),
    }).map_err(|_| EINVAL)?;
    let mut sizes = SIZES.lock().unwrap();
    let sizes = sizes.get_or_insert_with(HashMap::new);
    match set {
        None => Ok(*sizes.get(&key).unwrap_or(&65536) as i64),
        Some(n) if n > 1 << 20 => Err(crate::syscall::EPERM),
        Some(n) => {
            let n = n.max(4096).next_power_of_two();
            sizes.insert(key, n);
            Ok(n as i64)
        }
    }
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
        // F_SETSIG / F_GETSIG: which signal SIGIO would be. ponytail: no SIGIO, so it's only checked.
        10 => if arg > 64 { Err(EINVAL) } else { with(|fs| fs.fd(fd).map(|_| 0)) },
        11 => with(|fs| fs.fd(fd).map(|_| 0)),
        1031 | 1032 => pipe_size(fd, (cmd == 1031).then_some(arg)), // F_SETPIPE_SZ, F_GETPIPE_SZ
        4 => with(|fs| match fs.fd(fd)? {
            Fd::Socket(s) => { s.set_nonblocking(arg & O_NONBLOCK != 0); Ok(0) }
            Fd::Event(e) => { e.nonblock.store(arg & O_NONBLOCK != 0, std::sync::atomic::Ordering::Relaxed); Ok(0) }
            Fd::Signal(s) => { s.nonblock.store(arg & O_NONBLOCK != 0, std::sync::atomic::Ordering::Relaxed); Ok(0) }
            Fd::Pipe(p) => { p.nonblock.store(arg & O_NONBLOCK != 0, std::sync::atomic::Ordering::Relaxed); Ok(0) }
            _ => Ok(0),
        }),
        // F_GETFL: the access mode (and O_APPEND) a file or pipe end was opened with, plus O_NONBLOCK.
        3 => with(|fs| match fs.fd(fd)? {
            Fd::Socket(s) => Ok(2 | if s.nonblocking() { O_NONBLOCK as i64 } else { 0 }),
            Fd::Pipe(p) if p.pty.is_some() => Ok(2 | if p.nonblocking() { O_NONBLOCK as i64 } else { 0 }),
            Fd::Pipe(p) => Ok(access_flags(p.raw()) | if p.nonblocking() { O_NONBLOCK as i64 } else { 0 }),
            Fd::File { f, .. } => Ok(access_flags(f.as_raw_handle() as isize)),
            Fd::Handle(h) => Ok(access_flags(h.as_raw_handle() as isize)),
            Fd::Dir { .. } => Ok(0o200000), // O_RDONLY | O_DIRECTORY
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

// Mode, uid and gid live in an NTFS extended attribute, "LX" (12 bytes): set through a handle we may
// already hold, read with one attribute-only open; the :lx stream used before took a second file open
// to write (~600 us a new file against ~20) and to read, and is still read for older layers and images.
unsafe extern "system" {
    fn NtSetEaFile(h: isize, iosb: *mut [usize; 2], buf: *const u8, len: u32) -> i32;
    fn NtQueryEaFile(h: isize, iosb: *mut [usize; 2], buf: *mut u8, len: u32, single: u8, list: *const u8, list_len: u32,
                     index: *const u32, restart: u8) -> i32;
}

/// FILE_FULL_EA_INFORMATION for "LX" = m: next 0, flags 0, name length, value length, "LX\0", value.
fn ea_entry(m: [u32; 3]) -> Vec<u8> {
    let mut b = vec![0, 0, 0, 0, 0, 2, 12, 0];
    b.extend(b"LX\0");
    b.extend(m.iter().flat_map(|v| v.to_le_bytes()));
    b
}

/// Set our metadata on an open file or directory (it needs FILE_WRITE_EA).
fn set_meta_on(h: isize, m: [u32; 3]) -> bool {
    let e = ea_entry(m);
    let mut iosb = [0usize; 2];
    unsafe { NtSetEaFile(h, &mut iosb, e.as_ptr(), e.len() as u32) == 0 }
}

/// A handle with just `access` (FILE_READ_EA / FILE_WRITE_EA) to a file or directory, not its data.
fn ea_handle(host: &Path, access: u32) -> Option<File> {
    use std::os::windows::fs::OpenOptionsExt;
    OpenOptions::new().access_mode(access).share_mode(7).custom_flags(0x0200_0000).open(host).ok() // BACKUP_SEMANTICS
}

pub fn get_meta(host: &Path) -> Option<[u32; 3]> {
    let from_ea = ea_handle(host, 0x8).and_then(|f| { // FILE_READ_EA
        // The query names the one EA we want: FILE_GET_EA_INFORMATION { next 0, length 2, "LX\0" }.
        let want = [0u8, 0, 0, 0, 2, b'L', b'X', 0];
        let (mut out, mut iosb) = ([0u8; 64], [0usize; 2]);
        let st = unsafe { NtQueryEaFile(f.as_raw_handle() as isize, &mut iosb, out.as_mut_ptr(), 64, 1, want.as_ptr(), 8, std::ptr::null(), 1) };
        // A file without it answers with the name and an empty value.
        (st == 0 && u16::from_le_bytes([out[6], out[7]]) == 12).then(|| {
            let v = |i: usize| u32::from_le_bytes(out[11 + i * 4..15 + i * 4].try_into().unwrap());
            [v(0), v(1), v(2)]
        })
    });
    from_ea.or_else(|| {
        let b = fs::read(meta_stream(host)).ok()?;
        let v = |i: usize| Some(u32::from_le_bytes(b.get(i * 4..i * 4 + 4)?.try_into().ok()?));
        Some([v(0)?, v(1)?, v(2)?])
    })
}

pub fn set_meta(host: &Path, m: [u32; 3]) -> io::Result<()> {
    forget(&METAS, host);
    let f = ea_handle(host, 0x10).ok_or_else(|| io::Error::from_raw_os_error(5))?; // FILE_WRITE_EA
    if set_meta_on(f.as_raw_handle() as isize, m) { Ok(()) } else { Err(io::Error::from_raw_os_error(5)) }
}

/// What a newly created file or directory gets: `mode` less the umask, owned by the effective ids.
fn new_meta(mode: u64) -> [u32; 3] {
    [mode as u32 & 0o7777 & !UMASK.load(Relaxed), crate::proc::UID.load(Relaxed), crate::proc::GID.load(Relaxed)]
}

/// new_meta for an entry created at `host`: in a set-group-ID directory it takes the directory's group,
/// and a new directory there is set-group-ID too, as on Linux.
fn new_meta_in(host: &Path, mode: u64, dir: bool) -> [u32; 3] {
    let mut m = new_meta(mode);
    if let Some([_, _, gid]) = host.parent().and_then(get_meta).filter(|p| p[0] & 0o2000 != 0) {
        m[2] = gid;
        if dir {
            m[0] |= 0o2000;
        }
    }
    m
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
        // Setting S_ISGID takes being root or in the file's group (supplementary ones count), else it's
        // dropped silently.
        if crate::proc::UID.load(std::sync::atomic::Ordering::Relaxed) != 0 && !crate::proc::in_group(m[2]) {
            m[0] &= !0o2000;
        }
    }
    if let Some((uid, gid)) = owner {
        for (slot, id) in [(1, uid as u32), (2, gid as u32)] {
            if id != u32::MAX {
                m[slot] = id;
            }
        }
        // chown of a non-directory drops S_ISUID, and S_ISGID when it's group-executable, even for root.
        if !dir {
            m[0] &= !0o4000;
            if m[0] & 0o2010 == 0o2010 {
                m[0] &= !0o2000;
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

/// fchmodat2: fchmodat with its flags (AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH for the dirfd itself).
pub fn fchmodat2(dirfd: u64, path: u64, mode: u64, flags: u64) -> R {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(EINVAL);
    }
    if flags & AT_EMPTY_PATH != 0 && cstr(path)?.is_empty() {
        return fchmeta(dirfd, Some(mode), None);
    }
    chmeta_at(dirfd, path, flags & AT_SYMLINK_NOFOLLOW == 0, Some(mode), None)
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
    stat_of_attrs(host, attrs(host).ok_or(ENOENT)?)
}

/// stat_of with the entry's attributes already looked up (by resolve).
fn stat_of_attrs(host: &Path, m: Attrs) -> Result<[u64; 18], i64> {
    let link = link_target(host, &m);
    let sock = !m.dir && m.len == SOCK_MAGIC.len() as u64 && may_be_marker(host, &m) && fs::read(host).is_ok_and(|d| d == SOCK_MAGIC);
    let (mode, size, nlink) = match &link {
        _ if m.dir => (0o040755, 4096, 2),
        _ if sock => (0o140755, 0, 1), // S_IFSOCK
        _ if fifo_id(host, &m).is_some() => (0o010644, 0, 1), // S_IFIFO
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
    with_meta(&mut s, host);
    if link.is_some() {
        s[3] = (s[3] & !0o7777) | 0o777; // a symlink's own owner (lchown) counts; its mode is always 0777
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
            // The guest's own hard links, as fstatat counts them: not an image file's (hard-linked between
            // image copies, which the guest must not see).
            if !in_image(host) {
                let mut info = [0u32; 13];
                if unsafe { crate::win::GetFileInformationByHandle(f.as_raw_handle() as isize, &mut info) } != 0 {
                    s[2] = info[10].max(1) as u64; // nNumberOfLinks
                }
            }
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
        Fd::Pipe(p) if p.pty.is_some() => Ok(pty_stat(p.pty)),
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
    let (guest, host, meta) = with(|fs| fs.at_attrs(dirfd, path, flags & AT_SYMLINK_NOFOLLOW == 0))?;
    if let Some(d) = Dev::of(&guest) {
        return put_stat(buf, d.stat());
    }
    if guest == "/dev/ptmx" {
        return put_stat(buf, pty_stat(None));
    }
    if let Some(n) = guest.strip_prefix("/dev/pts/").and_then(|n| n.parse().ok()) {
        return put_stat(buf, pty_stat(Some((n, false))));
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
    let mut s = stat_of_attrs(&host, meta.ok_or(ENOENT)?)?;
    if s[3] & 0o170000 == 0o100000 && with(|fs| fs.upper.as_ref().is_some_and(|u| host.starts_with(u)) || fs.mounts.iter().any(|m| host.starts_with(&m.host))) {
        s[2] = links(&host); // the guest's own hard links (shadow's lock checks for 2)
    }
    put_stat(buf, s)
}

/// A file's NTFS hard links. Only asked in the container's layer and volumes: image files are hard-linked
/// between image copies, which the guest must not see.
fn links(host: &Path) -> u64 {
    use std::os::windows::fs::OpenOptionsExt;
    let Ok(f) = OpenOptions::new().access_mode(0x80).share_mode(7).open(host) else { return 1 }; // FILE_READ_ATTRIBUTES
    let mut info = [0u32; 13];
    if unsafe { crate::win::GetFileInformationByHandle(f.as_raw_handle() as isize, &mut info) } == 0 {
        return 1;
    }
    info[10].max(1) as u64 // nNumberOfLinks
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


/// access/faccessat: R_OK 4, W_OK 2, X_OK 1 against the file's mode and owner, as the caller.
/// Root may read and write anything, and execute what has any x bit (or is a directory).
/// ponytail: checked only where lx keeps a mode and owner (not volumes, whose files are the host's);
/// supplementary groups and AT_EACCESS aren't considered.
pub fn faccessat(dirfd: u64, path: u64, mode: u64) -> R {
    if mode & !7 != 0 {
        return Err(EINVAL);
    }
    let (guest, host) = with(|fs| fs.at(dirfd, path, true))?;
    if Dev::of(&guest).is_some() || fd_alias(&guest).is_some() || proc_dir(&guest).is_some() || crate::procfs::file(&guest).is_some() {
        return Ok(0);
    }
    let m = attrs(&host).ok_or(ENOENT)?;
    if mode == 0 || may_access(&host, &m, mode as u32) { Ok(0) } else { Err(EACCES) }
}

/// May the caller have `want` (4 read, 2 write, 1 execute/search) on the entry at `host`, by its stored
/// mode and owner? Root may read and write anything, and execute what has any x bit (or is a directory).
/// Entries without stored metadata allow it.
/// ponytail: AT_EACCESS and capabilities aren't considered; a volume's files are the host's (callers skip).
fn may_access(host: &Path, m: &Attrs, want: u32) -> bool {
    // Through stat's cache: which, make and shells call access(X_OK) for every $PATH entry.
    let Some([perm, uid, gid]) = cached(&METAS, host, m.mtime, || get_meta(host)) else { return true };
    let me = crate::proc::UID.load(std::sync::atomic::Ordering::Relaxed);
    if me == 0 {
        return want & 1 == 0 || m.dir || perm & 0o111 != 0;
    }
    let bits = if me == uid { perm >> 6 } else if crate::proc::in_group(gid) { perm >> 3 } else { perm } & 7;
    want & !bits == 0
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
    if pid != "self" && crate::proc::host_pid(pid.parse().ok()?) != crate::proc::pid() {
        // Another process of the container: its directory (no fd/ for it: ponytail).
        return (rest.is_empty() && crate::ptable::get(pid.parse().ok()?).is_some()).then_some(false);
    }
    match rest {
        "" => Some(false),
        "fd" => Some(true),
        _ => None,
    }
}

/// What getdents lists in a `proc_dir`: (name, d_type).
fn proc_entries(fd_dir: bool, fds: &[Option<Slot>]) -> Vec<(String, u8)> {
    const DT_REG: u8 = 8;
    const DT_DIR: u8 = 4;
    const DT_LNK: u8 = 10;
    if !fd_dir {
        let mut v: Vec<(String, u8)> = vec![("fd".into(), DT_DIR), ("exe".into(), DT_LNK), ("cwd".into(), DT_LNK), ("root".into(), DT_LNK)];
        v.extend(["cmdline", "comm", "stat", "status"].map(|f| (f.to_string(), DT_REG)));
        return v;
    }
    fds.iter().enumerate().filter(|(_, s)| s.is_some()).map(|(i, _)| (i.to_string(), DT_LNK)).collect()
}

/// The few /proc links programs actually read. ponytail: no /proc filesystem otherwise (DESIGN.md §5).
fn proc_link(guest: &str) -> Option<String> {
    // Another process's exe (pidof, ps -o comm on some builds), from the process table.
    if let Some((pid, "exe")) = guest.strip_prefix("/proc/").and_then(|r| r.split_once('/'))
        && let Ok(pid) = pid.parse::<u32>()
        && crate::proc::host_pid(pid) != crate::proc::pid()
    {
        return crate::ptable::get(pid).map(|p| p.exe);
    }
    let rest = guest.strip_prefix("/proc/self/").or_else(|| {
        let r = guest.strip_prefix("/proc/")?;
        let (pid, rest) = r.split_once('/')?;
        (crate::proc::host_pid(pid.parse().ok()?) == crate::proc::pid()).then_some(rest)
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
                Fd::Pipe(p) => Some(match p.pty {
                    Some((n, false)) => format!("/dev/pts/{n}"), // ttyname reads this
                    Some((_, true)) => "/dev/ptmx".into(),
                    None => format!("pipe:[{}]", p.raw()),
                }),
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
            let _ = set_meta(&up, new_meta_in(&up, mode, true));
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
        let (guest, _, meta) = fs.at_attrs(dirfd, path, false)?;
        let c = comps_of(&guest);
        let is_dir = meta.ok_or(ENOENT)?.dir;
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
        // Moved over a deleted image path, a directory must not show the image's old contents there,
        // like one mkdir makes (lookups check only the last level for whiteouts: see resolve).
        let opaque = is_dir && fs.upper.is_some() && fs.hidden(&tc);
        let dst = fs.writable(&tc, false)?;
        if exists(&dst) && !is_dir {
            let _ = fs::remove_file(&dst);
        }
        fs::rename(&src, &dst).map_err(errno)?;
        if opaque {
            fs::write(dst.join(OPAQUE), b"").map_err(errno)?;
        }
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
    // Growing leaves a hole, as on Linux (`truncate -s 10G` must not take 10 GB of the host's disk).
    let set = |f: &File| {
        if f.metadata().is_ok_and(|m| len > m.len()) {
            set_sparse(f);
        }
        match f.set_len(len) {
            // Shrinking a file we have mapped: NT wants the views out of the way first.
            Err(e) if e.raw_os_error() == Some(1224) => {
                crate::syscall::truncate_mapped(f.as_raw_handle() as isize, len, || f.set_len(len)).map(|_| 0).map_err(errno)
            }
            r => r.map(|_| 0).map_err(errno),
        }
    };
    with(|fs| {
        let f = match fd {
            Some(fd) => match fs.fd(fd)? {
                Fd::File { f, .. } => return set(f),
                _ => return Err(EINVAL),
            },
            None => {
                let (guest, _) = fs.at(dirfd, path, true)?;
                fs.writable(&comps_of(&guest), true)?
            }
        };
        set(&OpenOptions::new().write(true).open(f).map_err(errno)?)
    })
}

/// fallocate(fd, mode, off, len): mode 0 grows the file to cover [off, off+len) (posix_fallocate; postgres
/// sizes its /dev/shm segments so); FALLOC_FL_KEEP_SIZE alone has nothing to do. Hole punching etc.: EOPNOTSUPP.
pub fn fallocate(fd: u64, mode: u64, off: u64, len: u64) -> R {
    const FALLOC_FL_KEEP_SIZE: u64 = 1;
    if (off as i64) < 0 || (len as i64) <= 0 {
        return Err(EINVAL);
    }
    if off + len > i64::MAX as u64 {
        return Err(27); // EFBIG: past the largest file size
    }
    with(|fs| {
        let (f, host) = match fs.fd(fd)? {
            Fd::File { f, host } => (f, host),
            Fd::Pipe(_) | Fd::Socket(_) => return Err(ESPIPE),
            Fd::Dir { .. } => return Err(EISDIR),
            _ => return Err(crate::syscall::ENODEV),
        };
        if !writable_handle(f) {
            return Err(EBADF); // opened read-only
        }
        match mode {
            0 => {
                let end = off.checked_add(len).ok_or(EINVAL)?;
                if f.metadata().map_err(errno)?.len() < end {
                    // An O_APPEND fd may only append (FILE_APPEND_DATA): size the file through a new handle.
                    f.set_len(end).or_else(|_| OpenOptions::new().write(true).open(&*host).and_then(|w| w.set_len(end))).map_err(errno)?;
                }
                Ok(0)
            }
            FALLOC_FL_KEEP_SIZE => Ok(0),
            _ => Err(95), // EOPNOTSUPP
        }
    })
}

/// Whether an open file allows writing (FILE_WRITE_DATA or, for O_APPEND, FILE_APPEND_DATA).
fn writable_handle(f: &File) -> bool {
    // FILE_WRITE_DATA or FILE_APPEND_DATA (O_APPEND); unknown: let the write decide
    granted_access(f.as_raw_handle() as isize).is_none_or(|g| g & 0x6 != 0)
}

/// The access a handle was opened with (FileAccessInformation), if NT says.
fn granted_access(h: isize) -> Option<u32> {
    unsafe extern "system" {
        fn NtQueryInformationFile(h: isize, iosb: *mut [usize; 2], info: *mut u32, len: u32, class: u32) -> i32;
    }
    let (mut iosb, mut granted) = ([0usize; 2], 0u32);
    (unsafe { NtQueryInformationFile(h, &mut iosb, &mut granted, 4, 8) } == 0).then_some(granted)
}

/// F_GETFL's access mode and O_APPEND, from what the handle may do: FILE_READ_DATA 1, FILE_WRITE_DATA 2,
/// FILE_APPEND_DATA 4 (std's append(true) asks for that without FILE_WRITE_DATA).
fn access_flags(h: isize) -> i64 {
    let Some(g) = granted_access(h) else { return 2 }; // O_RDWR if NT won't say
    let (read, write, append) = (g & 1 != 0, g & 2 != 0, g & 4 != 0 && g & 2 == 0);
    let mode = match (read, write || append) {
        (true, true) => 2,  // O_RDWR
        (false, true) => 1, // O_WRONLY
        _ => 0,             // O_RDONLY
    };
    mode | if append { O_APPEND as i64 } else { 0 }
}

/// posix_fadvise: only advice, but its arguments are checked as Linux does.
pub fn fadvise(fd: u64, len: u64, advice: u64) -> R {
    if advice > 5 || (len as i64) < 0 {
        return Err(EINVAL);
    }
    with(|fs| match fs.fd(fd)? {
        Fd::Pipe(_) | Fd::Socket(_) => Err(ESPIPE),
        _ => Ok(0),
    })
}

pub fn getcwd(buf: u64, size: u64) -> R {
    with(|fs| {
        let n = fs.cwd.len() + 1;
        if (size as usize) < n { return Err(ERANGE) }
        crate::syscall::put_guest(buf, &[fs.cwd.as_bytes(), &[0]].concat())?;
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
            names.extend(fs.list(&comps_of(&guest))?);
            if guest == "/proc" {
                // The container's processes, and self (ps and friends list /proc for numeric names).
                names.extend(crate::ptable::all().into_iter().map(|p| (p.pid.to_string(), 4)));
                names.push(("self".into(), 10));
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

/// Make `dir` case-sensitive, like a Linux file system: `Makefile` and `makefile` are two files.
/// NTFS keeps a per-directory flag that subdirectories made later inherit, so setting it on an empty
/// rootfs or layer before anything is created covers the whole tree. Setting it needs "delete
/// subfolders and files" on the directory, which a plain Modify grant (the usual one outside the user
/// profile) lacks; we created the directory, so as its owner we grant ourselves that first.
/// Only for directories lx itself just created (image rootfs, container layer): never volumes or
/// other existing folders, since it changes their ACL. Best effort: where the volume doesn't
/// support it, names stay case-insensitive (as before).
pub fn case_sensitive(dir: &Path) {
    use std::ffi::c_void;
    use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle};
    #[repr(C)]
    struct ExplicitAccess { perms: u32, mode: u32, inherit: u32, multiple: *const c_void, multiple_op: u32, form: u32, kind: u32, name: *const u16 }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtSetInformationFile(h: isize, iosb: *mut [usize; 2], info: *const c_void, len: u32, class: u32) -> i32;
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn GetNamedSecurityInfoW(name: *const u16, kind: u32, info: u32, o: *mut c_void, g: *mut c_void, dacl: *mut *mut c_void, sacl: *mut c_void, sd: *mut *mut c_void) -> u32;
        fn SetEntriesInAclW(n: u32, ea: *const ExplicitAccess, old: *mut c_void, new: *mut *mut c_void) -> u32;
        fn SetNamedSecurityInfoW(name: *const u16, kind: u32, info: u32, o: *mut c_void, g: *mut c_void, dacl: *mut c_void, sacl: *mut c_void) -> u32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(p: *mut c_void) -> *mut c_void;
    }
    const FILE_CASE_SENSITIVE_INFORMATION: u32 = 71;
    const FILE_CS_FLAG_CASE_SENSITIVE_DIR: u32 = 1;
    let w: Vec<u16> = dir.as_os_str().encode_wide().chain([0]).collect();
    let me: Vec<u16> = "CURRENT_USER".encode_utf16().chain([0]).collect();
    // FILE_DELETE_CHILD, GRANT_ACCESS, inherited by subfolders and files, trustee by name
    let ea = ExplicitAccess { perms: 0x40, mode: 1, inherit: 3, multiple: std::ptr::null(), multiple_op: 0, form: 1, kind: 0, name: me.as_ptr() };
    let null = std::ptr::null_mut();
    unsafe {
        let (mut dacl, mut sd, mut new) = (null, null, null);
        if GetNamedSecurityInfoW(w.as_ptr(), 1, 4, null, null, &mut dacl, null, &mut sd) == 0 { // SE_FILE_OBJECT, DACL
            if SetEntriesInAclW(1, &ea, dacl, &mut new) == 0 {
                SetNamedSecurityInfoW(w.as_ptr(), 1, 4, null, null, new, null);
                LocalFree(new);
            }
            LocalFree(sd);
        }
    }
    let Ok(f) = OpenOptions::new().read(true).write(true).custom_flags(0x0200_0000).open(dir) else { return }; // BACKUP_SEMANTICS: a directory
    let mut iosb = [0usize; 2];
    let flag = FILE_CS_FLAG_CASE_SENSITIVE_DIR;
    unsafe { NtSetInformationFile(f.as_raw_handle() as isize, &mut iosb, (&flag as *const u32).cast(), 4, FILE_CASE_SENSITIVE_INFORMATION) };
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
        fs::copy(from, to)?;
        mark_if_marker(to); // from an image made before the attribute
        Ok(())
    }
}

fn remove_any(p: &Path) {
    let _ = if p.is_dir() { fs::remove_dir_all(p) } else { fs::remove_file(p) };
}

#[test]
fn resolve_stays_inside_rootfs() {
    let root = std::env::temp_dir().join(format!("lx-test-{}", std::process::id()));
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("etc")).unwrap();
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
fn markers_are_flagged() {
    let base = std::env::temp_dir().join(format!("lx-markers-{}", std::process::id()));
    let (lower, upper) = (base.join("img/rootfs"), base.join("upper"));
    fs::create_dir_all(&lower).unwrap();
    fs::create_dir_all(&upper).unwrap();
    let old = [LINK_MAGIC, b"target"].concat();
    fs::write(lower.join("old"), &old).unwrap(); // an image from before the attribute: no stamp, no flag
    note_marked_roots(&lower, Some(&upper));

    // Unstamped image: still read, so its old links work.
    assert_eq!(read_link(&lower.join("old")).as_deref(), Some("target"));
    // In the upper layer, a link we write is flagged and found...
    write_link(&upper.join("new"), "t2").unwrap();
    assert_eq!(read_link(&upper.join("new")).as_deref(), Some("t2"));
    // ...while an unflagged file with the same bytes is just a file (no read needed).
    fs::write(upper.join("plain"), &old).unwrap();
    assert_eq!(read_link(&upper.join("plain")), None);
    // Copy-up of an old image link flags it, so it stays a link up there.
    copy_up(&lower.join("old"), &upper.join("copied")).unwrap();
    assert_eq!(read_link(&upper.join("copied")).as_deref(), Some("target"));
    MARKED_ROOTS.write().unwrap().clear();
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn meta_in_an_ea_and_from_an_old_stream() {
    let d = std::env::temp_dir().join(format!("lx-meta-{}", std::process::id()));
    fs::create_dir_all(&d).unwrap();
    let (f, old, dir) = (d.join("f"), d.join("old"), d.join("sub"));
    fs::write(&f, "x").unwrap();
    fs::write(&old, "x").unwrap();
    fs::create_dir(&dir).unwrap();
    assert_eq!(get_meta(&f), None);
    set_meta(&f, [0o640, 7, 8]).unwrap();
    assert_eq!(get_meta(&f), Some([0o640, 7, 8]));
    set_meta(&f, [0o600, 9, 10]).unwrap(); // a change replaces it
    assert_eq!(get_meta(&f), Some([0o600, 9, 10]));
    set_meta(&dir, [0o2755, 0, 5]).unwrap(); // directories too
    assert_eq!(get_meta(&dir), Some([0o2755, 0, 5]));
    // Layers and images from before keep their :lx stream, and it still reads.
    fs::write(meta_stream(&old), [0o644u32, 1, 2].iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>()).unwrap();
    assert_eq!(get_meta(&old), Some([0o644, 1, 2]));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn layer_never_touches_the_image() {
    let base = std::env::temp_dir().join(format!("lx-layer-{}", std::process::id()));
    let (lower, upper) = (base.join("lower"), base.join("upper"));
    fs::create_dir_all(lower.join("etc/conf.d")).unwrap();
    fs::write(lower.join("etc/a.conf"), "image").unwrap();
    fs::write(lower.join("etc/conf.d/x"), "x").unwrap();
    fs::create_dir_all(lower.join("usr/lib/py")).unwrap();
    fs::write(lower.join("usr/lib/py/m.py"), "m").unwrap();
    fs::create_dir_all(&upper).unwrap();
    let f = Fs { root: lower.clone(), upper: Some(upper.clone()), mounts: vec![], cwd: "/".into(), fds: vec![] };
    let c = |p: &str| comps_of(p);
    let names = |p: &str| { let mut v: Vec<String> = f.list(&c(p)).unwrap().into_iter().map(|e| e.0).collect(); v.sort(); v };

    // Reads come from the image; a write copies up and leaves the image alone.
    assert_eq!(f.host(&c("/etc/a.conf")), lower.join("etc/a.conf"));
    // A deep image path the upper layer has none of resolves through the image alone.
    assert_eq!(f.resolve("/", "/usr/lib/py/m.py", true).unwrap().1, lower.join("usr/lib/py/m.py"));
    assert_eq!(f.resolve("/usr/lib", "py/m.py", false).unwrap().1, lower.join("usr/lib/py/m.py"));
    // The lookup's attributes (what stat and open use): there for image files; below a missing dir or
    // a file there's nothing (ENOENT, ENOTDIR), and a trailing slash wants a directory.
    let meta = |p: &str| f.resolve_attrs("/", p, true).unwrap().2;
    assert!(meta("/usr/lib/py/m.py").is_some_and(|m| !m.dir && m.len == 1) && meta("/usr/lib").is_some_and(|m| m.dir));
    assert!(meta("/usr/nope").is_none());
    let err = |p: &str| f.resolve_attrs("/", p, true).err();
    assert_eq!((err("/usr/nope/m.py"), err("/nope/a/b"), err("/usr/lib/py/m.py/x"), err("/usr/lib/py/m.py/")), (Some(ENOENT), Some(ENOENT), Some(ENOTDIR), Some(ENOTDIR)));
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
    assert_eq!(f.resolve("/", "/etc/conf.d/x", true).err(), Some(ENOENT));
    assert!(meta("/etc/conf.d").is_none());
    assert_eq!(names("/etc"), ["a.conf", "new"]);
    assert!(lower.join("etc/conf.d/x").exists());

    // Recreating the deleted directory starts empty (opaque), not with the image's old contents.
    let d = f.writable(&c("/etc/conf.d"), false).unwrap();
    fs::create_dir(&d).unwrap();
    fs::write(d.join(OPAQUE), b"").unwrap();
    assert_eq!(names("/etc/conf.d"), Vec::<String>::new());
    assert!(!exists(&f.host(&c("/etc/conf.d/x"))));
    assert!(!exists(&f.resolve("/etc", "conf.d/x", false).unwrap().1));
    assert!(meta("/etc/conf.d").is_some() && meta("/etc/conf.d/x").is_none());

    // A deleted image file opened for writing again (copy-up asked) is new, not the image's copy.
    f.remove(&c("/etc/a.conf"), false).unwrap();
    assert!(!exists(&f.writable(&c("/etc/a.conf"), true).unwrap()));

    fs::remove_dir_all(base).unwrap();
}
