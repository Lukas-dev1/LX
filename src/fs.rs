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
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

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

pub enum Fd {
    Std(isize),
    File { f: File, host: PathBuf },
    // ponytail: dup'd dir fds don't share the read position like Linux does.
    Dir { guest: String, pos: usize },
}

pub struct Fs {
    root: PathBuf,
    cwd: String,
    fds: Vec<Option<Fd>>,
}
static FS: Mutex<Option<Fs>> = Mutex::new(None);

pub fn init(root: PathBuf) {
    let std = |n: u32| Some(Fd::Std(unsafe { crate::win::GetStdHandle(n) }));
    *FS.lock().unwrap() = Some(Fs { root, cwd: "/".into(), fds: vec![std(-10i32 as u32), std(-11i32 as u32), std(-12i32 as u32)] });
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
    fn host(&self, comps: &[String]) -> PathBuf {
        let mut p = self.root.clone();
        p.extend(comps);
        p
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
        if dirfd == AT_FDCWD {
            return Ok(self.cwd.clone());
        }
        match self.fds.get(dirfd as usize) {
            Some(Some(Fd::Dir { guest, .. })) => Ok(guest.clone()),
            Some(Some(_)) => Err(ENOTDIR),
            _ => Err(EBADF),
        }
    }

    fn at(&self, dirfd: u64, path: u64, follow: bool) -> Result<(String, PathBuf), i64> {
        self.resolve(&self.dir_of(dirfd)?, &cstr(path)?, follow)
    }

    fn fd(&mut self, fd: u64) -> Result<&mut Fd, i64> {
        self.fds.get_mut(fd as usize).and_then(|f| f.as_mut()).ok_or(EBADF)
    }

    fn add(&mut self, fd: Fd, min: usize) -> i64 {
        while self.fds.len() <= min {
            self.fds.push(None);
        }
        let i = (min..self.fds.len()).find(|&i| self.fds[i].is_none()).unwrap_or_else(|| {
            self.fds.push(None);
            self.fds.len() - 1
        });
        self.fds[i] = Some(fd);
        i as i64
    }
}

/// Resolve an executable path for the CLI (PATH search like a shell when there's no slash).
pub fn find_exe(cmd: &str, path_var: &str) -> Result<(String, Vec<u8>), String> {
    with(|fs| {
        let dirs: Vec<&str> = if cmd.contains('/') { vec!["/"] } else { path_var.split(':').collect() };
        dirs.iter()
            .filter_map(|d| fs.resolve(d, cmd, true).ok())
            .find_map(|(guest, host)| fs::read(&host).ok().map(|b| (guest, b)))
            .ok_or_else(|| format!("{cmd}: not found in image"))
    })
}

// ---- syscalls ----

fn handle(fd: &Fd) -> Result<isize, i64> {
    match fd {
        Fd::Std(h) => Ok(*h),
        Fd::File { f, .. } => Ok(f.as_raw_handle() as isize),
        Fd::Dir { .. } => Err(EISDIR),
    }
}

pub fn read(fd: u64, buf: u64, len: u64) -> R {
    let h = with(|fs| handle(fs.fd(fd)?))?;
    read_handle(h, buf, len) // outside the lock: stdin may block
}

pub fn write(fd: u64, buf: u64, len: u64) -> R {
    let h = with(|fs| handle(fs.fd(fd)?))?;
    write_handle(h, buf, len)
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
    with(|fs| {
        let (guest, host) = fs.at(dirfd, path, flags & O_NOFOLLOW == 0)?;
        let meta = fs::metadata(&host);
        let acc = flags & 3;
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
        Ok(fs.add(fd, 0))
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
        Fd::Std(h) => Fd::Std(*h),
        Fd::File { f, host } => Fd::File { f: f.try_clone().map_err(errno)?, host: host.clone() },
        Fd::Dir { guest, pos } => Fd::Dir { guest: guest.clone(), pos: *pos },
    })
}

pub fn dup(fd: u64, min: u64) -> R {
    with(|fs| {
        let new = dup_fd(fs.fd(fd)?)?;
        Ok(fs.add(new, min as usize))
    })
}

pub fn dup3(old: u64, new: u64) -> R {
    with(|fs| {
        let d = dup_fd(fs.fd(old)?)?;
        if new > 65535 { return Err(EBADF) }
        while fs.fds.len() <= new as usize {
            fs.fds.push(None);
        }
        fs.fds[new as usize] = Some(d);
        Ok(new as i64)
    })
}

pub fn fcntl(fd: u64, cmd: u64, arg: u64) -> R {
    match cmd {
        0 | 1030 => dup(fd, arg), // F_DUPFD, F_DUPFD_CLOEXEC
        1 | 2 | 4 => with(|fs| fs.fd(fd).map(|_| 0)), // F_GETFD, F_SETFD, F_SETFL. ponytail: no CLOEXEC/NONBLOCK state yet
        3 => with(|fs| fs.fd(fd).map(|_| 2)),         // F_GETFL: O_RDWR
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
        Fd::Std(_) => Err(ESPIPE),
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
        Fd::Std(_) => {
            let mut s = [0u64; 18];
            (s[2], s[3], s[5], s[7]) = (1, 0o020620, 0x8801, 1024); // character device, like a tty
            Ok(s)
        }
    })?;
    put_stat(buf, s)
}

pub fn fstatat(dirfd: u64, path: u64, buf: u64, flags: u64) -> R {
    if flags & AT_EMPTY_PATH != 0 && cstr(path)?.is_empty() {
        return fstat(dirfd, buf);
    }
    let host = with_path(|fs| fs.at(dirfd, path, flags & AT_SYMLINK_NOFOLLOW == 0))?;
    put_stat(buf, stat_of(&host)?)
}

/// Run a resolution under the lock and hand back the host path.
fn with_path(f: impl FnOnce(&Fs) -> Result<(String, PathBuf), i64>) -> Result<PathBuf, i64> {
    with(|fs| f(fs).map(|r| r.1))
}

pub fn faccessat(dirfd: u64, path: u64) -> R {
    let host = with_path(|fs| fs.at(dirfd, path, true))?;
    fs::symlink_metadata(host).map(|_| 0).map_err(errno)
}

pub fn readlinkat(dirfd: u64, path: u64, buf: u64, size: u64) -> R {
    let host = with_path(|fs| fs.at(dirfd, path, false))?;
    let t = read_link(&host).ok_or(EINVAL)?;
    let n = t.len().min(size as usize);
    unsafe { guest_mut(buf, n) }.copy_from_slice(&t.as_bytes()[..n]);
    Ok(n as i64)
}

pub fn mkdirat(dirfd: u64, path: u64) -> R {
    let host = with_path(|fs| fs.at(dirfd, path, false))?;
    fs::create_dir(host).map(|_| 0).map_err(errno)
}

pub fn unlinkat(dirfd: u64, path: u64, flags: u64) -> R {
    let host = with_path(|fs| fs.at(dirfd, path, false))?;
    let is_dir = fs::symlink_metadata(&host).map_err(errno)?.is_dir();
    match (flags & AT_REMOVEDIR != 0, is_dir) {
        (true, true) => fs::remove_dir(host).map(|_| 0).map_err(errno),
        (true, false) => Err(ENOTDIR),
        (false, true) => Err(EISDIR),
        // ponytail: NT refuses to delete open files; POSIX-delete via FILE_DISPOSITION_POSIX_SEMANTICS later.
        (false, false) => fs::remove_file(host).map(|_| 0).map_err(errno),
    }
}

pub fn renameat(olddir: u64, old: u64, newdir: u64, new: u64) -> R {
    let from = with_path(|fs| fs.at(olddir, old, false))?;
    let to = with_path(|fs| fs.at(newdir, new, false))?;
    fs::rename(from, to).map(|_| 0).map_err(errno)
}

pub fn symlinkat(target: u64, dirfd: u64, path: u64) -> R {
    let target = cstr(target)?;
    let host = with_path(|fs| fs.at(dirfd, path, false))?;
    if fs::symlink_metadata(&host).is_ok() {
        return Err(EEXIST);
    }
    write_link(&host, &target).map(|_| 0).map_err(errno)
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
        let host = fs.resolve("/", &guest, true)?.1;
        let mut names: Vec<(String, u8)> = vec![(".".into(), 4), ("..".into(), 4)];
        for e in fs::read_dir(&host).map_err(errno)?.flatten() {
            let dt = if e.file_type().is_ok_and(|t| t.is_dir()) { 4 } else { 0 }; // DT_DIR / DT_UNKNOWN
            names.push((e.file_name().to_string_lossy().into_owned(), dt));
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

/// Unpack a (gzipped) OCI/Docker layer tarball into `dest`.
/// Entry paths are untrusted: absolute paths and `..` are rejected, never joined.
pub fn unpack(tgz: &Path, dest: &Path) -> Result<(u32, u32), String> {
    let f = File::open(tgz).map_err(|e| format!("{}: {e}", tgz.display()))?;
    let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(io::BufReader::new(f)));
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
        let ty = e.header().entry_type();
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

#[test]
fn resolve_stays_inside_rootfs() {
    let root = std::env::temp_dir().join(format!("lx-test-{}", std::process::id()));
    fs::create_dir_all(root.join("bin")).unwrap();
    write_link(&root.join("bin/sh"), "busybox").unwrap();
    write_link(&root.join("up"), "../../../..").unwrap();
    write_link(&root.join("loop"), "loop").unwrap();
    let fs_ = Fs { root: root.clone(), cwd: "/".into(), fds: vec![] };
    let r = |p: &str| fs_.resolve("/bin", p, true).map(|x| x.0);
    assert_eq!(r("sh"), Ok("/bin/busybox".into()));
    assert_eq!(r("/up/etc/passwd"), Ok("/etc/passwd".into()));
    assert_eq!(r("../../../x"), Ok("/x".into()));
    assert_eq!(r("/loop"), Err(ELOOP));
    assert_eq!(r("..\\..\\x"), Err(ENOENT));
    assert_eq!(fs_.resolve("/", "/bin/sh", false).unwrap().0, "/bin/sh");
    fs::remove_dir_all(root).unwrap();
}
