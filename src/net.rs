//! Networking: Linux socket syscalls on Winsock, and epoll.
//!
//! Every socket is non-blocking at the Winsock level. A guest socket in blocking mode waits in short
//! WSAPoll slices, so a signal (lx stop) can still interrupt a server sitting in accept().
//! Containers share the host's network stack, like `docker run --network host`.
use crate::fs::{self, Fd};
use crate::syscall::{R, EAGAIN, EAFNOSUPPORT, EFAULT, EINTR, EINVAL, ENOPROTOOPT};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::Relaxed};
use std::sync::{Arc, Mutex, Once};

#[repr(C)]
struct WsaPollFd {
    fd: usize,
    events: i16,
    revents: i16,
}

#[link(name = "ws2_32")]
unsafe extern "system" {
    fn WSAStartup(version: u16, data: *mut u8) -> i32;
    fn WSAGetLastError() -> i32;
    fn socket(af: i32, ty: i32, proto: i32) -> usize;
    fn closesocket(s: usize) -> i32;
    fn bind(s: usize, addr: *const u8, len: i32) -> i32;
    fn listen(s: usize, backlog: i32) -> i32;
    fn accept(s: usize, addr: *mut u8, len: *mut i32) -> usize;
    fn connect(s: usize, addr: *const u8, len: i32) -> i32;
    fn send(s: usize, buf: *const u8, len: i32, flags: i32) -> i32;
    fn recv(s: usize, buf: *mut u8, len: i32, flags: i32) -> i32;
    fn sendto(s: usize, buf: *const u8, len: i32, flags: i32, to: *const u8, tolen: i32) -> i32;
    fn recvfrom(s: usize, buf: *mut u8, len: i32, flags: i32, from: *mut u8, fromlen: *mut i32) -> i32;
    fn shutdown(s: usize, how: i32) -> i32;
    fn getsockname(s: usize, addr: *mut u8, len: *mut i32) -> i32;
    fn getpeername(s: usize, addr: *mut u8, len: *mut i32) -> i32;
    fn setsockopt(s: usize, level: i32, name: i32, val: *const u8, len: i32) -> i32;
    fn getsockopt(s: usize, level: i32, name: i32, val: *mut u8, len: *mut i32) -> i32;
    fn ioctlsocket(s: usize, cmd: i32, arg: *mut u32) -> i32;
    fn WSAPoll(fds: *mut WsaPollFd, n: u32, timeout: i32) -> i32;
}

const INVALID_SOCKET: usize = usize::MAX;
const FIONBIO: i32 = 0x8004667Eu32 as i32;
const FIONREAD: i32 = 0x4004667F;
const WSA_POLLRDNORM: i16 = 0x0100;
const WSA_POLLRDBAND: i16 = 0x0200;
const WSA_POLLWRNORM: i16 = 0x0010;
const WSA_POLLERR: i16 = 0x0001;
const WSA_POLLHUP: i16 = 0x0002;
// Linux poll/epoll bits.
const POLLIN: i16 = 1;
const POLLOUT: i16 = 4;
const POLLERR: i16 = 8;
const POLLHUP: i16 = 0x10;

fn init() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        let mut data = [0u8; 512]; // WSADATA
        WSAStartup(0x0202, data.as_mut_ptr());
    });
}

/// Winsock error -> Linux errno.
fn wsa_errno(e: i32) -> i64 {
    match e {
        10004 => EINTR,
        10009 => 9,     // EBADF
        10013 => 13,    // EACCES
        10014 => EFAULT,
        10022 => EINVAL,
        10024 => 24,    // EMFILE
        10035 => EAGAIN,
        10036 => 115,   // EINPROGRESS
        10037 => 114,   // EALREADY
        10038 => 88,    // ENOTSOCK
        10039 => 89,    // EDESTADDRREQ
        10040 => 90,    // EMSGSIZE
        10041 => 91,    // EPROTOTYPE
        10042 => ENOPROTOOPT,
        10043 => 93,    // EPROTONOSUPPORT
        10045 => 95,    // EOPNOTSUPP
        10047 => EAFNOSUPPORT,
        10048 => 98,    // EADDRINUSE
        10049 => 99,    // EADDRNOTAVAIL
        10050 => 100,   // ENETDOWN
        10051 => 101,   // ENETUNREACH
        10053 => 103,   // ECONNABORTED
        10054 => 104,   // ECONNRESET
        10055 => 105,   // ENOBUFS
        10056 => 106,   // EISCONN
        10057 => 107,   // ENOTCONN
        10058 => 108,   // ESHUTDOWN
        10060 => 110,   // ETIMEDOUT
        10061 => 111,   // ECONNREFUSED
        10065 => 113,   // EHOSTUNREACH
        _ => 5,         // EIO
    }
}

fn last_err() -> i64 {
    wsa_errno(unsafe { WSAGetLastError() })
}

pub struct Sock {
    pub s: usize,
    nonblock: AtomicBool,
    /// epoll edge-trigger re-arm: POLLIN/POLLOUT bits that hit EAGAIN since epoll last looked.
    eagain: AtomicU32,
}

impl Drop for Sock {
    fn drop(&mut self) {
        unsafe { closesocket(self.s) };
    }
}

impl Sock {
    fn new(s: usize, nonblock: bool) -> Sock {
        let mut on = 1u32;
        unsafe { ioctlsocket(s, FIONBIO, &mut on) }; // always non-blocking underneath
        Sock { s, nonblock: AtomicBool::new(nonblock), eagain: AtomicU32::new(0) }
    }

    /// A socket handle inherited from the parent lx (fork/exec).
    pub fn inherited(s: usize, nonblock: bool) -> Sock {
        init();
        Sock::new(s, nonblock)
    }

    pub fn nonblocking(&self) -> bool {
        self.nonblock.load(Relaxed)
    }

    pub fn set_nonblocking(&self, on: bool) {
        self.nonblock.store(on, Relaxed);
    }

    pub fn available(&self) -> u32 {
        let mut n = 0u32;
        unsafe { ioctlsocket(self.s, FIONREAD, &mut n) };
        n
    }

    /// Linux poll bits ready right now.
    pub fn ready(&self, events: i16) -> i16 {
        let mut p = WsaPollFd { fd: self.s, events: WSA_POLLRDNORM | WSA_POLLWRNORM, revents: 0 };
        if unsafe { WSAPoll(&mut p, 1, 0) } <= 0 {
            return 0;
        }
        let mut r = 0;
        if p.revents & (WSA_POLLRDNORM | WSA_POLLRDBAND) != 0 { r |= POLLIN }
        if p.revents & WSA_POLLWRNORM != 0 { r |= POLLOUT }
        if p.revents & WSA_POLLERR != 0 { r |= POLLERR }
        if p.revents & WSA_POLLHUP != 0 { r |= POLLHUP | POLLIN } // EOF is readable
        r & (events | POLLERR | POLLHUP)
    }

    /// Run a non-blocking Winsock op; in blocking mode, wait for `want` and retry. EINTR on a signal.
    fn op<T>(&self, want: i16, dontwait: bool, mut f: impl FnMut() -> Result<T, i64>) -> Result<T, i64> {
        loop {
            match f() {
                Err(EAGAIN) if !(self.nonblocking() || dontwait) => self.wait(want)?,
                Err(EAGAIN) => {
                    self.eagain.fetch_or(want as u32, Relaxed);
                    return Err(EAGAIN);
                }
                r => return r,
            }
        }
    }

    fn wait(&self, want: i16) -> Result<(), i64> {
        loop {
            let mut p = WsaPollFd { fd: self.s, events: if want == POLLOUT { WSA_POLLWRNORM } else { WSA_POLLRDNORM }, revents: 0 };
            if unsafe { WSAPoll(&mut p, 1, 50) } != 0 {
                return Ok(()); // ready, or an error the retried op will report
            }
            if crate::signal::deliverable() {
                return Err(EINTR);
            }
        }
    }

    pub fn recv(&self, buf: u64, len: u64, flags: u64) -> R {
        let len = len.min(i32::MAX as u64) as i32;
        self.op(POLLIN, flags & MSG_DONTWAIT != 0, || {
            let n = unsafe { recv(self.s, buf as *mut u8, len, msg_flags(flags)) };
            if n < 0 { Err(last_err()) } else { Ok(n as i64) }
        })
    }

    pub fn send(&self, buf: u64, len: u64, flags: u64) -> R {
        let len = len.min(i32::MAX as u64) as i32;
        self.op(POLLOUT, flags & MSG_DONTWAIT != 0, || {
            let n = unsafe { send(self.s, buf as *const u8, len, msg_flags(flags)) };
            // Winsock reports a closed peer as ECONNRESET/ECONNABORTED where Linux says EPIPE.
            if n < 0 { Err(match last_err() { 104 | 103 | 108 => crate::syscall::EPIPE, e => e }) } else { Ok(n as i64) }
        })
    }
}

const MSG_DONTWAIT: u64 = 0x40;

/// Linux send/recv flags Winsock understands: MSG_OOB, MSG_PEEK; MSG_WAITALL is 0x100 vs 0x8.
/// MSG_NOSIGNAL / MSG_DONTWAIT are handled by us (there's no SIGPIPE; non-blocking is per call).
fn msg_flags(f: u64) -> i32 {
    (f & 0x3) as i32 | if f & 0x100 != 0 { 0x8 } else { 0 }
}

// ---- addresses: same layout as Linux except AF_INET6 = 10 (Linux) vs 23 (Windows) ----

const AF_INET: u16 = 2;
const AF_INET6_LINUX: u16 = 10;
const AF_INET6_WIN: u16 = 23;

fn addr_in(p: u64, len: u64) -> Result<Vec<u8>, i64> {
    if p == 0 || !(2..=128).contains(&len) {
        return Err(EINVAL);
    }
    let mut a = unsafe { std::slice::from_raw_parts(p as *const u8, len as usize) }.to_vec();
    match u16::from_le_bytes([a[0], a[1]]) {
        AF_INET => {}
        AF_INET6_LINUX => a[..2].copy_from_slice(&AF_INET6_WIN.to_le_bytes()),
        // ponytail: AF_UNIX paths would need mapping into the rootfs; not yet.
        _ => return Err(EAFNOSUPPORT),
    }
    Ok(a)
}

/// Copy a Winsock address out to the guest (`p`, `*lenp`), truncating like Linux does.
fn addr_out(a: &[u8], p: u64, lenp: u64) {
    if p == 0 || lenp == 0 {
        return;
    }
    let mut a = a.to_vec();
    if a.len() >= 2 && u16::from_le_bytes([a[0], a[1]]) == AF_INET6_WIN {
        a[..2].copy_from_slice(&AF_INET6_LINUX.to_le_bytes());
    }
    let room = unsafe { *(lenp as *const u32) } as usize;
    let n = room.min(a.len());
    unsafe {
        std::ptr::copy_nonoverlapping(a.as_ptr(), p as *mut u8, n);
        *(lenp as *mut u32) = a.len() as u32;
    }
}

fn family(domain: u64) -> Result<i32, i64> {
    match domain as u16 {
        AF_INET => Ok(2),
        AF_INET6_LINUX => Ok(AF_INET6_WIN as i32),
        _ => Err(EAFNOSUPPORT),
    }
}

const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2000000;

pub fn sys_socket(domain: u64, ty: u64, proto: u64) -> R {
    init();
    let af = family(domain)?;
    let base = (ty & 0xf) as i32; // SOCK_STREAM 1, SOCK_DGRAM 2, SOCK_RAW 3: same numbers
    let s = unsafe { socket(af, base, proto as i32) };
    if s == INVALID_SOCKET {
        return Err(last_err());
    }
    if af == AF_INET6_WIN as i32 {
        let off = 0i32; // Linux default: IPv6 sockets also accept IPv4 (Windows defaults to v6-only)
        unsafe { setsockopt(s, 41, 27, (&off as *const i32).cast(), 4) };
    }
    let sock = Sock::new(s, ty & SOCK_NONBLOCK != 0);
    Ok(fs::add_fd(Fd::Socket(Arc::new(sock)), ty & SOCK_CLOEXEC != 0))
}

/// socketpair: Windows has no AF_UNIX pairs, so connect two loopback TCP sockets (CPython on
/// Windows does the same). ponytail: no SCM_RIGHTS fd passing over it.
pub fn sys_socketpair(_domain: u64, ty: u64, _proto: u64, out: u64) -> R {
    init();
    unsafe {
        let l = socket(2, 1, 0);
        let mut a = [0u8; 16];
        a[0] = 2;
        a[4..8].copy_from_slice(&[127, 0, 0, 1]);
        let mut alen = 16i32;
        if bind(l, a.as_ptr(), 16) != 0 || listen(l, 1) != 0 || getsockname(l, a.as_mut_ptr(), &mut alen) != 0 {
            let e = last_err();
            closesocket(l);
            return Err(e);
        }
        let c = socket(2, 1, 0);
        let ok = connect(c, a.as_ptr(), 16) == 0;
        let s = if ok { accept(l, std::ptr::null_mut(), std::ptr::null_mut()) } else { INVALID_SOCKET };
        closesocket(l);
        if s == INVALID_SOCKET {
            let e = last_err();
            closesocket(c);
            return Err(e);
        }
        let one = 1i32;
        for x in [c, s] {
            setsockopt(x, 6, 1, (&one as *const i32).cast(), 4); // TCP_NODELAY: behave like a local pipe
        }
        let (nb, cx) = (ty & SOCK_NONBLOCK != 0, ty & SOCK_CLOEXEC != 0);
        let a = fs::add_fd(Fd::Socket(Arc::new(Sock::new(c, nb))), cx);
        let b = fs::add_fd(Fd::Socket(Arc::new(Sock::new(s, nb))), cx);
        *(out as *mut [i32; 2]) = [a as i32, b as i32];
    }
    Ok(0)
}

pub fn sys_bind(fd: u64, addr: u64, len: u64) -> R {
    let s = fs::sock(fd)?;
    let a = addr_in(addr, len)?;
    if unsafe { bind(s.s, a.as_ptr(), a.len() as i32) } != 0 { Err(last_err()) } else { Ok(0) }
}

pub fn sys_listen(fd: u64, backlog: u64) -> R {
    let s = fs::sock(fd)?;
    if unsafe { listen(s.s, backlog.min(i32::MAX as u64) as i32) } != 0 { Err(last_err()) } else { Ok(0) }
}

pub fn sys_accept(fd: u64, addr: u64, lenp: u64, flags: u64) -> R {
    let s = fs::sock(fd)?;
    let mut a = [0u8; 128];
    let new = s.op(POLLIN, false, || {
        let mut alen = a.len() as i32;
        let n = unsafe { accept(s.s, a.as_mut_ptr(), &mut alen) };
        if n == INVALID_SOCKET { Err(last_err()) } else { Ok((n, alen as usize)) }
    })?;
    addr_out(&a[..new.1], addr, lenp);
    let sock = Sock::new(new.0, flags & SOCK_NONBLOCK != 0);
    Ok(fs::add_fd(Fd::Socket(Arc::new(sock)), flags & SOCK_CLOEXEC != 0))
}

fn so_error(s: usize) -> i64 {
    let (mut e, mut len) = (0i32, 4i32);
    unsafe { getsockopt(s, 0xffff, 0x1007, (&mut e as *mut i32).cast(), &mut len) };
    if e == 0 { 0 } else { wsa_errno(e) }
}

pub fn sys_connect(fd: u64, addr: u64, len: u64) -> R {
    let s = fs::sock(fd)?;
    let a = addr_in(addr, len)?;
    if unsafe { connect(s.s, a.as_ptr(), a.len() as i32) } == 0 {
        return Ok(0);
    }
    match last_err() {
        EAGAIN if s.nonblocking() => Err(115), // EINPROGRESS: caller polls for POLLOUT, then SO_ERROR
        EAGAIN => loop {
            let mut p = WsaPollFd { fd: s.s, events: WSA_POLLWRNORM, revents: 0 };
            let r = unsafe { WSAPoll(&mut p, 1, 50) };
            let e = so_error(s.s);
            if e != 0 {
                return Err(e);
            }
            if r > 0 {
                return Ok(0);
            }
            if crate::signal::deliverable() {
                return Err(EINTR);
            }
        },
        e => Err(e),
    }
}

pub fn sys_sendto(fd: u64, buf: u64, len: u64, flags: u64, addr: u64, alen: u64) -> R {
    let s = fs::sock(fd)?;
    if addr == 0 {
        return s.send(buf, len, flags);
    }
    let a = addr_in(addr, alen)?;
    let len = len.min(i32::MAX as u64) as i32;
    s.op(POLLOUT, flags & MSG_DONTWAIT != 0, || {
        let n = unsafe { sendto(s.s, buf as *const u8, len, msg_flags(flags), a.as_ptr(), a.len() as i32) };
        if n < 0 { Err(last_err()) } else { Ok(n as i64) }
    })
}

pub fn sys_recvfrom(fd: u64, buf: u64, len: u64, flags: u64, addr: u64, lenp: u64) -> R {
    let s = fs::sock(fd)?;
    let len = len.min(i32::MAX as u64) as i32;
    let mut a = [0u8; 128];
    let mut alen = 0i32;
    let n = s.op(POLLIN, flags & MSG_DONTWAIT != 0, || {
        alen = a.len() as i32;
        let n = unsafe { recvfrom(s.s, buf as *mut u8, len, msg_flags(flags), a.as_mut_ptr(), &mut alen) };
        if n < 0 { Err(last_err()) } else { Ok(n as i64) }
    })?;
    if alen > 0 {
        addr_out(&a[..alen as usize], addr, lenp);
    } else if lenp != 0 {
        unsafe { *(lenp as *mut u32) = 0 }; // connected stream: no address
    }
    Ok(n)
}

/// struct msghdr { name, namelen, iov, iovlen, control, controllen, flags }.
/// ponytail: data only; control messages (SCM_RIGHTS, credentials) aren't supported.
pub fn sys_sendmsg(fd: u64, msg: u64, flags: u64) -> R {
    let m = unsafe { *(msg as *const [u64; 7]) };
    let data = gather(m[2], m[3])?;
    sys_sendto(fd, data.as_ptr() as u64, data.len() as u64, flags, m[0], m[1] & 0xffff_ffff)
}

pub fn sys_recvmsg(fd: u64, msg: u64, flags: u64) -> R {
    let m = unsafe { &mut *(msg as *mut [u64; 7]) };
    let iovs = iovecs(m[2], m[3])?;
    let total: u64 = iovs.iter().map(|v| v[1]).sum();
    let mut buf = vec![0u8; total.min(1 << 20) as usize];
    let name_len_ptr = if m[0] != 0 { &mut m[1] as *mut u64 as u64 } else { 0 };
    let n = sys_recvfrom(fd, buf.as_mut_ptr() as u64, buf.len() as u64, flags, m[0], name_len_ptr)? as usize;
    let mut off = 0;
    for [base, len] in iovs {
        let k = (len as usize).min(n - off);
        unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr().add(off), base as *mut u8, k) };
        off += k;
        if off == n {
            break;
        }
    }
    (m[5], m[6]) = (0, 0); // no control data, no flags
    Ok(n as i64)
}

fn iovecs(iov: u64, n: u64) -> Result<Vec<[u64; 2]>, i64> {
    if n > 1024 {
        return Err(EINVAL);
    }
    Ok((0..n).map(|i| unsafe { *((iov + i * 16) as *const [u64; 2]) }).collect())
}

fn gather(iov: u64, n: u64) -> Result<Vec<u8>, i64> {
    let mut data = Vec::new();
    for [base, len] in iovecs(iov, n)? {
        data.extend_from_slice(unsafe { std::slice::from_raw_parts(base as *const u8, len as usize) });
    }
    Ok(data)
}

pub fn sys_shutdown(fd: u64, how: u64) -> R {
    let s = fs::sock(fd)?;
    if unsafe { shutdown(s.s, how as i32) } != 0 { Err(last_err()) } else { Ok(0) } // SHUT_* == SD_*
}

pub fn sys_getsockname(fd: u64, addr: u64, lenp: u64, peer: bool) -> R {
    let s = fs::sock(fd)?;
    let mut a = [0u8; 128];
    let mut alen = a.len() as i32;
    let r = unsafe { if peer { getpeername(s.s, a.as_mut_ptr(), &mut alen) } else { getsockname(s.s, a.as_mut_ptr(), &mut alen) } };
    if r != 0 {
        return Err(last_err());
    }
    addr_out(&a[..alen as usize], addr, lenp);
    Ok(0)
}

/// Linux (level, option) -> Winsock. None = accept and ignore (option has no useful Windows twin).
fn sockopt(level: u64, name: u64) -> Option<(i32, i32)> {
    match (level, name) {
        (1, 9) => Some((0xffff, 0x0008)),    // SO_KEEPALIVE
        (1, 6) => Some((0xffff, 0x0020)),    // SO_BROADCAST
        (1, 7) => Some((0xffff, 0x1001)),    // SO_SNDBUF
        (1, 8) => Some((0xffff, 0x1002)),    // SO_RCVBUF
        (6, 1) => Some((6, 1)),              // TCP_NODELAY
        (41, 26) => Some((41, 27)),          // IPV6_V6ONLY
        // SO_REUSEADDR is ignored on purpose: Linux semantics (rebind during TIME_WAIT) are Windows'
        // default, and Windows' SO_REUSEADDR would let another process steal the port.
        _ => None,
    }
}

pub fn sys_setsockopt(fd: u64, level: u64, name: u64, val: u64, len: u64) -> R {
    let s = fs::sock(fd)?;
    let Some((l, n)) = sockopt(level, name) else { return Ok(0) };
    if unsafe { setsockopt(s.s, l, n, val as *const u8, len.min(64) as i32) } != 0 { Err(last_err()) } else { Ok(0) }
}

pub fn sys_getsockopt(fd: u64, level: u64, name: u64, val: u64, lenp: u64) -> R {
    let s = fs::sock(fd)?;
    let int = |v: i32| unsafe {
        *(val as *mut i32) = v;
        *(lenp as *mut u32) = 4;
        Ok(0)
    };
    match (level, name) {
        (1, 4) => return int(so_error(s.s) as i32),          // SO_ERROR, as a Linux errno
        (1, 3) => {                                           // SO_TYPE
            let (mut t, mut len) = (0i32, 4i32);
            unsafe { getsockopt(s.s, 0xffff, 0x1008, (&mut t as *mut i32).cast(), &mut len) };
            return int(t);
        }
        (1, 2) | (1, 15) => return int(0),                     // SO_REUSEADDR / SO_REUSEPORT: as set (ignored)
        _ => {}
    }
    let Some((l, n)) = sockopt(level, name) else { return Err(ENOPROTOOPT) };
    let mut len = unsafe { *(lenp as *const u32) } as i32;
    if unsafe { getsockopt(s.s, l, n, val as *mut u8, &mut len) } != 0 {
        return Err(last_err());
    }
    unsafe { *(lenp as *mut u32) = len as u32 };
    Ok(0)
}

// ---- epoll ----

const EPOLLONESHOT: u32 = 1 << 30;
const EPOLLET: u32 = 1 << 31;

struct Entry {
    fd: i32,
    events: u32,
    data: u64,
    /// Edge-triggered: bits already reported and not yet re-armed (by going unready or an EAGAIN).
    reported: u32,
    disabled: bool,
}

#[derive(Default)]
pub struct Epoll {
    entries: Vec<Entry>,
}

pub fn sys_epoll_create(flags: u64) -> R {
    Ok(fs::add_fd(Fd::Epoll(Arc::new(Mutex::new(Epoll::default()))), flags & 0o2000000 != 0))
}

pub fn sys_epoll_ctl(epfd: u64, op: u64, fd: u64, ev: u64) -> R {
    let ep = fs::epoll(epfd)?;
    let (events, data) = if ev != 0 {
        let raw = unsafe { std::slice::from_raw_parts(ev as *const u8, 12) }; // packed { u32 events; u64 data }
        (u32::from_le_bytes(raw[..4].try_into().unwrap()), u64::from_le_bytes(raw[4..].try_into().unwrap()))
    } else {
        (0, 0)
    };
    let fd = fd as i32;
    if fs::readiness(fd, 0) & 0x20 != 0 {
        return Err(9); // EBADF
    }
    let mut e = ep.lock().unwrap();
    let pos = e.entries.iter().position(|x| x.fd == fd);
    match (op, pos) {
        (1, None) => e.entries.push(Entry { fd, events, data, reported: 0, disabled: false }), // ADD
        (1, Some(_)) => return Err(17),                                                         // EEXIST
        (2, Some(i)) => { e.entries.remove(i); }                                                // DEL
        (3, Some(i)) => e.entries[i] = Entry { fd, events, data, reported: 0, disabled: false }, // MOD
        (2 | 3, None) => return Err(crate::syscall::ENOENT),
        _ => return Err(EINVAL),
    }
    Ok(0)
}

/// epoll_wait: level-triggered by default, with edge-triggered and one-shot emulated on top of polling.
/// Waits in WSAPoll over the registered sockets (other fds are re-checked every slice).
pub fn sys_epoll_wait(epfd: u64, out: u64, max: u64, timeout_ms: i64) -> R {
    let ep = fs::epoll(epfd)?;
    if max == 0 || max > 1 << 16 {
        return Err(EINVAL);
    }
    let start = std::time::Instant::now();
    loop {
        let mut n = 0u64;
        let mut socks = Vec::new();
        {
            let mut e = ep.lock().unwrap();
            e.entries.retain(|x| fs::readiness(x.fd, 0) & 0x20 == 0); // closed fds drop out, as on Linux
            for x in e.entries.iter_mut() {
                if let Some(s) = fs::socket_of(x.fd) {
                    socks.push(s);
                    if let Ok(k) = fs::sock(x.fd as u64) {
                        x.reported &= !k.eagain.swap(0, Relaxed); // EAGAIN re-arms the edge
                    }
                }
                if x.disabled || n >= max {
                    continue;
                }
                let want = (x.events & 0xffff) as i16;
                let ready = fs::readiness(x.fd, want) as u32;
                let report = if x.events & EPOLLET != 0 {
                    x.reported &= ready; // bits that went unready re-arm
                    let new = ready & !x.reported;
                    x.reported |= new;
                    new
                } else {
                    ready
                };
                if report != 0 {
                    let rec = (out + n * 12) as *mut u8;
                    unsafe {
                        std::ptr::copy_nonoverlapping(report.to_le_bytes().as_ptr(), rec, 4);
                        std::ptr::copy_nonoverlapping(x.data.to_le_bytes().as_ptr(), rec.add(4), 8);
                    }
                    n += 1;
                    if x.events & EPOLLONESHOT != 0 {
                        x.disabled = true;
                    }
                }
            }
        }
        if n > 0 {
            return Ok(n as i64);
        }
        let elapsed = start.elapsed().as_millis() as i64;
        if timeout_ms >= 0 && elapsed >= timeout_ms {
            return Ok(0);
        }
        if crate::signal::deliverable() {
            return Err(EINTR);
        }
        // Sleep until a socket changes or the slice ends; non-socket fds are re-checked each slice.
        let slice = if timeout_ms < 0 { 20 } else { (timeout_ms - elapsed).clamp(1, 20) } as i32;
        if socks.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(slice as u64));
        } else {
            let mut p: Vec<WsaPollFd> = socks.iter().map(|&s| WsaPollFd { fd: s, events: WSA_POLLRDNORM, revents: 0 }).collect();
            unsafe { WSAPoll(p.as_mut_ptr(), p.len() as u32, slice) };
        }
    }
}

/// /etc/resolv.conf and /etc/hosts for a container, like Docker writes them: the host's DNS servers.
pub fn dns_files() -> (String, String) {
    let mut servers = Vec::new();
    unsafe {
        let mut len = 0u32;
        GetNetworkParams(std::ptr::null_mut(), &mut len);
        let mut buf = vec![0u8; len as usize + 16];
        if len > 0 && GetNetworkParams(buf.as_mut_ptr(), &mut len) == 0 {
            // FIXED_INFO: HostName[132], DomainName[132], CurrentDnsServer*, DnsServerList (IP_ADDR_STRING)
            let mut node = buf.as_ptr().add(272);
            while !node.is_null() && servers.len() < 3 {
                let ip = std::slice::from_raw_parts(node.add(8), 16);
                let ip = String::from_utf8_lossy(&ip[..ip.iter().position(|&b| b == 0).unwrap_or(16)]).into_owned();
                if !ip.is_empty() && ip != "0.0.0.0" {
                    servers.push(ip);
                }
                node = *(node as *const *const u8);
            }
        }
    }
    if servers.is_empty() {
        servers.push("1.1.1.1".into()); // fallback when the host's resolvers can't be read
    }
    let resolv = servers.iter().map(|s| format!("nameserver {s}\n")).collect();
    (resolv, "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n".into())
}

#[link(name = "iphlpapi")]
unsafe extern "system" {
    fn GetNetworkParams(info: *mut u8, len: *mut u32) -> u32;
}
