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
    fn WSAIoctl(s: usize, code: u32, inb: *const u8, inlen: u32, outb: *mut u8, outlen: u32, got: *mut u32,
        ov: *mut u8, done: *mut u8) -> i32;
}

#[link(name = "mswsock")]
unsafe extern "system" {
    fn AcceptEx(ls: usize, acc: usize, buf: *mut u8, rx: u32, local_len: u32, remote_len: u32, got: *mut u32, ov: *mut Overlapped) -> i32;
    fn GetAcceptExSockaddrs(buf: *const u8, rx: u32, local_len: u32, remote_len: u32,
        local: *mut *mut u8, local_n: *mut i32, remote: *mut *mut u8, remote_n: *mut i32);
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn WaitForSingleObject(h: isize, ms: u32) -> u32;
}

#[repr(C)]
#[derive(Default)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: isize,
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
    /// AF_UNIX: the guest's own address (bound) and the peer's (connected), as the guest wrote them.
    unix: Mutex<Option<Vec<u8>>>,
    peer: Mutex<Option<Vec<u8>>>,
    /// AF_UNIX SOCK_DGRAM: a loopback UDP socket underneath (see unix_dgram).
    udgram: bool,
    /// AF_NETLINK (NETLINK_ROUTE): the same, answering its own requests (see netlink_reply).
    netlink: bool,
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
        Sock { s, nonblock: AtomicBool::new(nonblock), eagain: AtomicU32::new(0), unix: Mutex::new(None), peer: Mutex::new(None), udgram: false, netlink: false }
    }

    /// A socket handle inherited from the parent lx (fork/exec); `tag` is what inherit_tag() gave.
    pub fn inherited(s: usize, tag: &str) -> Sock {
        init();
        let mut k = Sock::new(s, tag.starts_with('1'));
        k.udgram = tag.ends_with('u');
        k.netlink = tag.ends_with('n');
        k
    }

    /// What a child lx needs to rebuild this socket: "1"/"0" (non-blocking), "u" for AF_UNIX datagrams,
    /// "n" for netlink.
    pub fn inherit_tag(&self) -> String {
        format!("{}{}", self.nonblocking() as u8, if self.udgram { "u" } else if self.netlink { "n" } else { "" })
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
        if self.netlink {
            // A request to the "kernel": its answer goes to our own port, for recv to read.
            let req = unsafe { std::slice::from_raw_parts(buf as *const u8, len as usize) };
            let reply = netlink_reply(req, nl_pid()).ok_or(EINVAL)?;
            let a = loopback(udgram_port(self));
            unsafe { sendto(self.s, reply.as_ptr(), reply.len() as i32, 0, a.as_ptr(), 16) };
            return Ok(len as i64);
        }
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

const AF_UNIX: u16 = 1;
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
    // The container's own loopback address is its 127.0.0.1 (bind_addr, dest_addr): shown so, a server
    // on 127.0.0.1 says so (Go's httptest URLs, a TLS certificate for 127.0.0.1), and a client of it is
    // a 127.0.0.1 peer (pg_hba, redis protected mode). ponytail: a 0.0.0.0 listener shows 127.0.0.1 too.
    if let Some(ip) = own_ip() {
        let fam = u16::from_le_bytes([a[0], a[1]]);
        if fam == AF_INET && a.len() >= 8 && a[4..8] == ip {
            a[4..8].copy_from_slice(&[127, 0, 0, 1]);
        } else if fam == AF_INET6_LINUX && a.len() >= 24 && a[8..20] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] && a[20..24] == ip {
            a[20..24].copy_from_slice(&[127, 0, 0, 1]);
        }
    }
    let room = unsafe { *(lenp as *const u32) } as usize;
    let n = room.min(a.len());
    unsafe {
        std::ptr::copy_nonoverlapping(a.as_ptr(), p as *mut u8, n);
        *(lenp as *mut u32) = a.len() as u32;
    }
}

// ---- AF_NETLINK, NETLINK_ROUTE: the interface and address dumps ----
//
// Go's net.Interfaces / InterfaceAddrs and glibc's getifaddrs ask the kernel with RTM_GETLINK and
// RTM_GETADDR dumps. The container sees one interface, lo, holding 127.0.0.1/8, its own loopback
// address (LX_IP) and ::1. ponytail: dumps only; other requests get EOPNOTSUPP, no multicast groups.

const AF_NETLINK: u64 = 16;

/// The port id a netlink socket is bound to, as getsockname and the replies give it.
fn nl_pid() -> u32 {
    crate::proc::getpid().unwrap_or(0) as u32
}

/// struct sockaddr_nl { family, pad, pid, groups }.
fn nl_addr(pid: u32) -> Vec<u8> {
    let mut a = vec![AF_NETLINK as u8, 0, 0, 0];
    a.extend(pid.to_le_bytes());
    a.extend(0u32.to_le_bytes());
    a
}

fn nl_msg(out: &mut Vec<u8>, ty: u16, seq: u32, pid: u32, body: &[u8]) {
    const NLM_F_MULTI: u16 = 2;
    out.extend((16 + body.len() as u32).to_le_bytes());
    out.extend(ty.to_le_bytes());
    out.extend(NLM_F_MULTI.to_le_bytes());
    out.extend(seq.to_le_bytes());
    out.extend(pid.to_le_bytes());
    out.extend(body);
    out.resize(out.len().next_multiple_of(4), 0);
}

fn rta(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
    out.extend((4 + data.len() as u16).to_le_bytes());
    out.extend(ty.to_le_bytes());
    out.extend(data);
    out.resize(out.len().next_multiple_of(4), 0);
}

/// The kernel's answer to one request (nlmsghdr + rtgenmsg/ifinfomsg/ifaddrmsg), ending in NLMSG_DONE.
fn netlink_reply(req: &[u8], pid: u32) -> Option<Vec<u8>> {
    const RTM_NEWLINK: u16 = 16;
    const RTM_GETLINK: u16 = 18;
    const RTM_NEWADDR: u16 = 20;
    const RTM_GETADDR: u16 = 22;
    if req.len() < 16 {
        return None;
    }
    let ty = u16::from_le_bytes([req[4], req[5]]);
    let seq = u32::from_le_bytes(req[8..12].try_into().unwrap());
    let family = req.get(16).copied().unwrap_or(0);
    let mut out = Vec::new();
    match ty {
        RTM_GETLINK => {
            // ifinfomsg { family, pad, type ARPHRD_LOOPBACK, index 1, flags UP|LOOPBACK|RUNNING, change }
            let mut b = vec![0, 0];
            b.extend(772u16.to_le_bytes());
            b.extend(1i32.to_le_bytes());
            b.extend((0x1u32 | 0x8 | 0x40).to_le_bytes());
            b.extend(0u32.to_le_bytes());
            rta(&mut b, 3, b"lo\0"); // IFLA_IFNAME
            rta(&mut b, 4, &65536u32.to_le_bytes()); // IFLA_MTU
            rta(&mut b, 1, &[0; 6]); // IFLA_ADDRESS
            rta(&mut b, 2, &[0; 6]); // IFLA_BROADCAST
            nl_msg(&mut out, RTM_NEWLINK, seq, pid, &b);
        }
        RTM_GETADDR => {
            let mut v4 = vec![[127, 0, 0, 1]];
            v4.extend(own_ip().filter(|ip| *ip != [127, 0, 0, 1]));
            let mut addrs: Vec<(u8, u8, Vec<u8>)> = v4.into_iter().map(|ip| (2, 8, ip.to_vec())).collect();
            let mut one = [0u8; 16];
            one[15] = 1;
            addrs.push((10, 128, one.to_vec()));
            for (fam, prefix, ip) in addrs.into_iter().filter(|a| family == 0 || a.0 == family) {
                // ifaddrmsg { family, prefixlen, flags IFA_F_PERMANENT, scope RT_SCOPE_HOST, index 1 }
                let mut b = vec![fam, prefix, 0x80, 254];
                b.extend(1u32.to_le_bytes());
                rta(&mut b, 1, &ip); // IFA_ADDRESS
                if fam == 2 {
                    rta(&mut b, 2, &ip); // IFA_LOCAL
                    rta(&mut b, 3, b"lo\0"); // IFA_LABEL
                }
                nl_msg(&mut out, RTM_NEWADDR, seq, pid, &b);
            }
        }
        _ => {
            // NLMSG_ERROR: the error, then the request's header.
            let mut b = (-95i32).to_le_bytes().to_vec(); // EOPNOTSUPP
            b.extend(&req[..16]);
            nl_msg(&mut out, 2, seq, pid, &b);
            return Some(out);
        }
    }
    nl_msg(&mut out, 3, seq, pid, &0i32.to_le_bytes()); // NLMSG_DONE
    Some(out)
}

/// The ifreq ioctls (SIOCGIF*) for lo, the container's one interface, as the netlink dumps show it.
/// struct ifreq { char name[16]; union { sockaddr, short flags, int index/mtu/qlen, ... } }.
pub fn if_ioctl(req: u64, arg: u64) -> R {
    const ENODEV: i64 = 19;
    let ifr = unsafe { std::slice::from_raw_parts_mut(arg as *mut u8, 40) };
    let put_i32 = |ifr: &mut [u8], v: i32| ifr[16..20].copy_from_slice(&v.to_le_bytes());
    let put_in = |ifr: &mut [u8], ip: [u8; 4]| {
        ifr[16..32].fill(0);
        ifr[16] = AF_INET as u8;
        ifr[20..24].copy_from_slice(&ip);
    };
    match req {
        0x8912 => {
            // SIOCGIFCONF: struct ifconf { int len; char *buf } gets one ifreq, lo's.
            let conf = unsafe { &mut *(arg as *mut [u64; 2]) };
            if conf[1] != 0 && conf[0] as u32 >= 40 {
                let r = unsafe { std::slice::from_raw_parts_mut(conf[1] as *mut u8, 40) };
                r.fill(0);
                r[..2].copy_from_slice(b"lo");
                put_in(r, [127, 0, 0, 1]);
            }
            conf[0] = conf[0] & !0xffff_ffff | 40;
            return Ok(0);
        }
        0x8910 => {
            // SIOCGIFNAME: index -> name
            if i32::from_le_bytes(ifr[16..20].try_into().unwrap()) != 1 {
                return Err(ENODEV);
            }
            ifr[..16].fill(0);
            ifr[..2].copy_from_slice(b"lo");
            return Ok(0);
        }
        _ => {}
    }
    if &ifr[..3] != b"lo\0" {
        return Err(ENODEV);
    }
    match req {
        0x8913 => ifr[16..18].copy_from_slice(&0x49u16.to_le_bytes()), // SIOCGIFFLAGS: UP|LOOPBACK|RUNNING
        0x8915 => put_in(ifr, [127, 0, 0, 1]),                       // SIOCGIFADDR
        0x891b => put_in(ifr, [255, 0, 0, 0]),                       // SIOCGIFNETMASK
        0x8921 => put_i32(ifr, 65536),                               // SIOCGIFMTU
        0x8927 => {
            // SIOCGIFHWADDR: ARPHRD_LOOPBACK, all zeros
            ifr[16..32].fill(0);
            ifr[16..18].copy_from_slice(&772u16.to_le_bytes());
        }
        0x8933 => put_i32(ifr, 1),    // SIOCGIFINDEX
        0x8942 => put_i32(ifr, 1000), // SIOCGIFTXQLEN
        0x8914 | 0x8916 | 0x891c | 0x8922 | 0x8924 | 0x8943 => return Err(crate::syscall::EPERM), // the SIOCSIF* sets
        _ => return Err(crate::syscall::ENOTTY),
    }
    Ok(0)
}

// ---- published ports (`lx run -p`) ----
//
// Containers share the host's network stack, so publishing is done by rewriting addresses at the
// socket calls instead of with a proxy: bind() of a published container port binds the host port,
// getsockname() reports the container port back, and the container's own connections to that port on
// loopback are redirected. An `lx run` container's unpublished listeners on "any address" or 127.0.0.1
// are moved to its own loopback address (127.x.y.z, `LX_IP`), and so are its connections to 127.0.0.1:
// reachable from this machine, not from the network, which is the closest we get to Docker's isolation
// without network namespaces (and keeps Windows Firewall from prompting), and two containers can listen
// on the same port. IPv6 loopback is only ::1, so the container's ::1 is its IPv4 address too.

struct Publish {
    udp: bool,
    container: u16,
    host: u16,
    host_ip: Option<[u8; 4]>,
}

/// `LX_PORTS` (set by `lx run`, inherited by every lx process of the container): "tcp:80:8080:1.2.3.4,..."
/// Present (even empty) = this is an `lx run` container.
fn published() -> Option<&'static [Publish]> {
    static P: std::sync::OnceLock<Option<Vec<Publish>>> = std::sync::OnceLock::new();
    P.get_or_init(|| Some(parse_ports(&std::env::var("LX_PORTS").ok()?))).as_deref()
}

fn parse_ports(v: &str) -> Vec<Publish> {
    v.split(',').filter(|e| !e.is_empty()).filter_map(|e| {
        let f: Vec<&str> = e.split(':').collect();
        let ip = f.get(3).and_then(|s| s.parse::<std::net::Ipv4Addr>().ok()).map(|a| a.octets());
        Some(Publish { udp: f[0] == "udp", container: f.get(1)?.parse().ok()?, host: f.get(2)?.parse().ok()?, host_ip: ip })
    }).collect()
}

/// The published ports of the running container at loopback address `ip` (another service of a
/// compose project): from the containers' registered configs, remembered once found.
/// ponytail: a container that later takes the same address keeps the first one's ports.
fn ports_at(ip: [u8; 4]) -> Option<Vec<Publish>> {
    static SEEN: Mutex<Vec<([u8; 4], String)>> = Mutex::new(Vec::new());
    let want = std::net::Ipv4Addr::from(ip).to_string();
    let mut seen = SEEN.lock().unwrap();
    if let Some((_, v)) = seen.iter().find(|(a, _)| *a == ip) {
        return Some(parse_ports(v));
    }
    let v = crate::proc::ps().into_iter().find_map(|(pid, _)| {
        let cfg: serde_json::Value = serde_json::from_str(&crate::proc::container_config(pid)?).ok()?;
        (cfg["ip"].as_str() == Some(want.as_str())).then(|| cfg["ports"].as_str().unwrap_or("").to_string())
    })?;
    seen.push((ip, v.clone()));
    Some(parse_ports(&v))
}

/// The container's own loopback address: `LX_IP` (set by `lx run`, inherited like LX_PORTS).
fn own_ip() -> Option<[u8; 4]> {
    static IP: std::sync::OnceLock<Option<[u8; 4]>> = std::sync::OnceLock::new();
    *IP.get_or_init(|| Some(std::env::var("LX_IP").ok()?.parse::<std::net::Ipv4Addr>().ok()?.octets()))
}

/// A loopback address for the container this process is the root of (`lx run` without `--ip`):
/// 127.1-64.y.z from its Windows pid, which no other running container has.
/// ponytail: unique while pids stay under 2^24. The three ranges: lx run 127.1-64 (here), lx engine
/// 127.65-127 (engine.rs ip_for), lx compose 127.128-255 (compose.rs).
pub fn auto_ip() -> String {
    let v = std::process::id() >> 2; // Windows pids are multiples of 4
    format!("127.{}.{}.{}", 1 + (v >> 16 & 0x3f), v >> 8 & 0xff, v & 0xff)
}

/// `-p [hostip:]hostport:containerport[/udp]` -> an LX_PORTS entry.
pub fn parse_publish(spec: &str) -> Result<String, String> {
    let bad = || format!("bad -p {spec:?}: want [hostip:]hostport:containerport[/tcp|/udp]");
    let (ports, proto) = spec.split_once('/').unwrap_or((spec, "tcp"));
    if proto != "tcp" && proto != "udp" {
        return Err(bad());
    }
    let f: Vec<&str> = ports.split(':').collect();
    let (ip, host, cont) = match f.as_slice() {
        [h, c] => ("", *h, *c),
        [ip, h, c] if ip.parse::<std::net::Ipv4Addr>().is_ok() => (*ip, *h, *c),
        _ => return Err(bad()),
    };
    let (host, cont): (u16, u16) = (host.parse().map_err(|_| bad())?, cont.parse().map_err(|_| bad())?);
    if host == 0 || cont == 0 {
        return Err(bad());
    }
    Ok(format!("{proto}:{cont}:{host}:{ip}"))
}

fn is_udp(s: usize) -> bool {
    let (mut t, mut len) = (0i32, 4i32);
    unsafe { getsockopt(s, 0xffff, 0x1008, (&mut t as *mut i32).cast(), &mut len) }; // SO_TYPE
    t == 2
}

fn port_of(a: &[u8]) -> u16 {
    u16::from_be_bytes([a[2], a[3]]) // sin_port / sin6_port, network order, same offset in both
}

fn set_port(a: &mut [u8], p: u16) {
    a[2..4].copy_from_slice(&p.to_be_bytes());
}

fn is_loopback(a: &[u8]) -> bool {
    match u16::from_le_bytes([a[0], a[1]]) {
        AF_INET => a[4] == 127,
        AF_INET6_WIN if a.len() >= 24 => {
            let ip = &a[8..24];
            (ip[..15] == [0; 15] && ip[15] == 1) // ::1
                || (ip[..10] == [0; 10] && ip[10..12] == [0xff, 0xff] && ip[12] == 127) // ::ffff:127.x
        }
        _ => false,
    }
}

/// bind(): publish, or keep an unpublished any-address listener on loopback.
fn bind_addr(s: usize, a: &mut [u8]) {
    let Some(ports) = published() else { return };
    let port = port_of(a);
    if a.len() < 8 {
        return;
    }
    let fam = u16::from_le_bytes([a[0], a[1]]);
    if port == 0 {
        // An ephemeral port on loopback (a test server on 127.0.0.1:0) is where the container's clients of
        // 127.0.0.1 go: its own address. One on any address is usually a client's, which must keep
        // reaching other hosts: left alone. One on ::1 stays there (see below).
        let Some(ip) = own_ip() else { return };
        if fam == AF_INET && a[4..8] == [127, 0, 0, 1] {
            a[4..8].copy_from_slice(&ip);
        }
        return;
    }
    let udp = is_udp(s);
    if let Some(m) = ports.iter().find(|m| m.udp == udp && m.container == port) {
        set_port(a, m.host);
        if let Some(ip) = m.host_ip {
            if fam == AF_INET {
                a[4..8].copy_from_slice(&ip);
            } else if fam == AF_INET6_WIN && a.len() >= 24 {
                // An IPv6 listener published on an IPv4 host address: loopback stays loopback (::1),
                // anything else becomes the v4-mapped address.
                let v6 = if ip[0] == 127 { [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] }
                         else { [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ip[0], ip[1], ip[2], ip[3]] };
                a[8..24].copy_from_slice(&v6);
            }
        }
        return;
    }
    let ip = own_ip().unwrap_or([127, 0, 0, 1]);
    if fam == AF_INET && (a[4..8] == [0; 4] || a[4..8] == [127, 0, 0, 1]) {
        a[4..8].copy_from_slice(&ip);
    } else if fam == AF_INET6_WIN && a.len() >= 24 && (a[8..24] == [0; 16] || a[8..24] == LOOPBACK6) {
        // A dual-stack [::] listener answers IPv4 too (php-fpm's `listen = 9000`, clients dial 127.0.0.1):
        // ::ffff:<ip>. An IPV6_V6ONLY one (nginx's [::]:80 next to its 0.0.0.0:80), or one on ::1, takes
        // ::1 itself (Go's dual-stack servers, anything told to listen on ::1); the container's clients
        // of ::1 go there when something listens on it, else to its IPv4 address (dest_addr).
        // ponytail: ::1 is the host's, shared: two containers can't both listen on ::1 at one port.
        if v6only(s) || a[8..24] == LOOPBACK6 {
            a[8..24].copy_from_slice(&LOOPBACK6);
        } else {
            a[8..24].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ip[0], ip[1], ip[2], ip[3]]);
        }
    }
}

/// host.docker.internal in the container's /etc/hosts: the host's own 127.0.0.1 (dest_addr).
const HOST_GATEWAY: [u8; 4] = [127, 0, 0, 254];

const LOOPBACK6: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

fn v6only(s: usize) -> bool {
    let (mut v6only, mut l) = (0i32, 4i32);
    unsafe { getsockopt(s, 41, 27, (&mut v6only as *mut i32).cast(), &mut l) }; // IPPROTO_IPV6, IPV6_V6ONLY
    v6only != 0
}

/// connect()/sendto(): the container reaching its own published port on loopback goes to the host port,
/// its other connections to 127.0.0.1 or ::1 to its own loopback address, and host.docker.internal to
/// the host's 127.0.0.1.
fn dest_addr(s: usize, a: &mut [u8]) {
    // The wildcard address as a destination is this host on Linux; Winsock refuses it (WSAEADDRNOTAVAIL).
    match u16::from_le_bytes([a[0], a[1]]) {
        AF_INET if a.len() >= 8 && a[4..8] == [0; 4] => a[4..8].copy_from_slice(&[127, 0, 0, 1]),
        AF_INET6_WIN if a.len() >= 24 && a[8..24] == [0; 16] => a[23] = 1,
        _ => {}
    }
    let Some(ports) = published() else { return };
    if a.len() < 8 || !is_loopback(a) {
        return;
    }
    let fam = u16::from_le_bytes([a[0], a[1]]);
    if fam == AF_INET && a[4..8] == HOST_GATEWAY {
        a[4..8].copy_from_slice(&[127, 0, 0, 1]);
        return;
    }
    let at = [a[4], a[5], a[6], a[7]];
    if fam == AF_INET && at != [127, 0, 0, 1] && own_ip() != Some(at) {
        // Another container's address: a port it publishes listens on the host port (bind_addr), so a
        // service reaching `web:80` of a `-p 8091:80` container goes there, like Docker's container ports.
        let udp = is_udp(s);
        if let Some(m) = ports_at(at).and_then(|p| p.into_iter().find(|m| m.udp == udp && m.container == port_of(a))) {
            set_port(a, m.host);
            a[4..8].copy_from_slice(&m.host_ip.unwrap_or([127, 0, 0, 1]));
        }
        return;
    }
    let udp = is_udp(s);
    if let Some(m) = ports.iter().find(|m| m.udp == udp && m.container == port_of(a)) {
        set_port(a, m.host);
        return;
    }
    // A host resolver on loopback (a VPN's, dnscrypt) stays the host's.
    let (Some(ip), false) = (own_ip(), port_of(a) == 53) else { return };
    if fam == AF_INET && a[4..8] == [127, 0, 0, 1] {
        a[4..8].copy_from_slice(&ip);
    } else if fam == AF_INET6_WIN && a.len() >= 24 && a[8..24] == LOOPBACK6 && !v6only(s) && !bound_to_loopback6(s) && !on_loopback6(s, port_of(a)) {
        a[8..24].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ip[0], ip[1], ip[2], ip[3]]);
    }
}

/// Whether s is bound to ::1 (Go's dialer binds a local address first): it can only reach ::1 then.
fn bound_to_loopback6(s: usize) -> bool {
    let (mut a, mut l) = ([0u8; 28], 28i32);
    (unsafe { getsockname(s, a.as_mut_ptr(), &mut l) } == 0) && u16::from_le_bytes([a[0], a[1]]) == AF_INET6_WIN && a[8..24] == LOOPBACK6
}

/// Whether something has [::1]:port (of s's type): then a connection to ::1 goes there, as asked. Asked
/// by trying to bind it, only for connections to ::1 (rare).
fn on_loopback6(s: usize, port: u16) -> bool {
    let probe = unsafe { socket(AF_INET6_WIN as i32, if is_udp(s) { 2 } else { 1 }, 0) };
    if probe == usize::MAX {
        return false;
    }
    let mut a = [0u8; 28];
    a[..2].copy_from_slice(&AF_INET6_WIN.to_le_bytes());
    a[2..4].copy_from_slice(&port.to_be_bytes());
    a[8..24].copy_from_slice(&LOOPBACK6);
    let taken = unsafe { bind(probe, a.as_ptr(), 28) } != 0 && unsafe { WSAGetLastError() } == 10048; // WSAEADDRINUSE
    unsafe { closesocket(probe) };
    taken
}

/// getsockname(): show the container port the program asked for.
fn local_addr(s: usize, a: &mut [u8]) {
    let Some(ports) = published() else { return };
    if a.len() < 8 {
        return;
    }
    let udp = is_udp(s);
    if let Some(m) = ports.iter().find(|m| m.udp == udp && m.host == port_of(a)) {
        set_port(a, m.container);
    }
}

// ---- AF_UNIX ----
//
// Windows 10+ has AF_UNIX stream sockets backed by a file (no datagram ones). sun_path is limited to 108
// bytes and container paths are long, so the real socket file is `rootfs\s\<hash>` (relative to the
// project dir, every lx process's cwd); the hash covers the container's layer + the guest path, so
// processes of one container meet and containers don't collide. The guest path gets a marker file so
// it shows up as a socket. Abstract names (leading NUL) hash the same way, without a marker.
// ponytail: no SCM_RIGHTS / credentials.
//
// Datagram AF_UNIX (/dev/log, sd_notify): Windows has none, so it's a UDP socket bound to 127.0.0.1.
// The host file of a bound address holds the port; s\<container>\u<port> holds the guest address
// back, so recvfrom can name the sender (no file: unnamed).
// ponytail: those files stay after close (a later bind overwrites them); sending to a dead address
// succeeds silently where Linux says ECONNREFUSED.

const SOCK_DIR: &str = "rootfs\\s";

struct UnixAddr {
    win: Vec<u8>,          // struct sockaddr_un for Winsock (family 1, short host path)
    guest: Vec<u8>,        // what the guest passed, for getsockname/getpeername
    path: Option<String>,  // normalized guest path; None for abstract names
    exists: bool,
}

fn unix_addr(p: u64, len: u64) -> Result<UnixAddr, i64> {
    if p == 0 || !(3..=110).contains(&len) {
        return Err(EINVAL);
    }
    let guest = unsafe { std::slice::from_raw_parts(p as *const u8, len as usize) }.to_vec();
    let raw = &guest[2..];
    let (key, path, exists, dir) = if raw[0] == 0 {
        (format!("@{}", String::from_utf8_lossy(&raw[1..])), None, false, fs::container())
    } else {
        let s = String::from_utf8_lossy(&raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())]).into_owned();
        let (g, exists, dir) = fs::unix_path(&s)?;
        (g.clone(), Some(g), exists, dir)
    };
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut h = DefaultHasher::new(); // fixed keys: every lx process computes the same name
    key.hash(&mut h);
    // rootfs\s\<container>\<hash>: well under sun_path's 108 bytes, and removed with the container.
    let host = format!("{SOCK_DIR}\\{dir}\\{:016x}", h.finish());
    let mut win = vec![0u8; 110];
    win[0] = AF_UNIX as u8;
    win[2..2 + host.len()].copy_from_slice(host.as_bytes());
    Ok(UnixAddr { win, guest, path, exists })
}

impl UnixAddr {
    /// The host path (rootfs\s\<container>\<hash>).
    fn host(&self) -> String {
        let end = self.win.iter().skip(2).position(|&b| b == 0).map_or(110, |i| i + 2);
        String::from_utf8_lossy(&self.win[2..end]).into_owned()
    }
}

fn loopback(port: u16) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = AF_INET as u8;
    a[2..4].copy_from_slice(&port.to_be_bytes());
    a[4..8].copy_from_slice(&[127, 0, 0, 1]);
    a
}

fn unix_dgram(nonblock: bool) -> Result<Sock, i64> {
    let s = unsafe { socket(2, 2, 0) };
    if s == INVALID_SOCKET {
        return Err(last_err());
    }
    let mut sock = Sock::new(s, nonblock); // closes `s` on error
    sock.udgram = true;
    let a = loopback(0);
    if unsafe { bind(s, a.as_ptr(), 16) } != 0 {
        return Err(last_err());
    }
    // A send to a closed port must not fail the next recvfrom with ECONNRESET (Windows' default).
    let (off, mut got) = (0u32, 0u32);
    const SIO_UDP_CONNRESET: u32 = 0x9800000C;
    unsafe { WSAIoctl(s, SIO_UDP_CONNRESET, (&off as *const u32).cast(), 4, std::ptr::null_mut(), 0, &mut got, std::ptr::null_mut(), std::ptr::null_mut()) };
    Ok(sock)
}

fn udgram_port(s: &Sock) -> u16 {
    let (mut a, mut len) = ([0u8; 16], 16i32);
    unsafe { getsockname(s.s, a.as_mut_ptr(), &mut len) };
    u16::from_be_bytes([a[2], a[3]])
}

fn udgram_names(port: u16) -> String {
    format!("{SOCK_DIR}\\{}\\u{port}", fs::container())
}

/// The loopback address a datagram AF_UNIX destination lives at.
fn udgram_dest(p: u64, len: u64) -> Result<(UnixAddr, [u8; 16]), i64> {
    let a = unix_addr(p, len)?;
    if a.path.is_some() && !a.exists {
        return Err(crate::syscall::ENOENT);
    }
    let port = std::fs::read_to_string(a.host()).ok().and_then(|v| v.trim().parse().ok()).ok_or(111)?; // ECONNREFUSED
    Ok((a, loopback(port)))
}

fn is_unix_addr(p: u64, len: u64) -> bool {
    p != 0 && len >= 2 && unsafe { *(p as *const u16) } == AF_UNIX
}

fn unix_bind(s: &Sock, p: u64, len: u64) -> R {
    let a = unix_addr(p, len)?;
    if a.exists {
        return Err(98); // EADDRINUSE: Linux needs the path to be free (servers unlink it first)
    }
    let host = a.host();
    if let Some(d) = std::path::Path::new(&host).parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::remove_file(&host); // a stale socket file from an earlier run
    if s.udgram {
        let port = udgram_port(s);
        std::fs::write(&host, port.to_string()).map_err(|_| crate::syscall::EACCES)?;
        std::fs::write(udgram_names(port), &a.guest).map_err(|_| crate::syscall::EACCES)?;
    } else if unsafe { bind(s.s, a.win.as_ptr(), a.win.len() as i32) } != 0 {
        return Err(last_err());
    }
    if let Some(g) = &a.path {
        fs::mark_socket(g)?;
    }
    *s.unix.lock().unwrap() = Some(a.guest);
    Ok(0)
}

fn unix_connect(s: &Sock, p: u64, len: u64) -> R {
    if s.udgram {
        let (a, dest) = udgram_dest(p, len)?;
        if unsafe { connect(s.s, dest.as_ptr(), 16) } != 0 {
            return Err(last_err());
        }
        *s.peer.lock().unwrap() = Some(a.guest);
        return Ok(0);
    }
    let a = unix_addr(p, len)?;
    if a.path.is_some() && !a.exists {
        return Err(crate::syscall::ENOENT);
    }
    *s.peer.lock().unwrap() = Some(a.guest);
    if unsafe { connect(s.s, a.win.as_ptr(), a.win.len() as i32) } == 0 {
        return Ok(0);
    }
    match last_err() {
        EAGAIN if s.nonblocking() => Err(115),
        EAGAIN => {
            s.wait(POLLOUT)?;
            match so_error(s.s) { 0 => Ok(0), e => Err(e) }
        }
        e => Err(e),
    }
}

/// An AF_UNIX address for the guest: the stored path, or "unnamed" (just the family).
fn unix_out(saved: Option<Vec<u8>>, p: u64, lenp: u64) {
    let a = saved.unwrap_or_else(|| vec![AF_UNIX as u8, 0]);
    if p == 0 || lenp == 0 {
        return;
    }
    let room = unsafe { *(lenp as *const u32) } as usize;
    unsafe {
        std::ptr::copy_nonoverlapping(a.as_ptr(), p as *mut u8, room.min(a.len()));
        *(lenp as *mut u32) = a.len() as u32;
    }
}

fn family(domain: u64) -> Result<i32, i64> {
    match domain as u16 {
        AF_UNIX => Ok(1),
        AF_INET => Ok(2),
        AF_INET6_LINUX => Ok(AF_INET6_WIN as i32),
        _ => Err(EAFNOSUPPORT),
    }
}

const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2000000;

pub fn sys_socket(domain: u64, ty: u64, proto: u64) -> R {
    init();
    if domain == AF_NETLINK {
        if proto != 0 {
            return Err(93); // EPROTONOSUPPORT: only NETLINK_ROUTE
        }
        let mut sock = unix_dgram(ty & SOCK_NONBLOCK != 0)?;
        (sock.udgram, sock.netlink) = (false, true);
        return fs::add_fd(Fd::Socket(Arc::new(sock)), ty & SOCK_CLOEXEC != 0);
    }
    let af = family(domain)?;
    let base = (ty & 0xf) as i32; // SOCK_STREAM 1, SOCK_DGRAM 2, SOCK_RAW 3: same numbers
    if af == 1 && base == 2 {
        let sock = unix_dgram(ty & SOCK_NONBLOCK != 0)?;
        return fs::add_fd(Fd::Socket(Arc::new(sock)), ty & SOCK_CLOEXEC != 0);
    }
    if af == 1 && base != 1 {
        return Err(93); // EPROTONOSUPPORT: Windows has stream AF_UNIX sockets only
    }
    let s = unsafe { socket(af, base, proto as i32) };
    if s == INVALID_SOCKET {
        return Err(last_err());
    }
    if af == AF_INET6_WIN as i32 {
        let off = 0i32; // Linux default: IPv6 sockets also accept IPv4 (Windows defaults to v6-only)
        unsafe { setsockopt(s, 41, 27, (&off as *const i32).cast(), 4) };
    }
    let sock = Sock::new(s, ty & SOCK_NONBLOCK != 0);
    fs::add_fd(Fd::Socket(Arc::new(sock)), ty & SOCK_CLOEXEC != 0)
}

/// socketpair: Windows has no AF_UNIX pairs. A stream pair is two native AF_UNIX sockets met through a
/// listener at a throwaway path (getsockname says AF_UNIX, as on Linux); a datagram pair is two datagram
/// sockets connected to each other's port, so message boundaries hold.
pub fn sys_socketpair(_domain: u64, ty: u64, _proto: u64, out: u64) -> R {
    init();
    let (nb, cx) = (ty & SOCK_NONBLOCK != 0, ty & SOCK_CLOEXEC != 0);
    let (x, y) = if ty & 0xf == 2 { dgram_pair(nb)? } else { stream_pair(nb)? };
    let a = fs::add_fd(Fd::Socket(Arc::new(x)), cx)?;
    let b = fs::add_fd(Fd::Socket(Arc::new(y)), cx).inspect_err(|_| _ = fs::close(a as u64))?;
    unsafe { *(out as *mut [i32; 2]) = [a as i32, b as i32] };
    Ok(0)
}

fn dgram_pair(nb: bool) -> Result<(Sock, Sock), i64> {
    let (x, y) = (unix_dgram(nb)?, unix_dgram(nb)?);
    for (from, to) in [(&x, &y), (&y, &x)] {
        let a = loopback(udgram_port(to));
        if unsafe { connect(from.s, a.as_ptr(), 16) } != 0 {
            return Err(last_err());
        }
    }
    Ok((x, y))
}

fn stream_pair(nb: bool) -> Result<(Sock, Sock), i64> {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = format!("{SOCK_DIR}\\{}", fs::container());
    let _ = std::fs::create_dir_all(&dir);
    let path = format!("{dir}\\pair-{}-{}", std::process::id(), N.fetch_add(1, Relaxed));
    let mut a = vec![0u8; 110];
    a[0] = AF_UNIX as u8;
    a[2..2 + path.len()].copy_from_slice(path.as_bytes());
    let sock = |s: usize| if s == INVALID_SOCKET { Err(last_err()) } else { Ok(s) };
    let l = Sock::new(sock(unsafe { socket(1, 1, 0) })?, false); // closed (and its file removed) below
    let r = (|| {
        if unsafe { bind(l.s, a.as_ptr(), 110) } != 0 || unsafe { listen(l.s, 1) } != 0 {
            return Err(last_err());
        }
        let c = Sock::new(sock(unsafe { socket(1, 1, 0) })?, nb);
        if unsafe { connect(c.s, a.as_ptr(), 110) } != 0 && last_err() != EAGAIN {
            return Err(last_err());
        }
        // The connect is already queued on the listener: accepting can't block for long.
        let mut p = WsaPollFd { fd: l.s, events: WSA_POLLRDNORM, revents: 0 };
        unsafe { WSAPoll(&mut p, 1, 5000) };
        let s = Sock::new(sock(unsafe { accept(l.s, std::ptr::null_mut(), std::ptr::null_mut()) })?, nb);
        Ok((c, s))
    })();
    drop(l);
    let _ = std::fs::remove_file(&path);
    r
}

pub fn sys_bind(fd: u64, addr: u64, len: u64) -> R {
    let s = fs::sock(fd)?;
    if s.netlink {
        return Ok(0); // the port id is ours already; no multicast groups
    }
    if is_unix_addr(addr, len) {
        return unix_bind(&s, addr, len);
    }
    let mut a = addr_in(addr, len)?;
    bind_addr(s.s, &mut a);
    if unsafe { bind(s.s, a.as_ptr(), a.len() as i32) } != 0 { Err(last_err()) } else { Ok(0) }
}

pub fn sys_listen(fd: u64, backlog: u64) -> R {
    let s = fs::sock(fd)?;
    if unsafe { listen(s.s, backlog.min(i32::MAX as u64) as i32) } != 0 { Err(last_err()) } else { Ok(0) }
}

/// accept() that can't block, for IP listeners. Winsock's own accept() on a listening socket shared by
/// several processes (nginx workers after fork) can block forever even in non-blocking mode, when another
/// process takes the connection between our readiness check and the accept (probe/acceptrace.c). So:
/// nothing pending -> EAGAIN; else an overlapped AcceptEx, and if it hasn't completed within 10 ms the
/// connection went elsewhere: cancel, EAGAIN. Returns the new socket and the peer address.
fn accept_nowait(ls: usize) -> Result<(usize, Vec<u8>), i64> {
    let mut p = WsaPollFd { fd: ls, events: WSA_POLLRDNORM, revents: 0 };
    if unsafe { WSAPoll(&mut p, 1, 0) } <= 0 {
        return Err(EAGAIN);
    }
    let (mut la, mut ll) = ([0u8; 128], 128i32);
    if unsafe { getsockname(ls, la.as_mut_ptr(), &mut ll) } != 0 {
        return Err(last_err());
    }
    let acc = unsafe { socket(u16::from_le_bytes([la[0], la[1]]) as i32, 1, 0) }; // SOCK_STREAM, same family
    if acc == INVALID_SOCKET {
        return Err(last_err());
    }
    const ALEN: u32 = 128 + 16; // AcceptEx wants address space + 16 per side
    let mut buf = [0u8; 2 * ALEN as usize];
    let ev = unsafe { crate::win::CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
    let mut ov = Overlapped { event: ev, ..Default::default() };
    let mut got = 0u32;
    let done = unsafe {
        if AcceptEx(ls, acc, buf.as_mut_ptr(), 0, ALEN, ALEN, &mut got, &mut ov) != 0 {
            true
        } else if WSAGetLastError() != 997 { // not ERROR_IO_PENDING: a real error
            let e = last_err();
            crate::win::CloseHandle(ev);
            closesocket(acc);
            return Err(e);
        } else {
            if WaitForSingleObject(ev, 10) != 0 {
                crate::win::CancelIoEx(ls as isize, (&raw mut ov).cast());
            }
            // After a cancel the result still says whether a connection got in first.
            crate::win::GetOverlappedResult(ls as isize, (&raw mut ov).cast(), &mut got, 1) != 0
        }
    };
    unsafe { crate::win::CloseHandle(ev) };
    if !done {
        unsafe { closesocket(acc) };
        return Err(EAGAIN);
    }
    unsafe {
        setsockopt(acc, 0xffff, 0x700B, (&ls as *const usize).cast(), size_of::<usize>() as i32); // SO_UPDATE_ACCEPT_CONTEXT
        let (mut lp, mut rp) = (std::ptr::null_mut(), std::ptr::null_mut());
        let (mut ln, mut rn) = (0i32, 0i32);
        GetAcceptExSockaddrs(buf.as_ptr(), 0, ALEN, ALEN, &mut lp, &mut ln, &mut rp, &mut rn);
        Ok((acc, std::slice::from_raw_parts(rp, rn.max(0) as usize).to_vec()))
    }
}

pub fn sys_accept(fd: u64, addr: u64, lenp: u64, flags: u64) -> R {
    let s = fs::sock(fd)?;
    // A socket that can't accept fails at once on Linux; s.op below would wait for POLLIN forever.
    if is_udp(s.s) {
        return Err(95); // EOPNOTSUPP
    }
    let (mut listening, mut len) = (0i32, 4i32);
    if unsafe { getsockopt(s.s, 0xffff, 0x0002, (&mut listening as *mut i32).cast(), &mut len) } == 0 && listening == 0 {
        return Err(EINVAL); // SO_ACCEPTCONN: not listening
    }
    let unix = s.unix.lock().unwrap().is_some();
    let new = s.op(POLLIN, false, || {
        if !unix {
            return accept_nowait(s.s);
        }
        // ponytail: AF_UNIX listeners use plain accept(); Windows' AF_UNIX has no AcceptEx.
        let (mut a, mut alen) = ([0u8; 128], 128i32);
        let n = unsafe { accept(s.s, a.as_mut_ptr(), &mut alen) };
        if n == INVALID_SOCKET { Err(last_err()) } else { Ok((n, a[..alen as usize].to_vec())) }
    })?;
    if unix {
        unix_out(None, addr, lenp); // the connecting side is unnamed
    } else {
        addr_out(&new.1, addr, lenp);
    }
    let sock = Sock::new(new.0, flags & SOCK_NONBLOCK != 0);
    fs::add_fd(Fd::Socket(Arc::new(sock)), flags & SOCK_CLOEXEC != 0)
}

fn so_error(s: usize) -> i64 {
    let (mut e, mut len) = (0i32, 4i32);
    unsafe { getsockopt(s, 0xffff, 0x1007, (&mut e as *mut i32).cast(), &mut len) };
    if e == 0 { 0 } else { wsa_errno(e) }
}

pub fn sys_connect(fd: u64, addr: u64, len: u64) -> R {
    let s = fs::sock(fd)?;
    if is_unix_addr(addr, len) {
        return unix_connect(&s, addr, len);
    }
    let mut a = addr_in(addr, len)?;
    dest_addr(s.s, &mut a);
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
    if addr == 0 || s.netlink {
        return s.send(buf, len, flags);
    }
    let a = if s.udgram && is_unix_addr(addr, alen) {
        udgram_dest(addr, alen)?.1.to_vec() // our own plumbing on the host's loopback: not rewritten
    } else {
        let mut a = addr_in(addr, alen)?;
        dest_addr(s.s, &mut a);
        a
    };
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
    if s.netlink {
        addr_out(&nl_addr(0), addr, lenp); // from the kernel
    } else if s.udgram && alen >= 4 {
        unix_out(std::fs::read(udgram_names(u16::from_be_bytes([a[2], a[3]]))).ok(), addr, lenp);
    } else if alen > 0 {
        addr_out(&a[..alen as usize], addr, lenp);
    } else if lenp != 0 {
        unsafe { *(lenp as *mut u32) = 0 }; // connected stream: no address
    }
    Ok(n)
}

/// struct msghdr { name, namelen, iov, iovlen, control, controllen, flags }.
/// Control messages: SCM_RIGHTS (see below); credentials aren't supported.
/// sendmmsg/recvmmsg: an array of struct mmsghdr { msghdr (56 bytes); u32 msg_len; pad } = 64 bytes.
/// glibc's resolver sends its A and AAAA queries in one sendmmsg. Returns how many went through.
pub fn sys_mmsg(fd: u64, vec: u64, n: u64, flags: u64, send: bool) -> R {
    const MSG_WAITFORONE: u64 = 0x10000;
    let mut done = 0u64;
    for i in 0..n.min(1024) {
        let hdr = vec + i * 64;
        // After the first message, recvmmsg(MSG_WAITFORONE) must not block for more.
        let f = if !send && flags & MSG_WAITFORONE != 0 && done > 0 { flags | MSG_DONTWAIT } else { flags } & !MSG_WAITFORONE;
        let r = if send { sys_sendmsg(fd, hdr, f) } else { sys_recvmsg(fd, hdr, f) };
        match r {
            Ok(len) => {
                unsafe { *((hdr + 56) as *mut u32) = len as u32 };
                done += 1;
            }
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(done as i64)
}

pub fn sys_sendmsg(fd: u64, msg: u64, flags: u64) -> R {
    let m = unsafe { *(msg as *const [u64; 7]) };
    let data = gather(m[2], m[3])?;
    if m[4] != 0 && m[5] >= 16 {
        scm_send(&*fs::sock(fd)?, m[4], m[5])?; // the fds go out before the data they ride with
    }
    sys_sendto(fd, data.as_ptr() as u64, data.len() as u64, flags, m[0], m[1] & 0xffff_ffff)
}

pub fn sys_recvmsg(fd: u64, msg: u64, flags: u64) -> R {
    let m = unsafe { &mut *(msg as *mut [u64; 7]) };
    let iovs = iovecs(m[2], m[3])?;
    for &[base, len] in &iovs {
        crate::syscall::check_guest(base, len as usize, true)?;
    }
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
    const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;
    let ctl = if m[4] != 0 && m[5] >= 16 { scm_recv(&*fs::sock(fd)?, m[4], m[5], flags & MSG_CMSG_CLOEXEC != 0) } else { 0 };
    (m[5], m[6]) = (ctl, 0); // SCM_RIGHTS if any, no flags
    Ok(n as i64)
}


// ---- SCM_RIGHTS ----
//
// Passing fds over AF_UNIX: the sender duplicates each handle into the container's first lx process
// (it lives as long as the container and runs nothing for this), and drops a record naming them in a
// per-connection queue directory before it sends the data. recvmsg takes the oldest record after its
// data arrives and pulls the handles out with DUPLICATE_CLOSE_SOURCE. So the fds survive the sender
// closing them or exiting right after sendmsg (erts does).
// ponytail: a connection is keyed by the AF_UNIX path it was made through, which is unique for
// socketpairs; clients of one listening path share a queue (fine unless several pass fds at once).
// Records aren't tied to byte offsets: the next recvmsg with control space after the data takes them.

/// The handle-holding process: the container's first lx (LX_IN_JOB carries its pid), else ourselves.
fn holder() -> isize {
    static H: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);
    let h = H.load(Relaxed);
    if h != 0 {
        return h;
    }
    let pid = std::env::var("LX_IN_JOB").ok().and_then(|v| v.parse().ok()).unwrap_or(std::process::id());
    let h = unsafe { crate::win::OpenProcess(0x0040, 0, pid) }; // PROCESS_DUP_HANDLE
    let h = if h == 0 { unsafe { crate::win::GetCurrentProcess() } } else { h };
    H.store(h, Relaxed);
    h
}

/// The queue directory both ends of `s`'s connection agree on.
fn scm_dir(s: &Sock) -> Option<String> {
    let path = |f: unsafe extern "system" fn(usize, *mut u8, *mut i32) -> i32| {
        let mut a = [0u8; 110];
        let mut len = a.len() as i32;
        let ok = unsafe { f(s.s, a.as_mut_ptr(), &mut len) } == 0 && a[0] == AF_UNIX as u8 && a[2] != 0;
        ok.then(|| a[2..].iter().take_while(|&&b| b != 0).copied().collect::<Vec<u8>>())
    };
    let p = path(getpeername).or_else(|| path(getsockname))?;
    let mut h = std::hash::DefaultHasher::new();
    std::hash::Hash::hash(&p, &mut h);
    Some(format!("{SOCK_DIR}\\{}\\scm-{:016x}", fs::container(), std::hash::Hasher::finish(&h)))
}

/// sendmsg's SCM_RIGHTS control messages: queue the fds for the peer.
fn scm_send(s: &Sock, control: u64, len: u64) -> Result<(), i64> {
    use crate::win::*;
    let mut lines = Vec::new();
    let mut off = 0;
    while off + 16 <= len {
        let (clen, level, ty) = unsafe { (*((control + off) as *const u64), *((control + off + 8) as *const i32), *((control + off + 12) as *const i32)) };
        if clen < 16 {
            break;
        }
        if level == 1 && ty == 1 { // SOL_SOCKET, SCM_RIGHTS
            for i in 0..(clen - 16) / 4 {
                let fd = unsafe { *((control + off + 16 + i * 4) as *const i32) } as u64;
                let (kind, h, extra) = fs::export_fd(fd)?;
                let mut out = 0isize;
                if h != 0 && unsafe { DuplicateHandle(GetCurrentProcess(), h as isize, holder(), &mut out, 0, 0, 2) } == 0 {
                    return Err(EINVAL);
                }
                lines.push(format!("{kind}\t{out}\t{extra}"));
            }
        }
        off += clen.next_multiple_of(8);
    }
    if lines.is_empty() {
        return Ok(());
    }
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = scm_dir(s).ok_or(EINVAL)?;
    let _ = std::fs::create_dir_all(&dir);
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let name = format!("{dir}\\{t:024}-{}-{:06}", std::process::id(), N.fetch_add(1, Relaxed));
    std::fs::write(&name, lines.join("\n")).map_err(|_| EINVAL)
}

/// recvmsg: the oldest queued record for this connection as an SCM_RIGHTS control message.
/// Returns the control length written (0: none queued, or no room).
fn scm_recv(s: &Sock, control: u64, cap: u64, cloexec: bool) -> u64 {
    use crate::win::*;
    let Some(dir) = scm_dir(s) else { return 0 };
    let Ok(rd) = std::fs::read_dir(&dir) else { return 0 };
    let mut names: Vec<_> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_none_or(|e| e != "taken")).collect();
    names.sort();
    for p in names {
        let claimed = p.with_extension("taken");
        if std::fs::rename(&p, &claimed).is_err() {
            continue; // another receiver got it first
        }
        let text = std::fs::read_to_string(&claimed).unwrap_or_default();
        let _ = std::fs::remove_file(&claimed);
        let mut fds = Vec::new();
        for line in text.lines() {
            let mut f = line.splitn(3, '\t');
            let (Some(kind), Some(h), extra) = (f.next(), f.next().and_then(|h| h.parse::<isize>().ok()), f.next().unwrap_or("")) else { continue };
            let mut mine = 0isize;
            if h != 0 && unsafe { DuplicateHandle(holder(), h, GetCurrentProcess(), &mut mine, 0, 0, 1 | 2) } == 0 {
                continue; // DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS
            }
            if let Ok(fd) = fs::import_fd(kind, mine as usize, extra, cloexec) {
                fds.push(fd as i32);
            }
        }
        let need = 16 + 4 * fds.len() as u64;
        if fds.is_empty() || cap < need {
            for fd in fds {
                let _ = fs::close(fd as u64);
            }
            return 0;
        }
        unsafe {
            *(control as *mut u64) = need;
            *((control + 8) as *mut i32) = 1;
            *((control + 12) as *mut i32) = 1;
            std::ptr::copy_nonoverlapping(fds.as_ptr(), (control + 16) as *mut i32, fds.len());
        }
        return need.next_multiple_of(8).min(cap);
    }
    0
}
fn iovecs(iov: u64, n: u64) -> Result<Vec<[u64; 2]>, i64> {
    if n > 1024 {
        return Err(EINVAL);
    }
    crate::syscall::check_guest(iov, n as usize * 16, false)?;
    Ok((0..n).map(|i| unsafe { *((iov + i * 16) as *const [u64; 2]) }).collect())
}

fn gather(iov: u64, n: u64) -> Result<Vec<u8>, i64> {
    let mut data = Vec::new();
    for [base, len] in iovecs(iov, n)? {
        data.extend(crate::syscall::get_guest_vec(base, len as usize).ok_or(crate::syscall::EFAULT)?);
    }
    Ok(data)
}

pub fn sys_shutdown(fd: u64, how: u64) -> R {
    let s = fs::sock(fd)?;
    if unsafe { shutdown(s.s, how as i32) } != 0 { Err(last_err()) } else { Ok(0) } // SHUT_* == SD_*
}

pub fn sys_getsockname(fd: u64, addr: u64, lenp: u64, peer: bool) -> R {
    let s = fs::sock(fd)?;
    // *lenp (dispatch checked the pointer) must be >= 0, and that much of addr writable.
    let room = i32::from_le_bytes(crate::syscall::get_guest::<4>(lenp)?);
    if room < 0 {
        return Err(EINVAL);
    }
    crate::syscall::check_guest(addr, (room as usize).min(128), true)?;
    if s.netlink {
        addr_out(&nl_addr(if peer { 0 } else { nl_pid() }), addr, lenp);
        return Ok(0);
    }
    let mut a = [0u8; 128];
    let mut alen = a.len() as i32;
    let r = unsafe { if peer { getpeername(s.s, a.as_mut_ptr(), &mut alen) } else { getsockname(s.s, a.as_mut_ptr(), &mut alen) } };
    if r != 0 {
        return Err(last_err());
    }
    if s.udgram || u16::from_le_bytes([a[0], a[1]]) == AF_UNIX {
        let saved = if peer { s.peer.lock().unwrap().clone() } else { s.unix.lock().unwrap().clone() };
        unix_out(saved, addr, lenp);
        return Ok(0);
    }
    if !peer {
        local_addr(s.s, &mut a[..alen as usize]);
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
    if (level, name) == (1, 15) && is_udp(s.s) && len >= 4 && unsafe { *(val as *const i32) } != 0 {
        // SO_REUSEPORT on UDP (nginx's `listen 443 quic reuseport`: a socket per worker on one address):
        // Windows' SO_REUSEADDR lets them share it. ponytail: TCP keeps ignoring it, since SO_REUSEADDR
        // on a Windows TCP listener would let another process take the port.
        let on = 1i32;
        unsafe { setsockopt(s.s, 0xffff, 0x0004, (&on as *const i32).cast(), 4) };
        return Ok(0);
    }
    let Some((l, n)) = sockopt(level, name) else { return Ok(0) };
    if unsafe { setsockopt(s.s, l, n, val as *const u8, len.min(64) as i32) } != 0 { Err(last_err()) } else { Ok(0) }
}

pub fn sys_getsockopt(fd: u64, level: u64, name: u64, val: u64, lenp: u64) -> R {
    let s = fs::sock(fd)?;
    // *lenp must be readable and >= 0, and that much of val writable.
    let room = i32::from_le_bytes(crate::syscall::get_guest::<4>(lenp)?);
    if room < 0 {
        return Err(EINVAL);
    }
    crate::syscall::check_guest(lenp, 4, true)?;
    crate::syscall::check_guest(val, (room as usize).min(256), true)?;
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
        (1, 17) => {
            // SO_PEERCRED: struct ucred { pid, uid, gid } (s6's getpeereid, s6-sudod). ponytail: the peer isn't
            // known; both ends are in this container, usually as the same user, so it's our own credentials.
            let ids = [crate::proc::getpid().unwrap_or(0) as u32, crate::proc::UID.load(Relaxed), crate::proc::GID.load(Relaxed)];
            unsafe { *(val as *mut [u32; 3]) = ids };
            unsafe { *(lenp as *mut u32) = 12 };
            return Ok(0);
        }
        (6, 11) => {
            // TCP_INFO: the state (LISTEN or ESTABLISHED), counters zero. php-fpm reads its listen queue
            // from it every second. ponytail: no real statistics.
            let (mut listening, mut l) = (0i32, 4i32);
            unsafe { getsockopt(s.s, 0xffff, 0x0002, (&mut listening as *mut i32).cast(), &mut l) }; // SO_ACCEPTCONN
            let n = unsafe { *(lenp as *const u32) }.min(232) as usize;
            let out = unsafe { std::slice::from_raw_parts_mut(val as *mut u8, n) };
            out.fill(0);
            if n > 0 {
                out[0] = if listening != 0 { 10 } else { 1 }; // TCP_LISTEN / TCP_ESTABLISHED
            }
            unsafe { *(lenp as *mut u32) = n as u32 };
            return Ok(0);
        }
        (1, 38) | (1, 39) => {
            // SO_PROTOCOL, SO_DOMAIN (Python's socket(fileno=fd) asks both).
            let mut a = [0u8; 128];
            let mut len = a.len() as i32;
            unsafe { getsockname(s.s, a.as_mut_ptr(), &mut len) };
            let unix = s.udgram || a[0] == AF_UNIX as u8;
            let (mut t, mut tl) = (0i32, 4i32);
            unsafe { getsockopt(s.s, 0xffff, 0x1008, (&mut t as *mut i32).cast(), &mut tl) }; // SO_TYPE
            return int(match name {
                39 if unix => 1,
                39 => if a[0] == 23 { 10 } else { 2 }, // AF_INET6 is 23 on Windows, 10 on Linux
                _ if unix => 0,
                _ => if t == 1 { 6 } else { 17 },        // IPPROTO_TCP / IPPROTO_UDP
            });
        }
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

/// Adding epoll `inner` to `epfd`: ELOOP if `epfd` is inside it (a cycle), EINVAL past Linux's 4 levels.
fn nests(inner: &Mutex<Epoll>, epfd: i32, depth: u32) -> Result<(), i64> {
    if depth > 4 {
        return Err(EINVAL);
    }
    let fds: Vec<i32> = inner.lock().unwrap().entries.iter().map(|x| x.fd).collect();
    for fd in fds {
        if fd == epfd {
            return Err(40); // ELOOP
        }
        if let Ok(e) = fs::epoll(fd as u64) {
            nests(&e, epfd, depth + 1)?;
        }
    }
    Ok(())
}

/// An epoll fd in poll, select or another epoll: readable when one of its entries is ready (level).
/// ponytail: nesting is followed 4 deep at most; Linux refuses deeper or looping nests (ELOOP) instead.
pub fn epoll_ready(ep: &Mutex<Epoll>) -> bool {
    thread_local!(static DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) });
    if DEPTH.get() >= 4 {
        return false;
    }
    let fds: Vec<(i32, i16)> = ep.lock().unwrap().entries.iter().filter(|x| !x.disabled).map(|x| (x.fd, (x.events & 0xffff) as i16)).collect();
    DEPTH.set(DEPTH.get() + 1);
    let r = fds.iter().any(|&(fd, ev)| fs::readiness(fd, ev) & !0x20 != 0);
    DEPTH.set(DEPTH.get() - 1);
    r
}

/// An epoll's registrations for a fork/exec child: "fd:events:data:disabled" joined by ';'. Linux shares
/// the instance across fork; the child gets an equal one over the same fd numbers (php-fpm's workers use
/// the master's). ponytail: edge state starts fresh, and later changes on either side aren't shared.
pub fn epoll_export(ep: &Mutex<Epoll>) -> String {
    ep.lock().unwrap().entries.iter().map(|e| format!("{}:{}:{}:{}", e.fd, e.events, e.data, e.disabled as u8)).collect::<Vec<_>>().join(";")
}

pub fn epoll_import(s: &str) -> Epoll {
    let entries = s.split(';').filter_map(|e| {
        let f: Vec<&str> = e.split(':').collect();
        let [fd, events, data, disabled] = f.as_slice() else { return None };
        Some(Entry { fd: fd.parse().ok()?, events: events.parse().ok()?, data: data.parse().ok()?, reported: 0, disabled: *disabled == "1" })
    }).collect();
    Epoll { entries }
}

pub fn sys_epoll_create(flags: u64) -> R {
    if flags & !0o2000000 != 0 {
        return Err(EINVAL); // only EPOLL_CLOEXEC
    }
    fs::add_fd(Fd::Epoll(Arc::new(Mutex::new(Epoll::default()))), flags & 0o2000000 != 0)
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
    if fs::is_file(fd as u64) {
        return Err(crate::syscall::EPERM); // regular files and directories are always ready: not pollable
    }
    if fd < 0 || fs::readiness(fd, 0) & 0x20 != 0 {
        return Err(9); // EBADF
    }
    if fd as u64 == epfd {
        return Err(EINVAL);
    }
    if ev == 0 && op != 2 {
        return Err(crate::syscall::EFAULT);
    }
    if op == 1 && let Ok(inner) = fs::epoll(fd as u64) {
        nests(&inner, epfd as i32, 1)?;
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
    let _fine = crate::syscall::FineWait::for_ms(timeout_ms);
    let ep = fs::epoll(epfd)?;
    if max == 0 || max > 1 << 16 {
        return Err(EINVAL);
    }
    crate::syscall::check_guest(out, max as usize * 12, true)?; // struct epoll_event is 12 bytes, packed
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
                } else if x.events & EPOLLET != 0 {
                    x.reported &= !fs::take_rearm(x.fd); // read, or found full, since we looked
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

/// Sleep up to `ms` until one of these sockets is ready for its poll events (POLLIN, POLLOUT).
pub fn wait_sockets(socks: &[(usize, i16)], ms: i32) {
    let mut p: Vec<WsaPollFd> = socks.iter().map(|&(s, ev)| WsaPollFd {
        fd: s,
        events: if ev & 1 != 0 { WSA_POLLRDNORM } else { 0 } | if ev & 4 != 0 { WSA_POLLWRNORM } else { 0 },
        revents: 0,
    }).collect();
    unsafe { WSAPoll(p.as_mut_ptr(), p.len() as u32, ms) };
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
    // uname's nodename resolves too (httpd's ServerName guess, Java's getLocalHost, Erlang nodes), to
    // 127.0.0.1: that's where unpublished any-address listeners are (127.0.1.1 would miss epmd).
    (resolv, "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n127.0.0.1\tlx\n127.0.0.254\thost.docker.internal\n".into())
}

#[link(name = "iphlpapi")]
unsafe extern "system" {
    fn GetNetworkParams(info: *mut u8, len: *mut u32) -> u32;
}

#[test]
fn publish_specs_and_loopback() {
    assert_eq!(parse_publish("8080:80").unwrap(), "tcp:80:8080:");
    assert_eq!(parse_publish("127.0.0.1:8080:80/udp").unwrap(), "udp:80:8080:127.0.0.1");
    assert!(parse_publish("80").is_err() && parse_publish("x:80").is_err() && parse_publish("8080:80/sctp").is_err());
    let v4 = |ip: [u8; 4]| { let mut a = vec![0u8; 16]; a[0] = 2; a[4..8].copy_from_slice(&ip); a };
    let v6 = |last: u8| { let mut a = vec![0u8; 28]; a[0] = 23; a[23] = last; a };
    assert!(is_loopback(&v4([127, 0, 0, 1])) && !is_loopback(&v4([10, 0, 0, 1])));
    assert!(is_loopback(&v6(1)) && !is_loopback(&v6(2)));
}
