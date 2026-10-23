//! System V semaphores and message queues, shared by a container's processes.
//!
//! One table per container, in a named section, holds every set and queue (key, id, permissions,
//! semaphore values, queue counters); a named mutex guards it and the queues' messages, which live in
//! a named section per queue. A caller that must wait sleeps on one shared wake semaphore (and the
//! signal event) and re-checks: whoever changes a value or a queue releases the waiters.
//! ponytail: at most 128 sets and queues, 64 semaphores a set, 64 KB of messages a queue; a woken
//! waiter may find nothing for it and sleep again (spurious wakeups), at most 100 ms between re-checks.
use crate::syscall::{R, EAGAIN, EFAULT, EINTR, EINVAL, ENOENT, EEXIST};
use std::sync::Mutex;
use std::sync::atomic::Ordering::Relaxed;

const ENOSPC: i64 = 28;
const EIDRM: i64 = 43;
const ENOMSG: i64 = 42;
const E2BIG: i64 = 7;
const ERANGE: i64 = 34;
const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const IPC_NOWAIT: u64 = 0o4000;
const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;
const SEM_UNDO: u16 = 0x1000;
const NSETS: usize = 128;
const NSEMS: usize = 64;
const QSIZE: usize = 65536;
const SEMVMX: i32 = 32767;

unsafe extern "system" {
    fn CreateMutexW(attr: *mut std::ffi::c_void, owned: i32, name: *const u16) -> isize;
    fn ReleaseMutex(m: isize) -> i32;
    fn WaitForSingleObject(h: isize, ms: u32) -> u32;
    fn CreateSemaphoreW(attr: *mut std::ffi::c_void, initial: i32, max: i32, name: *const u16) -> isize;
    fn ReleaseSemaphore(sem: isize, n: i32, prev: *mut i32) -> i32;
    fn CreateFileMappingW(file: isize, attr: *mut std::ffi::c_void, prot: u32, hi: u32, lo: u32, name: *const u16) -> isize;
    fn MapViewOfFile(map: isize, access: u32, hi: u32, lo: u32, len: usize) -> *mut std::ffi::c_void;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Sem {
    val: i32,
    pid: u32,
    ncnt: u32,
    zcnt: u32,
}

/// One set (kind 1) or queue (kind 2). `seq` counts reuses of the slot: an id names (slot, seq).
#[repr(C)]
struct Entry {
    kind: u32,
    seq: u32,
    key: i32,
    mode: u32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    otime: i64, // sets: last semop; queues: last msgsnd
    ctime: i64,
    rtime: i64, // queues: last msgrcv
    nsems: u32,
    qbytes: u32,
    cbytes: u32,
    qnum: u32,
    used: u32, // queues: bytes of records in the queue's section
    lspid: u32,
    lrpid: u32,
    sems: [Sem; NSEMS],
}

#[repr(C)]
struct Table {
    waiters: u32,
    entries: [Entry; NSETS],
}

struct Ipc {
    table: *mut Table,
    lock: isize,
    wake: isize,
    root: String,
}
unsafe impl Send for Ipc {}

static IPC: Mutex<Option<Ipc>> = Mutex::new(None);
/// SEM_UNDO adjustments of this process, applied when it exits: (slot, seq, sem) -> adjustment.
static UNDO: Mutex<Vec<((usize, u32, usize), i32)>> = Mutex::new(Vec::new());
/// Mapped queue sections of this process: (slot, seq) -> address.
static QUEUES: Mutex<Vec<((usize, u32), usize)>> = Mutex::new(Vec::new());

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn ipc() -> Result<std::sync::MutexGuard<'static, Option<Ipc>>, i64> {
    let mut g = IPC.lock().unwrap();
    if g.is_none() {
        let root = std::env::var("LX_IN_JOB").unwrap_or_else(|_| std::process::id().to_string());
        let size = size_of::<Table>() as u32;
        let map = unsafe { CreateFileMappingW(-1, std::ptr::null_mut(), 0x04, 0, size, wide(&format!("Local\\lx-ipc-{root}")).as_ptr()) };
        let table = if map == 0 { std::ptr::null_mut() } else { unsafe { MapViewOfFile(map, 0x2, 0, 0, size as usize) } } as *mut Table;
        let lock = unsafe { CreateMutexW(std::ptr::null_mut(), 0, wide(&format!("Local\\lx-ipc-{root}-lock")).as_ptr()) };
        let wake = unsafe { CreateSemaphoreW(std::ptr::null_mut(), 0, i32::MAX, wide(&format!("Local\\lx-ipc-{root}-wake")).as_ptr()) };
        if table.is_null() || lock == 0 || wake == 0 {
            return Err(ENOSPC);
        }
        *g = Some(Ipc { table, lock, wake, root });
    }
    Ok(g)
}

/// Run `f` on the table under the container-wide lock.
fn locked<T>(f: impl FnOnce(&mut Table, &Ipc) -> T) -> Result<T, i64> {
    let g = ipc()?;
    let i = g.as_ref().unwrap();
    unsafe { WaitForSingleObject(i.lock, u32::MAX) }; // WAIT_ABANDONED (a holder died) also hands it over
    let r = f(unsafe { &mut *i.table }, i);
    unsafe { ReleaseMutex(i.lock) };
    Ok(r)
}

/// Let every waiter re-check (call with the lock held).
fn wake_all(t: &mut Table, i: &Ipc) {
    if t.waiters > 0 {
        unsafe { ReleaseSemaphore(i.wake, t.waiters as i32, std::ptr::null_mut()) };
        t.waiters = 0;
    }
}

/// Try `attempt` under the lock until it returns Some; between tries sleep until woken, a signal
/// (EINTR) or `timeout_ms` (< 0: none) runs out (EAGAIN).
fn wait_for(timeout_ms: i64, mut attempt: impl FnMut(&mut Table, &Ipc, bool) -> Option<R>) -> R {
    let start = std::time::Instant::now();
    let mut first = true;
    loop {
        if let Some(r) = locked(|t, i| {
            let r = attempt(t, i, first);
            if r.is_none() {
                t.waiters += 1;
            }
            r
        })? {
            return r;
        }
        first = false;
        if crate::signal::deliverable() {
            return Err(EINTR);
        }
        let left = if timeout_ms < 0 { 100 } else { (timeout_ms - start.elapsed().as_millis() as i64).clamp(0, 100) };
        if timeout_ms >= 0 && left == 0 {
            return Err(EAGAIN);
        }
        let wake = ipc()?.as_ref().unwrap().wake;
        let hs = [wake, crate::signal::intr_event()];
        unsafe { crate::win::WaitForMultipleObjects(if hs[1] != 0 { 2 } else { 1 }, hs.as_ptr(), 0, left as u32) };
    }
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

fn me() -> u32 {
    crate::proc::getpid().unwrap_or(0) as u32
}

/// An id is ((seq + 1) << 7) | slot: a removed and reused slot gets a new id, and no id is a small
/// number a program might pass as "surely invalid".
fn slot_of(t: &Table, id: u64, kind: u32) -> Result<usize, i64> {
    let slot = id as usize % NSETS;
    let e = &t.entries[slot];
    if (id as i64) < 0 || e.kind != kind || (e.seq as u64 + 1) != id >> 7 {
        return Err(EINVAL);
    }
    Ok(slot)
}

fn id_of(t: &Table, slot: usize) -> i64 {
    ((t.entries[slot].seq as i64 + 1) << 7) | slot as i64
}

/// ipcperms: may the caller have `want` (4 read, 2 write/alter) on `e`? Root may do anything.
fn allowed(e: &Entry, want: u32) -> bool {
    let uid = crate::proc::UID.load(Relaxed);
    if uid == 0 {
        return true;
    }
    let group = crate::proc::in_group(e.gid) || crate::proc::in_group(e.cgid); // supplementary groups count
    let granted = if uid == e.uid || uid == e.cuid { e.mode >> 6 } else if group { e.mode >> 3 } else { e.mode } & 7;
    want & !granted == 0
}

/// SEM_STAT / MSG_STAT (and their _ANY forms, which skip the read check) name a set by its table index
/// rather than its id (ipcs walks them so): the slot, and the command to run as.
fn by_index(t: &Table, id: u64, cmd: u64, kind: u32, stat: u64, any: u64) -> Result<Option<(usize, bool)>, i64> {
    if cmd != stat && cmd != any {
        return Ok(None);
    }
    let s = id as usize;
    if s >= NSETS || t.entries[s].kind != kind {
        return Err(EINVAL);
    }
    Ok(Some((s, cmd == any)))
}

/// IPC_RMID / IPC_SET: the owner, the creator or root.
fn owner(e: &Entry) -> Result<(), i64> {
    let uid = crate::proc::UID.load(Relaxed);
    if uid == 0 || uid == e.uid || uid == e.cuid { Ok(()) } else { Err(crate::syscall::EPERM) }
}

const EACCES: i64 = 13;

/// semget / msgget: find the key (IPC_PRIVATE: always new), or create the set or queue.
fn get(kind: u32, key: u64, flags: u64, nsems: u64) -> R {
    let key = key as i32;
    locked(|t, _| {
        if key != 0 && let Some(s) = (0..NSETS).find(|&s| t.entries[s].kind == kind && t.entries[s].key == key) {
            if flags & (IPC_CREAT | IPC_EXCL) == IPC_CREAT | IPC_EXCL {
                return Err(EEXIST);
            }
            let ask = flags as u32 & 0o777;
            if !allowed(&t.entries[s], (ask >> 6 | ask >> 3 | ask) & 7) {
                return Err(EACCES);
            }
            if kind == 1 && nsems > t.entries[s].nsems as u64 {
                return Err(EINVAL);
            }
            return Ok(id_of(t, s));
        }
        if key != 0 && flags & IPC_CREAT == 0 {
            return Err(ENOENT);
        }
        if kind == 1 && (nsems == 0 || nsems > NSEMS as u64) {
            return Err(EINVAL);
        }
        let s = (0..NSETS).find(|&s| t.entries[s].kind == 0).ok_or(ENOSPC)?;
        let e = &mut t.entries[s];
        let (uid, gid) = (crate::proc::UID.load(Relaxed), crate::proc::GID.load(Relaxed));
        let seq = e.seq;
        // SAFETY: Entry is plain data; all-zero is its empty state.
        *e = unsafe { std::mem::zeroed() };
        (e.kind, e.seq, e.key, e.mode, e.uid, e.gid, e.cuid, e.cgid) = (kind, seq, key, flags as u32 & 0o777, uid, gid, uid, gid);
        (e.nsems, e.qbytes, e.ctime) = (nsems as u32, if kind == 2 { 16384 } else { 0 }, now());
        Ok(id_of(t, s))
    })?
}

pub fn semget(key: u64, nsems: u64, flags: u64) -> R {
    get(1, key, flags, nsems)
}

pub fn msgget(key: u64, flags: u64) -> R {
    get(2, key, flags, 0)
}

/// Free a slot: the next user gets a new id, and waiters on the old one see EIDRM.
fn remove(t: &mut Table, i: &Ipc, slot: usize) {
    let e = &mut t.entries[slot];
    e.kind = 0;
    e.seq = e.seq.wrapping_add(1) & 0xff_ffff;
    wake_all(t, i);
}

/// semop / semtimedop: all of the operations or none, waiting while any can't be done.
pub fn semtimedop(id: u64, sops: u64, nsops: u64, timeout: u64) -> R {
    if nsops == 0 || nsops > 500 {
        return Err(if nsops == 0 { EINVAL } else { E2BIG });
    }
    let raw = crate::syscall::get_guest_vec(sops, nsops as usize * 6).ok_or(EFAULT)?;
    let ops: Vec<(usize, i16, u16)> = raw.chunks_exact(6)
        .map(|c| (u16::from_le_bytes([c[0], c[1]]) as usize, i16::from_le_bytes([c[2], c[3]]), u16::from_le_bytes([c[4], c[5]])))
        .collect();
    let timeout_ms = if timeout == 0 {
        -1
    } else {
        let t = crate::syscall::get_guest_vec(timeout, 16).ok_or(EFAULT)?;
        let (s, ns) = (i64::from_le_bytes(t[..8].try_into().unwrap()), i64::from_le_bytes(t[8..].try_into().unwrap()));
        if s < 0 || !(0..1_000_000_000).contains(&ns) {
            return Err(EINVAL);
        }
        s * 1000 + ns / 1_000_000
    };
    let nowait = ops.iter().any(|o| o.2 as u64 & IPC_NOWAIT != 0);
    let seq0 = std::cell::Cell::new(None);
    let (pid, mut counted) = (me(), false);
    let r = wait_for(timeout_ms, |t, i, first| {
        let slot = match slot_of(t, id, 1) {
            Ok(s) if seq0.get().is_none_or(|q| q == t.entries[s].seq) => s,
            _ => return Some(Err(if first { EINVAL } else { EIDRM })),
        };
        seq0.set(Some(t.entries[slot].seq));
        let e = &mut t.entries[slot];
        if ops.iter().any(|o| o.0 >= e.nsems as usize) {
            return Some(Err(EFBIG_SEM));
        }
        if !allowed(e, if ops.iter().any(|o| o.1 != 0) { 2 } else { 4 }) {
            return Some(Err(EACCES));
        }
        // Would all of them go through, applied in order?
        let mut vals: Vec<i32> = e.sems[..e.nsems as usize].iter().map(|s| s.val).collect();
        let mut blocked = None;
        for &(n, op, _) in &ops {
            match op {
                0 if vals[n] != 0 => { blocked = Some((n, true)); break }
                o if o < 0 && vals[n] < -(o as i32) => { blocked = Some((n, false)); break }
                o if o > 0 && vals[n] + o as i32 > SEMVMX => return Some(Err(ERANGE)),
                o => vals[n] += o as i32,
            }
        }
        if counted {
            // Last round's wait counts come off before this one decides again.
            for &(n, op, _) in &ops {
                if op == 0 { e.sems[n].zcnt = e.sems[n].zcnt.saturating_sub(1) } else if op < 0 { e.sems[n].ncnt = e.sems[n].ncnt.saturating_sub(1) }
            }
            counted = false;
        }
        match blocked {
            None => {
                for &(n, op, flg) in &ops {
                    e.sems[n].val = vals[n];
                    e.sems[n].pid = pid;
                    if flg & SEM_UNDO != 0 && op != 0 {
                        let k = (slot, e.seq, n);
                        let mut u = UNDO.lock().unwrap();
                        match u.iter_mut().find(|x| x.0 == k) {
                            Some(x) => x.1 -= op as i32,
                            None => u.push((k, -(op as i32))),
                        }
                    }
                }
                e.otime = now();
                wake_all(t, i);
                Some(Ok(0))
            }
            Some(_) if nowait => Some(Err(EAGAIN)),
            Some(_) => {
                for &(n, op, _) in &ops {
                    if op == 0 { e.sems[n].zcnt += 1 } else if op < 0 { e.sems[n].ncnt += 1 }
                }
                counted = true;
                None
            }
        }
    });
    if counted {
        let _ = locked(|t, _| {
            if let Ok(s) = slot_of(t, id, 1) {
                for &(n, op, _) in &ops {
                    let sem = &mut t.entries[s].sems[n.min(NSEMS - 1)];
                    if op == 0 { sem.zcnt = sem.zcnt.saturating_sub(1) } else if op < 0 { sem.ncnt = sem.ncnt.saturating_sub(1) }
                }
            }
        });
    }
    r
}

const EFBIG_SEM: i64 = 27; // EFBIG: sem_num past the set

/// struct ipc64_perm: key, uid, gid, cuid, cgid, mode, seq, padding (48 bytes).
fn perm_bytes(e: &Entry) -> Vec<u8> {
    let mut b = Vec::with_capacity(48);
    for v in [e.key as u32, e.uid, e.gid, e.cuid, e.cgid, e.mode] {
        b.extend(v.to_le_bytes());
    }
    b.extend((e.seq as u16).to_le_bytes());
    b.resize(48, 0);
    b
}

/// IPC_SET: uid, gid and the permission bits from the caller's ipc_perm.
fn set_perm(e: &mut Entry, buf: u64) -> Result<(), i64> {
    let p = crate::syscall::get_guest_vec(buf, 24).ok_or(EFAULT)?;
    let w = |o: usize| u32::from_le_bytes(p[o..o + 4].try_into().unwrap());
    (e.uid, e.gid, e.mode) = (w(4), w(8), e.mode & !0o777 | w(20) & 0o777);
    e.ctime = now();
    Ok(())
}

pub fn semctl(id: u64, num: u64, cmd: u64, arg: u64) -> R {
    const GETPID: u64 = 11;
    const GETVAL: u64 = 12;
    const GETALL: u64 = 13;
    const GETNCNT: u64 = 14;
    const GETZCNT: u64 = 15;
    const SETVAL: u64 = 16;
    const SETALL: u64 = 17;
    let cmd = cmd & !0x100; // IPC_64
    locked(|t, i| {
        if cmd == 3 || cmd == 19 {
            // IPC_INFO, SEM_INFO: struct seminfo (semmap semmni semmns semmnu semmsl semopm semume semusz
            // semvmx semaem); SEM_INFO counts sets in semusz and semaphores in semaem.
            let used = (0..NSETS).filter(|&s| t.entries[s].kind == 1);
            let (sets, sems) = (used.clone().count() as u32, used.clone().map(|s| t.entries[s].nsems).sum::<u32>());
            let mut v = [NSETS as u32, NSETS as u32, (NSETS * NSEMS) as u32, NSETS as u32, NSEMS as u32, 500, 500, 20, SEMVMX as u32, 32767];
            if cmd == 19 {
                (v[7], v[9]) = (sets, sems);
            }
            crate::syscall::put_guest(arg, &v.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<u8>>())?;
            return Ok(used.max().unwrap_or(0) as i64);
        }
        let indexed = by_index(t, id, cmd, 1, 18, 20)?; // SEM_STAT, SEM_STAT_ANY
        let slot = match indexed { Some((s, _)) => s, None => slot_of(t, id, 1)? };
        let (full_id, cmd) = (id_of(t, slot), if indexed.is_some() { IPC_STAT } else { cmd });
        let e = &mut t.entries[slot];
        let n = e.nsems as usize;
        let need = match cmd {
            _ if indexed.is_some_and(|(_, any)| any) => Ok(()),
            IPC_RMID | IPC_SET => owner(e),
            16 | 17 => if allowed(e, 2) { Ok(()) } else { Err(EACCES) }, // SETVAL, SETALL
            _ => if allowed(e, 4) { Ok(()) } else { Err(EACCES) },
        };
        need?;
        let sem = |num: u64| if (num as usize) < n { Ok(num as usize) } else { Err(EINVAL) };
        match cmd {
            IPC_RMID => {
                remove(t, i, slot);
                Ok(0)
            }
            IPC_STAT => {
                let mut b = perm_bytes(e);
                for v in [e.otime as u64, 0, e.ctime as u64, 0, n as u64, 0, 0] {
                    b.extend(v.to_le_bytes());
                }
                crate::syscall::put_guest(arg, &b)?;
                Ok(if indexed.is_some() { full_id } else { 0 })
            }
            IPC_SET => set_perm(e, arg).map(|_| 0),
            GETVAL => Ok(e.sems[sem(num)?].val as i64),
            GETPID => Ok(e.sems[sem(num)?].pid as i64),
            GETNCNT => Ok(e.sems[sem(num)?].ncnt as i64),
            GETZCNT => Ok(e.sems[sem(num)?].zcnt as i64),
            GETALL => {
                let b: Vec<u8> = e.sems[..n].iter().flat_map(|s| (s.val as u16).to_le_bytes()).collect();
                crate::syscall::put_guest(arg, &b)
            }
            SETVAL => {
                let (s, v) = (sem(num)?, arg as i32);
                if !(0..=SEMVMX).contains(&v) {
                    return Err(ERANGE);
                }
                (e.sems[s].val, e.sems[s].pid, e.ctime) = (v, me(), now());
                forget_undo(slot, e.seq, Some(s));
                wake_all(t, i);
                Ok(0)
            }
            SETALL => {
                let b = crate::syscall::get_guest_vec(arg, n * 2).ok_or(EFAULT)?;
                let vals: Vec<i32> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]) as i32).collect();
                if vals.iter().any(|&v| v > SEMVMX) {
                    return Err(ERANGE);
                }
                for (s, v) in e.sems[..n].iter_mut().zip(vals) {
                    s.val = v;
                }
                e.ctime = now();
                forget_undo(slot, e.seq, None);
                wake_all(t, i);
                Ok(0)
            }
            _ => Err(EINVAL),
        }
    })?
}

/// SETVAL / SETALL clear the undo values for those semaphores, as on Linux.
fn forget_undo(slot: usize, seq: u32, sem: Option<usize>) {
    UNDO.lock().unwrap().retain(|((s, q, n), _)| !(*s == slot && *q == seq && sem.is_none_or(|m| m == *n)));
}

/// Apply this process's SEM_UNDO adjustments (at exit).
pub fn undo_all() {
    let undo = std::mem::take(&mut *UNDO.lock().unwrap());
    if undo.is_empty() {
        return;
    }
    let _ = locked(|t, i| {
        for ((slot, seq, n), adj) in undo {
            let e = &mut t.entries[slot];
            if e.kind == 1 && e.seq == seq {
                e.sems[n].val = (e.sems[n].val + adj).clamp(0, SEMVMX);
            }
        }
        wake_all(t, i);
    });
}

/// A queue's records: [mtype i64][len u64][text, padded to 8], one after another from the start.
fn queue(i: &Ipc, slot: usize, seq: u32) -> Result<*mut u8, i64> {
    let mut q = QUEUES.lock().unwrap();
    if let Some(&(_, p)) = q.iter().find(|x| x.0 == (slot, seq)) {
        return Ok(p as *mut u8);
    }
    let name = wide(&format!("Local\\lx-ipc-{}-q{slot}-{seq}", i.root));
    let map = unsafe { CreateFileMappingW(-1, std::ptr::null_mut(), 0x04, 0, QSIZE as u32, name.as_ptr()) };
    let p = if map == 0 { std::ptr::null_mut() } else { unsafe { MapViewOfFile(map, 0x2, 0, 0, QSIZE) } } as *mut u8;
    if p.is_null() {
        return Err(ENOSPC);
    }
    q.push(((slot, seq), p as usize)); // ponytail: the mapping stays for the process's life
    Ok(p)
}

fn rec_len(text: usize) -> usize {
    16 + text.next_multiple_of(8)
}

pub fn msgsnd(id: u64, msgp: u64, size: u64, flags: u64) -> R {
    if (size as i64) < 0 || size as usize > QSIZE - 16 {
        return Err(EINVAL);
    }
    let msg = crate::syscall::get_guest_vec(msgp, 8 + size as usize).ok_or(EFAULT)?;
    let mtype = i64::from_le_bytes(msg[..8].try_into().unwrap());
    if mtype < 1 {
        return Err(EINVAL);
    }
    let seq0 = std::cell::Cell::new(None);
    wait_for(-1, |t, i, first| {
        let slot = match slot_of(t, id, 2) {
            Ok(s) if seq0.get().is_none_or(|q| q == t.entries[s].seq) => s,
            _ => return Some(Err(if first { EINVAL } else { EIDRM })),
        };
        let seq = t.entries[slot].seq;
        seq0.set(Some(seq));
        if !allowed(&t.entries[slot], 2) {
            return Some(Err(EACCES));
        }
        let e = &mut t.entries[slot];
        let need = rec_len(size as usize);
        if e.cbytes as u64 + size > e.qbytes as u64 || e.used as usize + need > QSIZE {
            return if flags & IPC_NOWAIT != 0 { Some(Err(EAGAIN)) } else { None };
        }
        let q = match queue(i, slot, seq) { Ok(q) => q, Err(err) => return Some(Err(err)) };
        unsafe {
            let at = q.add(e.used as usize);
            std::ptr::copy_nonoverlapping(mtype.to_le_bytes().as_ptr(), at, 8);
            std::ptr::copy_nonoverlapping(size.to_le_bytes().as_ptr(), at.add(8), 8);
            std::ptr::copy_nonoverlapping(msg[8..].as_ptr(), at.add(16), size as usize);
        }
        e.used += need as u32;
        e.cbytes += size as u32;
        e.qnum += 1;
        (e.lspid, e.otime) = (me(), now());
        wake_all(t, i);
        Some(Ok(0))
    })
}

pub fn msgrcv(id: u64, msgp: u64, size: u64, mtype: u64, flags: u64) -> R {
    const MSG_NOERROR: u64 = 0o10000;
    const MSG_EXCEPT: u64 = 0o20000;
    if (size as i64) < 0 {
        return Err(EINVAL);
    }
    let want = mtype as i64;
    let seq0 = std::cell::Cell::new(None);
    let mut got: Option<(i64, Vec<u8>)> = None;
    let r = wait_for(-1, |t, i, first| {
        let slot = match slot_of(t, id, 2) {
            Ok(s) if seq0.get().is_none_or(|q| q == t.entries[s].seq) => s,
            _ => return Some(Err(if first { EINVAL } else { EIDRM })),
        };
        let seq = t.entries[slot].seq;
        seq0.set(Some(seq));
        if !allowed(&t.entries[slot], 4) {
            return Some(Err(EACCES));
        }
        let q = match queue(i, slot, seq) { Ok(q) => q, Err(err) => return Some(Err(err)) };
        let e = &mut t.entries[slot];
        // The record to take: the first (0), the first of the type (> 0; MSG_EXCEPT: of another type),
        // or the first of the lowest type up to |type| (< 0).
        let (mut off, mut pick) = (0usize, None::<(usize, i64, usize)>);
        while off < e.used as usize {
            let ty = unsafe { std::ptr::read_unaligned(q.add(off) as *const i64) };
            let len = unsafe { std::ptr::read_unaligned(q.add(off + 8) as *const u64) } as usize;
            let fits = match want {
                0 => true,
                w if w > 0 => (ty == w) != (flags & MSG_EXCEPT != 0),
                w => ty <= -w && pick.is_none_or(|p| ty < p.1),
            };
            if fits {
                pick = Some((off, ty, len));
                if want >= 0 {
                    break;
                }
            }
            off += rec_len(len);
        }
        let Some((off, ty, len)) = pick else {
            return if flags & IPC_NOWAIT != 0 { Some(Err(ENOMSG)) } else { None };
        };
        if len > size as usize && flags & MSG_NOERROR == 0 {
            return Some(Err(E2BIG));
        }
        let text = unsafe { std::slice::from_raw_parts(q.add(off + 16), len.min(size as usize)) }.to_vec();
        let rl = rec_len(len);
        unsafe { std::ptr::copy(q.add(off + rl), q.add(off), e.used as usize - off - rl) };
        e.used -= rl as u32;
        e.cbytes -= len as u32;
        e.qnum -= 1;
        (e.lrpid, e.rtime) = (me(), now());
        wake_all(t, i);
        got = Some((ty, text));
        Some(Ok(0))
    });
    r?;
    let (ty, text) = got.unwrap();
    crate::syscall::put_guest(msgp, &[ty.to_le_bytes().as_slice(), &text].concat())?;
    Ok(text.len() as i64)
}

pub fn msgctl(id: u64, cmd: u64, buf: u64) -> R {
    let cmd = cmd & !0x100; // IPC_64
    locked(|t, i| {
        if cmd == 3 || cmd == 12 {
            // IPC_INFO, MSG_INFO: struct msginfo (msgpool msgmap msgmax msgmnb msgmni msgssz msgtql, msgseg);
            // MSG_INFO counts queues in msgpool, messages in msgmap and bytes in msgtql.
            let used = (0..NSETS).filter(|&s| t.entries[s].kind == 2);
            let mut v = [(NSETS * QSIZE / 1024) as u32, 0, (QSIZE - 16) as u32, 16384, NSETS as u32, 16, 0];
            if cmd == 12 {
                v[0] = used.clone().count() as u32;
                v[1] = used.clone().map(|s| t.entries[s].qnum).sum();
                v[6] = used.clone().map(|s| t.entries[s].cbytes).sum();
            }
            let mut b: Vec<u8> = v.iter().flat_map(|x| x.to_le_bytes()).collect();
            b.extend(0xffffu16.to_le_bytes()); // msgseg
            crate::syscall::put_guest(buf, &b)?;
            return Ok(used.max().unwrap_or(0) as i64);
        }
        let indexed = by_index(t, id, cmd, 2, 11, 13)?; // MSG_STAT, MSG_STAT_ANY
        let slot = match indexed { Some((s, _)) => s, None => slot_of(t, id, 2)? };
        let (full_id, cmd) = (id_of(t, slot), if indexed.is_some() { IPC_STAT } else { cmd });
        let e = &mut t.entries[slot];
        match cmd {
            _ if indexed.is_some_and(|(_, any)| any) => {}
            IPC_RMID | IPC_SET => owner(e)?,
            IPC_STAT if !allowed(e, 4) => return Err(EACCES),
            IPC_STAT => {}
            _ => return Err(EINVAL),
        }
        match cmd {
            IPC_RMID => {
                remove(t, i, slot);
                Ok(0)
            }
            IPC_STAT => {
                // struct msqid64_ds: perm, stime, rtime, ctime, cbytes, qnum, qbytes, lspid, lrpid, unused.
                let mut b = perm_bytes(e);
                for v in [e.otime as u64, e.rtime as u64, e.ctime as u64, e.cbytes as u64, e.qnum as u64, e.qbytes as u64] {
                    b.extend(v.to_le_bytes());
                }
                b.extend(e.lspid.to_le_bytes());
                b.extend(e.lrpid.to_le_bytes());
                b.resize(120, 0);
                crate::syscall::put_guest(buf, &b)?;
                Ok(if indexed.is_some() { full_id } else { 0 })
            }
            IPC_SET => {
                set_perm(e, buf)?;
                let q = crate::syscall::get_guest_vec(buf + 88, 8).ok_or(EFAULT)?;
                let qbytes = u64::from_le_bytes(q.try_into().unwrap());
                if qbytes > (QSIZE - 16) as u64 {
                    return Err(EINVAL); // ponytail: past what a queue's section holds
                }
                e.qbytes = qbytes as u32;
                wake_all(t, i);
                Ok(0)
            }
            _ => Err(EINVAL),
        }
    })?
}
