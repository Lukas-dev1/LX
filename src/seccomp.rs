//! seccomp: classic BPF filters over struct seccomp_data, run on every syscall once one is installed; the
//! strictest result of all of them wins, as on Linux. They belong to the process and go to every later
//! lx process of it (fork and exec start new ones) through the host environment, like the ids.
//! ponytail: per process, not per thread (as if always SECCOMP_FILTER_FLAG_TSYNC); no user notification;
//! SIGSYS from SECCOMP_RET_TRAP carries no siginfo details.

use crate::syscall::{EFAULT, EINVAL, ENOSYS, R};
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

/// Instructions as (code | jt << 16 | jf << 24, k).
type Prog = Vec<(u32, u32)>;
static FILTERS: RwLock<Vec<Prog>> = RwLock::new(Vec::new());
static ON: AtomicBool = AtomicBool::new(false);
static STRICT: AtomicBool = AtomicBool::new(false);

const KILL_PROCESS: u32 = 0x8000_0000;
const KILL_THREAD: u32 = 0;
const TRAP: u32 = 0x0003_0000;
const ERRNO: u32 = 0x0005_0000;
const TRACE: u32 = 0x7ff0_0000;
const LOG: u32 = 0x7ffc_0000;
const ALLOW: u32 = 0x7fff_0000;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

/// seccomp(op, flags, args).
pub fn seccomp(op: u64, flags: u64, args: u64) -> R {
    match op {
        0 if flags == 0 && args == 0 => set(1, 0), // SECCOMP_SET_MODE_STRICT
        // SECCOMP_SET_MODE_FILTER; TSYNC, LOG, SPEC_ALLOW accepted, NEW_LISTENER (user notification) not.
        1 if flags & !7 == 0 => set(2, args),
        // libseccomp probes flags with a NULL program (set() answers EFAULT for the supported ones above).
        2 if args == 0 => Err(EFAULT),
        2 => {
            // SECCOMP_GET_ACTION_AVAIL
            let action = unsafe { *(args as *const u32) };
            if [KILL_PROCESS, KILL_THREAD, TRAP, ERRNO, TRACE, LOG, ALLOW].contains(&action) { Ok(0) } else { Err(95) } // EOPNOTSUPP
        }
        _ => Err(EINVAL),
    }
}

/// prctl(PR_SET_SECCOMP, mode, prog), and seccomp's modes: 1 strict, 2 a filter (struct sock_fprog).
pub fn set(mode: u64, fprog: u64) -> R {
    let prog: Prog = match mode {
        // Strict: read, write, exit, rt_sigreturn (each jumps to the ALLOW at the end); anything else kills.
        1 => vec![(0x20, 0), (0x15 | 4 << 16, 0), (0x15 | 3 << 16, 1), (0x15 | 2 << 16, 60), (0x15 | 1 << 16, 15),
                  (0x06, KILL_THREAD), (0x06, ALLOW)],
        2 if fprog == 0 => return Err(EFAULT),
        2 => {
            let (len, insns) = unsafe { (*(fprog as *const u16) as usize, *((fprog + 8) as *const u64)) };
            if len == 0 || len > 4096 {
                return Err(EINVAL);
            }
            (0..len).map(|i| {
                let p = (insns + i as u64 * 8) as *const u8;
                let (code, jt, jf, k) = unsafe { (*(p as *const u16), *p.add(2), *p.add(3), *(p.add(4) as *const u32)) };
                (code as u32 | (jt as u32) << 16 | (jf as u32) << 24, k)
            }).collect()
        }
        _ => return Err(EINVAL),
    };
    if mode == 1 {
        STRICT.store(true, Relaxed);
    }
    FILTERS.write().unwrap().push(prog);
    ON.store(true, Relaxed);
    save();
    Ok(0)
}

/// PR_GET_SECCOMP: 0 none, 1 strict, 2 filtered.
pub fn mode() -> R {
    Ok(if STRICT.load(Relaxed) { 1 } else if ON.load(Relaxed) { 2 } else { 0 })
}

/// Before a syscall runs: None to run it, or what it returns instead.
pub fn check(nr: u64, a: &[u64; 6], ip: u64) -> Option<R> {
    if !ON.load(Relaxed) {
        return None;
    }
    let mut data = [0u8; 64];
    data[0..4].copy_from_slice(&(nr as u32).to_le_bytes());
    data[4..8].copy_from_slice(&AUDIT_ARCH_X86_64.to_le_bytes());
    data[8..16].copy_from_slice(&ip.to_le_bytes());
    for (i, v) in a.iter().enumerate() {
        data[16 + i * 8..24 + i * 8].copy_from_slice(&v.to_le_bytes());
    }
    // The action with the lowest precedence value (as a signed number: KILL_PROCESS first) wins.
    let ret = FILTERS.read().unwrap().iter().map(|p| run(p, &data)).min_by_key(|r| (r & 0xffff_0000) as i32)?;
    match ret & 0xffff_0000 {
        ALLOW | LOG => None,
        ERRNO => Some(match ret & 0xfff { 0 => Ok(0), e => Err(e as i64) }),
        TRACE => Some(Err(ENOSYS)), // no tracer attached
        TRAP => {
            let _ = crate::signal::raise(31); // SIGSYS, delivered as the syscall returns
            Some(Err(ENOSYS))
        }
        _ => crate::proc::die(31), // KILL_THREAD/KILL_PROCESS: the process dies of SIGSYS
    }
}

/// Run one classic BPF program; a malformed one kills, as the kernel's checker would have refused it.
fn run(prog: &Prog, data: &[u8; 64]) -> u32 {
    let (mut a, mut x, mut m) = (0u32, 0u32, [0u32; 16]);
    let word = |k: u32| (k % 4 == 0 && k < 64).then(|| u32::from_le_bytes(data[k as usize..k as usize + 4].try_into().unwrap()));
    let mut pc = 0usize;
    while let Some(&(op, k)) = prog.get(pc) {
        pc += 1;
        let (code, jt, jf) = (op & 0xffff, (op >> 16) & 0xff, op >> 24);
        let src = if code & 0x08 != 0 { x } else { k }; // BPF_X or BPF_K
        match code & 0x07 {
            0x00 | 0x01 => {
                // BPF_LD / BPF_LDX: IMM, ABS (a word of seccomp_data), MEM, LEN
                let v = match code & 0xe0 {
                    0x00 => k,
                    0x20 => match word(k) { Some(v) => v, None => return KILL_THREAD },
                    0x60 => m[k as usize & 15],
                    0x80 => 64,
                    _ => return KILL_THREAD,
                };
                if code & 0x07 == 0 { a = v } else { x = v }
            }
            0x02 => m[k as usize & 15] = a, // BPF_ST
            0x03 => m[k as usize & 15] = x, // BPF_STX
            0x04 => {
                // BPF_ALU
                a = match code & 0xf0 {
                    0x00 => a.wrapping_add(src),
                    0x10 => a.wrapping_sub(src),
                    0x20 => a.wrapping_mul(src),
                    0x30 => match a.checked_div(src) { Some(v) => v, None => return KILL_THREAD },
                    0x40 => a | src,
                    0x50 => a & src,
                    0x60 => a.checked_shl(src).unwrap_or(0),
                    0x70 => a.checked_shr(src).unwrap_or(0),
                    0x80 => a.wrapping_neg(),
                    0x90 => match a.checked_rem(src) { Some(v) => v, None => return KILL_THREAD },
                    0xa0 => a ^ src,
                    _ => return KILL_THREAD,
                }
            }
            0x05 => {
                // BPF_JMP: JA by k, the conditionals by jt/jf
                let take = match code & 0xf0 {
                    0x00 => {
                        pc += k as usize;
                        continue;
                    }
                    0x10 => a == src,
                    0x20 => a > src,
                    0x30 => a >= src,
                    0x40 => a & src != 0,
                    _ => return KILL_THREAD,
                };
                pc += if take { jt } else { jf } as usize;
            }
            0x06 => return if code & 0x18 == 0x10 { a } else { k }, // BPF_RET: A or K
            _ => if code & 0xf8 == 0 { x = a } else { a = x }, // BPF_MISC: TAX, TXA
        }
    }
    KILL_THREAD // fell off the end
}

/// The filters for later lx processes: "mode/op:k,op:k;op:k...".
fn save() {
    let progs = FILTERS.read().unwrap();
    let text: Vec<String> = progs.iter().map(|p| p.iter().map(|(op, k)| format!("{op:x}:{k:x}")).collect::<Vec<_>>().join(",")).collect();
    unsafe { std::env::set_var("LX_SECCOMP", format!("{}/{}", mode().unwrap_or(0), text.join(";"))) };
}

/// A forked or exec'd lx: the filters installed so far.
pub fn load() {
    let Ok(v) = std::env::var("LX_SECCOMP") else { return };
    let Some((mode, text)) = v.split_once('/') else { return };
    let progs: Vec<Prog> = text.split(';').filter(|p| !p.is_empty()).map(|p| {
        p.split(',').filter_map(|i| {
            let (op, k) = i.split_once(':')?;
            Some((u32::from_str_radix(op, 16).ok()?, u32::from_str_radix(k, 16).ok()?))
        }).collect()
    }).collect();
    if !progs.is_empty() {
        STRICT.store(mode == "1", Relaxed);
        *FILTERS.write().unwrap() = progs;
        ON.store(true, Relaxed);
    }
}

#[test]
fn bpf_filters() {
    // Allow everything but getpid (39), which gets EPERM; check the arch first.
    let p: Prog = vec![(0x20, 4), (0x15 | 1 << 16, AUDIT_ARCH_X86_64), (0x06, KILL_PROCESS), (0x20, 0),
                       (0x15 | 0 << 16 | 1 << 24, 39), (0x06, ERRNO | 1), (0x06, ALLOW)];
    let data = |nr: u32| {
        let mut d = [0u8; 64];
        d[0..4].copy_from_slice(&nr.to_le_bytes());
        d[4..8].copy_from_slice(&AUDIT_ARCH_X86_64.to_le_bytes());
        d
    };
    assert_eq!(run(&p, &data(39)), ERRNO | 1);
    assert_eq!(run(&p, &data(1)), ALLOW);
}
