//! Synthetic /proc and /proc/sys files: what images read at startup (cgroup, mounts, meminfo, cpuinfo,
//! a few sysctls). Contents are made when the file is opened, like the kernel does.
//! ponytail: a fixed list; /proc/<pid> of other processes, self/stat and self/status aren't here.

/// The contents of synthetic file `guest`, if it is one.
pub fn file(guest: &str) -> Option<String> {
    if let Some(rest) = self_rest(guest) {
        return match rest {
            "cgroup" => Some("0::/\n".into()), // cgroup v2, the container's root, like Docker
            "statm" => Some(statm()),
            "status" => Some(status()),
            "smaps_rollup" => Some({ let (_, rss) = mem(); format!("00000000-ffffffff ---p 00000000 00:00 0 [rollup]
Rss: {:>16} kB
Pss: {:>16} kB
", rss >> 10, rss >> 10) }),
            "mounts" => Some(mounts()),
            "mountinfo" => Some(MOUNTINFO.into()),
            "maps" => Some(crate::syscall::maps()),
            _ => table_file(crate::proc::getpid().unwrap_or(0) as u32, rest),
        };
    }
    // Another process of the container: from the process table.
    let numeric = guest.strip_prefix("/proc/").and_then(|r| r.split_once('/')).and_then(|(p, r)| Some((p.parse::<u32>().ok()?, r)));
    if let Some((pid, rest)) = numeric {
        return table_file(pid, rest);
    }
    Some(match guest {
        "/proc/mounts" => mounts(),
        "/proc/meminfo" => meminfo(),
        "/proc/cpuinfo" => cpuinfo(),
        "/proc/uptime" => {
            let s = unsafe { crate::win::GetTickCount64() } as f64 / 1000.0;
            format!("{s:.2} {s:.2}\n")
        }
        "/proc/stat" => stat(),
        // vmstat won't start without it. ponytail: no paging figures.
        "/proc/vmstat" => "nr_free_pages 0\npgpgin 0\npgpgout 0\npswpin 0\npswpout 0\npgfault 0\npgmajfault 0\n".into(),
        "/proc/loadavg" => format!("0.00 0.00 0.00 1/1 {}\n", crate::proc::getpid().unwrap_or(0)),
        "/proc/version" => "Linux version 6.6.0-lx (lx) #1 SMP lx\n".into(),
        "/proc/sys/kernel/hostname" => "lx\n".into(),
        "/proc/cmdline" => "BOOT_IMAGE=/boot/vmlinuz-6.6.0-lx root=/dev/sda1 ro quiet\n".into(),
        "/proc/sys/kernel/tainted" => "0\n".into(), // nothing has tainted this kernel
        "/proc/sys/fs/pipe-max-size" => "1048576\n".into(),
        "/proc/sys/kernel/osrelease" => "6.6.0-lx\n".into(),
        "/proc/sys/kernel/pid_max" => "4194304\n".into(),
        "/proc/sys/kernel/ngroups_max" => "65536\n".into(), // NGROUPS_MAX: setgroups' limit
        "/proc/sys/kernel/threads-max" => "1000000\n".into(),
        "/proc/sys/kernel/cap_last_cap" => "40\n".into(), // CAP_CHECKPOINT_RESTORE, as prctl(PR_CAPBSET_READ) agrees
        "/proc/sys/vm/overcommit_memory" => "1\n".into(), // NT commits on mmap; don't make redis warn
        "/proc/sys/vm/max_map_count" => "1048576\n".into(),
        "/proc/sys/net/core/somaxconn" => "4096\n".into(),
        "/proc/sys/fs/file-max" => "1048576\n".into(),
        "/proc/sys/fs/nr_open" => "1048576\n".into(),
        _ => return None,
    })
}

/// /proc/<pid>/{cmdline,comm,stat,status} from the container's process table (ps, pgrep, pidof).
fn table_file(pid: u32, rest: &str) -> Option<String> {
    let mut p = crate::ptable::get(pid)?;
    if crate::proc::host_pid(pid) == crate::proc::pid() {
        p.state = 'R'; // the reader itself is running, however long its own read has taken
    }
    Some(match rest {
        "cmdline" => String::from_utf8_lossy(&p.cmdline).into_owned(),
        "comm" => format!("{}\n", p.comm),
        // pid (comm) state ppid pgrp session tty tpgid flags minflt cminflt majflt cmajflt utime stime
        // cutime cstime priority nice threads itrealvalue starttime vsize rss ... (52 fields)
        "stat" => format!("{} ({}) {} {} {} {} 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 {} 0 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
            p.pid, p.comm, p.state, p.ppid, crate::proc::getpgid(p.pid).unwrap_or(p.pid as i64),
            crate::proc::getsid(p.pid).unwrap_or(p.pid as i64), p.start_ms / 10),
        "status" => format!("Name:\t{}\nUmask:\t0022\nState:\t{}\nTgid:\t{}\nPid:\t{}\nPPid:\t{}\n\
                             Uid:\t{u}\t{u}\t{u}\t{u}\nGid:\t{g}\t{g}\t{g}\t{g}\nThreads:\t1\n",
            p.comm, match p.state { 'S' => "S (sleeping)", 'Z' => "Z (zombie)", _ => "R (running)" }, p.pid, p.pid, p.ppid, u = p.uid, g = p.gid),
        _ => return None,
    })
}

/// "/proc/self/<rest>" or "/proc/<our pid>/<rest>" -> rest.
fn self_rest(guest: &str) -> Option<&str> {
    let r = guest.strip_prefix("/proc/")?;
    let (pid, rest) = r.split_once('/')?;
    (pid == "self" || crate::proc::host_pid(pid.parse().ok()?) == crate::proc::pid()).then_some(in_task(rest))
}

/// Below one of our process's own directories: `task/<tid>/x` (or `task/<tid>`) as `x`, for a tid of
/// ours. ponytail: a thread's files are its process's (Go's setuid test compares their Uid lines).
pub fn in_task(rest: &str) -> &str {
    let Some(t) = rest.strip_prefix("task/") else { return rest };
    let (tid, x) = t.split_once('/').unwrap_or((t, ""));
    if tid.parse().is_ok_and(|n: u32| crate::thread::tids().contains(&n)) { x } else { rest }
}

/// The machine's CPU times (in 1/100 s ticks) and boot time: ps reads btime, top the cpu lines.
/// ponytail: per-CPU lines split the totals evenly; no interrupt or context-switch counts.
fn stat() -> String {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemTimes(idle: *mut u64, kernel: *mut u64, user: *mut u64) -> i32;
    }
    let (mut idle, mut kernel, mut user) = (0u64, 0u64, 0u64);
    unsafe { GetSystemTimes(&mut idle, &mut kernel, &mut user) };
    let n = std::thread::available_parallelism().map_or(1, |n| n.get()) as u64;
    // 100 ns units -> ticks; kernel time includes idle time.
    let (idle, sys, user) = (idle / 100_000, kernel.saturating_sub(idle) / 100_000, user / 100_000);
    let line = |name: &str, d: u64| format!("{name} {} 0 {} {} 0 0 0 0 0 0\n", user / d, sys / d, idle / d);
    let mut s = line("cpu ", 1);
    for i in 0..n {
        s += &line(&format!("cpu{i}"), n);
    }
    let up = unsafe { crate::win::GetTickCount64() } / 1000;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    s + &format!("intr 0\nctxt 0\nbtime {}\nprocesses {}\nprocs_running 1\nprocs_blocked 0\n",
                 now.saturating_sub(up), crate::ptable::all().len())
}

fn mounts() -> String {
    "overlay / overlay rw,relatime 0 0\nproc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n\
     tmpfs /dev tmpfs rw,nosuid 0 0\nshm /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0\n".into()
}

fn meminfo() -> String {
    let mut m = [0u64; 8]; // MEMORYSTATUSEX: dwLength + dwMemoryLoad, ullTotalPhys, ullAvailPhys, page file ...
    m[0] = 64;
    unsafe { crate::win::GlobalMemoryStatusEx(&mut m) };
    let kb = |b: u64| b >> 10;
    let (total, free) = (kb(m[1]), kb(m[2]));
    let (swap, swap_free) = (kb(m[3].saturating_sub(m[1])), kb(m[4].saturating_sub(m[2])));
    format!("MemTotal:       {total:8} kB\nMemFree:        {free:8} kB\nMemAvailable:   {free:8} kB\n\
             Buffers:               0 kB\nCached:                0 kB\nSwapCached:            0 kB\n\
             SwapTotal:      {swap:8} kB\nSwapFree:       {swap_free:8} kB\nShmem:                 0 kB\n\
             HugePages_Total:       0\nHugePages_Free:        0\nHugepagesize:       2048 kB\n")
}

fn cpuinfo() -> String {
    use std::arch::x86_64::{__cpuid, __cpuid_count};
    let words = |r: [u32; 4]| r.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
    let l0 = __cpuid(0);
    let vendor = String::from_utf8_lossy(&words([l0.ebx, l0.edx, l0.ecx, 0])[..12]).into_owned();
    let model: String = (0x8000_0002..=0x8000_0004u32)
        .flat_map(|leaf| { let r = __cpuid(leaf); words([r.eax, r.ebx, r.ecx, r.edx]) })
        .map(|b| b as char).collect::<String>().trim_matches(|c: char| c == '\0' || c == ' ').to_string();
    let l1 = __cpuid(1);
    let l7 = __cpuid_count(7, 0);
    let has = |reg: u32, bit: u32| reg >> bit & 1 != 0;
    // The flags programs probe for (glibc tunables, numpy, JITs read these names).
    let flags: Vec<&str> = [
        (has(l1.edx, 0), "fpu"), (has(l1.edx, 4), "tsc"), (has(l1.edx, 8), "cx8"), (has(l1.edx, 15), "cmov"),
        (has(l1.edx, 23), "mmx"), (has(l1.edx, 24), "fxsr"), (has(l1.edx, 25), "sse"), (has(l1.edx, 26), "sse2"),
        (has(l1.edx, 28), "ht"), (true, "syscall"), (true, "nx"), (true, "lm"), (has(l1.ecx, 0), "pni"),
        (has(l1.ecx, 1), "pclmulqdq"), (has(l1.ecx, 9), "ssse3"), (has(l1.ecx, 12), "fma"), (has(l1.ecx, 13), "cx16"),
        (has(l1.ecx, 19), "sse4_1"), (has(l1.ecx, 20), "sse4_2"), (has(l1.ecx, 22), "movbe"), (has(l1.ecx, 23), "popcnt"),
        (has(l1.ecx, 25), "aes"), (has(l1.ecx, 26), "xsave"), (has(l1.ecx, 28), "avx"), (has(l1.ecx, 29), "f16c"),
        (has(l1.ecx, 30), "rdrand"), (has(l7.ebx, 3), "bmi1"), (has(l7.ebx, 5), "avx2"), (has(l7.ebx, 8), "bmi2"),
        (has(l7.ebx, 16), "avx512f"), (has(l7.ebx, 18), "rdseed"), (has(l7.ebx, 19), "adx"), (has(l7.ebx, 29), "sha_ni"),
    ].into_iter().filter(|f| f.0).map(|f| f.1).collect();
    let (family, model_no, stepping) = ((l1.eax >> 8) & 0xf, ((l1.eax >> 4) & 0xf) | ((l1.eax >> 12) & 0xf0), l1.eax & 0xf);
    let n = std::thread::available_parallelism().map_or(1, |n| n.get());
    (0..n).map(|i| format!("processor\t: {i}\nvendor_id\t: {vendor}\ncpu family\t: {family}\nmodel\t\t: {model_no}\n\
        model name\t: {model}\nstepping\t: {stepping}\nphysical id\t: 0\nsiblings\t: {n}\ncore id\t\t: {i}\n\
        cpu cores\t: {n}\napicid\t\t: {i}\nfpu\t\t: yes\nflags\t\t: {}\nbogomips\t: 4000.00\n\
        clflush size\t: 64\ncache_alignment\t: 64\naddress sizes\t: 48 bits physical, 48 bits virtual\n\n", flags.join(" ")))
        .collect()
}

const MOUNTINFO: &str = "1 0 0:1 / / rw,relatime - overlay overlay rw\n2 1 0:2 / /proc rw,nosuid,nodev,noexec - proc proc rw\n\
    3 1 0:3 / /dev rw,nosuid - tmpfs tmpfs rw\n4 3 0:4 / /dev/shm rw,nosuid,nodev,noexec - tmpfs shm rw\n";

#[link(name = "kernel32")]
unsafe extern "system" {
    fn K32GetProcessMemoryInfo(process: isize, counters: *mut [u64; 10], cb: u32) -> i32;
}

/// (virtual = committed bytes, resident = working set) of this process.
fn mem() -> (u64, u64) {
    // PROCESS_MEMORY_COUNTERS_EX: cb + PageFaultCount (u32 x2), then PeakWorkingSetSize, WorkingSetSize, quota
    // fields x4, PagefileUsage, PeakPagefileUsage, PrivateUsage.
    let mut c = [0u64; 10];
    c[0] = 80;
    unsafe { K32GetProcessMemoryInfo(crate::win::GetCurrentProcess(), &mut c, 80) };
    (c[9].max(c[7]), c[2])
}

/// /proc/self/statm in pages: size resident shared text lib data dt (RabbitMQ's memory monitor).
fn statm() -> String {
    let (vsz, rss) = mem();
    format!("{} {} 0 0 0 {} 0\n", vsz / 4096, rss / 4096, vsz / 4096)
}

/// /proc/self/status: the fields programs parse (ids, threads, memory).
fn status() -> String {
    let (vsz, rss) = mem();
    let pid = crate::proc::getpid().unwrap_or(0);
    let ppid = crate::proc::getppid().unwrap_or(0);
    let name = crate::fs::exe_name();
    let (uid, gid) = (crate::proc::UID.load(std::sync::atomic::Ordering::Relaxed), crate::proc::GID.load(std::sync::atomic::Ordering::Relaxed));
    format!("Name:\t{name}\nUmask:\t0022\nState:\tR (running)\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{ppid}\n\
             Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{gid}\t{gid}\t{gid}\t{gid}\nGroups:\t{}\nVmSize:\t{:8} kB\nVmRSS:\t{:8} kB\nThreads:\t{}\n\
             SigBlk:\t0000000000000000\nCpus_allowed_list:\t0-{}\n",
            crate::proc::groups().iter().map(|g| format!("{g} ")).collect::<String>(),
            vsz >> 10, rss >> 10, crate::thread::live(), std::thread::available_parallelism().map_or(1, |n| n.get()) - 1)
}
