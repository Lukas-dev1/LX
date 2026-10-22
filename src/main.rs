//! lx: run a static x86-64 Linux ELF natively on NT. See DESIGN.md.
mod build;
mod compose;
mod elf;
mod fs;
mod jump;
mod image;
mod net;
mod proc;
mod procfs;
mod signal;
mod syscall;
mod thread;

use std::ffi::c_void;
use std::{env, path::Path, process};

// ponytail: hand-declared Win32 surface instead of windows-sys; switch when it outgrows one screen.
pub mod win {
    use std::ffi::c_void;
    pub const MEM_COMMIT: u32 = 0x1000;
    pub const MEM_RESERVE: u32 = 0x2000;
    pub const MEM_COMMIT_RESERVE: u32 = 0x3000;
    pub const MEM_DECOMMIT: u32 = 0x4000;
    pub const MEM_FREE: u32 = 0x10000;
    pub const MEM_RELEASE: u32 = 0x8000;
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const PAGE_GUARD: u32 = 0x100;
    pub const FILE_MAP_WRITE: u32 = 0x02;
    pub const EVENT_MODIFY_STATE: u32 = 0x02;

    #[repr(C)]
    #[derive(Default)]
    pub struct MemoryBasicInformation {
        pub base: usize,
        pub allocation_base: usize,
        pub allocation_protect: u32,
        pub partition_id: u16,
        pub region_size: usize,
        pub state: u32,
        pub protect: u32,
        pub ty: u32,
    }
    const _: () = assert!(size_of::<MemoryBasicInformation>() == 48);

    #[repr(C)]
    pub struct ExceptionRecord {
        pub code: u32,
        pub flags: u32,
        pub next: *mut ExceptionRecord,
        pub address: *mut c_void,
        pub nparams: u32,
        pub info: [usize; 15],
    }
    /// Prefix of the x64 CONTEXT record; we only touch integer registers.
    #[repr(C)]
    pub struct Context {
        _home: [u64; 6],
        _flags: u32,
        _mxcsr: u32,
        _seg: [u16; 6],
        pub eflags: u32,
        _dr: [u64; 6],
        pub rax: u64, pub rcx: u64, pub rdx: u64, pub rbx: u64,
        pub rsp: u64, pub rbp: u64, pub rsi: u64, pub rdi: u64,
        pub r8: u64, pub r9: u64, pub r10: u64, pub r11: u64,
        pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
        pub rip: u64,
    }
    const _: () = assert!(std::mem::offset_of!(Context, rax) == 0x78);
    const _: () = assert!(std::mem::offset_of!(Context, rip) == 0xF8);

    #[repr(C)]
    pub struct ExceptionPointers {
        pub record: *mut ExceptionRecord,
        pub context: *mut Context,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn VirtualAlloc(addr: *mut c_void, size: usize, ty: u32, prot: u32) -> *mut c_void;
        pub fn VirtualProtect(addr: *mut c_void, size: usize, prot: u32, old: *mut u32) -> i32;
        pub fn VirtualQuery(addr: *const c_void, info: *mut MemoryBasicInformation, len: usize) -> usize;
        pub fn VirtualFree(addr: *mut c_void, size: usize, ty: u32) -> i32;
        pub fn AddVectoredExceptionHandler(
            first: u32,
            h: unsafe extern "system" fn(*mut ExceptionPointers) -> i32,
        ) -> *mut c_void;
        pub fn GetStdHandle(n: u32) -> isize;
        pub fn SetStdHandle(n: u32, h: isize) -> i32;
        pub fn WriteFile(h: isize, buf: *const u8, len: u32, done: *mut u32, ov: *mut c_void) -> i32;
        pub fn ReadFile(h: isize, buf: *mut u8, len: u32, done: *mut u32, ov: *mut c_void) -> i32;
        pub fn GetLastError() -> u32;
        pub fn ExitProcess(code: u32) -> !;
        pub fn CreateJobObjectW(attr: *mut c_void, name: *const u16) -> isize;
        pub fn OpenJobObjectW(access: u32, inherit: i32, name: *const u16) -> isize;
        pub fn SetInformationJobObject(job: isize, class: u32, info: *const c_void, len: u32) -> i32;
        pub fn AssignProcessToJobObject(job: isize, process: isize) -> i32;
        pub fn GetCurrentProcess() -> isize;
        pub fn GetCurrentProcessId() -> u32;
        pub fn TerminateProcess(process: isize, code: u32) -> i32;
        pub fn GetExitCodeProcess(process: isize, code: *mut u32) -> i32;
        pub fn WaitForMultipleObjects(n: u32, handles: *const isize, all: i32, ms: u32) -> u32;
        pub fn CloseHandle(h: isize) -> i32;
        pub fn SetHandleInformation(h: isize, mask: u32, flags: u32) -> i32;
        pub fn CreatePipe(r: *mut isize, w: *mut isize, attr: *mut c_void, size: u32) -> i32;
        pub fn GetFileType(h: isize) -> u32;
        pub fn GetFileAttributesW(name: *const u16) -> u32;
        pub fn GetFileAttributesExW(name: *const u16, level: u32, data: *mut [u32; 9]) -> i32;
        pub fn LockFileEx(h: isize, flags: u32, reserved: u32, len_lo: u32, len_hi: u32, ov: *mut c_void) -> i32;
        pub fn UnlockFileEx(h: isize, reserved: u32, len_lo: u32, len_hi: u32, ov: *mut c_void) -> i32;
        pub fn MapViewOfFileEx(map: isize, access: u32, hi: u32, lo: u32, len: usize, base: *mut c_void) -> *mut c_void;
        pub fn UnmapViewOfFile(base: *mut c_void) -> i32;
        pub fn FlushViewOfFile(base: *const c_void, len: usize) -> i32;
        pub fn CreateNamedPipeW(name: *const u16, mode: u32, pipe_mode: u32, instances: u32, out: u32, inp: u32, timeout: u32, attr: *mut c_void) -> isize;
        pub fn CreateFileW(name: *const u16, access: u32, share: u32, attr: *mut c_void, disposition: u32, flags: u32, template: isize) -> isize;
        pub fn GetOverlappedResult(h: isize, ov: *mut c_void, done: *mut u32, wait: i32) -> i32;
        pub fn CancelIoEx(h: isize, ov: *mut c_void) -> i32;
        pub fn GetPhysicallyInstalledSystemMemory(kb: *mut u64) -> i32;
        pub fn GetDiskFreeSpaceExW(dir: *const u16, avail: *mut u64, total: *mut u64, free: *mut u64) -> i32;
        pub fn CreateFileMappingW(file: isize, attr: *mut c_void, prot: u32, hi: u32, lo: u32, name: *const u16) -> isize;
        pub fn OpenFileMappingW(access: u32, inherit: i32, name: *const u16) -> isize;
        pub fn MapViewOfFile(map: isize, access: u32, hi: u32, lo: u32, len: usize) -> *mut c_void;
        pub fn CreateEventW(attr: *mut c_void, manual: i32, initial: i32, name: *const u16) -> isize;
        pub fn OpenEventW(access: u32, inherit: i32, name: *const u16) -> isize;
        pub fn SetEvent(ev: isize) -> i32;
        pub fn CancelSynchronousIo(thread: isize) -> i32;
        pub fn GetConsoleMode(h: isize, mode: *mut u32) -> i32;
        pub fn SetConsoleMode(h: isize, mode: u32) -> i32;
        pub fn GetConsoleScreenBufferInfo(h: isize, info: *mut [i16; 11]) -> i32;
        pub fn SetConsoleCtrlHandler(h: Option<unsafe extern "system" fn(u32) -> i32>, add: i32) -> i32;
        pub fn GetCurrentThread() -> isize;
        pub fn OpenProcess(access: u32, inherit: i32, pid: u32) -> isize;
        pub fn GlobalMemoryStatusEx(m: *mut [u64; 8]) -> i32;
        pub fn GetTickCount64() -> u64;
        pub fn GetCurrentProcessorNumber() -> u32;
        pub fn PeekNamedPipe(h: isize, buf: *mut c_void, len: u32, read: *mut u32, avail: *mut u32, left: *mut u32) -> i32;
        pub fn DuplicateHandle(sp: isize, h: isize, tp: isize, out: *mut isize, access: u32, inherit: i32, opts: u32) -> i32;
        pub fn ReadProcessMemory(p: isize, from: *const c_void, to: *mut c_void, len: usize, done: *mut usize) -> i32;
        pub fn TlsAlloc() -> u32;
        pub fn TlsGetValue(idx: u32) -> *mut c_void;
        pub fn TlsSetValue(idx: u32, v: *mut c_void) -> i32;
        pub fn CreateThread(
            attr: *mut c_void, stack: usize, start: unsafe extern "system" fn(*mut c_void) -> u32,
            param: *mut c_void, flags: u32, tid: *mut u32,
        ) -> isize;
        pub fn ResumeThread(h: isize) -> u32;
        pub fn ExitThread(code: u32) -> !;
        pub fn TerminateThread(h: isize, code: u32) -> i32;
        pub fn GetCurrentThreadId() -> u32;
        pub fn SwitchToThread() -> i32;
        pub fn FlushProcessWriteBuffers();
        pub fn GetModuleHandleW(name: *const u16) -> isize;
        pub fn GetModuleHandleExW(flags: u32, addr: *const c_void, out: *mut isize) -> i32;
    }
    #[link(name = "synchronization")]
    unsafe extern "system" {
        /// The futex of Windows: sleep while *addr == *compare, atomically with respect to WakeByAddress*.
        pub fn WaitOnAddress(addr: *const c_void, compare: *const c_void, size: usize, ms: u32) -> i32;
        pub fn WakeByAddressSingle(addr: *const c_void);
        pub fn WakeByAddressAll(addr: *const c_void);
    }
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        pub fn BCryptGenRandom(alg: *mut c_void, buf: *mut u8, len: u32, flags: u32) -> i32;
        pub fn BCryptCreateHash(alg: isize, h: *mut isize, obj: *mut u8, objlen: u32, secret: *mut u8, seclen: u32, flags: u32) -> i32;
        pub fn BCryptHashData(h: isize, data: *const u8, len: u32, flags: u32) -> i32;
        pub fn BCryptFinishHash(h: isize, out: *mut u8, len: u32, flags: u32) -> i32;
        pub fn BCryptDestroyHash(h: isize) -> i32;
    }
}

/// JOBOBJECT_EXTENDED_LIMIT_INFORMATION
#[repr(C)]
#[derive(Default)]
struct JobLimits {
    user_time: [i64; 2],
    flags: u32,
    working_set: [usize; 2],
    active_processes: u32,
    affinity: usize,
    priority_class: u32,
    scheduling_class: u32,
    io: [u64; 6],
    process_memory: usize,
    job_memory: usize,
    peaks: [usize; 2],
}
const _: () = assert!(size_of::<JobLimits>() == 144);

/// Self-confinement: memory cap, and everything we spawn dies with us.
/// Per-process memory cap (commit charge): `lx run -m`, carried to every lx process of the container in
/// LX_MEMORY; by default the machine's physical RAM. NT commits on mmap where Linux overcommits (OpenBLAS
/// reserves 32 MB per CPU up front), so a cap much below RAM breaks ordinary programs; RAM still keeps a
/// runaway container from taking more than the machine has.
fn memory_limit() -> usize {
    if let Some(v) = env::var("LX_MEMORY").ok().and_then(|v| v.parse().ok()) {
        return v;
    }
    let mut kb = 0u64;
    let ram = if unsafe { win::GetPhysicallyInstalledSystemMemory(&mut kb) } != 0 { kb << 10 } else { 4 << 30 };
    ram as usize
}

/// `-m 512m`, `2g`, `1073741824`: bytes (k/m/g suffixes, base 1024).
fn parse_memory(v: &str) -> Result<String, String> {
    let v = v.to_ascii_lowercase();
    let (num, mult) = match v.chars().last() {
        Some('k') => (&v[..v.len() - 1], 1u64 << 10),
        Some('m') => (&v[..v.len() - 1], 1 << 20),
        Some('g') => (&v[..v.len() - 1], 1 << 30),
        _ => (&v[..], 1),
    };
    let n: u64 = num.parse().map_err(|_| format!("bad -m {v:?}: want e.g. 512m or 2g"))?;
    if n * mult < 64 << 20 {
        return Err("-m: at least 64m".into());
    }
    Ok((n * mult).to_string())
}

fn job_name(pid: u32) -> Vec<u16> {
    format!("Local\\lx-job-{pid}").encode_utf16().chain([0]).collect()
}

/// The container's job: the first lx process of a container makes it, every later one (fork, exec)
/// starts inside it and stays there. It caps each process's memory and dies with that first process,
/// taking the whole container along, like PID 1. Only one per container: a job per lx process killed
/// a daemon (fork, then the parent exits: redis --daemonize, pg_ctl start) along with its parent.
fn enter_job() -> Result<(), String> {
    if env::var_os("LX_IN_JOB").is_some() {
        return Ok(());
    }
    // Inherited by every later lx process; the pid also names the process that holds SCM_RIGHTS handles.
    unsafe { env::set_var("LX_IN_JOB", std::process::id().to_string()) };
    const LIMIT_PROCESS_MEMORY: u32 = 0x100;
    const KILL_ON_JOB_CLOSE: u32 = 0x2000;
    let limits = JobLimits {
        flags: LIMIT_PROCESS_MEMORY | KILL_ON_JOB_CLOSE,
        process_memory: memory_limit(),
        ..Default::default()
    };
    unsafe {
        // The handle is deliberately leaked: it closes at process exit, which kills the job. Named so
        // `lx exec` can put its process in it too.
        let job = win::CreateJobObjectW(std::ptr::null_mut(), job_name(win::GetCurrentProcessId()).as_ptr());
        let ok = job != 0
            && win::SetInformationJobObject(job, 9, &limits as *const _ as *const c_void, 144) != 0
            && win::AssignProcessToJobObject(job, win::GetCurrentProcess()) != 0;
        if ok { Ok(()) } else { Err(format!("job object setup failed ({})", win::GetLastError())) }
    }
}

const USAGE: &str = "usage: lx pull <image>                     e.g. lx pull nginx:alpine
       lx run [-p [ip:]hostport:port[/udp]]... <image> [command args...]
                                             runs the image's entrypoint/cmd, or the given command;
                                             -p publishes a container port (others stay on localhost)
                                             -v C:\\data:/data[:ro] mounts a host folder (repeatable)
                                             -m 2g caps each process's memory (default: the machine's RAM)
                                             -e NAME=value (or -e NAME: the host's) sets an env var
                                             -w /dir sets the working directory
                                             -u user[:group] runs as that user (default: the image's USER)
                                             --name NAME names it (for exec, logs, stop, kill)
                                             --add-host name:ip adds a line to /etc/hosts
       lx run -d ...                         the same in the background: prints the container's pid
       lx build -t name[:tag] [-f Dockerfile] [--build-arg K=V] [--no-cache] <dir>
                                             builds an image from a Dockerfile
       lx logs <name|pid>                     output of a `lx run -d` container
       lx exec [-e ..] [-w dir] [-u user] <name|pid> <command> [args...]
                                             runs a command inside a running container
       lx compose [-f file] up [-d]|down|ps|logs   the services of a compose file
       lx images                             pulled and built images
       lx rmi <image>...                     remove images
       lx ps                                 running containers
       lx stop <name|pid>                    SIGTERM, then SIGKILL after 10s
       lx kill <name|pid> [SIGNAL]           default TERM
       lx <rootfs-dir> <command> [args...]   run a command in an unpacked rootfs
       lx unpack <layer.tar[.gz]> <rootfs-dir>";
const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// `-v HOST:/guest[:ro|:rw]`. HOST may be a Windows path with a drive letter (`C:\data:/data`), so the
/// guest part starts at the first ":/" after it. The host folder is created if missing, like Docker.
fn parse_volume(spec: &str) -> Result<(std::path::PathBuf, String, bool), String> {
    let bad = || format!("bad -v {spec:?}: want HOSTPATH:/container/path[:ro]");
    let i = spec.get(2..).and_then(|s| s.find(":/")).map(|i| i + 2).ok_or_else(bad)?;
    let (host, guest) = (&spec[..i], &spec[i + 1..]);
    let (guest, ro) = match guest.rsplit_once(':') {
        Some((g, "ro")) => (g, true),
        Some((g, "rw")) => (g, false),
        _ => (guest, false),
    };
    if host.is_empty() || !guest.starts_with('/') || guest.contains(':') {
        return Err(bad());
    }
    std::fs::create_dir_all(host).map_err(|e| format!("-v {host}: {e}"))?;
    let host = std::fs::canonicalize(host).map_err(|e| format!("-v {host}: {e}"))?;
    if !host.is_dir() {
        return Err(format!("-v {}: not a folder", host.display()));
    }
    Ok((host, guest.to_string(), ro))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    proc::load_ids(); // a forked or exec'd lx: the guest's uid, gid and umask so far
    if let [cmd, tgz, dest] = args.as_slice() && cmd == "unpack" {
        let (n, skipped) = fs::unpack(Path::new(tgz), Path::new(dest))?;
        eprintln!("[lx] unpacked {n} entries ({skipped} skipped) into {dest}");
        return Ok(());
    }
    if let [flag, handle] = args.as_slice() && flag == "--exec" {
        // We are the new program of a guest execve(): fds, cwd, argv and env come from the old one.
        let (exe, argv, env) = proc::receive_exec(handle)?;
        return start(&exe, argv, env);
    }
    if let [flag, state, parent, ready] = args.as_slice() && flag == "--fork" {
        // We are the child of a guest fork(): rebuild its address space from the parent, resume after the syscall.
        enter_job()?;
        syscall::install();
        let (regs, (lo, hi)) = proc::receive_fork(state, parent, ready)?;
        syscall::enter(regs, lo, hi)
    }
    if let [cmd, image] = args.as_slice() && cmd == "pull" {
        let dir = image::pull(&image::Ref::parse(image))?;
        eprintln!("[lx] pulled {image} into {}", dir.display());
        return Ok(());
    }
    if let [cmd] = args.as_slice() && cmd == "images" {
        println!("{:<50} TAG", "REPOSITORY");
        for (repo, tag) in image::list() {
            println!("{repo:<50} {tag}");
        }
        return Ok(());
    }
    if let [cmd, images @ ..] = args.as_slice() && cmd == "rmi" && !images.is_empty() {
        for i in images {
            let dir = image::Ref::parse(i).dir();
            if !dir.join("config.json").exists() {
                return Err(format!("{i}: no such image"));
            }
            std::fs::remove_dir_all(&dir).map_err(|e| format!("{i}: {e}"))?;
            println!("removed {i}");
        }
        return Ok(());
    }
    if let [cmd, rest @ ..] = args.as_slice() && cmd == "compose" {
        return compose::compose(rest);
    }
    if let [cmd, rest @ ..] = args.as_slice() && cmd == "build" {
        // lx build -t name[:tag] [-f Dockerfile] [--build-arg K=V] [--no-cache] <context>
        let no_cache = rest.iter().any(|a| a == "--no-cache");
        let rest: Vec<String> = rest.iter().filter(|a| *a != "--no-cache").cloned().collect();
        let (mut rest, mut tag, mut file, mut build_args) = (rest.as_slice(), None, None, Vec::new());
        while let [flag, value, more @ ..] = rest {
            match flag.as_str() {
                "-t" | "--tag" => tag = Some(value.clone()),
                "-f" | "--file" => file = Some(std::path::PathBuf::from(value)),
                "--build-arg" => build_args.push(value.split_once('=').map_or((value.clone(), String::new()), |(k, v)| (k.into(), v.into()))),
                _ => break,
            }
            rest = more;
        }
        let [context] = rest else { return Err(USAGE.into()) };
        let tag = tag.ok_or("lx build: -t name[:tag] is required")?;
        let context = std::path::Path::new(context);
        let file = file.unwrap_or_else(|| context.join("Dockerfile"));
        return build::build(&tag, context, &file, build_args, no_cache);
    }
    if let [cmd] = args.as_slice() && cmd == "ps" {
        println!("{:<8} {:<16} COMMAND", "PID", "NAME");
        for (pid, desc) in proc::ps() {
            let name = proc::name_of(pid).unwrap_or_else(|| "-".into());
            println!("{pid:<8} {name:<16} {}", desc.split_whitespace().collect::<Vec<_>>().join(" ")); // one line per container
        }
        return Ok(());
    }
    if let [cmd, id, rest @ ..] = args.as_slice() && (cmd == "kill" || cmd == "stop") {
        let pid = container(id)?;
        if cmd == "stop" {
            return proc::stop(pid, std::time::Duration::from_secs(10));
        }
        let sig = rest.first().map_or(Some(15), |s| signal::parse(s)).ok_or("unknown signal")?;
        return proc::send(pid, sig).map(|_| ()).map_err(|_| format!("{pid}: no such lx process"));
    }
    if let [cmd, rest @ ..] = args.as_slice() && cmd == "run" && let Some(i) = detach_flag(rest) {
        let mut run_args = rest.to_vec();
        run_args.remove(i);
        return detach(&run_args);
    }
    if let [cmd, id] = args.as_slice() && cmd == "logs" {
        let pid = container(id)?;
        let log = proc::log_of(pid).ok_or(format!("{pid}: no log (only `lx run -d` containers have one)"))?;
        let text = std::fs::read(&log).map_err(|e| format!("{log}: {e}"))?;
        std::io::Write::write_all(&mut std::io::stdout(), &text).map_err(|e| e.to_string())?;
        return Ok(());
    }
    if let [cmd, rest @ ..] = args.as_slice() && cmd == "run" {
        // Flags before the image: -p/--publish [hostip:]hostport:containerport[/udp], repeatable.
        let (mut rest, mut ports) = (rest, Vec::new());
        let (mut volumes, mut envs, mut workdir, mut user) = (Vec::new(), Vec::new(), None, None);
        let (mut entrypoint, mut keep_layer, mut name) = (None, None, None);
        let mut extra_hosts: Vec<(String, String)> = Vec::new();
        while let [flag, more @ ..] = rest {
            if NO_OP_FLAGS.contains(&flag.as_str()) {
                rest = more;
                continue;
            }
            let [value, more @ ..] = more else { break };
            match flag.as_str() {
                // --add-host name:ip, like Docker (lx compose names the other services this way).
                "--add-host" => {
                    let (n, ip) = value.split_once(':').ok_or(format!("bad --add-host {value:?}: want name:ip"))?;
                    extra_hosts.push((n.to_string(), ip.to_string()));
                }
                "-u" | "--user" => user = Some(value.clone()),
                "--name" => {
                    if let Some(pid) = proc::container_pid(value) {
                        return Err(format!("the name {value} is already in use by container {pid}"));
                    }
                    name = Some(value.clone());
                }
                "--entrypoint" => entrypoint = Some(value.clone()),
                // lx build: the step's writable layer goes here and stays after the container exits.
                "--layer" => keep_layer = Some(std::path::PathBuf::from(value)),
                // -e NAME=value, or -e NAME for the host's value (left out if the host has none), like Docker.
                "-e" | "--env" if value.contains('=') => envs.push(value.clone()),
                "-e" | "--env" => envs.extend(env::var(value).ok().map(|v| format!("{value}={v}"))),
                "-w" | "--workdir" => workdir = Some(value.clone()),
                "-p" | "--publish" => ports.push(net::parse_publish(value)?),
                "-v" | "--volume" => volumes.push(parse_volume(value)?),
                "-m" | "--memory" => unsafe { env::set_var("LX_MEMORY", parse_memory(value)?) },
                _ => break,
            }
            rest = more;
        }
        let [image, rest @ ..] = rest else { return Err(USAGE.into()) };
        // Every lx process of this container inherits it (fork and exec start new lx processes).
        unsafe { env::set_var("LX_PORTS", ports.join(",")) };
        let dir = match image.strip_prefix("dir:") {
            Some(d) => std::path::PathBuf::from(d), // lx build: an image being built
            None => {
                let r = image::Ref::parse(image);
                if r.dir().join("config.json").exists() { r.dir() } else { image::pull(&r)? }
            }
        };
        let mut c = image::run_config(&dir, rest, entrypoint.as_deref())?;
        for e in envs {
            let name = e.split('=').next().unwrap_or_default().to_string();
            c.env.retain(|x| x.split('=').next() != Some(name.as_str()));
            c.env.push(e);
        }
        c.workdir = workdir.unwrap_or(c.workdir);
        let root = std::fs::canonicalize(dir.join("rootfs")).map_err(|e| e.to_string())?;
        // USER (or -u): the ids the container starts with, and HOME from passwd unless the env has one.
        let (uid, gid, home) = image::resolve_user(&root, user.as_deref().unwrap_or(&c.user))?;
        (proc::UID.store(uid, std::sync::atomic::Ordering::Relaxed), proc::GID.store(gid, std::sync::atomic::Ordering::Relaxed));
        proc::save_ids();
        if !c.env.iter().any(|e| e.starts_with("HOME=")) {
            c.env.push(format!("HOME={}", if uid == 0 && home == "/" { "/root" } else { &home }));
        }
        // The container gets its own writable layer; the pulled image is never modified.
        // ponytail: removed when the container exits (like `docker run --rm`); no named, restartable containers yet.
        proc::gc_layers();
        let layer = match keep_layer {
            Some(d) => {
                std::fs::create_dir_all(d.join("upper")).map_err(|e| e.to_string())?;
                std::fs::canonicalize(d).map_err(|e| e.to_string())?
            }
            None => proc::new_layer().map_err(|e| format!("creating the container layer: {e}"))?,
        };
        fs::init(root.clone());
        fs::set_upper(layer.join("upper"));
        // Like Docker: the container resolves names through the host's DNS servers.
        let (resolv, mut hosts) = net::dns_files();
        for (name, ip) in &extra_hosts {
            hosts.push_str(&format!("{ip}\t{name}\n")); // --add-host
        }
        let _ = fs::write_guest_file("/etc/resolv.conf", resolv.as_bytes());
        let _ = fs::write_guest_file("/etc/hosts", hosts.as_bytes());
        let _ = fs::mkdir_guest("/dev/shm"); // POSIX shared memory and semaphores (glibc's sem_open) live here
        for (host, guest, ro) in &volumes {
            fs::add_mount(guest, host.clone(), *ro).map_err(|_| format!("-v: can't mount at {guest}"))?;
        }
        fs::set_cwd(&c.workdir).map_err(|_| format!("WorkingDir {} not found in image", c.workdir))?;
        // What `lx exec` needs to step into this container.
        let config = serde_json::json!({
            "root": root, "layer": layer, "env": c.env, "workdir": c.workdir, "uid": uid, "gid": gid,
            "ports": ports.join(","), "mounts": volumes.iter().map(|(h, g, ro)| serde_json::json!([h, g, ro])).collect::<Vec<_>>(),
            "name": name,
        });
        proc::register_container(&format!("{image}  {}", c.argv.join(" ")), &config.to_string());
        return start(&c.argv[0], c.argv.clone(), c.env);
    }
    if let [cmd, rest @ ..] = args.as_slice() && cmd == "exec" {
        return exec(rest);
    }
    let [rootfs, cmd, rest @ ..] = args.as_slice() else { return Err(USAGE.into()) };
    let root = std::fs::canonicalize(rootfs).map_err(|e| format!("{rootfs}: {e}"))?;
    fs::init(root);
    let env = vec![format!("PATH={PATH}"), "HOME=/root".into(), "HOSTNAME=lx".into()];
    start(cmd, std::iter::once(cmd).chain(rest).cloned().collect(), env)
}

/// A running container by `--name` or pid.
fn container(id: &str) -> Result<u32, String> {
    proc::container_pid(id).ok_or(format!("{id}: no such container (see lx ps)"))
}

/// `lx run` flags without a value, accepted for Docker's sake: stdin is always attached and containers
/// are always removed when they exit.
const NO_OP_FLAGS: [&str; 7] = ["-i", "-t", "-it", "-ti", "--interactive", "--tty", "--rm"];

/// Where `-d`/`--detach` is among `lx run`'s flags (the others take a value, or are NO_OP_FLAGS).
fn detach_flag(args: &[String]) -> Option<usize> {
    let mut i = 0;
    while let Some(a) = args.get(i) {
        match a.as_str() {
            "-d" | "--detach" => return Some(i),
            a if NO_OP_FLAGS.contains(&a) => i += 1,
            a if a.starts_with('-') => i += 2,
            _ => return None, // the image
        }
    }
    None
}

/// `lx run -d ...`: the same `lx run` as a background process with its output in a log file (`lx logs`);
/// prints the container's pid, like `docker run -d` prints its id. It leaves the caller's job object if it
/// may, so closing the terminal that started it doesn't end it. ponytail: logs stay until removed by hand.
fn detach(run_args: &[String]) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x8;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x200;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    let logs = std::path::Path::new("rootfs/logs");
    std::fs::create_dir_all(logs).map_err(|e| e.to_string())?;
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    let log = std::fs::canonicalize(logs).map_err(|e| e.to_string())?.join(format!("{nanos}.log"));
    let out = std::fs::File::create(&log).map_err(|e| format!("{}: {e}", log.display()))?;
    let spawn = |flags: u32| -> std::io::Result<std::process::Child> {
        std::process::Command::new(env::current_exe()?).arg("run").args(run_args)
            .stdin(std::process::Stdio::null()).stdout(out.try_clone()?).stderr(out.try_clone()?)
            .creation_flags(flags).spawn()
    };
    // Our own stdin/out/err (a shell's pipe, for `pid=$(lx run -d ...)`) must not leak into the
    // background process, or whoever reads that pipe waits for the container to end.
    for std in [-10i32, -11, -12] {
        unsafe { win::SetHandleInformation(win::GetStdHandle(std as u32), 1, 0) }; // HANDLE_FLAG_INHERIT off
    }
    let base = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    let child = spawn(base | CREATE_BREAKAWAY_FROM_JOB).or_else(|_| spawn(base)).map_err(|e| e.to_string())?;
    proc::set_log(child.id(), &log.to_string_lossy());
    println!("{}", child.id());
    Ok(())
}

/// `lx exec [-e NAME[=value]] [-w DIR] [-u USER] <pid> <command> [args...]`, like `docker exec`: the command
/// runs inside the running container `pid` (from `lx ps`): its image, writable layer and volumes, its env
/// and working directory, its user, and its job, so it ends with the container.
fn exec(args: &[String]) -> Result<(), String> {
    let (mut rest, mut envs, mut workdir, mut user) = (args, Vec::new(), None, None);
    while let [flag, value, more @ ..] = rest {
        match flag.as_str() {
            "-e" | "--env" if value.contains('=') => envs.push(value.clone()),
            "-e" | "--env" => envs.extend(env::var(value).ok().map(|v| format!("{value}={v}"))),
            "-w" | "--workdir" => workdir = Some(value.clone()),
            "-u" | "--user" => user = Some(value.clone()),
            _ => break,
        }
        rest = more;
    }
    let [id, cmd, ..] = rest else { return Err(USAGE.into()) };
    let pid = container(id)?;
    let raw = proc::container_config(pid).ok_or(format!("{id}: no such container (see lx ps)"))?;
    let cfg: serde_json::Value = serde_json::from_str(&raw).map_err(|e| format!("container {pid}: {e}"))?;
    let path = |k: &str| cfg[k].as_str().map(std::path::PathBuf::from).ok_or(format!("container {pid}: no {k}"));
    let (root, layer) = (path("root")?, path("layer")?);

    // Into the container's job: memory cap, and gone when the container is.
    unsafe {
        let job = win::OpenJobObjectW(0x1 | 0x8, 0, job_name(pid).as_ptr()); // ASSIGN_PROCESS | QUERY
        if job == 0 || win::AssignProcessToJobObject(job, win::GetCurrentProcess()) == 0 {
            return Err(format!("container {pid}: can't join its job ({})", win::GetLastError()));
        }
        win::CloseHandle(job); // kill-on-close fires when the container's own handle goes: ours mustn't hold it open
        env::set_var("LX_IN_JOB", pid.to_string()); // the container's first lx, as enter_job records it
        env::set_var("LX_PORTS", cfg["ports"].as_str().unwrap_or(""));
    }
    let mut envv: Vec<String> = cfg["env"].as_array().into_iter().flatten().filter_map(|e| e.as_str().map(String::from)).collect();
    for e in envs {
        let name = e.split('=').next().unwrap_or_default().to_string();
        envv.retain(|x| x.split('=').next() != Some(name.as_str()));
        envv.push(e);
    }
    let (uid, gid) = match &user {
        Some(u) => {
            let (uid, gid, _) = image::resolve_user(&root, u)?;
            (uid, gid)
        }
        None => (cfg["uid"].as_u64().unwrap_or(0) as u32, cfg["gid"].as_u64().unwrap_or(0) as u32),
    };
    (proc::UID.store(uid, std::sync::atomic::Ordering::Relaxed), proc::GID.store(gid, std::sync::atomic::Ordering::Relaxed));
    proc::save_ids();
    fs::init(root);
    fs::set_upper(layer.join("upper"));
    for m in cfg["mounts"].as_array().into_iter().flatten() {
        let (Some(h), Some(g)) = (m[0].as_str(), m[1].as_str()) else { continue };
        fs::add_mount(g, h.into(), m[2].as_bool().unwrap_or(false)).map_err(|_| format!("can't mount {g}"))?;
    }
    let dir = workdir.unwrap_or_else(|| cfg["workdir"].as_str().unwrap_or("/").to_string());
    fs::set_cwd(&dir).map_err(|_| format!("{dir}: no such directory in the container"))?;
    start(cmd, rest[1..].to_vec(), envv)
}

/// Load `cmd` (and its ELF interpreter, or its #! interpreter) and jump into it. Never returns on success.
fn start(cmd: &str, mut argv: Vec<String>, env: Vec<String>) -> Result<(), String> {
    let not_found = |e: i64| format!("{cmd}: {}", if e == syscall::EACCES { "permission denied" } else { "not found in image" });
    let path = env.iter().find_map(|e| e.strip_prefix("PATH=")).unwrap_or(PATH).to_string();
    let (mut exe, mut image) = fs::find_exe(cmd, &path).map_err(not_found)?;
    // #! scripts (nested up to 4 deep, like Linux): argv becomes [interp, optional-arg, script, args...].
    for _ in 0..4 {
        let Some(line) = image.strip_prefix(b"#!") else { break };
        let line = String::from_utf8_lossy(line.split(|&b| b == b'\n').next().unwrap_or_default()).trim().to_string();
        let (interp, arg) = match line.split_once([' ', '\t']) {
            Some((i, a)) => (i.to_string(), Some(a.trim().to_string())),
            None => (line.clone(), None),
        };
        let mut new = vec![interp.clone()];
        new.extend(arg);
        new.push(exe.clone());
        new.extend(argv.drain(..).skip(1));
        argv = new;
        (exe, image) = fs::find_exe(&interp, &path).map_err(|_| format!("{exe}: bad interpreter {interp}"))?;
    }
    fs::set_exe(&exe);

    enter_job()?;
    syscall::install();
    let img = elf::load(&image)?;
    // Dynamically linked: the kernel's job is to map ld.so too and start there; ld.so maps the rest via mmap.
    let (entry, interp_base) = match &img.interp {
        Some(ld) => {
            let ld = elf::load(&fs::find_exe(ld, "/").map_err(|_| format!("{exe}: interpreter {ld} not found"))?.1)?;
            (ld.entry, ld.base)
        }
        None => (img.entry, 0),
    };
    // argv[0] stays what the caller passed (busybox picks its applet from it); the image may live elsewhere.
    let argv: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    let env: Vec<&str> = env.iter().map(|s| s.as_str()).collect();
    let (sp, stack_lo, stack_hi) = elf::build_stack(&img, interp_base, &argv, &env)?;
    if syscall::debug() {
        eprintln!("[lx] {exe}: {} syscall sites patched{}", img.syscall_sites,
            img.interp.as_deref().map(|i| format!(", interpreter {i}")).unwrap_or_default());
    }

    // Linux _start ABI: rsp -> argc, rdx = atexit fn (none), everything else zero; IF set in rflags.
    let mut regs = [0u64; 18];
    (regs[4], regs[16], regs[17]) = (sp, entry, 0x202);
    syscall::enter(regs, stack_lo, stack_hi)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("lx: {e}");
        process::exit(127);
    }
}
