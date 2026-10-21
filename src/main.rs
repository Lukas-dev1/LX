//! lx: run a static x86-64 Linux ELF natively on NT. See DESIGN.md.
mod elf;
mod fs;
mod jump;
mod image;
mod net;
mod proc;
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

fn enter_job() -> Result<(), String> {
    const LIMIT_PROCESS_MEMORY: u32 = 0x100;
    const KILL_ON_JOB_CLOSE: u32 = 0x2000;
    let limits = JobLimits {
        flags: LIMIT_PROCESS_MEMORY | KILL_ON_JOB_CLOSE,
        process_memory: memory_limit(),
        ..Default::default()
    };
    unsafe {
        // The handle is deliberately leaked: it closes at process exit, which kills the job.
        let job = win::CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
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
       lx ps                                 running containers
       lx stop <pid>                         SIGTERM, then SIGKILL after 10s
       lx kill <pid> [SIGNAL]                default TERM
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
    if let [cmd] = args.as_slice() && cmd == "ps" {
        println!("{:<8} COMMAND", "PID");
        for (pid, desc) in proc::ps() {
            println!("{pid:<8} {}", desc.split_whitespace().collect::<Vec<_>>().join(" ")); // one line per container
        }
        return Ok(());
    }
    if let [cmd, pid, rest @ ..] = args.as_slice() && (cmd == "kill" || cmd == "stop") {
        let pid: u32 = pid.parse().map_err(|_| format!("bad pid {pid}"))?;
        if cmd == "stop" {
            return proc::stop(pid, std::time::Duration::from_secs(10));
        }
        let sig = rest.first().map_or(Some(15), |s| signal::parse(s)).ok_or("unknown signal")?;
        return proc::send(pid, sig).map(|_| ()).map_err(|_| format!("{pid}: no such lx process"));
    }
    if let [cmd, rest @ ..] = args.as_slice() && cmd == "run" {
        // Flags before the image: -p/--publish [hostip:]hostport:containerport[/udp], repeatable.
        let (mut rest, mut ports) = (rest, Vec::new());
        let mut volumes = Vec::new();
        while let [flag, value, more @ ..] = rest {
            match flag.as_str() {
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
        let r = image::Ref::parse(image);
        let dir = if r.dir().join("config.json").exists() { r.dir() } else { image::pull(&r)? };
        let c = image::run_config(&dir, rest)?;
        let root = std::fs::canonicalize(dir.join("rootfs")).map_err(|e| e.to_string())?;
        // The container gets its own writable layer; the pulled image is never modified.
        // ponytail: removed when the container exits (like `docker run --rm`); no named, restartable containers yet.
        proc::gc_layers();
        let layer = proc::new_layer().map_err(|e| format!("creating the container layer: {e}"))?;
        fs::init(root);
        fs::set_upper(layer.join("upper"));
        // Like Docker: the container resolves names through the host's DNS servers.
        let (resolv, hosts) = net::dns_files();
        let _ = fs::write_guest_file("/etc/resolv.conf", resolv.as_bytes());
        let _ = fs::write_guest_file("/etc/hosts", hosts.as_bytes());
        let _ = fs::mkdir_guest("/dev/shm"); // POSIX shared memory and semaphores (glibc's sem_open) live here
        for (host, guest, ro) in volumes {
            fs::add_mount(&guest, host, ro).map_err(|_| format!("-v: can't mount at {guest}"))?;
        }
        fs::set_cwd(&c.workdir).map_err(|_| format!("WorkingDir {} not found in image", c.workdir))?;
        proc::register_container(&format!("{image}  {}", c.argv.join(" ")));
        return start(&c.argv[0], c.argv.clone(), c.env);
    }
    let [rootfs, cmd, rest @ ..] = args.as_slice() else { return Err(USAGE.into()) };
    let root = std::fs::canonicalize(rootfs).map_err(|e| format!("{rootfs}: {e}"))?;
    fs::init(root);
    let env = vec![format!("PATH={PATH}"), "HOME=/root".into(), "HOSTNAME=lx".into()];
    start(cmd, std::iter::once(cmd).chain(rest).cloned().collect(), env)
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
