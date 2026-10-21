//! lx: run a static x86-64 Linux ELF natively on NT. See DESIGN.md.
mod elf;
mod fs;
mod proc;
mod signal;
mod syscall;

use std::ffi::c_void;
use std::{env, path::Path, process};

// ponytail: hand-declared Win32 surface instead of windows-sys; switch when it outgrows one screen.
pub mod win {
    use std::ffi::c_void;
    pub const MEM_COMMIT: u32 = 0x1000;
    pub const MEM_RESERVE: u32 = 0x2000;
    pub const MEM_COMMIT_RESERVE: u32 = 0x3000;
    pub const MEM_DECOMMIT: u32 = 0x4000;
    pub const PAGE_READWRITE: u32 = 0x04;

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
        pub fn PeekNamedPipe(h: isize, buf: *mut c_void, len: u32, read: *mut u32, avail: *mut u32, left: *mut u32) -> i32;
        pub fn DuplicateHandle(sp: isize, h: isize, tp: isize, out: *mut isize, access: u32, inherit: i32, opts: u32) -> i32;
        pub fn ReadProcessMemory(p: isize, from: *const c_void, to: *mut c_void, len: usize, done: *mut usize) -> i32;
    }
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        pub fn BCryptGenRandom(alg: *mut c_void, buf: *mut u8, len: u32, flags: u32) -> i32;
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
fn enter_job() -> Result<(), String> {
    const LIMIT_PROCESS_MEMORY: u32 = 0x100;
    const KILL_ON_JOB_CLOSE: u32 = 0x2000;
    let limits = JobLimits {
        flags: LIMIT_PROCESS_MEMORY | KILL_ON_JOB_CLOSE,
        process_memory: 512 << 20,
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

const USAGE: &str = "usage: lx <rootfs-dir> <command> [args...]\n       lx unpack <layer.tar.gz> <rootfs-dir>";
const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

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
    let [rootfs, cmd, rest @ ..] = args.as_slice() else { return Err(USAGE.into()) };
    let root = std::fs::canonicalize(rootfs).map_err(|e| format!("{rootfs}: {e}"))?;
    fs::init(root);
    let env = vec![format!("PATH={PATH}"), "HOME=/root".into(), "HOSTNAME=lx".into()];
    start(cmd, std::iter::once(cmd).chain(rest).cloned().collect(), env)
}

/// Load `cmd` (and its ELF interpreter, or its #! interpreter) and jump into it. Never returns on success.
fn start(cmd: &str, mut argv: Vec<String>, env: Vec<String>) -> Result<(), String> {
    let not_found = |e: i64| format!("{cmd}: {}", if e == syscall::EACCES { "permission denied" } else { "not found in image" });
    let (mut exe, mut image) = fs::find_exe(cmd, PATH).map_err(not_found)?;
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
        (exe, image) = fs::find_exe(&interp, PATH).map_err(|_| format!("{exe}: bad interpreter {interp}"))?;
    }

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
