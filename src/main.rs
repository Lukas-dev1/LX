//! lx: run a static x86-64 Linux ELF natively on NT. See DESIGN.md.
mod elf;
mod syscall;

use std::ffi::c_void;
use std::{env, fs, path::Path, process};

// ponytail: hand-declared Win32 surface instead of windows-sys; switch when it outgrows one screen.
pub mod win {
    use std::ffi::c_void;
    pub const MEM_COMMIT_RESERVE: u32 = 0x3000;
    pub const PAGE_READWRITE: u32 = 0x04;

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
        pub fn AddVectoredExceptionHandler(
            first: u32,
            h: unsafe extern "system" fn(*mut ExceptionPointers) -> i32,
        ) -> *mut c_void;
        pub fn GetStdHandle(n: u32) -> isize;
        pub fn WriteFile(h: isize, buf: *const u8, len: u32, done: *mut u32, ov: *mut c_void) -> i32;
        pub fn ReadFile(h: isize, buf: *mut u8, len: u32, done: *mut u32, ov: *mut c_void) -> i32;
        pub fn GetLastError() -> u32;
        pub fn ExitProcess(code: u32) -> !;
        pub fn CreateJobObjectW(attr: *mut c_void, name: *const u16) -> isize;
        pub fn SetInformationJobObject(job: isize, class: u32, info: *const c_void, len: u32) -> i32;
        pub fn AssignProcessToJobObject(job: isize, process: isize) -> i32;
        pub fn GetCurrentProcess() -> isize;
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

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let [rootfs, guest, ..] = args.as_slice() else {
        return Err("usage: lx <rootfs-dir> </path/in/rootfs> [args...]".into());
    };
    let root = fs::canonicalize(rootfs).map_err(|e| format!("{rootfs}: {e}"))?;
    let host = fs::canonicalize(root.join(guest.trim_start_matches('/')))
        .map_err(|e| format!("{guest}: {e}"))?;
    if !host.starts_with(&root) {
        return Err(format!("{guest} escapes the rootfs"));
    }
    let image = fs::read(&host).map_err(|e| format!("{}: {e}", host.display()))?;

    enter_job()?;
    let img = elf::load(&image)?;
    syscall::install(&img);
    let argv: Vec<&str> = std::iter::once(guest.as_str()).chain(args[2..].iter().map(|s| s.as_str())).collect();
    let sp = elf::build_stack(&img, &argv, &["PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/"])?;
    let name = Path::new(guest).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    eprintln!("[lx] {name}: entry {:#x}, {} syscall sites patched", img.entry, img.syscall_sites.len());

    // Linux _start ABI: rsp -> argc, rdx = atexit fn (none). Never returns: exit_group ends the process.
    unsafe {
        std::arch::asm!("mov rsp, {sp}", "jmp {entry}",
            sp = in(reg) sp, entry = in(reg) img.entry, in("rdx") 0u64, options(noreturn))
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("lx: {e}");
        process::exit(127);
    }
}
