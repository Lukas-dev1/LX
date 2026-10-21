//! lx: run a static x86-64 Linux ELF natively on NT. See DESIGN.md.
mod elf;
mod fs;
mod syscall;

use std::ffi::c_void;
use std::{env, path::Path, process};

// ponytail: hand-declared Win32 surface instead of windows-sys; switch when it outgrows one screen.
pub mod win {
    use std::ffi::c_void;
    pub const MEM_COMMIT: u32 = 0x1000;
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

const USAGE: &str = "usage: lx <rootfs-dir> <command> [args...]\n       lx unpack <layer.tar.gz> <rootfs-dir>";
const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if let [cmd, tgz, dest] = args.as_slice() && cmd == "unpack" {
        let (n, skipped) = fs::unpack(Path::new(tgz), Path::new(dest))?;
        eprintln!("[lx] unpacked {n} entries ({skipped} skipped) into {dest}");
        return Ok(());
    }
    let [rootfs, cmd, rest @ ..] = args.as_slice() else { return Err(USAGE.into()) };
    let root = std::fs::canonicalize(rootfs).map_err(|e| format!("{rootfs}: {e}"))?;
    fs::init(root);
    let (exe, image) = fs::find_exe(cmd, PATH)?;

    enter_job()?;
    syscall::install();
    let img = elf::load(&image)?;
    // Dynamically linked: the kernel's job is to map ld.so too and start there; ld.so maps the rest via mmap.
    let (entry, interp_base) = match &img.interp {
        Some(ld) => {
            let ld = elf::load(&fs::find_exe(ld, "/")?.1)?;
            (ld.entry, ld.base)
        }
        None => (img.entry, 0),
    };
    // argv[0] is what the user typed (busybox picks its applet from it); the image may live elsewhere.
    let argv: Vec<&str> = std::iter::once(cmd.as_str()).chain(rest.iter().map(|s| s.as_str())).collect();
    let path_env = format!("PATH={PATH}");
    let sp = elf::build_stack(&img, interp_base, &argv, &[&path_env, "HOME=/root", "HOSTNAME=lx"])?;
    eprintln!("[lx] {exe}: {} syscall sites patched{}", img.syscall_sites,
        img.interp.as_deref().map(|i| format!(", interpreter {i}")).unwrap_or_default());

    // Linux _start ABI: rsp -> argc, rdx = atexit fn (none). Never returns: exit_group ends the process.
    unsafe {
        std::arch::asm!("mov rsp, {sp}", "jmp {entry}",
            sp = in(reg) sp, entry = in(reg) entry, in("rdx") 0u64, options(noreturn))
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("lx: {e}");
        process::exit(127);
    }
}
