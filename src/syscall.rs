//! Syscall interception + Linux TLS (FS base) emulation, both driven by one vectored exception handler.
//!
//! - `syscall` sites were rewritten to `ud2` by the loader; the #UD lands here and is dispatched.
//! - NT resets FS base to 0 on context switches, so a guest `%fs:` access faults (low/kernel address).
//!   We bounce through `fs_tramp`, which reloads FS base in user mode and resumes the faulting instruction.
//!   Every return to the guest goes through the trampoline, because NtContinue also loses FS base.
use crate::elf::Image;
use crate::win::*;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

// ponytail: one guest thread, so plain globals. Move to TEB TLS slots (gs:[0x1480+8*i]) when clone() lands.
#[unsafe(no_mangle)]
static LX_GUEST_FS: AtomicU64 = AtomicU64::new(0);
#[unsafe(no_mangle)]
static LX_RESUME_RIP: AtomicU64 = AtomicU64::new(0);
static FS_RELOADS: AtomicU64 = AtomicU64::new(0);
static IMAGE: OnceLock<(u64, u64, Vec<u64>)> = OnceLock::new();

// Clobbers nothing the guest can see: skips the 128-byte red zone, touches only rax (restored).
// wrfsbase is emitted as bytes so we don't need the fsgsbase target feature.
std::arch::global_asm!(
    ".globl lx_fs_tramp",
    "lx_fs_tramp:",
    "lea rsp, [rsp - 128]",
    "push rax",
    "mov rax, qword ptr [rip + LX_GUEST_FS]",
    ".byte 0xf3, 0x48, 0x0f, 0xae, 0xd0", // wrfsbase rax
    "pop rax",
    "lea rsp, [rsp + 128]",
    "jmp qword ptr [rip + LX_RESUME_RIP]",
);
unsafe extern "C" {
    fn lx_fs_tramp();
}

const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;

const ENOTTY: i64 = 25;
const EBADF: i64 = 9;
const EINVAL: i64 = 22;
const EIO: i64 = 5;
const ENOSYS: i64 = 38;

pub fn install(img: &Image) {
    IMAGE.set((img.lo, img.hi, img.syscall_sites.clone())).ok();
    unsafe { AddVectoredExceptionHandler(1, veh) };
}

fn resume(c: &mut Context, rip: u64) -> i32 {
    LX_RESUME_RIP.store(rip, Relaxed);
    c.rip = lx_fs_tramp as *const () as u64;
    EXCEPTION_CONTINUE_EXECUTION
}

unsafe extern "system" fn veh(ep: *mut ExceptionPointers) -> i32 {
    let (rec, c) = unsafe { (&*(*ep).record, &mut *(*ep).context) };
    let Some((lo, hi, sites)) = IMAGE.get() else { return EXCEPTION_CONTINUE_SEARCH };
    if !(*lo..*hi).contains(&c.rip) {
        return EXCEPTION_CONTINUE_SEARCH; // not guest code: our own bug, let it crash normally
    }
    match rec.code {
        STATUS_ILLEGAL_INSTRUCTION if sites.binary_search(&c.rip).is_ok() => {
            let ret = dispatch(c);
            let next = c.rip + 2;
            (c.rax, c.rcx, c.r11) = (ret as u64, next, c.eflags as u64); // kernel ABI: rcx=rip, r11=rflags
            resume(c, next)
        }
        STATUS_ACCESS_VIOLATION if LX_GUEST_FS.load(Relaxed) != 0 && lost_fs_base(c, rec.info[1] as u64, *hi) => {
            FS_RELOADS.fetch_add(1, Relaxed);
            resume(c, c.rip)
        }
        _ => guest_crash(rec, c),
    }
}

/// Did this fault come from a `%fs:` access executed with NT's zeroed FS base (rather than a real bug)?
/// Exact: recompute the operand address with FS base 0 and compare with the faulting address.
fn lost_fs_base(c: &Context, fault_addr: u64, image_end: u64) -> bool {
    use iced_x86::{Decoder, DecoderOptions, Register as R};
    let len = (image_end - c.rip).min(15) as usize;
    let bytes = unsafe { std::slice::from_raw_parts(c.rip as *const u8, len) };
    let ins = Decoder::with_ip(64, bytes, c.rip, DecoderOptions::NONE).decode();
    if ins.memory_segment() != R::FS {
        return false;
    }
    let reg = |r: R, _, _| {
        let v = match r.full_register() {
            R::RAX => c.rax, R::RCX => c.rcx, R::RDX => c.rdx, R::RBX => c.rbx,
            R::RSP => c.rsp, R::RBP => c.rbp, R::RSI => c.rsi, R::RDI => c.rdi,
            R::R8 => c.r8, R::R9 => c.r9, R::R10 => c.r10, R::R11 => c.r11,
            R::R12 => c.r12, R::R13 => c.r13, R::R14 => c.r14, R::R15 => c.r15,
            R::FS => 0,
            _ => return None,
        };
        Some(if r.size() == 4 { v as u32 as u64 } else { v })
    };
    (0..ins.op_count()).any(|op| ins.virtual_address(op, 0, reg) == Some(fault_addr))
}

fn guest_crash(rec: &ExceptionRecord, c: &Context) -> ! {
    eprintln!("[lx] guest fault {:#x} at rip {:#x} (addr {:#x})", rec.code, c.rip, rec.info[1]);
    unsafe { ExitProcess(139) } // 128 + SIGSEGV, like a shell would report
}

/// The dispatch table. Linux ABI: nr in rax, args rdi rsi rdx r10 r8 r9, result (or -errno) in rax.
fn dispatch(c: &mut Context) -> i64 {
    let (a0, a1, a2) = (c.rdi, c.rsi, c.rdx);
    match c.rax {
        0 => sys_read(a0, a1, a2),
        1 => sys_write(a0, a1 as *const u8, a2),
        16 => -ENOTTY, // ioctl: no terminals yet; musl just picks full buffering
        20 => sys_writev(a0, a1, a2),
        60 | 231 => {
            // exit, exit_group (single thread)
            eprintln!("[lx] exit {}, {} fs-base reloads", a0 as u8, FS_RELOADS.load(Relaxed));
            unsafe { ExitProcess(a0 as u32 & 0xff) }
        }
        158 if a0 == 0x1002 => { LX_GUEST_FS.store(a1, Relaxed); 0 } // arch_prctl(ARCH_SET_FS)
        218 => 1, // set_tid_address -> our tid is 1
        nr => {
            eprintln!("[lx] unimplemented syscall {nr} ({a0:#x}, {a1:#x}, {a2:#x})");
            -ENOSYS
        }
    }
}

fn std_handle(fd: u64) -> Option<isize> {
    // STD_INPUT/OUTPUT/ERROR_HANDLE = -10/-11/-12. ponytail: no fd table until open() exists.
    (fd <= 2).then(|| unsafe { GetStdHandle((-10i32 - fd as i32) as u32) })
}

// Guest buffers go straight to the NT kernel, which probes them: a bad pointer is an error, not a crash.
fn sys_write(fd: u64, buf: *const u8, len: u64) -> i64 {
    let Some(h) = std_handle(fd) else { return -EBADF };
    let mut done = 0u32;
    let len = len.min(u32::MAX as u64) as u32;
    if unsafe { WriteFile(h, buf, len, &mut done, std::ptr::null_mut()) } == 0 { -EIO } else { done as i64 }
}

fn sys_read(fd: u64, buf: u64, len: u64) -> i64 {
    let Some(h) = std_handle(fd) else { return -EBADF };
    let mut done = 0u32;
    let len = len.min(u32::MAX as u64) as u32;
    if unsafe { ReadFile(h, buf as *mut u8, len, &mut done, std::ptr::null_mut()) } != 0 {
        return done as i64;
    }
    if unsafe { GetLastError() } == 109 { 0 } else { -EIO } // ERROR_BROKEN_PIPE is EOF
}

fn sys_writev(fd: u64, iov: u64, cnt: u64) -> i64 {
    if cnt > 1024 { return -EINVAL; }
    let mut total = 0;
    for i in 0..cnt {
        // ponytail: the iovec array is read directly; a bad pointer crashes us instead of returning EFAULT.
        let [base, len] = unsafe { *((iov + i * 16) as *const [u64; 2]) };
        let n = sys_write(fd, base as *const u8, len);
        if n < 0 { return if total > 0 { total } else { n }; }
        total += n;
        if (n as u64) < len { break; }
    }
    total
}
