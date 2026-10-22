# seccomp: a filter making getcwd fail with EPERM applies here and in an exec'd child; others pass.
import ctypes, errno, os, struct, subprocess, sys

libc = ctypes.CDLL(None, use_errno=True)
AUDIT_ARCH_X86_64, SYS_getcwd = 0xC000003E, 79
def insn(code, jt, jf, k):
    return struct.pack("HBBI", code, jt, jf, k)
prog = b"".join([
    insn(0x20, 0, 0, 4),                      # A = arch
    insn(0x15, 1, 0, AUDIT_ARCH_X86_64),      # if A == x86_64 skip the kill
    insn(0x06, 0, 0, 0x80000000),             # KILL_PROCESS
    insn(0x20, 0, 0, 0),                      # A = nr
    insn(0x15, 0, 1, SYS_getcwd),             # if A == getcwd
    insn(0x06, 0, 0, 0x00050000 | errno.EPERM),  #   ERRNO(EPERM)
    insn(0x06, 0, 0, 0x7FFF0000),             # ALLOW
])
buf = ctypes.create_string_buffer(prog)
fprog = struct.pack("HxxxxxxQ", len(prog) // 8, ctypes.addressof(buf))
fbuf = ctypes.create_string_buffer(fprog)
assert libc.prctl(38, 1, 0, 0, 0) == 0                      # PR_SET_NO_NEW_PRIVS
assert libc.syscall(317, 1, 0, fbuf) == 0, ctypes.get_errno()  # SECCOMP_SET_MODE_FILTER
try:
    os.getcwd()
    raise SystemExit("getcwd still works")
except PermissionError:
    pass
child = subprocess.run([sys.executable, "-c", "import os\ntry: os.getcwd(); print('child free')\nexcept PermissionError: print('child filtered')"],
                       capture_output=True, text=True).stdout.strip()
avail = ctypes.c_uint32(0x7FFF0000)
assert libc.syscall(317, 2, 0, ctypes.byref(avail)) == 0     # SECCOMP_GET_ACTION_AVAIL(ALLOW)
print("seccomp OK", child, libc.prctl(21, 0, 0, 0, 0))      # PR_GET_SECCOMP: 2
