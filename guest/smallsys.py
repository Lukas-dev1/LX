# arch_prctl: ARCH_GET_FS answers, unknown codes (CET status) are EINVAL; mlock and friends succeed.
import ctypes, errno

libc = ctypes.CDLL(None, use_errno=True)
fs = ctypes.c_uint64()
assert libc.syscall(158, 0x1003, ctypes.byref(fs)) == 0 and fs.value, fs.value
buf = (ctypes.c_uint64 * 3)()
assert libc.syscall(158, 0x3001, buf) == -1 and ctypes.get_errno() == errno.EINVAL, ctypes.get_errno()
page = ctypes.create_string_buffer(4096)
assert libc.mlock(page, 4096) == 0 and libc.munlock(page, 4096) == 0
assert libc.mlockall(3) == 0 and libc.munlockall() == 0
print("small syscalls OK")
