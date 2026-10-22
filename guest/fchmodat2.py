# fchmodat2 (452), as musl's fchmodat makes it: by path, and on the dirfd itself with AT_EMPTY_PATH.
import ctypes, os, stat

libc = ctypes.CDLL(None, use_errno=True)
AT_FDCWD, AT_EMPTY_PATH = -100, 0x1000
open("/tmp/f", "w").close()
assert libc.syscall(452, AT_FDCWD, b"/tmp/f", 0o640, 0) == 0, ctypes.get_errno()
a = stat.S_IMODE(os.stat("/tmp/f").st_mode)
fd = os.open("/tmp/f", os.O_RDONLY)
assert libc.syscall(452, fd, b"", 0o604, AT_EMPTY_PATH) == 0, ctypes.get_errno()
b = stat.S_IMODE(os.stat("/tmp/f").st_mode)
print(f"fchmodat2 {a:o} {b:o}")
