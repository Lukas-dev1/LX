# sendfile with an offset pointer that isn't mapped is EFAULT, not a crash.
import ctypes, errno, os
libc = ctypes.CDLL(None, use_errno=True)
libc.sendfile.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
open("/tmp/in", "wb").write(b"abc")
i, o = os.open("/tmp/in", os.O_RDONLY), os.open("/tmp/out", os.O_WRONLY | os.O_CREAT, 0o644)
r = libc.sendfile(o, i, 8, 3)
print("sendfile", r, errno.errorcode.get(ctypes.get_errno(), "-") if r < 0 else "")
