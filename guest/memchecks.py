# madvise, mincore and memfd_create check their arguments; MADV_DONTNEED on a shared file mapping works.
import ctypes, errno, mmap, os
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.syscall.argtypes = [ctypes.c_long] * 4
def call(*a):
    r = libc.syscall(*a, *[0] * (4 - len(a)))
    return "ok" if r >= 0 else errno.errorcode[ctypes.get_errno()]
m = mmap.mmap(-1, 8192)
a = ctypes.addressof(ctypes.c_char.from_buffer(m))
vec = ctypes.create_string_buffer(2)
long_name = ctypes.create_string_buffer(b"n" * 250)
open("/tmp/f", "wb").write(b"x" * 4096)
fm = mmap.mmap(os.open("/tmp/f", os.O_RDWR), 4096, mmap.MAP_SHARED)
fa = ctypes.addressof(ctypes.c_char.from_buffer(fm))
out = [
    "madvise odd " + call(28, a + 1, 4096, 4),
    "advice " + call(28, a, 4096, 1212),
    "unmapped " + call(28, 0x7f0000000000, 4096, 3),
    "shared dontneed " + call(28, fa, 4096, 4) + " " + fm[:1].decode(),
    "mincore odd " + call(27, a + 1, 4096, ctypes.addressof(vec)),
    "memfd long " + call(319, ctypes.addressof(long_name), 0),
]
print(", ".join(out))
