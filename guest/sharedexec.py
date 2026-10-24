# MAP_SHARED with PROT_EXEC works on a file and on a memfd (.NET's W^X double mapping does the latter).
import mmap, os
out = []
open("/tmp/f", "wb").write(b"\xc3" * 4096)  # ret
for name, fd, prot in [("file", os.open("/tmp/f", os.O_RDONLY), mmap.PROT_READ | mmap.PROT_EXEC),
                       ("memfd", os.memfd_create("jit"), mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)]:
    if name == "memfd":
        os.ftruncate(fd, 4096)
    try:
        m = mmap.mmap(fd, 4096, mmap.MAP_SHARED, prot)
        out.append("%s ok %02x" % (name, m[0] if name == "file" else 0))
    except OSError as e:
        out.append("%s %s" % (name, e.strerror))
print(", ".join(out))
# CoreCLR's double mapping: a PROT_NONE shared view of a memfd, later made executable with mprotect.
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
fd = os.memfd_create("dbl")
os.ftruncate(fd, 1 << 34)  # a 16 GB reserve, as CoreCLR makes
rw = libc.mmap(None, 4096, 3, 1, fd, 0)
ctypes.memmove(rw, b"\xb8\x2a\x00\x00\x00\xc3", 6)  # mov eax, 42; ret
rx = libc.mmap(None, 4096, 0, 1, fd, 0)
r = libc.mprotect(rx, 4096, 5)
print("mprotect", r, "call", ctypes.CFUNCTYPE(ctypes.c_int)(rx)() if r == 0 else "-")
