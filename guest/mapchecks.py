# mmap and friends reject what Linux rejects: the fd's access mode, bad fds, misaligned or unknown arguments.
import ctypes, errno, os
libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
for f in (libc.munmap, libc.msync):
    f.argtypes = [ctypes.c_void_p, ctypes.c_size_t] + ([ctypes.c_int] if f is libc.msync else [])
libc.syscall.restype = ctypes.c_long
libc.syscall.argtypes = [ctypes.c_long] * 6
libc.sendfile.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
PROT_READ, PROT_WRITE, MAP_SHARED, MAP_PRIVATE, MAP_ANON = 1, 2, 1, 2, 0x20

def err(r):
    return "ok" if r not in (-1, 2**64 - 1, None) else errno.errorcode[ctypes.get_errno()]

open("/tmp/f", "wb").write(b"x" * 4096)
ro, wo = os.open("/tmp/f", os.O_RDONLY), os.open("/tmp/f", os.O_WRONLY)
r, w = os.pipe()
out = [
    "shared write on rdonly " + err(libc.mmap(None, 4096, PROT_WRITE, MAP_SHARED, ro, 0)),
    "read on wronly " + err(libc.mmap(None, 4096, PROT_READ, MAP_PRIVATE, wo, 0)),
    "private write on rdonly " + err(libc.mmap(None, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, ro, 0)),
    "bad fd " + err(libc.mmap(None, 4096, PROT_READ, MAP_SHARED, 99, 0)),
    "pipe " + err(libc.mmap(None, 4096, PROT_READ, MAP_PRIVATE, r, 0)),
    "no type " + err(libc.mmap(None, 4096, PROT_READ, MAP_ANON, -1, 0)),
]
p = libc.mmap(None, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0)
out += [
    "munmap odd " + err(libc.munmap(p + 1, 4096)),
    "munmap 0 " + err(libc.munmap(p, 0)),
    "msync both " + err(libc.msync(p, 4096, 1 | 4)),
    "msync odd " + err(libc.msync(p + 1, 4096, 4)),
    # mremap(p, 4096, 4096, MREMAP_FIXED, p + 4096) without MREMAP_MAYMOVE
    "mremap fixed " + err(libc.syscall(25, p, 4096, 4096, 2, p + 4096)),
    "sendfile to rdonly " + err(libc.sendfile(ro, ro, None, 0)),
]
huge = libc.mmap(None, 2**64 - 4096, PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0)
out.append("huge " + err(huge) + ", after " + err(libc.mmap(None, 4096, PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0)))
print(", ".join(out))
