# F_SETLK only reads its struct flock: one in read-only memory (a `static const`) locks fine.
import ctypes, mmap, os, struct
libc = ctypes.CDLL(None, use_errno=True)
libc.fcntl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
fd = os.open("/tmp/f", os.O_RDWR | os.O_CREAT, 0o644)
ro = mmap.mmap(-1, 4096)
ro.write(struct.pack("hhqqi", 1, 0, 0, 10, 0))  # F_WRLCK, SEEK_SET, start 0, len 10
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
addr = ctypes.addressof(ctypes.c_char.from_buffer(ro))
libc.mprotect(addr & ~4095, 4096, 1)  # PROT_READ
r = libc.fcntl(fd, 6, addr)  # F_SETLK
print("setlk", r, os.strerror(ctypes.get_errno()) if r else "")
