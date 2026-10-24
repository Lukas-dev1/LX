# MAP_FIXED_NOREPLACE: placed exactly at a free address, EEXIST over an existing mapping.
import ctypes, errno
libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
RW, PRIV_ANON, NOREPLACE = 3, 0x22, 0x100000
p = libc.mmap(None, 8192, RW, PRIV_ANON, -1, 0)
over = libc.mmap(p + 4096, 4096, RW, PRIV_ANON | NOREPLACE, -1, 0)
free = 0x300000000000
q = libc.mmap(free, 4096, RW, PRIV_ANON | NOREPLACE, -1, 0)
print("over", errno.errorcode[ctypes.get_errno()] if over in (None, 2**64 - 1) else "mapped",
      "free", "exact" if q == free else hex(q or 0))
