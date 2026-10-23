# A MAP_SHARED file mapping longer than the file sees the file grow (bbolt maps ahead of its writes).
import ctypes, os

libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
fd = os.open("/tmp/grow", os.O_RDWR | os.O_CREAT | os.O_TRUNC)
os.write(fd, b"a" * 4096)
m = libc.mmap(None, 1 << 20, 1, 1, fd, 0)  # PROT_READ, MAP_SHARED
assert m not in (None, ctypes.c_void_p(-1).value), ctypes.get_errno()
os.pwrite(fd, b"b" * 4096, 200000)  # past the first view, far into the mapping
os.ftruncate(fd, 300000)
print("grown", ctypes.string_at(m, 1), ctypes.string_at(m + 200000, 1), ctypes.string_at(m + 299999, 1))
