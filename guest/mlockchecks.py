# mlockall and mlock2 check their flags; mlock of a never-mapped range is ENOMEM.
import ctypes, errno
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.syscall.argtypes = [ctypes.c_long] * 4
def call(*a):
    r = libc.syscall(*a, *[0] * (4 - len(a)))
    return "ok" if r >= 0 else errno.errorcode[ctypes.get_errno()]
buf = ctypes.create_string_buffer(4096)
print("mlockall 0", call(151, 0), "mlockall cur", call(151, 1), "mlock2 flag", call(325, ctypes.addressof(buf), 4096, 2),
      "mlock unmapped", call(149, 0x7f0000000000, 4096), "mlock", call(149, ctypes.addressof(buf), 4096))
