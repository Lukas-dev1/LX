# A bad struct pointer is EFAULT (lx used to fault itself), and the argument checks around it hold.
import ctypes, errno
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.syscall.argtypes = [ctypes.c_long] * 5
BAD = 0x10  # never mapped

def call(*a):
    r = libc.syscall(*a, *[0] * (5 - len(a)))
    return "ok" if r >= 0 else errno.errorcode[ctypes.get_errno()]

hdr = (ctypes.c_uint32 * 2)(0x12345678, 0)
data = (ctypes.c_uint32 * 6)()
out = [
    "uname " + call(63, BAD),
    "sysinfo " + call(99, BAD),
    "pipe " + call(22, BAD),
    "sigprocmask oldset " + call(14, 0, 0, BAD, 8),
    "sigprocmask size " + call(14, 0, 0, 0, 4),
    "capget version " + call(125, ctypes.addressof(hdr), ctypes.addressof(data)) + " %#x" % hdr[0],
    "timerfd_gettime " + call(287, 999, 0),
]
print(", ".join(out))
