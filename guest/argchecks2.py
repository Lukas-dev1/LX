# CPU-time itimers keep their values; getrusage, getpriority and ioctl check their arguments.
import ctypes, errno, os, resource, signal
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.syscall.argtypes = [ctypes.c_long] * 4
def call(*a):
    r = libc.syscall(*a, *[0] * (4 - len(a)))
    return "ok" if r >= 0 else errno.errorcode[ctypes.get_errno()]
signal.setitimer(signal.ITIMER_PROF, 5, 1)
out = ["prof %s" % (signal.getitimer(signal.ITIMER_PROF),)]
signal.setitimer(signal.ITIMER_PROF, 0)
out.append("rusage who " + call(98, (-2) & 2**64 - 1, ctypes.addressof(ctypes.create_string_buffer(144))))
out.append("rusage buf " + call(98, 0, 16))
out.append("prio who " + call(140, 0, (-1) & 2**64 - 1))
r, w = os.pipe()
out.append("pipe winsz " + call(16, r, 0x5413, 16))
out.append("pipe fionread " + call(16, r, 0x541B, 16))
print(", ".join(out))
