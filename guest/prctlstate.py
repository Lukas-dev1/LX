# prctl keeps what it's told (thread name, pdeathsig, dumpable, timerslack, no_new_privs), checks its
# arguments; personality and the nice value are kept too.
import ctypes, errno, os, threading
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
libc.personality.argtypes = [ctypes.c_ulong]
def prctl(*a):
    r = libc.prctl(*a, *[0] * (5 - len(a)))
    return r if r >= 0 else errno.errorcode[ctypes.get_errno()]
name = ctypes.create_string_buffer(16)
new_name = ctypes.create_string_buffer(b"worker-thread-name")
prctl(15, ctypes.addressof(new_name))
prctl(16, ctypes.addressof(name))
sig = ctypes.c_int(0)
prctl(1, 10); prctl(2, ctypes.addressof(sig))
other = []
t = threading.Thread(target=lambda: (prctl(16, ctypes.addressof(n2 := ctypes.create_string_buffer(16))), other.append(n2.value)))
t.start(); t.join()
out = ["name %s" % name.value.decode(), "other thread %s" % (other[0] != name.value), "pdeathsig %d" % sig.value,
       "bad sig " + str(prctl(1, 99)), "dumpable 2 " + str(prctl(4, 2)), "slack " + str((prctl(29, 1000), prctl(30))[1]),
       "nnp " + str((prctl(38, 1), prctl(39))[1]), "option 999 " + str(prctl(999, 1)),
       "personality %#x" % (libc.personality(0x0040000), libc.personality(0xffffffff))[1]]
os.nice(5)
out.append("nice %d, lower " % os.getpriority(os.PRIO_PROCESS, 0))
try:
    os.setpriority(os.PRIO_PROCESS, 0, 0)
    out[-1] = out[-1].replace("lower ", "lower ok")
except OSError as e:
    out[-1] = out[-1].replace("lower ", "lower " + errno.errorcode[e.errno])
print(", ".join(out))
