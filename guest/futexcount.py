# FUTEX_WAKE reports how many it woke; a timed FUTEX_WAIT never ends early; bad words are EFAULT/EINVAL.
import ctypes, errno, threading, time
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.syscall.argtypes = [ctypes.c_long] * 7
word = ctypes.c_uint32(0)
a = ctypes.addressof(word)
def futex(addr, op, val, ts=0):
    r = libc.syscall(202, addr, op, val, ts, 0, 0)
    return r if r >= 0 else errno.errorcode[ctypes.get_errno()]
ts = (ctypes.c_long * 2)(0, 50_000_000)
t0 = time.monotonic()
waited = futex(a, 0, 0, ctypes.addressof(ts))
short = time.monotonic() - t0 < 0.05
ws = [threading.Thread(target=futex, args=(a, 0, 0)) for _ in range(3)]
[w.start() for w in ws]
time.sleep(0.3)
one = futex(a, 1, 1)
rest, deadline = 0, time.monotonic() + 10
while rest < 2 and time.monotonic() < deadline:  # under load a waiter may not be waiting yet
    rest += futex(a, 1, 10)
    time.sleep(0.05)
[w.join(5) for w in ws]
print("wait %s short %s, woke %s then %s, none %s, unmapped %s, odd %s" % (waited, short, one, rest, futex(a, 1, 1), futex(16, 1, 1), futex(a + 1, 1, 1)))
