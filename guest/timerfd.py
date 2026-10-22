# timerfd through libc: one-shot, periodic (expirations add up), poll readiness, gettime, disarm.
import ctypes, os, select, struct, time
libc = ctypes.CDLL(None, use_errno=True)
class ts(ctypes.Structure): _fields_ = [("s", ctypes.c_long), ("ns", ctypes.c_long)]
class its(ctypes.Structure): _fields_ = [("interval", ts), ("value", ts)]
def arm(fd, value, interval=0.0):
    t = its(ts(int(interval), int(interval % 1 * 1e9)), ts(int(value), int(value % 1 * 1e9)))
    assert libc.timerfd_settime(fd, 0, ctypes.byref(t), None) == 0, ctypes.get_errno()
fd = libc.timerfd_create(1, os.O_CLOEXEC)        # CLOCK_MONOTONIC
assert fd >= 0, ctypes.get_errno()
t0 = time.monotonic(); arm(fd, 0.05)
assert select.select([fd], [], [], 2)[0] == [fd]
assert struct.unpack("Q", os.read(fd, 8))[0] == 1 and 0.04 <= time.monotonic() - t0 < 1
arm(fd, 0.02, 0.02); time.sleep(0.2)              # periodic: ~10 expirations by now
n = struct.unpack("Q", os.read(fd, 8))[0]; assert 5 <= n <= 12, n
cur = its(); libc.timerfd_gettime(fd, ctypes.byref(cur)); assert cur.interval.ns == 20_000_000, cur.interval.ns
arm(fd, 0); assert select.select([fd], [], [], 0.1)[0] == [], "disarmed timer fired"
print("OK")
