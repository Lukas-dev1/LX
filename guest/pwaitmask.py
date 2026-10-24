# ppoll waits under its sigmask: a signal it blocks doesn't end the wait (it's handled after), one it
# unblocks does, and the thread's own mask is back afterwards.
import ctypes, errno, os, signal, time
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.syscall.argtypes = [ctypes.c_long] * 6
got = []
signal.signal(signal.SIGUSR1, lambda *_: got.append(1))

def ppoll(mask, secs):
    ts = (ctypes.c_long * 2)(secs, 0)
    m = ctypes.c_uint64(mask)
    r = libc.syscall(271, 0, 0, ctypes.addressof(ts), ctypes.addressof(m), 8, 0)
    return "timeout" if r == 0 else errno.errorcode[ctypes.get_errno()]

def kick():
    if os.fork() == 0:
        time.sleep(0.2); os.kill(os.getppid(), signal.SIGUSR1); os._exit(0)

out = []
kick()
r = ppoll(1 << (signal.SIGUSR1 - 1), 1)
os.wait()
out.append("blocked %s, handled after %d" % (r, len(got)))
signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGUSR1])
kick()
r = ppoll(0, 5)
os.wait()
out.append("unblocked %s, handled %d, mask back %s" % (r, len(got), signal.SIGUSR1 in signal.pthread_sigmask(signal.SIG_BLOCK, [])))
print(", ".join(out))
