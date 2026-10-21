import os, signal, threading, time
got = []
signal.signal(signal.SIGUSR1, lambda s, f: got.append(threading.current_thread().name))
# 1. A worker blocks SIGUSR1 for itself only: the main thread's mask is untouched.
ready, done = threading.Event(), threading.Event()
def worker():
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
    ready.set(); done.wait()
    assert signal.SIGUSR1 in signal.pthread_sigmask(signal.SIG_BLOCK, set())
t = threading.Thread(target=worker, name="w"); t.start(); ready.wait()
assert signal.SIGUSR1 not in signal.pthread_sigmask(signal.SIG_BLOCK, set()), "worker's mask leaked into main"
os.kill(os.getpid(), signal.SIGUSR1); time.sleep(0.1)
assert got == ["MainThread"], got
done.set(); t.join()
# 2. A new thread inherits its creator's mask; fork keeps the forking thread's mask.
signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
seen = []
t = threading.Thread(target=lambda: seen.append(signal.SIGUSR2 in signal.pthread_sigmask(signal.SIG_BLOCK, set()))); t.start(); t.join()
assert seen == [True], seen
pid = os.fork()
if pid == 0:
    os._exit(0 if signal.SIGUSR2 in signal.pthread_sigmask(signal.SIG_BLOCK, set()) else 1)
assert os.waitpid(pid, 0)[1] == 0, "fork lost the mask"
# 3. A blocked signal stays pending and arrives once unblocked.
os.kill(os.getpid(), signal.SIGUSR1)
got.clear(); signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1}); os.kill(os.getpid(), signal.SIGUSR1); time.sleep(0.05)
assert got == [], got
signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGUSR1}); time.sleep(0.05)
assert got == ["MainThread"], got
print("OK")
