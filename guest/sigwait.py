import os, signal, threading, time
signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1, signal.SIGUSR2})
threading.Timer(0.2, lambda: os.kill(os.getpid(), signal.SIGUSR2)).start()
assert signal.sigwait({signal.SIGUSR1, signal.SIGUSR2}) == signal.SIGUSR2
os.kill(os.getpid(), signal.SIGUSR1)
i = signal.sigwaitinfo({signal.SIGUSR1}); assert i.si_signo == signal.SIGUSR1, i
t0 = time.time(); assert signal.sigtimedwait({signal.SIGUSR1}, 0.3) is None and time.time() - t0 >= 0.29
print("OK")
