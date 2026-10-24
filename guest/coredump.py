# A child killed by a core-dumping signal reports WCOREDUMP; one killed by SIGTERM doesn't.
import os, signal
out = []
for sig in (signal.SIGABRT, signal.SIGTERM):
    pid = os.fork()
    if pid == 0:
        signal.signal(sig, signal.SIG_DFL); os.kill(os.getpid(), sig); os._exit(0)
    _, st = os.waitpid(pid, 0)
    out.append("%s core %s" % (signal.Signals(sig).name, os.WCOREDUMP(st)))
print(", ".join(out))
