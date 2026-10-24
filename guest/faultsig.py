# A child that faults dies of the signal (WIFSIGNALED), not with exit code 139.
import ctypes, os, signal
pid = os.fork()
if pid == 0:
    ctypes.string_at(16, 1)  # read from an unmapped address
    os._exit(0)
_, st = os.waitpid(pid, 0)
print("signaled", os.WIFSIGNALED(st), "sig", os.WTERMSIG(st) if os.WIFSIGNALED(st) else os.WEXITSTATUS(st))
