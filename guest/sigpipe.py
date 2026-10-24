# A write to a pipe without a reader: EPIPE plus SIGPIPE, which kills a writer that keeps the default
# action (a producer whose consumer quit), and is ignored by Python itself (BrokenPipeError).
import os, signal

r, w = os.pipe()
os.close(r)
try:
    os.write(w, b"x")
    ignored = "no error"
except BrokenPipeError:
    ignored = "EPIPE"
pid = os.fork()
if pid == 0:
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    os.write(w, b"x")
    os._exit(0)
print(f"python {ignored}, default killed by {-os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])}")
