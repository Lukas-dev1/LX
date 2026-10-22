# dup'd fds share one handle; after fork or exec, closing one dup must leave the other working.
import os, socket, subprocess, sys
if len(sys.argv) > 1:
    os.close(int(sys.argv[1]))                  # exec'd child: close the original, use its dup
    s = socket.socket(fileno=int(sys.argv[2])); s.sendall(b"exec-ok"); sys.exit(0)
a, b = socket.socketpair()
r, w = os.pipe()
pid = os.fork()
if pid == 0:                                # forked child: dup, close the original, use the dup
    s2 = os.dup(b.fileno()); b.close(); os.write(s2, b"fork-ok")
    w2 = os.dup(w); os.close(w); os.write(w2, b"pipe-ok"); os._exit(0)
os.close(w)
assert a.recv(16) == b"fork-ok"
assert os.read(r, 16) == b"pipe-ok"
os.waitpid(pid, 0)
a2, b2 = socket.socketpair()
d = os.dup(b2.fileno())
p = subprocess.Popen([sys.executable, __file__, str(b2.fileno()), str(d)], pass_fds=[b2.fileno(), d])
b2.close(); os.close(d)
assert a2.recv(16) == b"exec-ok", "exec'd dup lost"
assert p.wait() == 0
assert a2.recv(16) == b"", "peer exit should read as EOF"
print("OK")
