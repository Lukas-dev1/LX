# accept fails at once on a socket that isn't listening (EINVAL) or can't (UDP: EOPNOTSUPP); listeners
# (TCP, AF_UNIX, and one inherited by a forked child) still accept.
import errno, os, socket
out = []
for name, s in [("unlistened", socket.socket()), ("udp", socket.socket(socket.AF_INET, socket.SOCK_DGRAM))]:
    try:
        s.accept()
        out.append(name + " ok")
    except OSError as e:
        out.append(name + " " + errno.errorcode[e.errno])
for fam, addr in [(socket.AF_INET, ("127.0.0.1", 0)), (socket.AF_UNIX, "/tmp/sock")]:
    l = socket.socket(fam); l.bind(addr); l.listen()
    pid = os.fork()
    if pid == 0:
        c, _ = l.accept(); c.sendall(b"x"); os._exit(0)
    c = socket.socket(fam); c.connect(l.getsockname()); os.waitpid(pid, 0)
    out.append("%s %s" % ("unix" if fam == socket.AF_UNIX else "tcp", c.recv(1).decode()))
print(", ".join(out))
