# Connecting or sending to the wildcard address reaches this host, as on Linux.
import socket
out = []
for fam, any_ in [(socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")]:
    l = socket.socket(fam); l.bind((any_, 0)); l.listen()
    c = socket.socket(fam); c.connect((any_, l.getsockname()[1]))
    a, _ = l.accept(); c.sendall(b"hi")
    u = socket.socket(fam, socket.SOCK_DGRAM); u.bind((any_, 0))
    socket.socket(fam, socket.SOCK_DGRAM).sendto(b"yo", (any_, u.getsockname()[1]))
    out.append("%s tcp %s udp %s" % (any_, a.recv(2).decode(), u.recv(2).decode()))
print(", ".join(out))
