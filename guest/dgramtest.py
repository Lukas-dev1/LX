"""AF_UNIX datagram sockets: path and abstract names, sender names, connect, fork. Prints OK."""
import os, socket

D = socket.AF_UNIX, socket.SOCK_DGRAM
for p in ("/tmp/dg.srv", "/tmp/dg.cli"):
    if os.path.exists(p):
        os.unlink(p)

srv = socket.socket(*D)
srv.bind("/tmp/dg.srv")
assert srv.getsockname() == "/tmp/dg.srv", srv.getsockname()

# An unnamed sender: the receiver sees no name.
c = socket.socket(*D)
c.sendto(b"one", "/tmp/dg.srv")
data, frm = srv.recvfrom(100)
assert (data, frm) == (b"one", None) or (data, frm) == (b"one", ""), (data, frm)

# A bound sender is named, and the reply finds it.
c2 = socket.socket(*D)
c2.bind("/tmp/dg.cli")
c2.sendto(b"two", "/tmp/dg.srv")
data, frm = srv.recvfrom(100)
assert (data, frm) == (b"two", "/tmp/dg.cli"), (data, frm)
srv.sendto(b"back", frm)
assert c2.recv(100) == b"back"

# Datagrams keep their boundaries.
c2.connect("/tmp/dg.srv")
assert c2.getpeername() == "/tmp/dg.srv"
c2.send(b"a")
c2.send(b"bc")
assert srv.recv(100) == b"a" and srv.recv(100) == b"bc"

# Abstract names.
ab = socket.socket(*D)
ab.bind("\0dgtest")
c.sendto(b"abs", "\0dgtest")
assert ab.recv(100) == b"abs"

# No such path.
try:
    c.sendto(b"x", "/tmp/nope")
    raise SystemExit("sendto a missing path succeeded")
except FileNotFoundError:
    pass

# A forked child keeps the socket a datagram AF_UNIX one.
# Only the child reads c2 and only the parent reads srv (a shared socket hands each datagram to one reader).
if os.fork() == 0:
    c2.send(b"child")
    data, frm = c2.recvfrom(100)  # the parent answers after it gets ours
    os._exit(0 if (data, frm) == (b"to child", "/tmp/dg.srv") else 1)
assert srv.recvfrom(100) == (b"child", "/tmp/dg.cli")
srv.sendto(b"to child", "/tmp/dg.cli")
_, status = os.wait()
assert status == 0, status
print("OK")
