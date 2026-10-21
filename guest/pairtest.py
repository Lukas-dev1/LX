"""socketpair: stream and datagram pairs, across fork, and multiprocessing.Pipe on top. Prints OK."""
import multiprocessing as mp, os, socket

a, b = socket.socketpair()
assert a.family == socket.AF_UNIX
if os.fork() == 0:  # more than any socket buffer: a writer process, the reader drains as it goes
    b.close()
    a.sendall(b"x" * 1_000_000)
    a.shutdown(socket.SHUT_WR)
    os._exit(0)
a.close()
got = bytearray()
while chunk := b.recv(65536):
    got += chunk
os.wait()
assert len(got) == 1_000_000, len(got)

# Datagram pairs keep message boundaries.
x, y = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
x.send(b"a")
x.send(b"bc")
assert y.recv(100) == b"a" and y.recv(100) == b"bc"
y.send(b"back")
assert x.recv(100) == b"back"

# Each side of a fork keeps its end.
p, c = socket.socketpair()
if os.fork() == 0:
    p.close()
    c.sendall(c.recv(100).upper())
    os._exit(0)
c.close()
p.sendall(b"ping")
assert p.recv(100) == b"PING"
os.wait()


def child(conn):
    conn.send(conn.recv() * 2)


if __name__ == "__main__":
    mp.set_start_method("fork")
    here, there = mp.Pipe()
    w = mp.Process(target=child, args=(there,))
    w.start()
    here.send([1, 2])
    assert here.recv() == [1, 2, 1, 2]
    w.join()
    assert w.exitcode == 0
    print("OK")
