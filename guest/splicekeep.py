# splice from a socket into a non-blocking pipe loses nothing, even when the pipe fills (Go's TCP->TCP splice).
import hashlib, os, socket, threading
N = 3 << 20
data = os.urandom(N)
a, b = socket.socketpair()
r, w = os.pipe()
os.set_blocking(w, False)
threading.Thread(target=lambda: a.sendall(data), daemon=True).start()
got = bytearray()
def drain():
    while len(got) < N:
        got.extend(os.read(r, 1 << 16))
t = threading.Thread(target=drain); t.start()
moved = 0
while moved < N:
    try:
        moved += os.splice(b.fileno(), w, N - moved, flags=os.SPLICE_F_NONBLOCK)
    except BlockingIOError:
        pass
t.join(30)
print("moved", moved == N, "intact", hashlib.sha1(got).digest() == hashlib.sha1(data).digest())
