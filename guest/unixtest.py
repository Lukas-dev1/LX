# AF_UNIX stream sockets under lx (glibc and musl): a threaded echo server on a filesystem path and on an
# abstract name, 10 clients each. Prints OK/FAIL.
import os, socket, threading

def serve(srv, n):
    for _ in range(n):
        c, _ = srv.accept()
        with c:
            c.sendall(c.recv(64).upper())

def run(addr, label):
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(addr)
    srv.listen(16)
    t = threading.Thread(target=serve, args=(srv, 10))
    t.start()
    got = []
    for i in range(10):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
            c.connect(addr)
            c.sendall(f"ping {i}".encode())
            got.append(c.recv(64).decode())
    t.join()
    srv.close()
    ok = got == [f"PING {i}" for i in range(10)]
    print(f"{label}: {len(got)}/10 echoes", "ok" if ok else f"bad: {got}")
    return ok

path = "/tmp/lx-unixtest.sock"
if os.path.exists(path):
    os.unlink(path)
ok = run(path, "path socket") & run("\0lx-unixtest", "abstract socket")
print("OK" if ok else "FAIL")
raise SystemExit(0 if ok else 1)
