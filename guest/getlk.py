# F_GETLK names the holder of a conflicting lock: its type, range and pid (the first one by start).
import fcntl, os, struct

fd = os.open("/tmp/l", os.O_RDWR | os.O_CREAT)
os.write(fd, b"x" * 100)
fcntl.fcntl(fd, fcntl.F_SETLK, struct.pack("hhqqi", fcntl.F_WRLCK, 0, 10, 5, 0))
fcntl.fcntl(fd, fcntl.F_SETLK, struct.pack("hhqqi", fcntl.F_RDLCK, 0, 30, 3, 0))
r, w = os.pipe()
me = os.getpid()
pid = os.fork()
if pid == 0:
    t, _, s, l, holder = struct.unpack("hhqqi", fcntl.fcntl(fd, fcntl.F_GETLK, struct.pack("hhqqi", fcntl.F_WRLCK, 0, 8, 40, 0)))
    os.write(w, f"holder type={t} start={s} len={l} is_parent={holder == me}".encode())
    os._exit(0)
os.waitpid(pid, 0)
print(os.read(r, 200).decode())
