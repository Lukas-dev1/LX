# fcntl owners and leases are kept per fd; flock wants exactly one operation; fsync of a pipe is EINVAL.
import errno, fcntl, os, struct
out = []
fd = os.open("/tmp/f", os.O_RDWR | os.O_CREAT, 0o644)
fcntl.fcntl(fd, fcntl.F_SETOWN, 7)
out.append("owner %d" % fcntl.fcntl(fd, fcntl.F_GETOWN))
F_SETOWN_EX, F_GETOWN_EX = 15, 16
fcntl.fcntl(fd, F_SETOWN_EX, struct.pack("ii", 1, 42))
out.append("owner_ex %s" % (struct.unpack("ii", fcntl.fcntl(fd, F_GETOWN_EX, bytes(8))),))
F_SETLEASE, F_GETLEASE = 1024, 1025
def err(f):
    try:
        f(); return "ok"
    except OSError as e:
        return errno.errorcode[e.errno]
out.append("rdlease on rdwr " + err(lambda: fcntl.fcntl(fd, F_SETLEASE, fcntl.F_RDLCK)))
ro = os.open("/tmp/f", os.O_RDONLY)
fcntl.fcntl(ro, F_SETLEASE, fcntl.F_RDLCK)
out.append("lease %d" % fcntl.fcntl(ro, F_GETLEASE))
out.append("flock both " + err(lambda: fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_EX)))
r, w = os.pipe()
out.append("fsync pipe " + err(lambda: os.fsync(w)))
print(", ".join(out))
