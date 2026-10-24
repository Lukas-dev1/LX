# eventfd edges: writing u64 max is EINVAL, a full counter isn't writable, F_GETFL shows O_NONBLOCK.
import errno, fcntl, os, select
fd = os.eventfd(0, os.EFD_NONBLOCK)
out = []
try:
    os.eventfd_write(fd, 2**64 - 1)
except OSError as e:
    out.append("max " + errno.errorcode[e.errno])
os.eventfd_write(fd, 2**64 - 2)
out.append("full writable %s" % bool(select.select([], [fd], [], 0)[1]))
out.append("nonblock %s" % bool(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_NONBLOCK))
print(", ".join(out))
