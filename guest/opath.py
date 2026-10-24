# An O_PATH fd names a file without opening it: read and write are EBADF, fstat and fchdir work.
import errno, os
open("/tmp/f", "w").write("data")
fd = os.open("/tmp/f", os.O_PATH | os.O_CREAT | os.O_TRUNC)
out = []
for name, op in [("read", lambda: os.read(fd, 1)), ("write", lambda: os.write(fd, b"x"))]:
    try:
        op()
        out.append(name + " ok")
    except OSError as e:
        out.append(name + " " + errno.errorcode[e.errno])
out.append("size %d" % os.fstat(fd).st_size)  # O_TRUNC is ignored with O_PATH
d = os.open("/tmp", os.O_PATH | os.O_DIRECTORY)
os.fchdir(d)
out.append(os.getcwd())
print(", ".join(out))
