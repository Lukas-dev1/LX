# mkfifo: stat shows a FIFO; a writer without a reader gets ENXIO when non-blocking; a reader waits for
# a writer (a forked child) and gets its data, then EOF.
import errno, os, stat, time

os.mkfifo("/tmp/ff", 0o600)
st = os.stat("/tmp/ff")
assert stat.S_ISFIFO(st.st_mode), oct(st.st_mode)
try:
    os.open("/tmp/ff", os.O_WRONLY | os.O_NONBLOCK)
    raise SystemExit("opened a FIFO for writing with no reader")
except OSError as e:
    assert e.errno == errno.ENXIO, e
if os.fork() == 0:
    time.sleep(0.3)
    fd = os.open("/tmp/ff", os.O_WRONLY)
    os.write(fd, b"through the fifo")
    os._exit(0)
fd = os.open("/tmp/ff", os.O_RDONLY)  # waits for the child
data = b""
while chunk := os.read(fd, 100):
    data += chunk
os.wait()
# A non-blocking reader (s6's fifodirs) polls quietly until a writer comes, then sees its data.
import select
r = os.open("/tmp/ff", os.O_RDONLY | os.O_NONBLOCK)
p = select.poll()
p.register(r, select.POLLIN)
quiet = p.poll(100)
w = os.open("/tmp/ff", os.O_WRONLY | os.O_NONBLOCK)
os.write(w, b"x")
ready = p.poll(1000)
assert quiet == [] and ready and ready[0][1] & select.POLLIN, (quiet, ready)
assert os.read(r, 10) == b"x"
print("fifo OK", oct(stat.S_IMODE(st.st_mode)), data.decode())
