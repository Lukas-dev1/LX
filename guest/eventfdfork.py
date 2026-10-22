# An eventfd made before fork is still an eventfd in the child: its fd number isn't handed to the
# child's next file (curl's wakeups once landed in pacman's download that way).
import os

efd = os.eventfd(0, os.EFD_NONBLOCK)
os.eventfd_write(efd, 2)
pid = os.fork()
if pid == 0:
    f = os.open("/tmp/out", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    ok = f != efd
    os.eventfd_write(efd, 1)          # must not reach the file
    os.write(f, b"data")
    os.close(f)
    os._exit(0 if ok and os.eventfd_read(efd) == 3 else 1)
_, status = os.waitpid(pid, 0)
assert os.waitstatus_to_exitcode(status) == 0, status
assert open("/tmp/out", "rb").read() == b"data"
print("eventfd fork OK")
