# A fork child closing its parent's (CLOEXEC) epoll after making its own keeps its own (postgres's
# background workers do exactly that).
import os, select
parent = select.epoll()  # EPOLL_CLOEXEC
pid = os.fork()
if pid == 0:
    mine = select.epoll()
    r, w = os.pipe()
    mine.register(r, select.EPOLLIN)
    os.close(parent.fileno())
    os.write(w, b"x")
    try:
        os._exit(0 if mine.poll(1) else 3)
    except OSError:
        os._exit(4)
_, st = os.waitpid(pid, 0)
print("child", os.WEXITSTATUS(st))
