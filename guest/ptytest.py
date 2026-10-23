# A pseudo terminal: openpty both ways (ONLCR, ICRNL, ECHO), then pty.fork with a child that reads a line.
import os, pty

m, s = os.openpty()
assert os.isatty(s) and os.isatty(m)
os.write(s, b"hi\n")
assert os.read(m, 100) == b"hi\r\n"
os.write(m, b"abc\r")
assert os.read(s, 100) == b"abc\n"
assert os.read(m, 100) == b"abc\r\n"  # ECHO
os.close(s)
os.close(m)

pid, fd = pty.fork()
if pid == 0:
    line = input()
    os.write(1, b"child read " + line.encode() + b"\n")
    os._exit(3)
os.write(fd, b"typed\r")
out = b""
while True:
    try:
        d = os.read(fd, 1024)
    except OSError:  # EIO: the child hung up
        break
    if not d:
        break
    out += d
assert b"child read typed\r\n" in out, out
assert os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]) == 3

# ISIG: ^C typed at the terminal is SIGINT to the child reading it.
pid, fd = pty.fork()
if pid == 0:
    os.read(0, 10)
    os._exit(0)
os.write(fd, b"\x03")
assert os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]) == -2

# A child that handles SIGINT sees ^C as the signal, not as end of input, and reads on.
pid, fd = pty.fork()
if pid == 0:
    import signal
    signal.signal(signal.SIGINT, lambda *_: os.write(1, b"INT "))
    os.write(1, b"ready ")
    os._exit(len(os.read(0, 10)))
os.read(fd, 100)  # "ready ": the handler is set
os.write(fd, b"\x03")
os.read(fd, 100)  # "INT "
os.write(fd, b"ok\r")
assert os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]) == 3

# ^C goes to the whole process group: a grandchild sleeping in it dies of SIGINT too.
pid, fd = pty.fork()
if pid == 0:
    import signal, time
    r, w = os.pipe()
    g = os.fork()
    if g == 0:
        os.write(w, b"g")
        time.sleep(30)
        os._exit(0)
    os.read(r, 1)  # the grandchild runs
    signal.signal(signal.SIGINT, lambda *_: os._exit(100 + (os.waitpid(g, 0)[1] & 0x7f)))
    os.write(1, b"ready ")
    while True:
        os.read(0, 10)
os.read(fd, 100)
os.write(fd, b"\x03")
assert os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]) == 102
print("pty OK")
