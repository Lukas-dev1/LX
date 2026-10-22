# SCM_RIGHTS: pass a pipe end and a file over a socketpair to a forked child, which uses them.
import array, os, socket, sys
a, b = socket.socketpair()
r, w = os.pipe()
f = open("/tmp/scm.txt", "w+"); f.write("from a file"); f.flush(); f.seek(0)
pid = os.fork()
if pid == 0:
    a.close()
    msg, anc, flags, _ = b.recvmsg(16, socket.CMSG_SPACE(2 * 4))
    fds = array.array("i", anc[0][2]) if anc else []
    assert msg == b"fds" and len(fds) == 2, (msg, anc)
    os.write(fds[0], b"via pipe")              # the passed pipe write end
    os.write(fds[0], os.read(fds[1], 64))      # the passed file
    os._exit(0)
b.close()
a.sendmsg([b"fds"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [w, f.fileno()]))])
os.close(w); f.close()                         # the child's copies must outlive ours
os.waitpid(pid, 0)
got = os.read(r, 64)
assert got == b"via pipefrom a file", got
print("OK")
