# SO_PEERCRED on a unix socket answers (pid, uid, gid): s6's getpeereid needs it.
import os, socket, struct

a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
pid, uid, gid = struct.unpack("3i", a.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
assert (pid, uid, gid) == (os.getpid(), os.getuid(), os.getgid()), (pid, uid, gid)
print("peercred OK", uid, gid)
