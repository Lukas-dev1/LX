"""File modes and owners: from the image, on creation (umask), chmod/chown, and across exec. Prints OK."""
import os, stat, subprocess, sys

def mode(p, follow=True):
    return stat.S_IMODE(os.stat(p, follow_symlinks=follow).st_mode)

# From the image's tar headers (images pulled with this lx).
assert mode("/tmp") == 0o1777, oct(mode("/tmp"))
assert mode("/etc/passwd") == 0o644, oct(mode("/etc/passwd"))

# Creation: mode less the umask, owned by the effective ids.
os.chdir("/tmp")
os.umask(0o022)
fd = os.open("a", os.O_CREAT | os.O_WRONLY, 0o666)
os.close(fd)
assert mode("a") == 0o644, oct(mode("a"))
assert os.umask(0o077) == 0o022
open("b", "w").close()
assert mode("b") == 0o600, oct(mode("b"))
os.mkdir("d", 0o777)
assert mode("d") == 0o700 and stat.S_ISDIR(os.stat("d").st_mode), oct(mode("d"))
os.umask(0o022)

# chmod / fchmod / chown, and -1 keeps an id.
os.chmod("a", 0o4751)
assert mode("a") == 0o4751, oct(mode("a"))
fd = os.open("b", os.O_RDONLY)
os.fchmod(fd, 0o640)
os.close(fd)
assert mode("b") == 0o640
os.chown("a", 1000, 1001)
st = os.stat("a")
assert (st.st_uid, st.st_gid) == (1000, 1001), (st.st_uid, st.st_gid)
os.chown("a", -1, 50)
st = os.stat("a")
assert (st.st_uid, st.st_gid) == (1000, 50), (st.st_uid, st.st_gid)

# A symlink: lchown changes the link, chmod follows it to the target.
os.symlink("a", "l")
os.lchown("l", 7, 7)
assert os.stat("a").st_uid == 1000
os.chmod("l", 0o700)
assert mode("a") == 0o700

# An image file changed in the container: the change shows, a directory keeps its other entries.
os.chmod("/etc/passwd", 0o600)
assert mode("/etc/passwd") == 0o600
os.chown("/etc", 0, 42)
assert os.stat("/etc").st_gid == 42 and os.path.exists("/etc/group")
assert mode("/etc") == 0o755, oct(mode("/etc"))

# Another process sees the same, and files it creates as another user are that user's.
out = subprocess.run(["stat", "-c", "%a %u:%g", "/tmp/a"], capture_output=True, text=True).stdout.split()
assert out == ["700", "1000:50"], out
if os.fork() == 0:
    os.setgid(1001)
    os.setuid(1001)
    open("/tmp/mine", "w").close()
    os._exit(0)
os.wait()
st = os.stat("/tmp/mine")
assert (st.st_uid, st.st_gid) == (1001, 1001), (st.st_uid, st.st_gid)
print("OK")
