# inotify tells a metadata change (chmod, utime: IN_ATTRIB) from a write (IN_MODIFY).
import ctypes, os, select, struct, time
libc = ctypes.CDLL(None, use_errno=True)
IN_MODIFY, IN_ATTRIB = 0x2, 0x4
os.makedirs("/srv/w"); open("/srv/w/f", "w").close()
fd = libc.inotify_init1(os.O_NONBLOCK)
libc.inotify_add_watch(fd, b"/srv/w", IN_MODIFY | IN_ATTRIB)
def masks():
    got = set()
    while select.select([fd], [], [], 1)[0]:
        data = os.read(fd, 4096)
        while data:
            _, mask, _, n = struct.unpack("iIII", data[:16]); got.add(mask); data = data[16 + n:]
    return "+".join(sorted({IN_MODIFY: "modify", IN_ATTRIB: "attrib"}.get(m, hex(m)) for m in got)) or "none"
os.chmod("/srv/w/f", 0o600); a = masks()
with open("/srv/w/f", "a") as f: f.write("x")
b = masks()
os.utime("/srv/w/f", (1, 1)); c = masks()
print("chmod", a, "write", b, "utime", c)
