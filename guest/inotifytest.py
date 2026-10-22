# inotify: events for a directory in the container (create, write, rename, delete) and for an image
# directory, where deleting an image file must read as IN_DELETE (it's a whiteout underneath).
import ctypes, os, select, struct

libc = ctypes.CDLL(None, use_errno=True)
IN_MODIFY, IN_MOVED_FROM, IN_MOVED_TO, IN_CREATE, IN_DELETE = 0x2, 0x40, 0x80, 0x100, 0x200
NAMES = {IN_MODIFY: "modify", IN_MOVED_FROM: "from", IN_MOVED_TO: "to", IN_CREATE: "create", IN_DELETE: "delete"}

fd = libc.inotify_init1(os.O_NONBLOCK)
assert fd >= 0, ctypes.get_errno()
os.makedirs("/tmp/w")
wd = libc.inotify_add_watch(fd, b"/tmp/w", IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO)
wd2 = libc.inotify_add_watch(fd, b"/etc", IN_CREATE | IN_DELETE)
assert wd > 0 and wd2 > 0, ctypes.get_errno()

def events(until):
    seen = []
    while until not in seen and select.select([fd], [], [], 3)[0]:
        data = os.read(fd, 4096)
        while data:
            w, mask, cookie, n = struct.unpack("iIII", data[:16])
            name = data[16:16 + n].rstrip(b"\0").decode()
            seen.append(("etc " if w == wd2 else "") + NAMES.get(mask & 0xfff, hex(mask)) + " " + name)
            data = data[16 + n:]
    return seen

with open("/tmp/w/a", "w") as f:
    f.write("x")
os.rename("/tmp/w/a", "/tmp/w/b")
os.remove("/tmp/w/b")
got = events("delete b")
assert got[0] == "create a" and "from a" in got and "to b" in got and got[-1] == "delete b", got
open("/etc/lx-new", "w").close()
os.remove("/etc/motd")  # an image file: a whiteout underneath
got2 = events("etc delete motd")
assert "etc create lx-new" in got2 and got2[-1] == "etc delete motd", got2
print("inotify OK", got2[-1])
