# MAP_SHARED with PROT_EXEC works on a file and on a memfd (.NET's W^X double mapping does the latter).
import mmap, os
out = []
open("/tmp/f", "wb").write(b"\xc3" * 4096)  # ret
for name, fd, prot in [("file", os.open("/tmp/f", os.O_RDONLY), mmap.PROT_READ | mmap.PROT_EXEC),
                       ("memfd", os.memfd_create("jit"), mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)]:
    if name == "memfd":
        os.ftruncate(fd, 4096)
    try:
        m = mmap.mmap(fd, 4096, mmap.MAP_SHARED, prot)
        out.append("%s ok %02x" % (name, m[0] if name == "file" else 0))
    except OSError as e:
        out.append("%s %s" % (name, e.strerror))
print(", ".join(out))
