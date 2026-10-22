# splice: pipe to pipe, and file (with an offset) to pipe.
import os

a_r, a_w = os.pipe()
b_r, b_w = os.pipe()
os.write(a_w, b"spliced")
assert os.splice(a_r, b_w, 100) == 7 and os.read(b_r, 100) == b"spliced"
with open("/tmp/s", "wb") as f:
    f.write(b"0123456789")
fd = os.open("/tmp/s", os.O_RDONLY)
assert os.splice(fd, b_w, 4, offset_src=3) == 4 and os.read(b_r, 100) == b"3456"
print("splice OK")
