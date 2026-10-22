# fsync of a read-only fd works on Linux (dnf fsyncs downloaded metadata that way).
import os

with open("/tmp/data", "w") as f:
    f.write("x")
fd = os.open("/tmp/data", os.O_RDONLY)
os.fsync(fd)
os.fdatasync(fd)
print("fsync read-only OK")
