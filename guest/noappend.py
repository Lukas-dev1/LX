# musl's pwrite is pwritev2(RWF_NOAPPEND): it writes at the offset, even on an O_APPEND fd; plain pwritev
# on one appends, as on Linux. sqlite writes through pwrite.
import ctypes, errno, os, sqlite3
out = []
try:
    os.pwrite(-1, b"x", 0)
except OSError as e:
    out.append("bad " + errno.errorcode[e.errno])
open("/tmp/a", "w").write("abc")
fd = os.open("/tmp/a", os.O_WRONLY | os.O_APPEND)
os.pwrite(fd, b"X", 0)
os.pwritev(fd, [b"Y"], 0)
out.append("append " + open("/tmp/a").read())
db = sqlite3.connect("/tmp/t.db")
db.execute("create table t(x)"); db.executemany("insert into t values (?)", [(i,) for i in range(100)]); db.commit()
out.append("sqlite %d" % db.execute("select sum(x) from t").fetchone()[0])
print(", ".join(out))
