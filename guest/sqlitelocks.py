# Two SQLite connections in one process share its POSIX locks: c1's leftover read lock mustn't block
# c2's write (Grafana's "database is locked"). A second process still has to wait for a writer.
import os, sqlite3, subprocess, sys

db = "/tmp/locks.db"
c1 = sqlite3.connect(db, timeout=1, isolation_level=None)
c1.execute("create table t (x)")
c2 = sqlite3.connect(db, timeout=1, isolation_level=None)
c1.execute("begin"); c1.execute("select * from t").fetchall()
c2.execute("begin"); c2.execute("select * from t").fetchall()
c1.execute("commit")
c2.execute("insert into t values (1)")
c2.execute("commit")
c1.execute("begin immediate")  # a write lock, held while another process tries to write
other = subprocess.run([sys.executable, "-c",
    "import sqlite3; c = sqlite3.connect('/tmp/locks.db', timeout=0.2)\n"
    "try:\n c.execute('insert into t values (2)'); c.commit(); print('wrote')\n"
    "except sqlite3.OperationalError as e: print(e)"], capture_output=True, text=True).stdout.strip()
assert other == "database is locked", other
c1.execute("commit")
c1.close()  # closing one connection mustn't drop c2's locks: SQLite defers the close itself
print("sqlite locks OK", c2.execute("select count(*) from t").fetchone()[0])
