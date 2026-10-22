# Locks on an append-only fd (dnf's log: O_WRONLY|O_APPEND, then flock): taken at once, seen by other
# processes, and gone with the fd.
import fcntl, os, subprocess, sys

def other_can_lock(kind):
    code = ("import fcntl, os\n"
            "fd = os.open('/tmp/applock', os.O_WRONLY | os.O_APPEND)\n"
            f"try: fcntl.{kind}(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); print('free')\n"
            "except OSError: print('held')")
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True).stdout.strip()

for kind in ("flock", "lockf"):
    fd = os.open("/tmp/applock", os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    getattr(fcntl, kind)(fd, fcntl.LOCK_EX)
    os.write(fd, b"logged\n")
    held = other_can_lock(kind)
    os.close(fd)
    print(kind, held, other_can_lock(kind))
