# RLIMIT_NOFILE is enforced: EMFILE at the soft limit, setrlimit's limits carry into children.
import errno, os, resource, subprocess, sys
out = ["default %d" % resource.getrlimit(resource.RLIMIT_NOFILE)[0]]
resource.setrlimit(resource.RLIMIT_NOFILE, (50, 4096))
fds = []
try:
    while True:
        fds.append(os.open("/dev/null", os.O_RDONLY))
except OSError as e:
    out.append("open %s at %d" % (errno.errorcode[e.errno], fds[-1] + 1))
for name, op in [("pipe", os.pipe), ("dup2", lambda: os.dup2(0, 60))]:
    try:
        op()
    except OSError as e:
        out.append("%s %s" % (name, errno.errorcode[e.errno]))
for fd in fds:
    os.close(fd)
try:
    resource.setrlimit(resource.RLIMIT_NOFILE, (50, 8192))
except ValueError:  # Python's word for EPERM here
    out.append("raise hard refused")
child = subprocess.run([sys.executable, "-c", "import resource; print(resource.getrlimit(resource.RLIMIT_NOFILE))"], capture_output=True, text=True)
out.append("child " + child.stdout.strip())
print(", ".join(out))
