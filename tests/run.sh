#!/bin/sh
# lx test suite. From the repo root, in Git Bash:   sh tests/run.sh
#   REPEAT=n   repetitions of the multithreaded tests (default 20)
#   QUICK=1    skip the network tests (nginx, wget, python)
#   TOOLS=dir  where the toolchains live (default tools/; a git worktree can point at the main checkout's)
#
# Builds lx and the guest programs, prepares rootfs/ (an Alpine test rootfs plus pulled images), and runs
# everything. Guest scripts live in guest/ and are copied into the images only for the duration of the
# run (removed again on exit), so no image in the store is modified by hand.
set -u
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1
ROOT=$(pwd -W)
TOOLS=${TOOLS:-$ROOT/tools}
export RUSTUP_HOME="$TOOLS/rust/rustup" CARGO_HOME="$TOOLS/rust/cargo"
CARGO=$TOOLS/rust/cargo/bin/cargo.exe
ZIG=$TOOLS/zig-x86_64-windows-0.15.2/zig.exe
GO=$TOOLS/go/bin/go.exe
LX=./target/release/lx.exe
REPEAT=${REPEAT:-20}
STORE=rootfs/images/registry-1.docker.io
OUT=$(mktemp -d)

pass=0; fail=0; warn=0
ok()   { echo "PASS  $*"; pass=$((pass + 1)); }
bad()  { echo "FAIL  $*"; fail=$((fail + 1)); }
note() { echo "WARN  $*"; warn=$((warn + 1)); }
die()  { echo "setup: $*"; exit 2; }

# ---- build ----
$CARGO build --release -q || die "cargo build failed"
if $CARGO test --release -q > "$OUT/unit" 2>&1; then ok "unit tests"; else bad "unit tests"; tail -20 "$OUT/unit"; fi

cc_static() { $ZIG cc -target x86_64-linux-musl -static -O"$1" -o "$2" "$3" || die "build $3"; }
cc_dynamic() { $ZIG cc -target x86_64-linux-musl -dynamic -O2 -o "$1" "$2" || die "build $2"; }

# Alpine test rootfs (a scratch rootfs, not an image in the store), from the pinned minirootfs.
ALPINE_TGZ=rootfs/dl/alpine.tar.gz
ALPINE_SHA=c5ca053cfe1d85c5b96dff8b9bc57045f7f184a30ffb6b65776409ca90388677
if [ ! -d rootfs/alpine ]; then
  mkdir -p rootfs/dl
  [ -f $ALPINE_TGZ ] || curl -sSfL -o $ALPINE_TGZ \
    https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-minirootfs-3.24.2-x86_64.tar.gz || die "download minirootfs"
  [ "$(sha256sum $ALPINE_TGZ | cut -d' ' -f1)" = $ALPINE_SHA ] || die "minirootfs checksum mismatch"
  $LX unpack $ALPINE_TGZ rootfs/alpine 2> /dev/null || die "unpack minirootfs"
fi

cc_static 2 rootfs/hello guest/hello.c
cc_static 1 rootfs/stress guest/stress.c
cc_static 2 rootfs/threads guest/threads.c
cc_static 2 rootfs/stacktest guest/stacktest.c
cc_static 2 rootfs/sigfdtest guest/sigfdtest.c
cc_static 2 rootfs/sigfutex guest/sigfutex.c
cc_static 2 rootfs/restarttest guest/restarttest.c
cc_static 2 rootfs/ptimer guest/ptimer.c
cc_static 2 rootfs/sysvipc guest/sysvipc.c
cc_static 2 rootfs/epollet guest/epollet.c
cc_static 2 rootfs/pipenb guest/pipenb.c
cc_static 2 rootfs/pipewait guest/pipewait.c
cc_static 1 rootfs/spinsig guest/spinsig.c
cc_static 2 rootfs/pgrptest guest/pgrptest.c
cc_static 2 rootfs/waitidtest guest/waitidtest.c
cc_static 2 rootfs/shfutex guest/shfutex.c
cc_static 2 rootfs/sysbench guest/sysbench.c
cc_static 2 rootfs/xmmtest guest/xmmtest.c
cc_static 2 rootfs/sigxmm guest/sigxmm.c
cc_static 1 rootfs/alpine/deepstack guest/deepstack.c
cc_dynamic rootfs/alpine/threads-dyn guest/threads.c
cc_dynamic rootfs/alpine/dltest guest/dltest.c
cp guest/regress.sh guest/entrypoint.sh rootfs/alpine/
HAVE_GO=0
if [ -x $GO ]; then
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOTOOLCHAIN=local GOTELEMETRY=off GO111MODULE=off \
    GOCACHE="$TOOLS/gocache" GOPATH="$TOOLS/gopath" $GO build -o rootfs/gotest ./guest/gotest || die "go build"
  HAVE_GO=1
fi

# ---- images: pull what's missing; guest scripts reach containers through a read-only volume ----
for img in alpine:latest python:3.12-alpine python:3.12 nginx:alpine httpd:alpine eclipse-temurin:21-jre-alpine redis:alpine postgres:alpine node:alpine golang:alpine mariadb:11 rabbitmq:3-alpine mongo:7 wordpress:fpm-alpine; do
  dir=$STORE/library_${img%%:*}/${img#*:}/rootfs
  # Pulled before lx kept file modes, every file reads 0755 (no real image has /etc/passwd so): re-pull.
  if [ -d "$dir" ] && [ "$($LX run "$img" stat -c %a /etc/passwd 2> /dev/null < /dev/null)" = 755 ]; then
    rm -rf "$dir"
  fi
  [ -d "$dir" ] || $LX pull "$img" > /dev/null 2>&1 || die "pull $img"
done
GUEST="$ROOT/guest:/t:ro" # nothing is copied into an image: containers never modify the image store
cleanup() { rm -rf "$OUT" rootfs/voltest-suite; }
trap cleanup EXIT
trap 'exit 130' INT TERM

# ---- single runs ----
expect() { # expect <name> <exit code> <text in output> -- <lx args...>
  name=$1 code=$2 text=$3; shift 4
  timeout 120 $LX "$@" < /dev/null > "$OUT/one" 2>&1
  got=$?
  if [ $got = "$code" ] && grep -qF -- "$text" "$OUT/one"; then ok "$name"; else bad "$name (exit $got)"; tail -5 "$OUT/one"; fi
}
expect "hello"            7   "tls=42"                   -- rootfs /hello
expect "stress (TLS under preemption)" 0 "sum=79999999800000000" -- rootfs /stress
expect "xmm0-15 survive syscalls (direct path)" 0 "xmm OK" -- rootfs /xmmtest
expect "a signal handler's xmm use doesn't leak into the interrupted code" 0 "sigxmm OK" -- rootfs /sigxmm
expect "crash -> SIGSEGV" 139 "guest fault"              -- rootfs /stress crash
expect "signalfd in epoll, woken by a child's signal" 0 "OK" -- rootfs /sigfdtest
expect "SIGTERM reaches threads parked in futexes (Go idle)" 0 "sigfutex OK" -- rootfs /sigfutex
expect "SA_RESTART: an interrupted read continues" 0 "read=1" -- rootfs /restarttest
expect "POSIX timers: a periodic timer_create timer keeps firing" 0 "ticks=3 armed=1" -- rootfs /ptimer
expect "SysV semaphores and message queues across fork" 0 "sysv waiting=1 got=hello n=16 child=0 nowait=EAGAIN/ENOMSG nsems=2 perm=1 info=1 stat=1 key=1 gone=1" -- rootfs /sysvipc
expect "edge-triggered epoll: data arriving after a drain to EAGAIN is a new edge (pipe, eventfd)" 0 "epollet pipe=1 eventfd=1" -- rootfs /epollet
expect "non-blocking pipe writes: EAGAIN when full (PIPE_BUF all or nothing), POLLOUT only with room, and its edge re-arms" 0 "pipenb first=1 filled=1 eagain=1 full-pollout=0 small-eagain=1 room=1 edge=1" -- rootfs /pipenb
expect "a reader blocked in a big read leaves a non-blocking writer room (NT counts it against the quota); FIFOs too" 0 "pipewait blocked-reader=1 drained=1 fifo=1" -- rootfs /pipewait
expect "a handled signal interrupts a thread spinning in guest code" 0 "main=1 worker=1" -- rootfs /spinsig
expect "kill(-pgid) reaches the whole process group" 0 "pgid=1 eof=1" -- rootfs /pgrptest
expect "waitid: P_PID, WNOWAIT, CLD_KILLED, WNOHANG" 0 "peek=1 reap=1 killed=1 none=1" -- rootfs /waitidtest
expect "a shared futex wakes another process (FUTEX_WAKE counts it)" 0 "woke=1 child=0" -- rootfs /shfutex
expect "regress.sh"       0   "ALL OK"                   -- rootfs/alpine /regress.sh
expect "entrypoint.sh"    0   "APP_MODE=production"      -- rootfs/alpine /entrypoint.sh
expect "the first process is pid 1"  0 "pid1 OK" -- run -v "$GUEST" alpine sh /t/pid1.sh
expect "ps, pidof, pgrep, /proc/<pid> of other processes" 0 "comm=sleep cmd=sleep 30  ppid=1 exe=/bin/busybox" -- run -v "$GUEST" alpine sh /t/pstest.sh
expect "deep stack + fork" 0  "child exit 3"             -- rootfs/alpine /deepstack
expect "dlopen while threads run" 0 " OK"                -- rootfs/alpine /dltest
# Debian (glibc) image: the three usual ways a Python image starts.
expect "debian: python3 -c"         0 "hi"               -- run python:3.12 python3 -c "print('hi')"
expect "debian: python3 /script.py" 0 "script ran: 3.12" -- run -v "$GUEST" python:3.12 python3 /t/hello.py
expect "debian: AF_UNIX echo (path + abstract)" 0 "OK" -- run -v "$GUEST" python:3.12 python3 /t/unixtest.py
expect "SO_PEERCRED on a unix socket" 0 "peercred OK" -- run -v "$GUEST" python:3.12 python3 /t/peercred.py
expect "inotify: container dir and image dir" 0 "inotify OK etc delete motd" -- run -v "$GUEST" python:3.12-alpine python3 /t/inotifytest.py
expect "eventfd keeps its fd number in a forked child" 0 "eventfd fork OK" -- run -v "$GUEST" python:3.12-alpine python3 /t/eventfdfork.py
expect "seccomp: a filter here and in an exec'd child" 0 "seccomp OK child filtered 2" -- run -v "$GUEST" python:3.12 python3 /t/seccomptest.py
expect "debian: pty (openpty, pty.fork)" 0 "pty OK" -- run -v "$GUEST" python:3.12 python3 /t/ptytest.py
expect "a MAP_SHARED mapping past EOF sees the file grow (bbolt)" 0 "grown b'a' b'b'" -- run -v "$GUEST" python:3.12 python3 /t/mmapgrow.py
expect "FIFOs: mkfifo, open waits, ENXIO, poll" 0 "fifo OK 0o600 through the fifo" -- run -v "$GUEST" python:3.12 python3 /t/fifotest.py
expect "exec with a 5000-byte argument (MAX_ARG_STRLEN, not PATH_MAX)" 0 "5001" -- run alpine sh -c 'a=$(printf "%05000d" 0); /bin/echo "$a" | wc -c'
expect "FIFOs in a shell loop" 0 "got round 2" -- run alpine sh -c 'mkfifo /tmp/p; for i in 1 2; do (echo round $i > /tmp/p &); read line < /tmp/p; echo "got $line"; done'
expect "names differing only in case are two files" 0 "case 2 lower UPPER" -- run alpine sh -c 'cd /tmp && echo lower > make && echo UPPER > MAKE && mkdir d && touch d/x d/X && echo case $(ls d | wc -l) $(cat make) $(cat MAKE)'
expect "run -it --rm (Docker's no-op flags)" 0 "1 /tmp"     -- run -it -e A=1 --rm -w /tmp alpine sh -c 'echo $A $(pwd)'
expect "AF_UNIX datagrams"         0 "OK" -- run -v "$GUEST" python:3.12-alpine python3 /t/dgramtest.py
expect "debian: AF_UNIX datagrams" 0 "OK" -- run -v "$GUEST" python:3.12 python3 /t/dgramtest.py
expect "socketpair (stream, dgram, fork, mp.Pipe)" 0 "OK" -- run -v "$GUEST" python:3.12-alpine python3 /t/pairtest.py
expect "file modes + owners"       0 "OK" -- run -v "$GUEST" python:3.12-alpine python3 /t/modetest.py
expect "debian: file modes + owners" 0 "OK" -- run -v "$GUEST" python:3.12 python3 /t/modetest.py
expect "per-thread signal masks (threads, fork)" 0 "OK" -- run -v "$GUEST" python:3.12 python3 /t/masktest.py
expect "sigwait / sigwaitinfo / sigtimedwait" 0 "OK" -- run -v "$GUEST" python:3.12 python3 /t/sigwait.py
expect "dup'd fds survive fork/exec (socket, pipe)" 0 "OK" -- run -v "$GUEST" python:3.12 python3 /t/dupfds.py
expect "SCM_RIGHTS: pipe + file to a forked child" 0 "OK" -- run -v "$GUEST" python:3.12 python3 /t/scmtest.py
expect "timerfd: one-shot, periodic, poll, disarm" 0 "OK" -- run -v "$GUEST" python:3.12 python3 /t/timerfd.py
expect "sqlite: connections in one process share fcntl locks" 0 "sqlite locks OK 1" -- run -v "$GUEST" python:3.12 python3 /t/sqlitelocks.py
expect "flock/lockf on an append-only fd" 0 "flock held free" -- run -v "$GUEST" python:3.12 python3 /t/appendlock.py
expect "short timed waits sleep ~1 ms (no spin, no 15 ms tick)" 0 "OK" -- run -v "$GUEST" python:3.12 python3 /t/timedwait.py
expect "erlang: VM, 1000 processes, os:cmd port" 0 "sum=6 procs=1000 port-ok" -- run rabbitmq:3-alpine erl -noshell -eval 'io:format("sum=~p procs=~p ~s~n",[lists:sum([1,2,3]), length([spawn(fun() -> ok end) || _ <- lists:seq(1,1000)]), os:cmd("echo port-ok")]), halt().'
expect "/proc/self/fd lists open fds" 0 "0 1 2 3" -- run alpine sh -c 'ls /proc/self/fd | tr "\n" " "'
expect "fsync of a read-only fd" 0 "fsync read-only OK" -- run -v "$GUEST" python:3.12 python3 /t/fsyncro.py
expect "splice: pipe to pipe, file to pipe" 0 "splice OK" -- run -v "$GUEST" python:3.12 python3 /t/splicetest.py
expect "SIGSEGV reaches the guest's handler" 139 "Fatal Python error: Segmentation fault" -- run python:3.12 python3 -X faulthandler -c "import ctypes; ctypes.string_at(0)"
expect "httpd: config check (ErrorLog /proc/self/fd/2)" 0 "Syntax OK" -- run httpd:alpine httpd -t
expect "fchmodat2 by path and by fd" 0 "fchmodat2 640 604" -- run -v "$GUEST" python:3.12 python3 /t/fchmodat2.py
expect "arch_prctl codes; mlock" 0 "small syscalls OK" -- run -v "$GUEST" python:3.12 python3 /t/smallsys.py
expect "java -version (HotSpot's SIGSEGV use)" 0 "OpenJDK 64-Bit Server VM" -- run eclipse-temurin:21-jre-alpine java -version
# mariadb through its official entrypoint (gosu, install-db, InnoDB). -p: the host may run its own 3306.
# Wait for "init process done": the entrypoint's temporary init server answers first, then restarts.
expect "mariadb: entrypoint + InnoDB query" 0 "hello,lx" -- run -p 13306:3306 -e MARIADB_ROOT_PASSWORD=x mariadb:11 sh -c 'docker-entrypoint.sh mariadbd > /tmp/log 2>&1 & for i in $(seq 1 100); do grep -q "init process done" /tmp/log && mariadb -uroot -px -e "select 1" > /dev/null 2>&1 && break; sleep 1; done; mariadb -uroot -px -e "create database t; create table t.a (id int primary key, s text) engine=innodb; insert into t.a values (1, \"hello\"), (2, \"lx\"); select group_concat(s) from t.a"; mariadb-admin -uroot -px shutdown; wait'
expect "mongodb: mongod + mongosh aggregate" 0 "sum=42" -- run -p 27018:27017 mongo:7 sh -c 'mongod --bind_ip_all > /tmp/log 2>&1 & for i in $(seq 1 60); do grep -q "Waiting for connections" /tmp/log && break; sleep 1; done; mongosh --quiet --eval "db.t.insertOne({a:1}); db.t.insertOne({a:41}); print(\"sum=\" + db.t.aggregate([{\$group:{_id:null,s:{\$sum:\"\$a\"}}}]).toArray()[0].s)"; mongosh --quiet admin --eval "db.shutdownServer()" > /dev/null 2>&1; wait'
# -e adds and overrides the image's env (PYTHON_VERSION is set by the image), -w sets the directory.
expect "run -e / -w"               0 "A=1 V=9 /usr" -- run -e A=1 -e PYTHON_VERSION=9 -w /usr python:3.12-alpine sh -c 'echo A=$A V=$PYTHON_VERSION $(pwd)'
expect "/proc/<getpid()> after exec" 0 "own pid ['0', '1', '2']" -- run python:3.12-alpine sh -c 'exec python3 -c "import os; p=f\"/proc/{os.getpid()}\"; os.stat(p); print(\"own pid\", sorted(os.listdir(p + \"/fd\"))[:3])"'
expect "hard link counts (container files; image files stay 1)" 0 "nlink 2 1 image 1" -- run alpine sh -c 'touch /tmp/a; ln /tmp/a /tmp/b; x=$(stat -c %h /tmp/a); rm /tmp/b; echo "nlink $x $(stat -c %h /tmp/a) image $(stat -c %h /bin/busybox)"'
expect "fstat counts a container file's hard links (image files stay 1)" 0 "fstat nlink 2 1 image 1" -- run python:3.12-alpine python3 -c 'import os; fd=os.open("/tmp/a",os.O_RDWR|os.O_CREAT); os.link("/tmp/a","/tmp/b"); n1=os.fstat(fd).st_nlink; os.unlink("/tmp/b"); n2=os.fstat(fd).st_nlink; print("fstat nlink", n1, n2, "image", os.fstat(os.open("/usr/lib/libz.so.1",0)).st_nlink)'
expect "lchown sets a symlink's own owner; chown follows it" 0 "f=1000:1001 l=2000:2001 lmode=777" -- run alpine sh -c 'cd /tmp; touch f; chown 1000:1001 f; ln -s f l; chown -h 2000:2001 l; echo "f=$(stat -c %u:%g f) l=$(stat -c %u:%g l) lmode=$(stat -c %a l)"'
expect "a set-group-ID directory's group goes to what's made in it" 0 "f=1234 sub=1234:2755 fifo=1234" -- run alpine sh -c 'mkdir /tmp/g && chown 0:1234 /tmp/g && chmod 2777 /tmp/g && su -s /bin/sh nobody -c "touch /tmp/g/f; mkdir /tmp/g/sub; mkfifo /tmp/g/p"; echo "f=$(stat -c %g /tmp/g/f) sub=$(stat -c %g:%a /tmp/g/sub) fifo=$(stat -c %g /tmp/g/p)"'
expect "chmod g+s by a member of the file's group through a supplementary group" 0 "mode=2777" -- run alpine sh -c 'echo "grp:x:1234:nobody" >> /etc/group; mkdir /tmp/g && chmod 777 /tmp/g; mkdir /tmp/g/d; chown 65534:1234 /tmp/g/d; su -s /bin/sh nobody -c "chmod 2777 /tmp/g/d"; echo "mode=$(stat -c %a /tmp/g/d)"'
expect "ftruncate grows a file with a hole (size and data right)" 0 "big 1073741824 hi" -- run alpine sh -c 'truncate -s 1G /tmp/big; echo hi | dd of=/tmp/big bs=1 seek=1000 conv=notrunc 2>/dev/null; echo "big $(stat -c %s /tmp/big) $(dd if=/tmp/big bs=1 skip=1000 count=2 2>/dev/null)"'
expect "ftruncate shrinks a mapped file (shared and private views)" 0 "shrunk 4096 b'a' b'P' b'aZ'" -- run python:3.12-alpine python3 -c 'import mmap,os; fd=os.open("/tmp/m",os.O_RDWR|os.O_CREAT); os.write(fd,b"a"*16384); m=mmap.mmap(fd,16384); p=mmap.mmap(fd,16384,flags=mmap.MAP_PRIVATE); p[0:1]=b"P"; os.ftruncate(fd,4096); m[1:2]=b"Z"; os.lseek(fd,0,0); print("shrunk",os.fstat(fd).st_size,m[0:1],p[0:1],os.read(fd,2))'
expect "chown drops setuid/setgid; chmod g+s outside the group is dropped" 0 "chown:755 sgid:777" -- run alpine sh -c 'cd /tmp && touch f && chmod 6755 f && chown 0:0 f && mkdir d && chown 65534:0 d && chmod 777 d && su -s /bin/sh nobody -c "chmod 2777 d"; echo "chown:$(stat -c %a f) sgid:$(stat -c %a d)"'
expect "a 300-byte name is ENAMETOOLONG" 0 "too long" -- run alpine sh -c 'cd $(printf "%0300d" 0) 2>&1; true'
expect "procps ps, vmstat (/proc/stat, /proc/vmstat)" 0 "ps ok vmstat ok" -- run python:3.12 sh -c 'ps aux > /dev/null && p="ps ok"; vmstat > /dev/null && echo "$p vmstat ok"'
expect "an exited child is a zombie until reaped (none when SIGCHLD is ignored)" 0 "default: Z then gone; SIG_IGN: gone" -- run python:3.12-alpine python3 -c 'import os,time,signal
st=lambda p: (lambda f: f.read().split()[2])(open("/proc/%d/stat" % p)) if os.path.exists("/proc/%d" % p) else "gone"
c=os.fork()
if c == 0: os._exit(3)
time.sleep(0.5); a=st(c); os.waitpid(c,0); b=st(c)
signal.signal(signal.SIGCHLD, signal.SIG_IGN); d=os.fork()
if d == 0: os._exit(0)
time.sleep(0.5); print("default: %s then %s; SIG_IGN: %s" % (a, b, st(d)))'
expect "/proc/<pid>/stat: S for a process blocked in a syscall, R for one running" 0 "sleep:S busy:R self:R" -- run alpine sh -c 'sleep 5 & s=$!; (while :; do :; done) & b=$!; sleep 1; echo "sleep:$(cut -d" " -f3 /proc/$s/stat) busy:$(cut -d" " -f3 /proc/$b/stat) self:$(cut -d" " -f3 /proc/self/stat)"; kill $b'
expect "F_GETFL shows how a file was opened; FIONBIO makes a pipe non-blocking" 0 "rd=0 wr=1 rw=2 ap=1025 nb=True" -- run python:3.12-alpine python3 -c 'import os,fcntl; g=lambda fd: fcntl.fcntl(fd,fcntl.F_GETFL) & 0o3003; r,w=os.pipe(); os.set_blocking(r,False); print("rd=%d wr=%d rw=%d ap=%d nb=%s" % (g(os.open("/etc/hostname",0)), g(os.open("/tmp/a",os.O_WRONLY|os.O_CREAT)), g(os.open("/tmp/a",os.O_RDWR)), g(os.open("/tmp/a",os.O_WRONLY|os.O_APPEND)), not os.get_blocking(r)))'
expect "F_GETLK names the holder of a conflicting lock (type, range, pid)" 0 "holder type=1 start=10 len=5 is_parent=True" -- run -v "$GUEST" python:3.12-alpine python3 /t/getlk.py
expect "SIGPIPE on a write without a reader (default kills, Python gets EPIPE)" 0 "python EPIPE, default killed by 13" -- run -v "$GUEST" python:3.12-alpine python3 /t/sigpipe.py
expect "bad struct pointers are EFAULT, not a fault in lx" 0 "uname EFAULT, sysinfo EFAULT, pipe EFAULT, sigprocmask oldset EFAULT, sigprocmask size EINVAL, capget version EINVAL 0x20080522, timerfd_gettime EBADF" -- run -v "$GUEST" python:3.12-alpine python3 /t/efault.py
expect "splice socket -> non-blocking pipe loses nothing when the pipe fills" 0 "moved True intact True" -- run -v "$GUEST" python:3.12-alpine python3 /t/splicekeep.py
expect "sendfile with an unmapped offset pointer is EFAULT" 0 "sendfile -1 EFAULT" -- run -v "$GUEST" python:3.12-alpine python3 /t/sendfilefault.py
expect "MAP_FIXED_NOREPLACE: EEXIST over a mapping, exact at a free address" 0 "over EEXIST free exact" -- run -v "$GUEST" python:3.12-alpine python3 /t/noreplace.py
expect "mmap, munmap, msync, mremap and sendfile check their arguments" 0 "shared write on rdonly EACCES, read on wronly EACCES, private write on rdonly ok, bad fd EBADF, pipe ENODEV, no type EINVAL, munmap odd EINVAL, munmap 0 EINVAL, msync both EINVAL, msync odd EINVAL, mremap fixed EINVAL, sendfile to rdonly EBADF, huge ENOMEM, after ok" -- run -v "$GUEST" python:3.12-alpine python3 /t/mapchecks.py
expect "O_PATH fds: no read/write, fstat and fchdir work" 0 "read EBADF, write EBADF, size 4, /tmp" -- run -v "$GUEST" python:3.12-alpine python3 /t/opath.py
expect "hard links share an inode (tar stores the second as a link)" 0 "same=1 nlink=2 tar=t/y -> t/x" -- run alpine sh -c 'mkdir /tmp/t; echo z > /tmp/t/x; ln /tmp/t/x /tmp/t/y; [ "$(stat -c %i /tmp/t/x)" = "$(stat -c %i /tmp/t/y)" ] && s=1 || s=0; cd /tmp && tar cf t.tar t && echo "same=$s nlink=$(stat -c %h t/y) tar=$(tar tvf t.tar | grep -o "t/y -> t/x")"'
expect "utimensat: atime apart from mtime, directories too, and a read-only file's owner may" 0 "a=2002 m=2003 dir=2001 ro=2004" -- run alpine sh -c 'echo x > /tmp/f; touch -a -d "2002-01-01 00:00:00" /tmp/f; touch -m -d "2003-01-01 00:00:00" /tmp/f; a=$(stat -c %x /tmp/f | cut -c1-4); m=$(stat -c %y /tmp/f | cut -c1-4); touch -d "2001-02-03 04:05:06" /usr; chmod 444 /tmp/f; touch -m -d "2004-01-01 00:00:00" /tmp/f; echo "a=$a m=$m dir=$(stat -c %y /usr | cut -c1-4) ro=$(date -r /tmp/f +%Y)"'
expect "a path goes on only through directories: below a missing one ENOENT (mkdir and creat make no parents), below a file ENOTDIR; a trailing slash follows a symlink" 0 "mk=1 parent=0 creat=1 notdir=1 slash=1 link=d" -- run alpine sh -c 'mkdir /nope/a 2>/dev/null; mk=$?; [ -e /nope ]; p=$?; (true > /nope2/f) 2>/dev/null; c=$?; cat /etc/group/x 2>&1 | grep -q "Not a directory"; n=$?; ls /etc/hostname/ >/dev/null 2>&1; s=$?; ln -s /etc /l; echo "mk=$mk parent=$((1-p)) creat=$c notdir=$((1-n)) slash=$s link=$(ls -ld /l/ | cut -c1)"'
expect "RLIMIT_NOFILE: EMFILE at the soft limit, inherited by children" 0 "default 1024, open EMFILE at 50, pipe EMFILE, dup2 EBADF, raise hard refused, child (50, 4096)" -- run -v "$GUEST" python:3.12-alpine python3 /t/nofile.py
expect "O_NOFOLLOW on a symlink is ELOOP" 0 "ELOOP" -- run python:3.12-alpine python3 -c 'import os,errno; os.symlink("/etc/hostname","/tmp/l"); r="opened"
try: os.open("/tmp/l", os.O_RDONLY|os.O_NOFOLLOW)
except OSError as e: r=errno.errorcode[e.errno]
print(r)'
expect "access(X_OK) as root needs an x bit; nobody needs its own bits" 0 "x:no w:no r:yes" -- run alpine sh -c 'touch /tmp/f; chmod 604 /tmp/f; [ -x /tmp/f ] && x=yes || x=no; su -s /bin/sh nobody -c "[ -w /tmp/f ] && w=yes || w=no; [ -r /tmp/f ] && r=yes || r=no; echo x:$x w:\$w r:\$r"'
expect "open() checks a file's mode for non-root (EACCES), root may write anything" 0 "ro-read ok ro-write EACCES shadow EACCES root ok" -- run alpine sh -c 'touch /tmp/ro && chmod 400 /tmp/ro && chown nobody /tmp/ro; su -s /bin/sh nobody -c "cat /tmp/ro >/dev/null && r=ok; (echo x >> /tmp/ro) 2>/dev/null && w=ok || w=EACCES; cat /etc/shadow >/dev/null 2>&1 && s=ok || s=EACCES; echo ro-read \$r ro-write \$w shadow \$s" | tr "\n" " "; echo x >> /tmp/ro && echo root ok'
expect "supplementary groups: su shows them in id" 0 "groups=1000(u1),1001(g1)" -- run alpine sh -c 'adduser -D u1; addgroup g1; addgroup u1 g1; su u1 -c id'
expect "/proc/self/maps lists mapped code" 0 "maps ok" -- run alpine sh -c 'grep -q " r-xp " /proc/self/maps && echo maps ok'
expect "pty: ttyname, slave opened twice" 0 "pts ok x" -- run python:3.12-alpine python3 -c 'import os,pty; m,s=pty.openpty(); n=os.ttyname(s); f=os.open(n, os.O_RDWR); os.write(f, b"x"); print("pts ok", os.read(m, 1).decode())'
expect "a signal cuts clock_nanosleep short (Python's time.sleep)" 0 "woke after 1" -- run python:3.12-alpine python3 -c 'import signal,sys,time; t=time.time(); signal.signal(signal.SIGALRM, lambda *_: (print("woke after", round(time.time()-t)), sys.exit(0))); signal.alarm(1); time.sleep(10)'
expect "#! script run through a link sees the link's name" 0 "/tmp/l ./l" -- run alpine sh -c 'printf "#!/bin/sh\necho \$0\n" > /tmp/s; chmod +x /tmp/s; ln -s /tmp/s /tmp/l; cd /tmp; echo $(/tmp/l) $(./l)'
expect "run -u / USER + HOME"      0 "65534:65533 HOME=/." -- run -u nobody:nogroup alpine sh -c 'echo $(id -u):$(id -g) HOME=$HOME.'
# lx build: an image from guest/buildctx/Dockerfile, then run (and the base image keeps its /etc/motd).
expect "lx build"                  0 "built lxtest-build:1" -- build -t lxtest-build:1 --build-arg FLAVOR=spicy guest/buildctx
expect "lx build: run the image"   0 "hello from lx build: spicy in /srv/app as builder, motd gone, owned.sh nobody" -- run lxtest-build:1
expect "lx build: base untouched"  0 "motd kept" -- run alpine sh -c 'test -e /etc/motd && echo motd kept'
expect "lx build: cache reused"    0 "(cached)" -- build -t lxtest-build:1 --build-arg FLAVOR=spicy guest/buildctx
expect "lx build: multi-stage"     0 "built lxtest-multi:1" -- build -t lxtest-multi:1 -f guest/buildctx/Dockerfile.multi guest/buildctx
expect "lx build: COPY --from"     0 "made in stage make, mode 600" -- run lxtest-multi:1
expect "lx images lists a build"   0 "lxtest-multi" -- images
expect "lx rmi"                    0 "removed lxtest-multi:1" -- rmi lxtest-multi:1
expect "lx rmi: gone from images"  127 "no such image" -- rmi lxtest-multi:1
# A daemon outlives the process that started it (redis --daemonize forks; its parent exits at once).
expect "redis: daemonized server"  0 "PONG" -- run redis:alpine sh -c 'redis-server --port 6390 --daemonize yes > /dev/null; sleep 2; redis-cli -p 6390 ping; redis-cli -p 6390 shutdown nosave'
# The image's own entrypoint (it drops to the redis user with setpriv, which reads the capability set).
expect "redis: stock entrypoint"   0 "PONG" -- run redis:alpine sh -c 'docker-entrypoint.sh redis-server --port 6392 --daemonize yes > /dev/null; sleep 2; redis-cli -p 6392 ping; redis-cli -p 6392 shutdown nosave'
expect "postgres: initdb, pg_ctl start, query, stop" 0 "answer 42" -- run -v "$GUEST" postgres:alpine sh /t/pgtest.sh
# node: musl's pthread_getattr_np measures the main stack with mremap; an HTTP round trip in one process.
expect "node: http server + client" 0 "node ok 2" -- run node:alpine node -e 'const h=require("http");const s=h.createServer((q,r)=>r.end("ok")).listen(0,()=>h.get("http://127.0.0.1:"+s.address().port,r=>{let d="";r.on("data",c=>d+=c);r.on("end",()=>{console.log("node",d,1+1);s.close()})}))'
# go run builds the standard library first, forking compilers from many threads at once.
expect "golang: go run (parallel forks)" 0 "go ok" -- run golang:alpine sh -c 'cd /tmp && printf "package main\nimport \"fmt\"\nfunc main(){fmt.Println(\"go ok\")}\n" > m.go && go run m.go'

# ---- volumes: data written in one container run is there in the next; the image stays untouched ----
VOL="$ROOT/rootfs/voltest-suite"
rm -rf rootfs/voltest-suite
img_sum() { (cd $STORE/library_alpine/latest/rootfs && find . -type f -print0 | sort -z | xargs -0 sha1sum | sha1sum); }
before=$(img_sum)
expect "volume: run 1 writes"   0 "wrote"       -- run -v "$VOL:/data" alpine sh -c 'echo run1 > /data/log && mkdir -p /data/d && echo n > /data/d/f && echo wrote'
expect "volume: run 2 reads + appends" 0 "run1" -- run -v "$VOL:/data" alpine sh -c 'cat /data/log /data/d/f && echo run2 >> /data/log'
expect "volume: run 3 sees both runs" 0 "run1 run2" -- run -v "$VOL:/data" alpine sh -c 'tr "\n" " " < /data/log'
[ "$(cat rootfs/voltest-suite/log 2>/dev/null | tr '\n' ' ')" = "run1 run2 " ] && ok "volume: host sees the data" || bad "volume: host sees the data"
expect "volume: read-only"      0 "Read-only file system" -- run -v "$VOL:/data:ro" alpine sh -c 'echo x > /data/new; cat /data/log >/dev/null'
# A named volume (lx's folder under rootfs/volumes, as lx compose makes) keeps Linux modes and owners.
rm -rf rootfs/volumes/lxtest-named; mkdir -p rootfs/volumes/lxtest-named
expect "named volume: modes kept" 0 "600 1:2" -- run -v "$ROOT/rootfs/volumes/lxtest-named:/data" alpine sh -c 'touch /data/f; chmod 600 /data/f; chown 1:2 /data/f; stat -c "%a %u:%g" /data/f'
expect "container layer: changes stay in the run" 0 "done" -- run alpine sh -c 'rm -f /etc/motd; echo x > /etc/new; echo done'
expect "container layer: next run starts pristine" 0 "pristine" -- run alpine sh -c '[ -f /etc/motd ] && [ ! -e /etc/new ] && echo pristine'
expect "GNU tar extracts into an image dir (its inode survives copy-up)" 0 "tar into image dir ok" -- run python:3.12 sh -c 'tar cf - -C /etc/default . | tar xf - -C /usr/local/share && echo "tar into image dir ok"'
expect "a dir moved over a deleted image tree doesn't show the image's old contents" 0 "hidden" -- run alpine sh -c 'mv /usr/share /tmp/gone && mkdir /usr/share && mkdir /tmp/d && mv /tmp/d /usr/share/apk && if [ -e /usr/share/apk/keys ]; then echo LEAK; else echo hidden; fi'
[ "$before" = "$(img_sum)" ] && ok "image store unchanged by containers" || bad "image store unchanged by containers"

# ---- repeated runs: every run must print OK; the trap fallback and FS faults must stay unused ----
repeat() { # repeat <name> <n> <lx args...>
  name=$1 n=$2; shift 2
  good=0 traps=0
  for i in $(seq "$n"); do
    if LX_PATCHLOG=1 timeout 120 $LX "$@" < /dev/null > "$OUT/rep" 2>&1 && grep -q " OK$" "$OUT/rep"; then
      good=$((good + 1))
    else
      echo "  run $i of $name failed (exit $?); its output:"; grep -v "^\[lx" "$OUT/rep" | tail -20 | sed 's/^/    /' # rare failures need it
    fi
    traps=$((traps + $(grep -o "[0-9]* fallback traps\|[0-9]* FS-base faults" "$OUT/rep" | awk '{s += $1} END {print s + 0}')))
  done
  if [ $good = "$n" ] && [ $traps = 0 ]; then ok "$name $good/$n"; else bad "$name $good/$n, $traps fallback traps/FS faults"; fi
}
repeat "pthreads (static)" "$REPEAT" rootfs /threads
repeat "pthreads (dynamic)" "$REPEAT" rootfs/alpine /threads-dyn
if [ $HAVE_GO = 1 ]; then repeat "Go runtime" "$REPEAT" rootfs /gotest; else note "Go test skipped (no tools/go)"; fi
repeat "guest stack untouched" 10 rootfs /stacktest

# Control: with rewriting off, the trap path must still be caught corrupting the stack.
if LX_NOJUMP=1 timeout 120 $LX rootfs /stacktest < /dev/null 2>&1 | grep -q "FAIL$"; then ok "stack test detects the trap path (control)"; else bad "stack test control did not detect corruption"; fi

direct=$($LX rootfs /sysbench < /dev/null | grep -o "[0-9]* ns")
trap_ns=$(LX_NOJUMP=1 $LX rootfs /sysbench < /dev/null | grep -o "[0-9]* ns")
echo "INFO  syscall cost: direct $direct, trap path $trap_ns"

# ---- network and signals ----
if [ "${QUICK:-0}" = 1 ]; then
  note "network tests skipped (QUICK=1)"
else
  if netstat -ano | grep "LISTENING" | grep -q ":80 "; then
    note "port 80 busy: nginx test skipped"
  else
    stuck=0 served=0 runs=5
    for i in $(seq $runs); do
      $LX run --name "lxnginx-$$" -p 80:80 nginx:alpine > "$OUT/nginx" 2>&1 < /dev/null & # named: only ours is stopped
      for t in $(seq 50); do
        [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 http://127.0.0.1/)" = 200 ] && break
        sleep 0.2
      done
      for r in $(seq 40); do
        [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1/)" = 200 ] && served=$((served + 1))
      done
      $LX stop "lxnginx-$$" > /dev/null
      wait
      grep -q "exited with code 137" "$OUT/nginx" && stuck=$((stuck + 1))
    done
    if [ $served = $((runs * 40)) ]; then ok "nginx: $served/$((runs * 40)) requests"; else bad "nginx: $served/$((runs * 40)) requests"; fi
    # A worker SIGKILLed at stop means it missed the shutdown (was: blocked in a shared accept(), fixed).
    if [ $stuck = 0 ]; then ok "nginx: $runs/$runs stops clean"; else bad "nginx: $stuck/$runs stops had a worker killed after ~3 s"; fi
  fi
  # These need the internet (DNS + example.com): one retry, so a host/VPN DNS hiccup shows as a warning.
  online() { # online <name> <text> <lx args...>
    name=$1 text=$2; shift 2
    for try in 1 2; do
      timeout 120 $LX "$@" < /dev/null > "$OUT/net" 2>&1
      if [ $? = 0 ] && grep -qF -- "$text" "$OUT/net"; then
        ok "$name"
        [ $try = 2 ] && note "$name passed only on retry (DNS/network hiccup?)"
        return
      fi
    done
    bad "$name"; tail -3 "$OUT/net"
  }
  online "wget (DNS + HTTP out)" "<title>Example Domain</title>" run alpine wget -qO- http://example.com
  online "python3 /script.py: sockets + threaded server" "20/20 responses" run -v "$GUEST" python:3.12-alpine python3 /t/nettest.py
  online "debian: sockets + threaded server" "20/20 responses" run -v "$GUEST" python:3.12 python3 /t/nettest.py
  online "debian: apt-get install jq" "jq says 6" run python:3.12 sh -c 'apt-get update -qq && apt-get install -qqy --no-install-recommends jq && echo "jq says $(echo "{\"lx\": [1, 2, 3]}" | jq ".lx | add")"'
  online "php-fpm: workers serve PHP over FastCGI" "php-fpm says 42" run wordpress:fpm-alpine sh -c 'php-fpm -D 2>/dev/null; printf "<?php echo \"php-fpm says \" . (6*7);" > /var/www/html/t.php; apk add -q fcgi > /dev/null 2>&1; sleep 1; SCRIPT_FILENAME=/var/www/html/t.php REQUEST_METHOD=GET cgi-fcgi -bind -connect 127.0.0.1:9000'
  # The package managers a Dockerfile's RUN lines use most.
  online "alpine: apk add" "jq says 1" run alpine sh -c 'apk add -q --no-cache jq && echo "jq says $(echo "{\"a\": 1}" | jq .a)"'
  online "pip install" "requests 2" run python:3.12-alpine sh -c 'pip install -q --root-user-action=ignore requests 2> /dev/null; python3 -c "import requests; print(\"requests\", requests.__version__)"'
  # --no-audit: the registry's audit endpoint can stall on npm's User-Agent (seen 2026-10-22); it's not what this tests.
  online "npm install" "left-pad --x" run node:alpine sh -c 'cd /tmp && npm init -y > /dev/null && npm install --no-audit --no-fund -s left-pad && node -e "console.log(\"left-pad\", require(\"left-pad\")(\"x\", 3, \"-\"))"'
  # glibc should stay off the trap path too: no fallback traps in a full threaded run. An FS-base fault is
  # NT dropping the FS base on a context switch at one of the few sites left unrewritten; it's recovered
  # by design (lost_fs_base), and thread suspensions (kicks) make it likelier, so it only warns.
  LX_PATCHLOG=1 timeout 120 $LX run -v "$GUEST" python:3.12 python3 /t/nettest.py < /dev/null > "$OUT/deb" 2>&1
  if ! grep -q " 0 fallback traps;" "$OUT/deb"; then bad "debian: trap fallbacks taken"; grep "exit:" "$OUT/deb"
  elif grep -q " 0 FS-base faults" "$OUT/deb"; then ok "debian: no trap fallbacks"
  else note "debian: no trap fallbacks, but FS-base faults (recovered)"; grep "exit:" "$OUT/deb"; fi
fi

stop_test() { # stop_test <mode> <expected exit> [text]
  # The tag (an argument sigtest.sh ignores) finds this container in `lx ps`, among any others running.
  tag=stoptest-$$-$1
  $LX run -v "$GUEST" alpine sh /t/sigtest.sh "$1" "$tag" < /dev/null > "$OUT/stop" 2>&1 &
  job=$!
  # Wait until the container is registered (a busy machine can take longer than any fixed sleep), then
  # give the script a moment to install its trap.
  mine() { $LX ps | awk -v t="$tag" 'index($0, t) {print $1; exit}'; }
  for _ in $(seq 100); do [ -n "$(mine)" ] && break; sleep 0.1; done
  sleep 1
  $LX stop "$(mine)" > /dev/null
  wait $job
  code=$?
  if [ $code = "$2" ] && { [ -z "${3:-}" ] || grep -qF -- "$3" "$OUT/stop"; }; then ok "lx stop: $1 -> $code"; else bad "lx stop: $1 -> $code (want $2)"; fi
}
stop_test handler 7 "got TERM"
stop_test busy 143
stop_test exec 143

# lx stop -t: a container that ignores SIGTERM is killed after the given time (1 s here, not 10).
tag=stopt-$$
$LX run alpine sh -c "trap '' TERM; while :; do sleep 0.1; done # $tag" < /dev/null > /dev/null 2>&1 &
job=$!
for _ in $(seq 100); do cpid=$($LX ps | awk -v t="$tag" 'index($0, t) {print $1; exit}'); [ -n "$cpid" ] && break; sleep 0.1; done
sleep 1
start=$(date +%s); $LX stop -t 1 "$cpid" > /dev/null 2>&1; wait $job; code=$?; took=$(( $(date +%s) - start ))
if [ $code = 137 ] && [ $took -le 5 ]; then ok "lx stop -t 1"; else bad "lx stop -t 1: exit $code after ${took}s"; fi

# lx exec: a command in a running container sees its files, env and directory (here as another user),
# and an exec'd process ends with the container.
tag=exectest-$$
$LX run -e GREETING=hi -w /tmp alpine sh -c "echo inside > /tmp/marker; sleep 60 # $tag" < /dev/null > /dev/null 2>&1 &
job=$!
for _ in $(seq 100); do cpid=$($LX ps | awk -v t="$tag" 'index($0, t) {print $1; exit}'); [ -n "$cpid" ] && break; sleep 0.1; done
sleep 1
out=$($LX exec -u nobody "$cpid" sh -c 'echo "$(cat /tmp/marker) $GREETING $(pwd) $(id -u)"' 2>&1)
$LX exec "$cpid" sleep 60 < /dev/null > /dev/null 2>&1 &
ejob=$!
sleep 1
$LX stop "$cpid" > /dev/null
wait $job
start=$(date +%s); wait $ejob; took=$(( $(date +%s) - start ))
if [ "$out" = "inside hi /tmp 65534" ] && [ $took -lt 10 ]; then ok "lx exec into a running container"; else bad "lx exec: got '$out', exec'd process outlived the container by ${took}s"; fi

# lx run -d returns at once with the pid (even inside $(...)), the container runs on, lx logs has its output.
start=$(date +%s)
dpid=$($LX run -d alpine sh -c 'echo started; sleep 60')
took=$(( $(date +%s) - start ))
sleep 2
logs=$($LX logs "$dpid" 2>&1)
listed=$($LX ps | awk -v p="$dpid" '$1 == p' | wc -l)
$LX stop "$dpid" > /dev/null 2>&1
if [ $took -lt 5 ] && [ "$listed" = 1 ] && [ "$logs" = started ]; then ok "lx run -d + lx logs"; else bad "lx run -d: ${took}s, listed $listed, logs '$logs'"; fi

# --name: exec and stop by name; a second container can't take a name in use.
nm=lxname-$$
$LX run -d --name "$nm" alpine sleep 60 > /dev/null
sleep 2
out=$($LX exec "$nm" echo by-name 2>&1)
dup=$($LX run --name "$nm" alpine true 2>&1)
$LX stop "$nm" > /dev/null 2>&1
if [ "$out" = by-name ] && echo "$dup" | grep -q "already in use"; then ok "lx run --name"; else bad "--name: exec '$out', duplicate '$dup'"; fi

# lx compose: a built service reaches another by its service name; down stops both.
CF=guest/composetest/compose.yaml
$LX compose -f $CF up -d > "$OUT/compose" 2>&1
for _ in $(seq 40); do got=$($LX exec composetest-cache redis-cli -p 6391 get greeting 2>/dev/null); [ "$got" = "hello from app" ] && break; sleep 0.5; done
$LX compose -f $CF down > /dev/null 2>&1
left=$($LX ps | grep -c composetest)
if [ "$got" = "hello from app" ] && [ "$left" = 0 ]; then ok "lx compose up/down"; else bad "lx compose: got '$got', $left left"; tail -3 "$OUT/compose"; fi

# Each container has its own loopback address: two can listen on the same unpublished port.
for n in A B; do $LX run -d --name "lxip$n-$$" busybox sh -c "mkdir /w; echo $n > /w/i; httpd -f -p 8088 -h /w" < /dev/null > /dev/null 2>&1; done
for _ in $(seq 40); do
  got=$($LX exec "lxipA-$$" wget -qO- http://127.0.0.1:8088/i 2>/dev/null)$($LX exec "lxipB-$$" wget -qO- http://localhost:8088/i 2>/dev/null)
  [ "$got" = "AB" ] && break; sleep 0.5
done
$LX stop "lxipA-$$" > /dev/null 2>&1; $LX stop "lxipB-$$" > /dev/null 2>&1
if [ "$got" = "AB" ]; then ok "two containers on the same port"; else bad "two containers on the same port: got '$got'"; fi
expect "netlink: ip addr lists lo (Go's net.Interfaces, getifaddrs)" 0 "inet 127.0.0.1/8 scope host lo" -- run alpine ip addr
expect "SIOCGIFINDEX / SIOCGIFNAME (musl's if_nametoindex)" 0 "lo is 1 lo" -- run python:3.12-alpine python3 -c 'import socket; print("lo is", socket.if_nametoindex("lo"), socket.if_indextoname(1))'

# Another container's published port is reached at its container port (web:80 of a -p 8098:80 service).
$LX run -d --name "lxpp-$$" --ip 127.77.0.1 -p 8098:8088 busybox sh -c "mkdir /w; echo pp > /w/i; httpd -f -p 8088 -h /w" < /dev/null > /dev/null 2>&1
for _ in $(seq 40); do got=$($LX run busybox wget -qO- http://127.77.0.1:8088/i 2>/dev/null); [ "$got" = pp ] && break; sleep 0.5; done
$LX stop "lxpp-$$" > /dev/null 2>&1
if [ "$got" = pp ]; then ok "another container's published port at its container port"; else bad "another container's published port: got '$got'"; fi

# lx compose up in the foreground: prefixed output of every service, back when all have ended.
expect "lx compose up (foreground)" 0 "b | hi from b" -- compose -f guest/composefg/compose.yaml up

# Only this checkout's lx.exe (every lx of a container runs it): another worktree's containers may run.
exe=$(cygpath -w "$ROOT/target/release/lx.exe")
left=$(powershell -NoProfile -Command "@(Get-CimInstance Win32_Process -Filter \"Name='lx.exe'\" | Where-Object ExecutablePath -eq '$exe').Count" | tr -d '\r')
[ "$left" = 0 ] && ok "no lx processes left" || bad "$left lx processes left running"

echo "---- $pass passed, $fail failed, $warn warnings"
[ $fail = 0 ]
