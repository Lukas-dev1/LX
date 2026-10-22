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
cc_static 2 rootfs/sysbench guest/sysbench.c
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
for img in alpine:latest python:3.12-alpine python:3.12 nginx:alpine httpd:alpine eclipse-temurin:21-jre-alpine redis:alpine postgres:alpine node:alpine golang:alpine mariadb:11 rabbitmq:3-alpine; do
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
expect "crash -> SIGSEGV" 139 "guest fault"              -- rootfs /stress crash
expect "signalfd in epoll, woken by a child's signal" 0 "OK" -- rootfs /sigfdtest
expect "regress.sh"       0   "ALL OK"                   -- rootfs/alpine /regress.sh
expect "entrypoint.sh"    0   "APP_MODE=production"      -- rootfs/alpine /entrypoint.sh
expect "deep stack + fork" 0  "child exit 3"             -- rootfs/alpine /deepstack
expect "dlopen while threads run" 0 " OK"                -- rootfs/alpine /dltest
# Debian (glibc) image: the three usual ways a Python image starts.
expect "debian: python3 -c"         0 "hi"               -- run python:3.12 python3 -c "print('hi')"
expect "debian: python3 /script.py" 0 "script ran: 3.12" -- run -v "$GUEST" python:3.12 python3 /t/hello.py
expect "debian: AF_UNIX echo (path + abstract)" 0 "OK" -- run -v "$GUEST" python:3.12 python3 /t/unixtest.py
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
expect "short timed waits sleep ~1 ms (no spin, no 15 ms tick)" 0 "OK" -- run -v "$GUEST" python:3.12 python3 /t/timedwait.py
expect "erlang: VM, 1000 processes, os:cmd port" 0 "sum=6 procs=1000 port-ok" -- run rabbitmq:3-alpine erl -noshell -eval 'io:format("sum=~p procs=~p ~s~n",[lists:sum([1,2,3]), length([spawn(fun() -> ok end) || _ <- lists:seq(1,1000)]), os:cmd("echo port-ok")]), halt().'
expect "/proc/self/fd lists open fds" 0 "0 1 2 3" -- run alpine sh -c 'ls /proc/self/fd | tr "\n" " "'
expect "SIGSEGV reaches the guest's handler" 139 "Fatal Python error: Segmentation fault" -- run python:3.12 python3 -X faulthandler -c "import ctypes; ctypes.string_at(0)"
expect "httpd: config check (ErrorLog /proc/self/fd/2)" 0 "Syntax OK" -- run httpd:alpine httpd -t
expect "java -version (HotSpot's SIGSEGV use)" 0 "OpenJDK 64-Bit Server VM" -- run eclipse-temurin:21-jre-alpine java -version
# mariadb through its official entrypoint (gosu, install-db, InnoDB). -p: the host may run its own 3306.
expect "mariadb: entrypoint + InnoDB query" 0 "hello,lx" -- run -p 13306:3306 -e MARIADB_ROOT_PASSWORD=x mariadb:11 sh -c 'docker-entrypoint.sh mariadbd > /tmp/log 2>&1 & for i in $(seq 1 100); do mariadb -uroot -px -e "select 1" > /dev/null 2>&1 && break; sleep 1; done; mariadb -uroot -px -e "create database t; create table t.a (id int primary key, s text) engine=innodb; insert into t.a values (1, \"hello\"), (2, \"lx\"); select group_concat(s) from t.a"; mariadb-admin -uroot -px shutdown; wait'
# -e adds and overrides the image's env (PYTHON_VERSION is set by the image), -w sets the directory.
expect "run -e / -w"               0 "A=1 V=9 /usr" -- run -e A=1 -e PYTHON_VERSION=9 -w /usr python:3.12-alpine sh -c 'echo A=$A V=$PYTHON_VERSION $(pwd)'
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
expect "container layer: changes stay in the run" 0 "done" -- run alpine sh -c 'rm -f /etc/motd; echo x > /etc/new; echo done'
expect "container layer: next run starts pristine" 0 "pristine" -- run alpine sh -c '[ -f /etc/motd ] && [ ! -e /etc/new ] && echo pristine'
[ "$before" = "$(img_sum)" ] && ok "image store unchanged by containers" || bad "image store unchanged by containers"

# ---- repeated runs: every run must print OK; the trap fallback and FS faults must stay unused ----
repeat() { # repeat <name> <n> <lx args...>
  name=$1 n=$2; shift 2
  good=0 traps=0
  for i in $(seq "$n"); do
    LX_PATCHLOG=1 timeout 120 $LX "$@" < /dev/null > "$OUT/rep" 2>&1 && grep -q " OK$" "$OUT/rep" && good=$((good + 1))
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
      $LX run --name "lxnginx-$$" nginx:alpine > "$OUT/nginx" 2>&1 < /dev/null & # named: only ours is stopped
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
  # The package managers a Dockerfile's RUN lines use most.
  online "alpine: apk add" "jq says 1" run alpine sh -c 'apk add -q --no-cache jq && echo "jq says $(echo "{\"a\": 1}" | jq .a)"'
  online "pip install" "requests 2" run python:3.12-alpine sh -c 'pip install -q --root-user-action=ignore requests 2> /dev/null; python3 -c "import requests; print(\"requests\", requests.__version__)"'
  online "npm install" "left-pad --x" run node:alpine sh -c 'cd /tmp && npm init -y > /dev/null && npm install -s left-pad && node -e "console.log(\"left-pad\", require(\"left-pad\")(\"x\", 3, \"-\"))"'
  # glibc should stay off the trap path too: no fallback traps, no FS faults in a full threaded run.
  LX_PATCHLOG=1 timeout 120 $LX run -v "$GUEST" python:3.12 python3 /t/nettest.py < /dev/null > "$OUT/deb" 2>&1
  if grep -q " 0 fallback traps;.* 0 FS-base faults" "$OUT/deb"; then ok "debian: no trap fallbacks"; else bad "debian: trap fallbacks taken"; grep "exit:" "$OUT/deb"; fi
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
$LX compose -f $CF up > "$OUT/compose" 2>&1
for _ in $(seq 40); do got=$($LX exec composetest-cache redis-cli -p 6391 get greeting 2>/dev/null); [ "$got" = "hello from app" ] && break; sleep 0.5; done
$LX compose -f $CF down > /dev/null 2>&1
left=$($LX ps | grep -c composetest)
if [ "$got" = "hello from app" ] && [ "$left" = 0 ]; then ok "lx compose up/down"; else bad "lx compose: got '$got', $left left"; tail -3 "$OUT/compose"; fi

# Only this checkout's lx.exe (every lx of a container runs it): another worktree's containers may run.
exe=$(cygpath -w "$ROOT/target/release/lx.exe")
left=$(powershell -NoProfile -Command "@(Get-CimInstance Win32_Process -Filter \"Name='lx.exe'\" | Where-Object ExecutablePath -eq '$exe').Count" | tr -d '\r')
[ "$left" = 0 ] && ok "no lx processes left" || bad "$left lx processes left running"

echo "---- $pass passed, $fail failed, $warn warnings"
[ $fail = 0 ]
