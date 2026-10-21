#!/bin/sh
# lx test suite. From the repo root, in Git Bash:   sh tests/run.sh
#   REPEAT=n   repetitions of the multithreaded tests (default 20)
#   QUICK=1    skip the network tests (nginx, wget, python)
#
# Builds lx and the guest programs, prepares rootfs/ (an Alpine test rootfs plus pulled images), and runs
# everything. Guest scripts live in guest/ and are copied into the images only for the duration of the
# run (removed again on exit), so no image in the store is modified by hand.
set -u
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1
ROOT=$(pwd -W)
export RUSTUP_HOME="$ROOT/tools/rust/rustup" CARGO_HOME="$ROOT/tools/rust/cargo"
CARGO=tools/rust/cargo/bin/cargo.exe
ZIG=tools/zig-x86_64-windows-0.15.2/zig.exe
GO=tools/go/bin/go.exe
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
cc_static 2 rootfs/sysbench guest/sysbench.c
cc_static 1 rootfs/alpine/deepstack guest/deepstack.c
cc_dynamic rootfs/alpine/threads-dyn guest/threads.c
cc_dynamic rootfs/alpine/dltest guest/dltest.c
cp guest/regress.sh guest/entrypoint.sh rootfs/alpine/
HAVE_GO=0
if [ -x $GO ]; then
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOTOOLCHAIN=local GOTELEMETRY=off GO111MODULE=off \
    GOCACHE="$ROOT/tools/gocache" GOPATH="$ROOT/tools/gopath" $GO build -o rootfs/gotest ./guest/gotest || die "go build"
  HAVE_GO=1
fi

# ---- images: pull what's missing; guest scripts reach containers through a read-only volume ----
for img in alpine:latest python:3.12-alpine nginx:alpine; do
  dir=$STORE/library_${img%%:*}/${img#*:}/rootfs
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
expect "regress.sh"       0   "ALL OK"                   -- rootfs/alpine /regress.sh
expect "entrypoint.sh"    0   "APP_MODE=production"      -- rootfs/alpine /entrypoint.sh
expect "deep stack + fork" 0  "child exit 3"             -- rootfs/alpine /deepstack
expect "dlopen while threads run" 0 " OK"                -- rootfs/alpine /dltest

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
      $LX run nginx:alpine > "$OUT/nginx" 2>&1 < /dev/null &
      for t in $(seq 50); do
        [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 http://127.0.0.1/)" = 200 ] && break
        sleep 0.2
      done
      for r in $(seq 40); do
        [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1/)" = 200 ] && served=$((served + 1))
      done
      $LX stop "$($LX ps | awk 'NR==2 {print $1}')" > /dev/null
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
fi

stop_test() { # stop_test <mode> <expected exit> [text]
  $LX run -v "$GUEST" alpine sh /t/sigtest.sh "$1" < /dev/null > "$OUT/stop" 2>&1 &
  job=$!
  # Wait until the container is registered (a busy machine can take longer than any fixed sleep), then
  # give the script a moment to install its trap.
  for _ in $(seq 100); do [ -n "$($LX ps | awk 'NR==2 {print $1}')" ] && break; sleep 0.1; done
  sleep 1
  $LX stop "$($LX ps | awk 'NR==2 {print $1}')" > /dev/null
  wait $job
  code=$?
  if [ $code = "$2" ] && { [ -z "${3:-}" ] || grep -qF -- "$3" "$OUT/stop"; }; then ok "lx stop: $1 -> $code"; else bad "lx stop: $1 -> $code (want $2)"; fi
}
stop_test handler 7 "got TERM"
stop_test busy 143
stop_test exec 143

left=$(tasklist //FI "IMAGENAME eq lx.exe" 2> /dev/null | grep -c lx.exe)
[ "$left" = 0 ] && ok "no lx processes left" || bad "$left lx processes left running"

echo "---- $pass passed, $fail failed, $warn warnings"
[ $fail = 0 ]
