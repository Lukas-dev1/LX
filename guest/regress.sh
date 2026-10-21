#!/bin/sh
# Guest-side regression checks for lx (run inside an Alpine rootfs). Prints one line per check, then a summary.
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2', want '$3'"; fail=1; fi; }

check "subshell"   "$(echo sub)"                                   "sub"
check "pipeline"   "$(printf 'b\na\nb\n' | sort | uniq | tr '\n' ' ')" "a b "
check "exit codes" "$(sh -c 'exit 42'; echo $?)"                   "42"
check "ppid"       "$(sh -c 'echo $PPID')"                          "$$"
check "trap"       "$(sh -c 'trap "echo caught" USR1; kill -USR1 $$; echo after' | tr '\n' ' ')" "caught after "
check "default TERM" "$(sh -c 'kill -TERM $$; echo no'; echo $?)"  "143"
sleep 1 & bg=$!
wait "$bg"
check "bg + wait"  "$?"                                             "0"
check "dev/null"   "$(echo x > /dev/null; cat /dev/null | wc -c)"   "0"
check "files"      "$(mkdir -p /tmp/r && echo d > /tmp/r/f && ln -sf f /tmp/r/l && readlink /tmp/r/l && cat /tmp/r/l; rm -r /tmp/r)" "f
d"
[ "$fail" = 0 ] && echo "ALL OK" || echo "SOME FAILED"
exit "$fail"
