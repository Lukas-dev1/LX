#!/bin/sh
# The container's first process is pid 1 (parent 0); its children see parent 1; pid 1 can be signalled,
# and /proc/1 is it.
trap 'got=usr1' USR1
child=$(sh -c 'echo $PPID; kill -USR1 1')
sleep 0.2
[ "$$ $PPID $child $got" = "1 0 1 usr1" ] && kill -0 1 && test -d /proc/1 && echo "pid1 OK" || echo "pid1 FAIL: $$ $PPID $child $got"
