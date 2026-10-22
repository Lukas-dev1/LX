#!/bin/sh
# The container's other processes show up in /proc: ps, pidof, pgrep, and their files.
sleep 30 &
s=$!
sh -c 'exec sleep 31' &
sleep 1
ps -o pid,ppid,comm,args | grep -v "ps -o" | sed 's/  */ /g'
echo "pidof: $(pidof sleep | wc -w) sleeps; pgrep: $(pgrep -f 'sleep 31')"
echo "comm=$(cat /proc/$s/comm) cmd=$(tr '\0' ' ' < /proc/$s/cmdline) ppid=$(awk '{print $4}' /proc/$s/stat) exe=$(readlink /proc/$s/exe)"
kill $s
sleep 0.5
test -d /proc/$s && echo "still listed after exit" || echo "gone after exit"
