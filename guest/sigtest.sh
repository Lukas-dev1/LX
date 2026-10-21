#!/bin/sh
# Container for the lx stop tests. $1 picks the behaviour:
#   handler  handle TERM (prints "got TERM", exits 7)
#   busy     spin without syscalls (default action must still end it: 143)
#   exec     exec into sleep (the signal must reach the exec'd program: 143)
case "$1" in
  handler) trap 'echo "got TERM"; exit 7' TERM; while :; do sleep 0.1; done ;;
  busy) while :; do :; done ;;
  exec) exec sleep 1000 ;;
esac
