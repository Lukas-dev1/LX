#!/bin/sh
# Shaped like a typical Docker ENTRYPOINT script: setup, pipelines, background work, then exec.
set -e
log() { echo "[entrypoint] $*"; }
log "starting as uid $(id -u) in $(pwd), pid $$"
mkdir -p /tmp/app && cd /tmp/app
printf 'b\na\nc\na\n' > items
log "unique items: $(sort items | uniq | tr '\n' ' ')"
count=0
ls /etc | while read -r f; do count=$((count + 1)); if [ "$count" -eq 3 ]; then log "third entry in /etc: $f"; fi; done
sleep 1 & bg=$!
log "background job $bg started"
wait "$bg" && log "background job finished"
echo /etc/os-release | xargs grep -c '='
export APP_MODE=production
exec env | grep '^APP_MODE='
