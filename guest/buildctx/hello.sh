#!/bin/sh
# Prints what the suite checks: env, ARG baked in by RUN, workdir, user, a deleted file, --chown.
echo "$GREETING $1: $(cat flavor) in $(pwd) as $(id -un), motd $(test -e /etc/motd && echo kept || echo gone), owned.sh $(stat -c %U /tmp/owned.sh)"
