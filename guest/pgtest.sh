#!/bin/sh
# postgres:alpine the way people run it by hand: initdb as the postgres user, pg_ctl start (it daemonizes
# the server and waits for the pid it forked to report ready), a query, pg_ctl stop.
set -e
mkdir -p /tmp/pg && chown postgres /tmp/pg
su postgres -c "initdb -D /tmp/pg -A trust" > /tmp/init.log 2>&1 || { tail -5 /tmp/init.log; exit 1; }
su postgres -c "pg_ctl -D /tmp/pg -l /tmp/pg.log -o '-p 5440 -k /tmp' -w -t 30 start"
psql -h /tmp -p 5440 -U postgres -Atc "select 'answer ' || 6 * 7"
su postgres -c "pg_ctl -D /tmp/pg -m fast -w stop"
