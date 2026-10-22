#!/bin/sh
# Waits for the cache service (by its name), stores a value there, then stays up.
for i in $(seq 50); do redis-cli -h "$CACHE" -p 6391 ping > /dev/null 2>&1 && break; sleep 0.2; done
redis-cli -h "$CACHE" -p 6391 set greeting "hello from app" > /dev/null
echo "app wrote to $CACHE"
exec sleep 600
