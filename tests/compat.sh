#!/bin/sh
# Compatibility sweep: popular images, each with one smoke test, run one at a time.
# `sh tests/compat.sh [name-filter]` from the repo root (Git Bash). Prints a table and writes it to
# $OUT (default: compat-results.md in the repo root, not committed).
# An image this run pulled is removed again afterwards unless the suite uses it (keeps disk use flat).
# Each line: name | image | text the output must contain | lx run args (after the image: a command).
cd "$(dirname "$0")/.." || exit 1
LX=${LX:-./target/release/lx.exe}
OUT=${OUT:-compat-results.md}
T=${T:-180}
SUITE_IMAGES=" alpine:latest python:3.12-alpine python:3.12 nginx:alpine httpd:alpine eclipse-temurin:21-jre-alpine redis:alpine postgres:alpine node:alpine golang:alpine mariadb:11 rabbitmq:3-alpine mongo:7 wordpress:fpm-alpine "
export MSYS_NO_PATHCONV=1

# A service started in the background, polled from inside the container until it answers.
# bg <start command> <check command>
bg() { printf '%s > /tmp/svc.log 2>&1 & for i in $(seq 1 120); do %s && break; sleep 1; done; echo; tail -2 /tmp/svc.log' "$1" "$2"; }

cat > /tmp/lx-compat-list.txt <<'EOF'
alpine|alpine:latest|Alpine Linux|sh -c 'cat /etc/os-release | head -1'
busybox|busybox:latest|compat-ok|sh -c 'echo compat-ok'
debian|debian:bookworm-slim|compat-ok|sh -c 'apt-get --version > /dev/null && echo compat-ok'
ubuntu|ubuntu:24.04|compat-ok|sh -c 'ls /usr/bin | wc -l > /dev/null && echo compat-ok'
fedora|fedora:latest|compat-ok|sh -c 'rpm -q bash > /dev/null && echo compat-ok'
python|python:3.12-alpine|3628800|python3 -c 'import math, json, sqlite3, ssl; print(math.factorial(10))'
node|node:alpine|node-ok 6|node -e 'console.log("node-ok", [1,2,3].reduce((a,b)=>a+b))'
ruby|ruby:alpine|ruby-ok 6|ruby -e 'puts "ruby-ok #{[1,2,3].sum}"'
php|php:cli-alpine|php-ok 6|php -r 'echo "php-ok ", array_sum([1,2,3]), "\n";'
perl|perl:slim|perl-ok 6|perl -e 'my $s=0; $s+=$_ for 1..3; print "perl-ok $s\n"'
golang|golang:alpine|go-ok|sh -c 'cd /tmp && printf "package main\nimport \"fmt\"\nfunc main(){fmt.Println(\"go-ok\")}\n" > m.go && go run m.go'
java|eclipse-temurin:21-jre-alpine|OpenJDK|java -version
elixir|elixir:alpine|elixir-ok 6|elixir -e 'IO.puts("elixir-ok #{Enum.sum([1,2,3])}")'
nginx|nginx:alpine|Welcome to nginx|SVC:nginx -g 'daemon off;'|wget -qO- http://127.0.0.1/
httpd|httpd:alpine|It works|SVC:httpd-foreground|wget -qO- http://127.0.0.1/
caddy|caddy:alpine|Caddy|SVC:caddy run --config /etc/caddy/Caddyfile --adapter caddyfile|wget -qO- http://127.0.0.1/
haproxy|haproxy:alpine|haproxy-ok|SVC:printf 'defaults\n mode http\n timeout connect 5s\n timeout client 5s\n timeout server 5s\nfrontend f\n bind 127.0.0.1:8099\n http-request return status 200 content-type text/plain string haproxy-ok\n' > /tmp/h.cfg && haproxy -f /tmp/h.cfg|wget -qO- http://127.0.0.1:8099/
traefik|traefik:latest|Version|SVC:traefik --api.insecure=true --entrypoints.web.address=:8088|wget -qO- http://127.0.0.1:8080/api/version
redis|redis:alpine|PONG|SVC:redis-server --port 6395|redis-cli -p 6395 ping
memcached|memcached:alpine|STAT pid|SVC:memcached -p 11299|printf "stats\r\nquit\r\n" | nc 127.0.0.1 11299
postgres|postgres:alpine|answer 42|sh -c 'su postgres -c "initdb -D /tmp/pg > /dev/null && pg_ctl -D /tmp/pg -o \"-p 5499\" -l /tmp/pg.log start > /dev/null && sleep 2 && psql -p 5499 -tAc \"select 40+2\" | sed s/^/answer\ / ; pg_ctl -D /tmp/pg stop > /dev/null"'
mariadb|mariadb:11|hello|-e MARIADB_ROOT_PASSWORD=x -p 13307:3306 mariadb:11 sh -c 'docker-entrypoint.sh mariadbd > /tmp/log 2>&1 & for i in $(seq 1 100); do grep -q "init process done" /tmp/log && mariadb -uroot -px -e "select 1" > /dev/null 2>&1 && break; sleep 1; done; mariadb -uroot -px -Nse "select \"hello\""; mariadb-admin -uroot -px shutdown; wait'
mongo|mongo:7|sum=42|-p 27019:27017 mongo:7 sh -c 'mongod --bind_ip_all > /tmp/log 2>&1 & for i in $(seq 1 60); do grep -q "Waiting for connections" /tmp/log && break; sleep 1; done; mongosh --quiet --eval "db.t.insertOne({a:42}); print(\"sum=\" + db.t.findOne().a)"; mongosh --quiet admin --eval "db.shutdownServer()" > /dev/null 2>&1; wait'
rabbitmq|rabbitmq:3-alpine|sum=6|erl -noshell -eval 'io:format("sum=~p~n",[lists:sum([1,2,3])]), halt().'
mosquitto|eclipse-mosquitto:latest|compat-msg|sh -c 'mosquitto -p 1899 > /dev/null 2>&1 & sleep 1; mosquitto_sub -p 1899 -t t -C 1 & sleep 1; mosquitto_pub -p 1899 -t t -m compat-msg; wait %2'
prometheus|prom/prometheus:latest|Ready|SVC:prometheus --config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/tmp/prom|wget -qO- http://127.0.0.1:9090/-/ready
grafana|grafana/grafana:latest|"database": "ok"|SVC:/run.sh|wget -qO- http://127.0.0.1:3000/api/health
influxdb|influxdb:2-alpine|"status": "pass"|SVC:influxd --bolt-path /tmp/b.db --engine-path /tmp/e|wget -qO- http://127.0.0.1:8086/health
consul|hashicorp/consul:latest|alive|SVC:consul agent -dev -client 127.0.0.1|consul members
vault|hashicorp/vault:latest|"initialized":true|SVC:vault server -dev -dev-listen-address=127.0.0.1:8200|wget -qO- http://127.0.0.1:8200/v1/sys/health
registry|registry:2|{}|SVC:registry serve /etc/docker/registry/config.yml|wget -qO- http://127.0.0.1:5000/v2/
minio|quay.io/minio/minio:latest|200|SVC:minio server /tmp/data --address 127.0.0.1:9000|curl -s -o /dev/null -w %{http_code} http://127.0.0.1:9000/minio/health/live
gitea|gitea/gitea:latest|"status": "pass"|SVC:/usr/bin/entrypoint|wget -qO- http://127.0.0.1:3000/api/healthz
vaultwarden|vaultwarden/server:latest|20|SVC:/start.sh|curl -s http://127.0.0.1:80/alive
adminer|adminer:latest|Login - Adminer|SVC:php -S 127.0.0.1:8080 -t /var/www/html|wget -qO- http://127.0.0.1:8080/
wordpress-fpm|wordpress:fpm-alpine|ready to handle connections|sh -c 'php-fpm -F 2>&1 & sleep 3; kill %1'
tomcat|tomcat:10-jre21|Server version|catalina.sh version
EOF

printf '| image | result | seconds | detail |\n|---|---|---|---|\n' > "$OUT"
pass=0 fail=0
while IFS='|' read -r name image expect rest; do
  [ -n "$1" ] && case "$name" in *"$1"*) ;; *) continue ;; esac
  # The pulled-by-us test is "the image dir doesn't exist yet".
  pulled=0
  "$LX" images 2>/dev/null | grep -q "^${image%%:*}[[:space:]]*${image#*:}\b" || pulled=1
  start=$(date +%s)
  case "$rest" in
    SVC:*) svc=${rest#SVC:}; cmd=$(bg "${svc%%|*}" "${svc#*|}"); log=$(timeout "$T" "$LX" run --entrypoint "" "$image" sh -c "$cmd" < /dev/null 2>&1) ;; # our sh -c, not the image's entrypoint
    -*) log=$(eval "timeout $T $LX run $rest" < /dev/null 2>&1) ;;
    *) log=$(eval "timeout $T $LX run $image $rest" < /dev/null 2>&1) ;;
  esac
  code=$? secs=$(( $(date +%s) - start ))
  if printf '%s' "$log" | grep -qF -- "$expect"; then
    res=PASS pass=$((pass + 1)) detail=""
  else
    res=FAIL fail=$((fail + 1)) detail="exit $code: $(printf '%s' "$log" | grep -v 'unimplemented syscall' | tail -1 | tr '|' '/' | cut -c1-100)"
  fi
  printf '| %s (`%s`) | %s | %s | %s |\n' "$name" "$image" "$res" "$secs" "$detail" | tee -a "$OUT"
  case "$SUITE_IMAGES" in *" $image "*) ;; *) [ $pulled = 1 ] && "$LX" rmi "$image" > /dev/null 2>&1 ;; esac
done < /tmp/lx-compat-list.txt
printf '\n%s passed, %s failed\n' "$pass" "$fail" | tee -a "$OUT"
