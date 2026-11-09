#!/bin/sh
# Run Squid locally as an explicit proxy on 127.0.0.1:3128 using the LeechProxy helper.
# For testing on a laptop: no interception, no certificates, nothing to install but squid.
#   brew install squid      # or: apt install squid
#   ./run-local.sh
# Then: curl -x http://127.0.0.1:3128 -I https://reddit.com   (or set it as the browser/OS proxy)
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
DATA=${LEECHPROXY_DATA:-$HOME/.local/share/leechproxy}
PORT=${LEECHPROXY_PORT:-3128}
UI=${LEECHPROXY_UI:-http://127.0.0.1:8080}
PY=$(command -v python3)
RUN="$DATA/squid"
mkdir -p "$RUN"

cat > "$RUN/squid.conf" <<EOF
http_port 127.0.0.1:$PORT

external_acl_type leechproxy ttl=0 negative_ttl=0 children-max=1 children-startup=1 concurrency=50 \\
    %ssl::>sni %DST \\
    /usr/bin/env LEECHPROXY_DATA=$DATA PYTHONPATH=$HERE $PY -m leechproxy.acl_helper
acl leech_blocked external leechproxy

acl SSL_ports port 443
acl CONNECT method CONNECT
http_access deny CONNECT !SSL_ports
http_access deny leech_blocked
http_access allow localhost
http_access deny all
deny_info $UI/blocked?host=%H&msg=%o leech_blocked

cache deny all
cache_mem 8 MB
pid_filename $RUN/squid.pid
access_log stdio:$RUN/access.log squid
cache_log $RUN/cache.log
coredump_dir $RUN
pconn_timeout 30 seconds
client_idle_pconn_timeout 30 seconds
EOF

squid -k parse -f "$RUN/squid.conf" >/dev/null 2>&1 || { squid -k parse -f "$RUN/squid.conf"; exit 1; }
echo "Squid on 127.0.0.1:$PORT (logs: $RUN/access.log, $RUN/cache.log). Ctrl-C to stop."
exec squid -N -d1 -f "$RUN/squid.conf"
