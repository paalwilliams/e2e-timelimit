#!/bin/sh
# LeechProxy on macOS: runs the web UI + Rust proxy locally and points the
# macOS system proxy (HTTP + HTTPS, all network services) at it.
#
#   ./leechproxy-mac.sh run         # foreground; Ctrl-C stops and restores proxy settings
#   ./leechproxy-mac.sh install     # LaunchAgents (start at login) + system proxy on
#   ./leechproxy-mac.sh uninstall   # remove LaunchAgents, system proxy off
#   ./leechproxy-mac.sh status
#
# Apps that honour the system proxy (Safari, Chrome, Edge, most apps) go through
# it; Firefox does too when set to "Use system proxy settings" (its default).
# Some apps ignore system proxies; for true enforcement run the transparent
# proxy on the router/gateway instead (see ../README.md).
set -eu

HERE=$(cd "$(dirname "$0")/.." && pwd)            # the proxy/ directory
DATA=${LEECHPROXY_DATA:-$HOME/.local/share/leechproxy}
APP="$DATA/app"
PORT=${LEECHPROXY_PORT:-3128}
UI_PORT=${LEECHPROXY_UI_PORT:-8080}
PY=$(command -v python3)
AGENTS="$HOME/Library/LaunchAgents"
LABEL=com.leechproxy

services() {
	# enabled network services (disabled ones are prefixed with "*")
	networksetup -listallnetworkservices | tail -n +2 | grep -v '^\*'
}

proxy_on() {
	services | while IFS= read -r s; do
		networksetup -setwebproxy "$s" 127.0.0.1 "$PORT" off
		networksetup -setsecurewebproxy "$s" 127.0.0.1 "$PORT" off
		networksetup -setproxybypassdomains "$s" "*.local" "169.254/16" "localhost" "127.0.0.1" "::1"
	done
	echo "System proxy -> 127.0.0.1:$PORT"
}

proxy_off() {
	services | while IFS= read -r s; do
		networksetup -setwebproxystate "$s" off
		networksetup -setsecurewebproxystate "$s" off
	done
	echo "System proxy off"
}

build() {
	if [ ! -x "$HERE/sni/target/release/leechproxy-sni" ] || [ -n "$(find "$HERE/sni/src" -newer "$HERE/sni/target/release/leechproxy-sni" 2>/dev/null)" ]; then
		echo "Building leechproxy-sni..."
		(cd "$HERE/sni" && cargo build --release -q)
	fi
}

case "${1:-}" in
run)
	build
	mkdir -p "$DATA"
	export LEECHPROXY_DATA="$DATA" PYTHONPATH="$HERE"
	"$PY" -m leechproxy.webui --port "$UI_PORT" &
	UI_PID=$!
	"$HERE/sni/target/release/leechproxy-sni" --explicit "127.0.0.1:$PORT" \
		--block-page "http://127.0.0.1:$UI_PORT/blocked" &
	PX_PID=$!
	sleep 1
	proxy_on
	trap 'proxy_off; kill $UI_PID $PX_PID 2>/dev/null; exit 0' INT TERM
	echo "Web UI: http://127.0.0.1:$UI_PORT/   (Ctrl-C to stop)"
	open "http://127.0.0.1:$UI_PORT/" || true
	wait
	;;
install)
	build
	mkdir -p "$APP" "$AGENTS"
	rm -rf "$APP/leechproxy"
	cp -R "$HERE/leechproxy" "$APP/"
	cp "$HERE/sni/target/release/leechproxy-sni" "$APP/"
	cat > "$AGENTS/$LABEL.web.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL.web</string>
  <key>ProgramArguments</key><array><string>$PY</string><string>-m</string><string>leechproxy.webui</string>
    <string>--port</string><string>$UI_PORT</string></array>
  <key>EnvironmentVariables</key><dict><key>LEECHPROXY_DATA</key><string>$DATA</string>
    <key>PYTHONPATH</key><string>$APP</string></dict>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$DATA/web.log</string><key>StandardErrorPath</key><string>$DATA/web.log</string>
</dict></plist>
EOF
	cat > "$AGENTS/$LABEL.sni.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL.sni</string>
  <key>ProgramArguments</key><array><string>$APP/leechproxy-sni</string>
    <string>--explicit</string><string>127.0.0.1:$PORT</string>
    <string>--helper</string><string>$PY -m leechproxy.acl_helper</string>
    <string>--block-page</string><string>http://127.0.0.1:$UI_PORT/blocked</string></array>
  <key>EnvironmentVariables</key><dict><key>LEECHPROXY_DATA</key><string>$DATA</string>
    <key>PYTHONPATH</key><string>$APP</string></dict>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$DATA/proxy.log</string><key>StandardErrorPath</key><string>$DATA/proxy.log</string>
</dict></plist>
EOF
	for a in web sni; do
		launchctl bootout "gui/$(id -u)/$LABEL.$a" 2>/dev/null || true
		# bootout is asynchronous; wait until the old job is gone before loading the new one
		i=0
		while launchctl print "gui/$(id -u)/$LABEL.$a" >/dev/null 2>&1 && [ $i -lt 50 ]; do
			sleep 0.2
			i=$((i + 1))
		done
		launchctl bootstrap "gui/$(id -u)" "$AGENTS/$LABEL.$a.plist"
	done
	sleep 1
	proxy_on
	echo "Installed. Web UI: http://127.0.0.1:$UI_PORT/  Logs: $DATA/{web,proxy}.log"
	;;
uninstall)
	proxy_off
	for a in web sni; do
		launchctl bootout "gui/$(id -u)/$LABEL.$a" 2>/dev/null || true
		rm -f "$AGENTS/$LABEL.$a.plist"
	done
	echo "Uninstalled (config and usage kept in $DATA)"
	;;
status)
	for a in web sni; do
		if st=$(launchctl print "gui/$(id -u)/$LABEL.$a" 2>/dev/null); then
			echo "$a: $(echo "$st" | awk '/^\tstate/{print $3; exit}')"
		else
			echo "$a: not installed"
		fi
	done
	scutil --proxy | grep -E 'HTTPS?(Enable|Proxy|Port)'
	;;
*)
	sed -n '2,13p' "$0"
	exit 2
	;;
esac
