#!/usr/bin/with-contenv bashio
# LeechProxy Home Assistant add-on entrypoint.
#
# Turns the HA host into a filtering gateway for devices that use it as their
# default gateway ("router on a stick" on one LAN interface):
#   * TCP 80/443 forwarded through the host is redirected to leechproxy-sni
#   * other forwarded traffic is accepted and masqueraded towards the real router
#   * forwarded QUIC (UDP 443) is rejected so browsers fall back to TCP
#   * ICMP redirects are suppressed so clients keep using this gateway
# All rules live in LEECHPROXY* chains and are removed on stop.
set -e

IF=$(bashio::config 'interface')
PROXY_PORT=3130
EXPLICIT_PORT=3128
UI_PORT=8765
export LEECHPROXY_DATA=/data PYTHONPATH=/opt/leechproxy

LAN_CIDR=$(ip -4 -o addr show dev "$IF" | awk '{print $4}' | head -n1)
if [ -z "$LAN_CIDR" ]; then
	bashio::exit.nok "Interface '$IF' has no IPv4 address. Set 'interface' in the add-on options (see: ha network info)."
fi
HOST_IP=${LAN_CIDR%/*}
bashio::log.info "Gateway on $IF ($LAN_CIDR)"

# Use the same iptables backend Docker uses on this host.
if iptables-legacy -t nat -S 2>/dev/null | grep -q -- '-N DOCKER'; then IPT=iptables-legacy; else IPT=iptables-nft; fi
bashio::log.info "Using $IPT"

ipt() { $IPT "$@"; }
chain() { ipt -t "$1" -N "$2" 2>/dev/null || true; ipt -t "$1" -F "$2"; }
jump() { # table parent-chain args...
	local t=$1 c=$2; shift 2
	ipt -t "$t" -C "$c" "$@" 2>/dev/null || ipt -t "$t" -I "$c" 1 "$@"
}
unjump() {
	local t=$1 c=$2; shift 2
	while ipt -t "$t" -C "$c" "$@" 2>/dev/null; do ipt -t "$t" -D "$c" "$@"; done
}

cleanup() {
	bashio::log.info "Removing gateway rules"
	unjump nat PREROUTING -i "$IF" -j LEECHPROXY || true
	unjump nat POSTROUTING -o "$IF" -j LEECHPROXY_POST || true
	unjump filter FORWARD -j LEECHPROXY_FWD || true
	unjump filter OUTPUT -o "$IF" -p icmp --icmp-type redirect -j DROP || true
	kill "$UI_PID" "$PX_PID" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 0' TERM INT

# --- forwarding
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
	echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || bashio::log.warning "net.ipv4.ip_forward is 0 and can't be changed"
fi
for f in /proc/sys/net/ipv4/conf/all/send_redirects "/proc/sys/net/ipv4/conf/$IF/send_redirects"; do
	{ echo 0 > "$f"; } 2>/dev/null || true  # read-only in add-ons; the OUTPUT rule below covers it
done
jump filter OUTPUT -o "$IF" -p icmp --icmp-type redirect -j DROP

# --- NAT: send forwarded web traffic to the proxy; leave local/LAN destinations alone
chain nat LEECHPROXY
ipt -t nat -A LEECHPROXY -m addrtype --dst-type LOCAL -j RETURN
for n in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 224.0.0.0/4; do
	ipt -t nat -A LEECHPROXY -d "$n" -j RETURN
done
ipt -t nat -A LEECHPROXY -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports "$PROXY_PORT"
jump nat PREROUTING -i "$IF" -j LEECHPROXY

chain nat LEECHPROXY_POST
ipt -t nat -A LEECHPROXY_POST -s "$LAN_CIDR" ! -d "$LAN_CIDR" -j MASQUERADE
jump nat POSTROUTING -o "$IF" -j LEECHPROXY_POST

# --- filter: allow LAN -> internet forwarding through this host
chain filter LEECHPROXY_FWD
if bashio::config.true 'block_quic'; then
	ipt -A LEECHPROXY_FWD -i "$IF" -p udp --dport 443 -j REJECT
fi
ipt -A LEECHPROXY_FWD -i "$IF" -o "$IF" -j ACCEPT
jump filter FORWARD -j LEECHPROXY_FWD

# --- web UI (admin only via HA ingress, or with ui_password; block page + CA open to the LAN)
UI_ARGS=(--bind 0.0.0.0 --port "$UI_PORT" --admin-ip 172.30.32.2)
if bashio::config.has_value 'ui_password'; then
	UI_ARGS+=(--password "$(bashio::config 'ui_password')")
fi
python3 -m leechproxy.webui "${UI_ARGS[@]}" &
UI_PID=$!

# --- proxy
PX_ARGS=(--transparent "0.0.0.0:$PROXY_PORT"
	--block-page "http://$HOST_IP:$UI_PORT/blocked"
	--active-bytes "$(bashio::config 'active_bytes')"
	--recheck "$(bashio::config 'recheck_seconds')"
	--ca-dir /data/ca)
if bashio::config.true 'explicit_proxy'; then
	PX_ARGS+=(--explicit "0.0.0.0:$EXPLICIT_PORT")
fi
if ! bashio::config.true 'https_block_page'; then
	PX_ARGS+=(--no-block-page-tls)
fi
leechproxy-sni "${PX_ARGS[@]}" &
PX_PID=$!

bashio::log.info "Ready. Point devices' default gateway at $HOST_IP (DHCP option 3 on your router)."
bashio::log.info "Block page / CA download: http://$HOST_IP:$UI_PORT/ca.pem"
wait -n "$UI_PID" "$PX_PID"
bashio::log.error "A LeechProxy process exited; stopping add-on"
exit 1
