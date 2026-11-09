# LeechProxy

Network-wide, per-person blocking and daily time limits by hostname, with a web
UI for managing blocklists.
Nothing is decrypted: the proxy only reads the TLS SNI / HTTP Host and splices bytes.

```
 devices ─► router/gateway ─(REDIRECT 80,443)─► leechproxy-sni (Rust) ──► internet
                                                   │  "is host X blocked for client IP/MAC?"
                                                   ▼
                              leechproxy.acl_helper (Python) ── config.json / usage.sqlite3
                                                   ▲
              browser ─► web UI (leechproxy.webui) ┘
```

* **Lists**: your own domains (`reddit.com` also matches `*.reddit.com`), subscribed
  blocklists (hosts files, domain lists, `||domain^` lists; refreshed daily), exceptions,
  block periods, a daily limit, active days, and who it applies to.
* **People**: each person owns devices identified by MAC (best, survives DHCP) or IP.
  Every person has their own allowance per list; unassigned devices are tracked
  individually and listed in the UI for one-click assignment.
* **Time**: a connection adds a minute to its person's usage only if it moved at least
  `--active-bytes` during that interval, so idle keep-alives don't count, though
  background tabs that keep streaming do.
* **Enforcement**: live connections are re-checked every `--recheck` seconds (15 by
  default), so reaching a limit or entering a block period also ends ongoing streams.

## Components

| Path | What |
|---|---|
| `sni/` | `leechproxy-sni`: Rust (tokio) proxy. `--transparent` for firewall-redirected traffic (Linux), `--explicit` as a normal HTTP/CONNECT proxy (any OS). |
| `leechproxy/acl_helper.py` | Policy engine, Squid-compatible line protocol; spawned by the proxy (or by Squid). |
| `leechproxy/webui.py` | Web UI + JSON API, block page. |
| `mac/leechproxy-mac.sh` | Run or install everything on macOS using the system proxy. |
| `squid.conf`, `run-local.sh` | Alternative frontend using Squid instead of `leechproxy-sni`. |

Build: `cd sni && cargo build --release`. Tests: `cargo test` and
`python3 -m unittest discover -s tests` (Python 3.9+, stdlib only).

## Try it on a Mac

```sh
./mac/leechproxy-mac.sh run        # UI + proxy, system proxy on; Ctrl-C restores it
./mac/leechproxy-mac.sh install    # same, but as LaunchAgents that start at login
./mac/leechproxy-mac.sh uninstall
```

Safari, Chrome and most apps use the system proxy. Some apps ignore it, and it's easy
to switch off, so for real enforcement run it on the gateway.

## Home Assistant add-on (HA as the network gateway)

This directory is also a Home Assistant add-on (`config.yaml`, `Dockerfile`, `run.sh`;
user docs in `DOCS.md`). Install it either by copying `proxy/` to `/addons/leechproxy`
(local add-on), or by adding `https://github.com/paalwilliams/e2e-timelimit#leechproxy`
under *Settings → Add-ons → Add-on store → ⋮ → Repositories*. Then set your router's
DHCP gateway to the HA host.

## Run on a router / gateway (Linux, OpenWrt)

```sh
LEECHPROXY_DATA=/var/lib/leechproxy PYTHONPATH=/opt/leechproxy \
  leechproxy-sni --transparent 0.0.0.0:3130 --block-page http://192.168.1.1:8080/blocked &
LEECHPROXY_DATA=/var/lib/leechproxy PYTHONPATH=/opt/leechproxy \
  python3 -m leechproxy.webui --bind 192.168.1.1 --port 8080 --password CHANGE-ME &

LAN=br-lan
iptables -t nat -A PREROUTING -i $LAN -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 3130
iptables -A FORWARD -i $LAN -p udp --dport 443 -j REJECT   # no QUIC/HTTP3: browsers fall back to TCP
```

* **OpenWrt** (≥128 MB RAM): cross-compile with `cargo zigbuild --release --target
  aarch64-unknown-linux-musl` (or `mipsel-unknown-linux-musl`, `armv7-…`), and
  `opkg install python3-light python3-sqlite3`. MAC addresses come from `/proc/net/arp`.
* **Stock ISP router**: put a Raspberry Pi or mini PC in as the network's gateway
  (set it as the DHCP default gateway, enable `net.ipv4.ip_forward`), and run the above there.
* **pfSense/OPNsense**: FreeBSD has no `SO_ORIGINAL_DST`, so use their Squid package
  with `squid.conf`'s helper lines, or `--explicit` with a WPAD/PAC file.
* Block DNS-over-HTTPS resolvers and VPNs too if it needs to be hard to bypass.

## Limitations

* Blocked HTTPS sites get a TLS `access_denied` alert (the browser shows a connection
  error), not a block page; that would need decryption. Plain HTTP is redirected to `/blocked`.
* Daily limits only.
* Transparent mode is IPv4 and IPv6 via netfilter REDIRECT; the MAC is only known for
  clients on the same L2 segment as the proxy.
