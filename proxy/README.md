# LeechProxy

Network-wide, hostname-level blocking and daily time limits using Squid, with a
web UI for managing blocklists, and optional integration with LeechBlock NG.

```
 devices ──► router ──► Squid ──(external ACL)──► leechproxy.acl_helper ─┐
                          │  peeks at TLS SNI, splices or terminates      │ config.json
                          ▼                                               │ usage.sqlite3
                       internet          web UI (leechproxy.webui) ◄──────┘
                                              ▲
                     LeechBlock ── POST focused time / GET site lists
```

* **No decryption.** HTTPS is peeked (SNI) and spliced. Rules are per hostname
  (`reddit.com` also matches every `*.reddit.com`); paths and keywords can't be matched.
* **Lists** contain hand-entered domains, subscribed blocklists (hosts files,
  domain-per-line or `||domain^` lists, refreshed daily), exceptions, block periods,
  a daily limit and active days.
* **Time** counted by the proxy = distinct minutes in which a device opened a
  request/connection to the site. It's an approximation: background tabs count, and
  reading an already-loaded page doesn't. Link a list to a LeechBlock set to also
  count LeechBlock's focused-tab time (the larger of the two is used).

## Run the web UI

```sh
cd proxy
LEECHPROXY_DATA=~/.local/share/leechproxy python3 -m leechproxy.webui --port 8080
# --bind 0.0.0.0 to reach it from other devices; --password X to require basic auth
```

Python 3.9+ and nothing else. Tests: `python3 -m unittest discover -s tests`.

## LeechBlock integration

1. **Import**: in LeechBlock, *Options → General → Export Options to Text File*, then
   *Import from LeechBlock…* in the UI. Each block set becomes a list linked to its set
   number. Patterns the proxy can't express by hostname (keywords, regexps, path-specific
   patterns) are skipped and listed as warnings.
2. **Report time** (this repo's modified LeechBlock): *Options → General → Network Proxy*,
   set to `http://<ui-host>:8080/api/leechblock/report`. LeechBlock then POSTs every
   set's focused time for the current limit period every 30 s or more, and the proxy
   blocks the linked list on *every* device once the limit is used up.
3. **Share lists back**: set a block set's *Load sites from URL* to
   `http://<ui-host>:8080/leechblock/set/$S` (or `/leechblock/sites/<list-id>`; add
   `?sources=1` to include subscribed blocklists, which can be large).

## Where to run Squid

Transparent interception needs Squid on the path packets take, i.e. on the router
or on a box that devices use as their gateway.

| Setup | Works? | How |
|---|---|---|
| **OpenWrt** router (≥256 MB RAM) | Yes | `opkg install squid python3-light python3-sqlite3`, copy this dir, use `squid.conf`, add the firewall redirects below. |
| **pfSense / OPNsense** | Yes | Built-in Squid package with transparent HTTP + "SSL splice all". Add the `external_acl_type` lines as custom options; run the UI on the box or elsewhere with a shared data dir. |
| **ASUS Merlin / other Entware routers** | Maybe | Entware has `squid`; low RAM/CPU can be a problem. |
| **Stock ISP / consumer router** | No | Can't run Squid. Use a Raspberry Pi/Linux box as the network's gateway (set it as the DHCP default gateway) **or** use explicit proxy mode. |
| **Explicit proxy** (no router changes) | Yes, but opt-in | Run Squid anywhere, set devices' proxy to `host:3128` (or a PAC/WPAD file). Easy to bypass by removing the proxy setting. |
| **Just this Mac** | Yes, explicit | `brew install squid`, set the macOS/Firefox proxy to `127.0.0.1:3128`. Remove the `https_port`/`3129` lines if you don't intercept. |

### Firewall rules for transparent mode (Linux/OpenWrt, on the Squid box)

```sh
LAN=br-lan
iptables -t nat -A PREROUTING -i $LAN -p tcp --dport 80  -j REDIRECT --to-ports 3129
iptables -t nat -A PREROUTING -i $LAN -p tcp --dport 443 -j REDIRECT --to-ports 3130
# Force browsers off QUIC/HTTP3 (UDP 443) so they fall back to TCP via Squid:
iptables -A FORWARD -i $LAN -p udp --dport 443 -j REJECT
```

Also consider blocking DNS-over-HTTPS resolvers and VPNs if you want it hard to bypass.

Create the (never-used-for-decryption) certificate Squid's `https_port` requires:

```sh
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
  -subj "/CN=leechproxy" -keyout /etc/squid/leechproxy.pem -out /etc/squid/leechproxy.pem
```

Edit the `###` paths in `squid.conf` (data dir, code dir, block page URL), then
`squid -k parse && squid -k reconfigure`.

## Limitations

* An already-open tunnel (e.g. a long-lived HTTP/2 connection) isn't cut when a limit
  is reached; it's blocked when the browser opens a new connection.
* On HTTPS a blocked site shows a connection error, not a block page (that would need
  decryption). Plain HTTP gets the `/blocked` page.
* Daily limits only; LeechBlock's other limit periods are applied per day.
