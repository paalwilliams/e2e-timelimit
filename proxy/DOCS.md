# LeechProxy

Per-person site blocking and daily time limits for your whole network. Home
Assistant acts as the network's gateway; web traffic passing through it goes
via a transparent proxy that reads only the hostname (TLS SNI / HTTP Host).

## Setup

1. Start the add-on and open **LeechProxy** in the sidebar. Add lists and people.
2. Make Home Assistant the default gateway for your devices: in your router's
   DHCP settings set the **gateway / router (option 3)** to this host's IP, then
   reconnect devices (or wait for DHCP renewal). To test with one device first,
   set its gateway manually.
3. IPv6: if your network has IPv6, devices can bypass the gateway over IPv6.
   Turn off IPv6 on your router's LAN (or for the devices you want to filter).
4. Optional, for proper block pages on HTTPS sites: on each device open
   `http://<this host>:8765/ca.pem` and install/trust the certificate. It's only
   ever used for blocked sites; all other traffic is passed through untouched.
   Without it, blocked HTTPS sites just fail to load.

## Options

| Option | Default | |
|---|---|---|
| `interface` | `end0` | LAN interface (see *Settings → System → Network*) |
| `block_quic` | `true` | Reject forwarded UDP 443 so browsers use TCP (needed for filtering) |
| `explicit_proxy` | `true` | Also offer an HTTP proxy on port 3128 for devices configured to use one |
| `https_block_page` | `true` | Show the block page on HTTPS (needs the CA on devices) |
| `active_bytes` | `2048` | Bytes per check interval for a connection to count as active time |
| `recheck_seconds` | `15` | How often live connections are re-checked (and cut when blocked) |
| `ui_password` | – | Allow the UI on `http://<host>:8765/` from the LAN with this password (any username); otherwise only via the HA sidebar |

## Notes

* Devices are identified by MAC address (from the host's ARP table) or IP.
* Rules are removed when the add-on stops; devices using it as gateway then
  still get internet, unfiltered.
