"""Squid external ACL helper.

squid.conf:
  external_acl_type leechproxy ttl=0 negative_ttl=0 children-max=1 concurrency=50 \
      %SRC %SRCEUI48 %ssl::>sni %DST /usr/bin/python3 -m leechproxy.acl_helper
  acl leech_blocked external leechproxy

Input lines:  "<channel-id> <client-ip> <client-mac> <sni> <dst>"
              (values are %-encoded, "-" when unknown; the MAC is only known when
              Squid shares a LAN segment with the client, e.g. on the router)
Output lines: "<channel-id> OK message=..."  -> ACL matches -> request is blocked
              "<channel-id> ERR"             -> allowed
The helper must never crash or stall Squid, so all errors fail open (ERR).
"""

import sys
import urllib.parse

from .core import Engine


def handle(engine, line):
    parts = line.split()
    chan = ""
    count = True
    if len(parts) >= 6:  # leechproxy-sni: "<chan> <ip> <mac> <sni> <dst> <count 0|1>"
        count = parts[5] != "0"
        parts = parts[:5]
    if len(parts) >= 5:  # concurrency>0: leading channel ID
        chan, parts = parts[0], parts[1:]
    vals = [urllib.parse.unquote(p) for p in parts] + ["-"] * 4
    ip, mac, sni, dst = vals[:4]
    host = sni if sni not in ("", "-") else dst
    prefix = f"{chan} " if chan else ""
    try:
        blocked, name, reason = engine.check(host, mac=mac, ip=ip, count=count)
    except Exception as e:  # fail open
        sys.stderr.write(f"leechproxy: error checking {host!r}: {e}\n")
        return prefix + "ERR"
    if blocked:
        msg = urllib.parse.quote(f"{name} ({reason})")
        return f"{prefix}OK message={msg}"
    return prefix + "ERR"


def main():
    engine = Engine()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        sys.stdout.write(handle(engine, line) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
