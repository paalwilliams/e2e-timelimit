"""Squid external ACL helper.

squid.conf:
  external_acl_type leechproxy ttl=0 negative_ttl=0 children-max=1 concurrency=50 \
      %ssl::>sni %DST /usr/bin/python3 -m leechproxy.acl_helper
  acl leech_blocked external leechproxy

Input lines:  "<channel-id> <sni> <dst>"   (values are %-encoded, "-" when unknown)
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
    if len(parts) >= 3:  # concurrency>0: leading channel ID
        chan, parts = parts[0], parts[1:]
    vals = [urllib.parse.unquote(p) for p in parts]
    sni = vals[0] if vals else "-"
    dst = vals[1] if len(vals) > 1 else "-"
    host = sni if sni not in ("", "-") else dst
    prefix = f"{chan} " if chan else ""
    try:
        blocked, name, reason = engine.check(host)
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
