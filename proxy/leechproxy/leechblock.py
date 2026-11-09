"""Interop with the LeechBlock NG browser extension.

* import_options(): turn a LeechBlock options export (text or JSON) into proxy lists.
* sites_for_leechblock(): render a list in LeechBlock's site syntax, so a block
  set can load it via "Load sites from URL" (sitesURL option).
"""

import json
import re

from .core import DAYS, normalize_domain, _DOMAIN_RE

# LeechBlock's days array / bitmask is Sunday-first (JS Date.getDay()).
_LB_DAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"]


def _js_unescape(s):
    """Inverse of JavaScript's escape(), which LeechBlock applies to exported strings."""
    s = re.sub(r"%u([0-9A-Fa-f]{4})", lambda m: chr(int(m.group(1), 16)), s)
    return re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), s)


def parse_export(text):
    """Parse LeechBlock's text export (key=value lines) or JSON export into a dict."""
    text = text.strip()
    if text.startswith("{"):
        return json.loads(text)
    opts = {}
    for line in text.splitlines():
        m = re.match(r"^(\w+)=(.*)$", line.strip())
        if not m:
            continue
        k, v = m.groups()
        if re.match(r"^days\d+$", k):
            code = int(v or 0)
            opts[k] = [bool(code & (1 << i)) for i in range(7)]
        elif v in ("true", "false"):
            opts[k] = v == "true"
        else:
            opts[k] = v
    return opts


def _site_to_domain(site):
    """Map one LeechBlock site pattern to a hostname, or None if it can't be expressed
    at hostname level (keywords, regexps, path-specific patterns, wildcard TLDs)."""
    site = re.sub(r"^[a-z-]+:/+", "", site)
    host, _, path = site.partition("/")
    if path.strip("*"):
        return None, "path"
    if "*" in host.lstrip("*."):
        return None, "wildcard"
    d = normalize_domain(host)
    if not d or not _DOMAIN_RE.match(d) or "." not in d:
        return None, "invalid"
    return d, None


def import_options(text):
    """Return (lists, warnings)."""
    opts = parse_export(text)
    num_sets = int(opts.get("numSets") or 6)
    lists, warnings = [], []
    for n in range(1, num_sets + 1):
        sites = str(opts.get(f"sites{n}") or "").split()
        if not sites:
            continue
        name = _js_unescape(str(opts.get(f"setName{n}") or "")) or f"LeechBlock set {n}"
        domains, allow, skipped = [], [], []
        for s in sites:
            if s[0] in "~>" or s in ("FILE", "+FILE"):
                skipped.append(s)
                continue
            target = allow if s[0] == "+" else domains
            d, why = _site_to_domain(s.lstrip("+"))
            if d is None:
                # A path-level block can still be enforced as a host block only if the user wants;
                # we skip it rather than over-block.
                skipped.append(s)
            elif d not in target:
                target.append(d)
        if skipped:
            warnings.append(f"{name}: skipped {len(skipped)} pattern(s) the proxy can't match by hostname: "
                            + " ".join(skipped[:10]) + (" ..." if len(skipped) > 10 else ""))

        times = str(opts.get(f"times{n}") or "")
        periods = [p for p in re.split(r"[,\s]+", times) if p]

        limit = str(opts.get(f"limitMins{n}") or "").strip()
        limit_period = str(opts.get(f"limitPeriod{n}") or "").strip()
        if limit and limit_period and limit_period != "86400":
            warnings.append(f"{name}: limit period is {limit_period}s; the proxy only supports daily limits, "
                            "so it is applied per day")

        days_arr = opts.get(f"days{n}")
        if not isinstance(days_arr, list) or len(days_arr) != 7:
            days_arr = [False, True, True, True, True, True, False]  # LeechBlock default
        days = [d for d in DAYS if days_arr[_LB_DAYS.index(d)]]

        if opts.get(f"conjMode{n}"):
            warnings.append(f"{name}: 'within periods AND after limit' mode is imported as "
                            "'within periods OR after limit'")
        lists.append({
            "name": name,
            "enabled": not opts.get(f"disable{n}", False),
            "domains": domains,
            "allow": allow,
            "sources": [],
            "periods": periods,
            "limit_minutes": int(limit) if limit.isdigit() and int(limit) > 0 else None,
            "days": days,
            "leechblock_set": n,
            "imported": True,
        })
    return lists, warnings


def sites_for_leechblock(lst, extra_domains=()):
    """One site per line: blocked domains, then '+domain' exceptions."""
    out = sorted(set(lst["domains"]) | set(extra_domains))
    out += ["+" + d for d in lst["allow"]]
    return "\n".join(out) + "\n"
