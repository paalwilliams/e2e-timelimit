"""Core logic shared by the Squid ACL helper and the web UI.

Config lives in a JSON file (see DEFAULT_CONFIG); usage lives in SQLite.
Time is counted in "active minutes": a site set accrues one minute for every
distinct wall-clock minute in which the proxy saw a new request/connection to
one of its hosts. This is a traffic-based approximation, not focused-tab time.
"""

import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import tempfile
import threading
import time
import urllib.request
import uuid

DATA_DIR = os.environ.get(
    "LEECHPROXY_DATA", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
)

DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]

DEFAULT_LIST = {
    "name": "New list",
    "enabled": True,
    "domains": [],        # hand-entered: "reddit.com" matches reddit.com and *.reddit.com
    "allow": [],          # exceptions that are never blocked/counted
    "sources": [],        # URLs of hosts-format or domain-per-line blocklists
    "periods": [],        # ["0900-1200", "1300-1700"]; empty = no time-window blocking
    "limit_minutes": None,  # daily allowance; None = no limit
    "days": DAYS[:],      # days on which the rules apply
    "leechblock_set": None,  # LeechBlock block set number whose reported time also counts
    "imported": False,    # created by LeechBlock import (re-import replaces it)
}


def config_path():
    return os.path.join(DATA_DIR, "config.json")


def sources_dir():
    return os.path.join(DATA_DIR, "sources")


def db_path():
    return os.path.join(DATA_DIR, "usage.sqlite3")


# ---------------------------------------------------------------- config I/O

_PERIOD_RE = re.compile(r"^(\d{2})(\d{2})-(\d{2})(\d{2})$")
_DOMAIN_RE = re.compile(r"^(\*\.)?([a-z0-9_-]+\.)*[a-z0-9_-]+$")


def normalize_domain(d):
    d = d.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)
    d = d.split("/")[0].split(":")[0]
    if d.startswith("*."):
        d = d[2:]
    d = d.strip(".")
    if d.startswith("www."):
        d = d[4:]
    return d


def validate_list(raw):
    """Return a cleaned list dict or raise ValueError."""
    out = dict(DEFAULT_LIST)
    out["id"] = str(raw.get("id") or uuid.uuid4().hex[:12])
    out["name"] = str(raw.get("name") or "Untitled").strip()[:100]
    out["enabled"] = bool(raw.get("enabled", True))
    out["imported"] = bool(raw.get("imported", False))

    for key in ("domains", "allow"):
        vals = []
        for d in raw.get(key) or []:
            d = normalize_domain(str(d))
            if not d:
                continue
            if not _DOMAIN_RE.match(d):
                raise ValueError(f"invalid domain: {d!r}")
            if d not in vals:
                vals.append(d)
        out[key] = vals

    srcs = []
    for u in raw.get("sources") or []:
        u = str(u).strip()
        if not u:
            continue
        if not re.match(r"^https?://", u):
            raise ValueError(f"source must be an http(s) URL: {u!r}")
        srcs.append(u)
    out["sources"] = srcs

    periods = []
    for p in raw.get("periods") or []:
        p = str(p).strip().replace(":", "")
        if not p:
            continue
        m = _PERIOD_RE.match(p)
        if not m:
            raise ValueError(f"invalid period {p!r}, expected HHMM-HHMM")
        h1, m1, h2, m2 = map(int, m.groups())
        if not (0 <= h1 <= 24 and 0 <= h2 <= 24 and m1 < 60 and m2 < 60):
            raise ValueError(f"invalid period {p!r}")
        periods.append(p)
    out["periods"] = periods

    lim = raw.get("limit_minutes")
    if lim in (None, "", 0, "0"):
        out["limit_minutes"] = None
    else:
        lim = int(lim)
        if lim < 0 or lim > 1440:
            raise ValueError("limit_minutes must be 0-1440")
        out["limit_minutes"] = lim

    days = raw.get("days")
    days = DAYS if days is None else [d for d in days if d in DAYS]
    out["days"] = [d for d in DAYS if d in days]

    lbs = raw.get("leechblock_set")
    if lbs in (None, "", 0, "0"):
        out["leechblock_set"] = None
    else:
        lbs = int(lbs)
        if not 1 <= lbs <= 99:
            raise ValueError("leechblock_set must be 1-99")
        out["leechblock_set"] = lbs
    return out


def load_config():
    try:
        with open(config_path()) as f:
            cfg = json.load(f)
    except FileNotFoundError:
        cfg = {"lists": []}
    cfg.setdefault("lists", [])
    return cfg


def save_config(cfg):
    os.makedirs(DATA_DIR, exist_ok=True)
    cfg = {"lists": [validate_list(l) for l in cfg.get("lists", [])]}
    fd, tmp = tempfile.mkstemp(dir=DATA_DIR, prefix=".config.")
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, config_path())  # atomic: the helper never sees a half-written file
    return cfg


# ----------------------------------------------------------- remote sources

def source_cache_file(url):
    return os.path.join(sources_dir(), hashlib.sha256(url.encode()).hexdigest()[:16] + ".list")


def parse_blocklist(text):
    """Parse hosts-format ("0.0.0.0 example.com") or plain domain-per-line lists.
    Also tolerates AdBlock-style "||example.com^" lines."""
    domains = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].split("!", 1)[0].strip()
        if not line:
            continue
        if line.startswith("||"):
            line = line[2:].split("^", 1)[0]
        parts = line.split()
        cand = parts[-1] if len(parts) >= 2 else parts[0]
        d = normalize_domain(cand)
        if d in ("localhost", "localhost.localdomain", "local", "broadcasthost", "0.0.0.0"):
            continue
        if _DOMAIN_RE.match(d) and "." in d:
            domains.add(d)
    return domains


def fetch_source(url, timeout=30):
    """Download a blocklist and cache it. Returns number of domains."""
    req = urllib.request.Request(url, headers={"User-Agent": "leechproxy/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        text = r.read(50 * 1024 * 1024).decode("utf-8", "replace")
    domains = parse_blocklist(text)
    os.makedirs(sources_dir(), exist_ok=True)
    path = source_cache_file(url)
    fd, tmp = tempfile.mkstemp(dir=sources_dir())
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(sorted(domains)))
    os.replace(tmp, path)
    return len(domains)


def source_info(url):
    path = source_cache_file(url)
    try:
        st = os.stat(path)
        with open(path) as f:
            n = sum(1 for _ in f)
        return {"url": url, "domains": n, "fetched": int(st.st_mtime)}
    except FileNotFoundError:
        return {"url": url, "domains": 0, "fetched": None}


# ------------------------------------------------------------------ usage DB

_local = threading.local()


def db():
    conn = getattr(_local, "conn", None)
    if conn is None:
        os.makedirs(DATA_DIR, exist_ok=True)
        conn = sqlite3.connect(db_path(), timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS usage (list_id TEXT, day TEXT, minute INTEGER,"
            " PRIMARY KEY (list_id, day, minute)) WITHOUT ROWID"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS hosts (host TEXT, day TEXT, minute INTEGER,"
            " PRIMARY KEY (host, day, minute)) WITHOUT ROWID"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS lbreports (client TEXT, lbset INTEGER, day TEXT,"
            " name TEXT, secs INTEGER, updated INTEGER, PRIMARY KEY (client, lbset, day)) WITHOUT ROWID"
        )
        _local.conn = conn
    return conn


def proxy_minutes(list_id, day):
    row = db().execute("SELECT COUNT(*) FROM usage WHERE list_id=? AND day=?", (list_id, day)).fetchone()
    return row[0]


def leechblock_minutes(lbset, day):
    """Focused time reported by LeechBlock browsers for a set today, summed over browsers."""
    if not lbset:
        return 0
    row = db().execute("SELECT COALESCE(SUM(secs),0) FROM lbreports WHERE lbset=? AND day=?", (lbset, day)).fetchone()
    return row[0] // 60


def used_minutes(l, day):
    """Proxy-observed minutes, or LeechBlock-reported minutes if larger.
    (max rather than sum: the same browsing usually shows up in both.)"""
    return max(proxy_minutes(l["id"], day), leechblock_minutes(l.get("leechblock_set"), day))


def record_leechblock_report(client, payload, now=None):
    """Store a report POSTed by LeechBlock's reportTimeDataToProxy().
    Only time from the current limit period is used, and only if that period
    started today (i.e. a daily limit, or a shorter period within today)."""
    now = now or dt.datetime.now()
    day = now.strftime("%Y-%m-%d")
    midnight = dt.datetime.combine(now.date(), dt.time()).timestamp()
    count = 0
    with db() as c:
        for s in payload.get("sets") or []:
            try:
                lbset = int(s["set"])
                start = float(s.get("periodStart") or 0)
                secs = int(float(s.get("periodSecs") or 0))
            except (KeyError, TypeError, ValueError):
                continue
            if start < midnight - 60:  # period started before today: not comparable to a daily count
                secs = 0
            c.execute(
                "INSERT OR REPLACE INTO lbreports VALUES (?,?,?,?,?,?)",
                (client, lbset, day, str(s.get("name") or "")[:100], max(0, secs), int(time.time())),
            )
            count += 1
    return count


def leechblock_reports(day):
    rows = db().execute(
        "SELECT client, lbset, name, secs, updated FROM lbreports WHERE day=? ORDER BY lbset, client", (day,)
    ).fetchall()
    return [dict(zip(("client", "set", "name", "secs", "updated"), r)) for r in rows]


def record(list_ids, host, now):
    day = now.strftime("%Y-%m-%d")
    minute = now.hour * 60 + now.minute
    c = db()
    with c:
        for lid in list_ids:
            c.execute("INSERT OR IGNORE INTO usage VALUES (?,?,?)", (lid, day, minute))
        c.execute("INSERT OR IGNORE INTO hosts VALUES (?,?,?)", (host, day, minute))


def host_stats(day, limit=50):
    return db().execute(
        "SELECT host, COUNT(*) AS m FROM hosts WHERE day=? GROUP BY host ORDER BY m DESC LIMIT ?",
        (day, limit),
    ).fetchall()


def reset_usage(list_id, day):
    with db() as c:
        c.execute("DELETE FROM usage WHERE list_id=? AND day=?", (list_id, day))


# ----------------------------------------------------------------- matching

def host_suffixes(host):
    """www.news.example.com -> [www.news.example.com, news.example.com, example.com, com]"""
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(len(labels))]


def in_period(periods, now):
    cur = now.hour * 60 + now.minute
    for p in periods:
        m = _PERIOD_RE.match(p)
        h1, m1, h2, m2 = map(int, m.groups())
        start, end = h1 * 60 + m1, h2 * 60 + m2
        if start <= end:
            if start <= cur < end:
                return True
        elif cur >= start or cur < end:  # wraps past midnight, e.g. 2200-0600
            return True
    return False


class Engine:
    """Holds the compiled config; reloads automatically when files change."""

    def __init__(self):
        self._stamp = None
        self.lists = []
        self.index = {}   # domain -> set(list_id) for blocking
        self.allow = {}   # domain -> set(list_id) for exceptions

    def _files_stamp(self):
        stamps = []
        for path in [config_path()] + [source_cache_file(u) for l in self.lists for u in l["sources"]]:
            try:
                stamps.append((path, os.stat(path).st_mtime_ns))
            except FileNotFoundError:
                stamps.append((path, None))
        return tuple(stamps)

    def maybe_reload(self):
        stamp = self._files_stamp()
        if stamp == self._stamp:
            return
        cfg = load_config()
        self.lists = [validate_list(l) for l in cfg["lists"]]
        index, allow = {}, {}
        for l in self.lists:
            if not l["enabled"]:
                continue
            doms = set(l["domains"])
            for u in l["sources"]:
                try:
                    with open(source_cache_file(u)) as f:
                        doms.update(x.strip() for x in f if x.strip())
                except FileNotFoundError:
                    pass
            for d in doms:
                index.setdefault(d, set()).add(l["id"])
            for d in l["allow"]:
                allow.setdefault(d, set()).add(l["id"])
        self.index, self.allow = index, allow
        self._stamp = self._files_stamp()  # include newly referenced source files

    def matching_lists(self, host):
        hit, exc = set(), set()
        for s in host_suffixes(host):
            hit |= self.index.get(s, set())
            exc |= self.allow.get(s, set())
        return [l for l in self.lists if l["id"] in hit and l["id"] not in exc]

    def list_status(self, l, now):
        """Return (blocked: bool, reason: str|None, used_minutes: int)."""
        day = now.strftime("%Y-%m-%d")
        used = used_minutes(l, day)
        if not l["enabled"] or DAYS[now.weekday()] not in l["days"]:
            return False, None, used
        has_rules = bool(l["periods"]) or l["limit_minutes"] is not None
        if not has_rules:
            return True, "always", used
        if l["periods"] and in_period(l["periods"], now):
            return True, "period", used
        if l["limit_minutes"] is not None and used >= l["limit_minutes"]:
            return True, "limit", used
        return False, None, used

    def check(self, host, now=None, count=True):
        """Decide for one request. Returns (blocked, list_name, reason)."""
        now = now or dt.datetime.now()
        host = normalize_domain(host or "")
        if not host or host == "-" or _is_ip(host):
            return False, None, None
        self.maybe_reload()
        matches = self.matching_lists(host)
        if not matches:
            return False, None, None
        for l in matches:
            blocked, reason, _ = self.list_status(l, now)
            if blocked:
                return True, l["name"], reason
        if count:
            record([l["id"] for l in matches], host, now)
        return False, None, None


def _is_ip(s):
    try:
        ipaddress.ip_address(s.strip("[]"))
        return True
    except ValueError:
        return False
