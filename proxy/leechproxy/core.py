"""Core logic shared by the Squid ACL helper and the web UI.

Config lives in a JSON file; usage lives in SQLite.

People ("users") own devices, identified by MAC address (preferred: survives DHCP
changes; only visible when Squid runs on the router or same LAN segment) or IP.
Each list applies to everyone or to selected users, and every user has their own
daily allowance. Devices that don't belong to a user are tracked individually.

Time is counted in "active minutes": a (list, user) pair accrues one minute for
every distinct wall-clock minute in which the proxy saw a new request/connection
to one of the list's hosts from that user's devices. This is a traffic-based
approximation, not focused-tab time.
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
    "limit_minutes": None,  # daily allowance per user; None = no limit
    "days": DAYS[:],      # days on which the rules apply
    "users": [],          # user ids this list applies to; empty = everyone (incl. unknown devices)
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
_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


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


def normalize_mac(m):
    m = (m or "").strip().lower().replace("-", ":")
    if re.fullmatch(r"[0-9a-f]{12}", m):
        m = ":".join(m[i:i + 2] for i in range(0, 12, 2))
    # Squid may print single-digit octets without padding
    if ":" in m:
        m = ":".join(p.zfill(2) for p in m.split(":"))
    return m


def normalize_ip(ip):
    ip = (ip or "").strip().strip("[]")
    try:
        a = ipaddress.ip_address(ip)
        if a.version == 6 and a.ipv4_mapped:
            a = a.ipv4_mapped
        return str(a)
    except ValueError:
        return ""


def validate_user(raw):
    out = {"id": str(raw.get("id") or uuid.uuid4().hex[:12]),
           "name": str(raw.get("name") or "").strip()[:100]}
    if not out["name"]:
        raise ValueError("user needs a name")
    devices = []
    for d in raw.get("devices") or []:
        mac, ip = normalize_mac(d.get("mac")), normalize_ip(d.get("ip"))
        if d.get("mac") and not _MAC_RE.match(mac):
            raise ValueError(f"invalid MAC address: {d.get('mac')!r}")
        if d.get("ip") and not ip:
            raise ValueError(f"invalid IP address: {d.get('ip')!r}")
        if not mac and not ip:
            continue
        devices.append({"label": str(d.get("label") or "").strip()[:60], "mac": mac or None, "ip": ip or None})
    out["devices"] = devices
    return out


def validate_list(raw, user_ids=None):
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

    users = [str(u) for u in raw.get("users") or []]
    if user_ids is not None:
        users = [u for u in users if u in user_ids]  # drop references to deleted users
    out["users"] = list(dict.fromkeys(users))

    lbs = raw.get("leechblock_set")
    if lbs in (None, "", 0, "0"):
        out["leechblock_set"] = None
    else:
        lbs = int(lbs)
        if not 1 <= lbs <= 99:
            raise ValueError("leechblock_set must be 1-99")
        out["leechblock_set"] = lbs
    return out


def validate_config(cfg):
    users = [validate_user(u) for u in cfg.get("users", [])]
    seen = {}
    for u in users:
        for d in u["devices"]:
            for key in ("mac", "ip"):
                if d[key]:
                    other = seen.setdefault((key, d[key]), u["name"])
                    if other != u["name"]:
                        raise ValueError(f"{key.upper()} {d[key]} is assigned to both {other} and {u['name']}")
    ids = {u["id"] for u in users}
    return {"users": users, "lists": [validate_list(l, ids) for l in cfg.get("lists", [])]}


def load_config():
    try:
        with open(config_path()) as f:
            cfg = json.load(f)
    except FileNotFoundError:
        cfg = {}
    cfg.setdefault("lists", [])
    cfg.setdefault("users", [])
    return cfg


def save_config(cfg):
    os.makedirs(DATA_DIR, exist_ok=True)
    cfg = validate_config(cfg)
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
#
# "who" identifies whose allowance is used: "u:<user id>" for a known user,
# "d:<mac or ip>" for a device that isn't assigned to anyone.

_local = threading.local()


def db():
    conn = getattr(_local, "conn", None)
    if conn is None:
        os.makedirs(DATA_DIR, exist_ok=True)
        conn = sqlite3.connect(db_path(), timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS usage2 (list_id TEXT, who TEXT, day TEXT, minute INTEGER,
                PRIMARY KEY (list_id, who, day, minute)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS hosts2 (host TEXT, who TEXT, day TEXT, minute INTEGER,
                PRIMARY KEY (host, who, day, minute)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS devices (mac TEXT, ip TEXT, last_seen INTEGER,
                PRIMARY KEY (mac, ip)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS lbreports (client TEXT, lbset INTEGER, day TEXT,
                name TEXT, secs INTEGER, updated INTEGER, PRIMARY KEY (client, lbset, day)) WITHOUT ROWID;
        """)
        _local.conn = conn
    return conn


def proxy_minutes(list_id, who, day):
    row = db().execute("SELECT COUNT(*) FROM usage2 WHERE list_id=? AND who=? AND day=?",
                       (list_id, who, day)).fetchone()
    return row[0]


def record(list_ids, host, who, mac, ip, now):
    day = now.strftime("%Y-%m-%d")
    minute = now.hour * 60 + now.minute
    c = db()
    with c:
        for lid in list_ids:
            c.execute("INSERT OR IGNORE INTO usage2 VALUES (?,?,?,?)", (lid, who, day, minute))
        c.execute("INSERT OR IGNORE INTO hosts2 VALUES (?,?,?,?)", (host, who, day, minute))


def note_device(mac, ip, now_ts=None):
    """Remember devices seen recently so the UI can offer to assign them."""
    if not (mac or ip):
        return
    with db() as c:
        c.execute("INSERT OR REPLACE INTO devices VALUES (?,?,?)", (mac or "", ip or "", int(now_ts or time.time())))


def recent_devices(since_secs=7 * 86400):
    rows = db().execute("SELECT mac, ip, last_seen FROM devices WHERE last_seen > ? ORDER BY last_seen DESC",
                        (int(time.time()) - since_secs,)).fetchall()
    return [{"mac": m or None, "ip": i or None, "last_seen": t} for m, i, t in rows]


def host_stats(day, limit=50):
    return db().execute(
        "SELECT host, who, COUNT(*) AS m FROM hosts2 WHERE day=? GROUP BY host, who ORDER BY m DESC LIMIT ?",
        (day, limit),
    ).fetchall()


def reset_usage(list_id, day, who=None):
    with db() as c:
        if who:
            c.execute("DELETE FROM usage2 WHERE list_id=? AND day=? AND who=?", (list_id, day, who))
        else:
            c.execute("DELETE FROM usage2 WHERE list_id=? AND day=?", (list_id, day))


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
                (normalize_ip(client) or client, lbset, day, str(s.get("name") or "")[:100], max(0, secs), int(time.time())),
            )
            count += 1
    return count


def leechblock_reports(day):
    rows = db().execute(
        "SELECT client, lbset, name, secs, updated FROM lbreports WHERE day=? ORDER BY lbset, client", (day,)
    ).fetchall()
    return [dict(zip(("client", "set", "name", "secs", "updated"), r)) for r in rows]


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
        self.users = []
        self.index = {}   # domain -> set(list_id) for blocking
        self.allow = {}   # domain -> set(list_id) for exceptions
        self.by_mac = {}  # mac -> user
        self.by_ip = {}   # ip -> user
        self._seen = {}   # (mac, ip) -> last time written to devices table

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
        cfg = validate_config(load_config())
        self.users, self.lists = cfg["users"], cfg["lists"]
        self.by_mac = {d["mac"]: u for u in self.users for d in u["devices"] if d["mac"]}
        self.by_ip = {d["ip"]: u for u in self.users for d in u["devices"] if d["ip"]}
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

    def identify(self, mac=None, ip=None):
        """Return (user or None, who-key)."""
        mac, ip = normalize_mac(mac) if mac and mac != "-" else "", normalize_ip(ip)
        user = self.by_mac.get(mac) if mac else None
        user = user or (self.by_ip.get(ip) if ip else None)
        if user:
            return user, "u:" + user["id"]
        return None, "d:" + (mac or ip or "unknown")

    def ips_of(self, who):
        """IPs whose LeechBlock reports count for this who-key."""
        if who.startswith("u:"):
            return [ip for ip, u in self.by_ip.items() if u["id"] == who[2:]]
        dev = who[2:]
        return [dev] if normalize_ip(dev) else []

    def matching_lists(self, host, user):
        hit, exc = set(), set()
        for s in host_suffixes(host):
            hit |= self.index.get(s, set())
            exc |= self.allow.get(s, set())
        return [l for l in self.lists if l["id"] in hit and l["id"] not in exc
                and (not l["users"] or (user and user["id"] in l["users"]))]

    def used_minutes(self, l, who, day):
        """Proxy-observed minutes, or LeechBlock-reported minutes if larger.
        (max rather than sum: the same browsing usually shows up in both.)"""
        used = proxy_minutes(l["id"], who, day)
        ips = self.ips_of(who)
        if l["leechblock_set"] and ips:
            q = "SELECT COALESCE(SUM(secs),0) FROM lbreports WHERE lbset=? AND day=? AND client IN (%s)" % \
                ",".join("?" * len(ips))
            secs = db().execute(q, (l["leechblock_set"], day, *ips)).fetchone()[0]
            used = max(used, secs // 60)
        return used

    def list_status(self, l, who, now):
        """Return (blocked: bool, reason: str|None, used_minutes: int)."""
        day = now.strftime("%Y-%m-%d")
        used = self.used_minutes(l, who, day)
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

    def check(self, host, now=None, count=True, mac=None, ip=None):
        """Decide for one request. Returns (blocked, list_name, reason)."""
        now = now or dt.datetime.now()
        host = normalize_domain(host or "")
        self.maybe_reload()
        user, who = self.identify(mac, ip)
        if count:
            self._note(mac, ip, now)
        if not host or host == "-" or normalize_ip(host):
            return False, None, None
        matches = self.matching_lists(host, user)
        if not matches:
            return False, None, None
        for l in matches:
            blocked, reason, _ = self.list_status(l, who, now)
            if blocked:
                return True, l["name"], reason
        if count:
            record([l["id"] for l in matches], host, who, mac, ip, now)
        return False, None, None

    def _note(self, mac, ip, now):
        mac = normalize_mac(mac) if mac and mac != "-" else ""
        ip = normalize_ip(ip)
        ts = now.timestamp()
        if ts - self._seen.get((mac, ip), 0) > 60:  # write at most once a minute per device
            self._seen[(mac, ip)] = ts
            note_device(mac, ip, ts)
