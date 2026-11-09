"""Web configuration UI + JSON API for LeechProxy.

    python3 -m leechproxy.webui [--bind 127.0.0.1] [--port 8080] [--password SECRET]

Endpoints (UI/API are behind --password if given; /blocked and /ca.pem are not,
since every device on the network needs them):
  GET  /                              config UI
  GET  /api/state                     lists, people, today's usage
  POST /api/lists                     create list            (JSON body)
  PUT  /api/lists/<id>                replace list           (JSON body)
  DELETE /api/lists/<id>              delete list
  POST /api/lists/<id>/refresh        re-download subscribed blocklists
  POST /api/lists/<id>/reset          reset today's usage
  POST/PUT/DELETE /api/users[/<id>]   manage people and their devices
  GET  /blocked?host=&msg=            block page (the proxy redirects blocked requests here)
  GET  /ca.pem                        the proxy's local CA, to install on devices
"""

import argparse
import base64
import datetime as dt
import hmac
import html
import json
import os
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import core

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
_lock = threading.Lock()  # serialize config read-modify-write
_engine = core.Engine()
PASSWORD = None


def _who_label(who, users):
    if who.startswith("u:"):
        return users.get(who[2:], {}).get("name", "deleted user")
    return "unassigned device " + who[2:]


def state():
    now = dt.datetime.now()
    day = now.strftime("%Y-%m-%d")
    _engine.maybe_reload()
    users = {u["id"]: u for u in _engine.users}
    lists = []
    for l in _engine.lists:
        l = dict(l)
        # Whose status to show: the selected users, or everyone + unassigned devices seen today
        whos = ["u:" + u for u in l["users"]] if l["users"] else ["u:" + u for u in users]
        if not l["users"]:
            whos += [r[0] for r in core.db().execute(
                "SELECT DISTINCT who FROM usage2 WHERE list_id=? AND day=? AND who LIKE 'd:%'", (l["id"], day))]
        status = []
        for who in whos:
            blocked, reason, used = _engine.list_status(l, who, now)
            status.append({"who": who, "label": _who_label(who, users), "blocked": blocked, "reason": reason,
                           "used_minutes": used, "proxy_minutes": core.proxy_minutes(l["id"], who, day)})
        if not status:  # no users defined yet: show the rule state for an anonymous device
            blocked, reason, used = _engine.list_status(l, "d:-", now)
            status.append({"who": "d:-", "label": "everyone", "blocked": blocked, "reason": reason,
                           "used_minutes": used, "proxy_minutes": used})
        l["status"] = status
        l["source_info"] = [core.source_info(u) for u in l["sources"]]
        lists.append(l)

    known_macs = {d["mac"] for u in users.values() for d in u["devices"] if d["mac"]}
    known_ips = {d["ip"] for u in users.values() for d in u["devices"] if d["ip"]}
    unassigned = [d for d in core.recent_devices()
                  if d["mac"] not in known_macs and (d["mac"] or d["ip"] not in known_ips)]
    return {
        "now": now.isoformat(timespec="seconds"),
        "users": list(users.values()),
        "lists": lists,
        "unassigned_devices": unassigned[:50],
        "hosts": [{"host": h, "who": _who_label(w, users), "minutes": m} for h, w, m in core.host_stats(day)],
        "ca_installed_hint": os.path.exists(os.path.join(core.DATA_DIR, "ca", "ca.pem")),
    }


def _mutate_users(fn):
    """Apply fn(cfg) under the lock and save; returns the saved config."""
    with _lock:
        cfg = core.load_config()
        fn(cfg)
        return core.save_config(cfg)


def refresh_sources(lst):
    results = []
    for u in lst["sources"]:
        try:
            results.append({"url": u, "domains": core.fetch_source(u)})
        except Exception as e:
            results.append({"url": u, "error": str(e)})
    return results


def refresh_all_loop(interval=24 * 3600):
    while True:
        for l in core.load_config()["lists"]:
            for u in l.get("sources") or []:
                info = core.source_info(u)
                if not info["fetched"] or time.time() - info["fetched"] > interval:
                    try:
                        core.fetch_source(u)
                    except Exception as e:
                        print(f"refresh {u}: {e}")
        time.sleep(600)


class Handler(BaseHTTPRequestHandler):
    server_version = "LeechProxy/1.0"

    # ------------------------------------------------------------ helpers
    def _send(self, code, body, ctype="application/json"):
        if not isinstance(body, (bytes, str)):
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if "charset" not in ctype else ""))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(min(n, 20 * 1024 * 1024)).decode("utf-8", "replace")

    def _json(self):
        return json.loads(self._body() or "{}")

    def _authed(self):
        if not PASSWORD:
            return True
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                _, pw = base64.b64decode(h[6:]).decode().split(":", 1)
                if hmac.compare_digest(pw, PASSWORD):
                    return True
            except Exception:
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="LeechProxy"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def _path(self):
        u = urllib.parse.urlsplit(self.path)
        return [p for p in u.path.split("/") if p], urllib.parse.parse_qs(u.query)

    # ------------------------------------------------------------- routes
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parts, q = self._path()
        if parts[:1] == ["blocked"]:
            return self._blocked_page(q)
        if parts == ["ca.pem"]:
            try:
                with open(os.path.join(core.DATA_DIR, "ca", "ca.pem"), "rb") as f:
                    return self._send(200, f.read(), "application/x-pem-file")
            except FileNotFoundError:
                return self._send(404, "CA not created yet: start leechproxy-sni once", "text/plain")
        if not self._authed():
            return
        if not parts:
            with open(os.path.join(STATIC, "index.html"), "rb") as f:
                return self._send(200, f.read(), "text/html")
        if parts == ["api", "state"]:
            return self._send(200, state())
        self._send(404, {"error": "not found"})

    def do_POST(self):
        parts, _ = self._path()
        if not self._authed():
            return
        try:
            if parts == ["api", "lists"]:
                with _lock:
                    cfg = core.load_config()
                    new = core.validate_list(self._json())
                    cfg["lists"].append(new)
                    core.save_config(cfg)
                result = {"list": new}
                if new["sources"]:
                    result["refresh"] = refresh_sources(new)
                return self._send(200, result)
            if len(parts) == 4 and parts[:2] == ["api", "lists"]:
                lst = self._find(parts[2])
                if lst is None:
                    return self._send(404, {"error": "no such list"})
                if parts[3] == "refresh":
                    return self._send(200, {"refresh": refresh_sources(lst)})
                if parts[3] == "reset":
                    who = self._json().get("who")
                    core.reset_usage(lst["id"], dt.date.today().isoformat(), who)
                    return self._send(200, {"ok": True})
            if parts == ["api", "users"]:
                new = core.validate_user(self._json())
                _mutate_users(lambda cfg: cfg["users"].append(new))
                return self._send(200, {"user": new})
        except (ValueError, json.JSONDecodeError) as e:
            return self._send(400, {"error": str(e)})
        self._send(404, {"error": "not found"})

    def do_PUT(self):
        parts, _ = self._path()
        if not self._authed():
            return
        if len(parts) == 3 and parts[:2] == ["api", "users"]:
            try:
                body = self._json()
                body["id"] = parts[2]
                new = core.validate_user(body)

                def replace(cfg):
                    ids = [u["id"] for u in cfg["users"]]
                    if parts[2] not in ids:
                        raise KeyError(parts[2])
                    cfg["users"][ids.index(parts[2])] = new
                _mutate_users(replace)
                return self._send(200, {"user": new})
            except KeyError:
                return self._send(404, {"error": "no such user"})
            except (ValueError, json.JSONDecodeError) as e:
                return self._send(400, {"error": str(e)})
        if len(parts) == 3 and parts[:2] == ["api", "lists"]:
            try:
                with _lock:
                    cfg = core.load_config()
                    for i, l in enumerate(cfg["lists"]):
                        if l["id"] == parts[2]:
                            body = self._json()
                            body["id"] = parts[2]
                            old_sources = set(l.get("sources") or [])
                            cfg["lists"][i] = core.validate_list(body)
                            core.save_config(cfg)
                            new = cfg["lists"][i]
                            break
                    else:
                        return self._send(404, {"error": "no such list"})
                result = {"list": new}
                if set(new["sources"]) - old_sources:
                    result["refresh"] = refresh_sources(new)
                return self._send(200, result)
            except (ValueError, json.JSONDecodeError) as e:
                return self._send(400, {"error": str(e)})
        self._send(404, {"error": "not found"})

    def do_DELETE(self):
        parts, _ = self._path()
        if not self._authed():
            return
        if len(parts) == 3 and parts[:2] == ["api", "users"]:
            def drop(cfg):
                cfg["users"] = [u for u in cfg["users"] if u["id"] != parts[2]]
            saved = _mutate_users(drop)  # validate_config also removes the user from lists
            return self._send(200, {"ok": True, "users": saved["users"]})
        if len(parts) == 3 and parts[:2] == ["api", "lists"]:
            with _lock:
                cfg = core.load_config()
                before = len(cfg["lists"])
                cfg["lists"] = [l for l in cfg["lists"] if l["id"] != parts[2]]
                core.save_config(cfg)
            return self._send(200 if len(cfg["lists"]) < before else 404, {"ok": len(cfg["lists"]) < before})
        self._send(404, {"error": "not found"})

    # -------------------------------------------------------------- pages
    def _find(self, list_id):
        for l in core.load_config()["lists"]:
            if l["id"] == list_id:
                return core.validate_list(l)
        return None

    def _blocked_page(self, q):
        host = q.get("host", [""])[0]
        msg = q.get("msg", [""])[0]
        # msg is "<list name> (<reason>)" as produced by the helper
        name, _, reason = msg.rpartition(" (")
        reason = reason.rstrip(")")
        why = {
            "limit": "You've used up today's time for this site.",
            "period": "This site is blocked at this time of day.",
            "always": "This site is blocked.",
        }.get(reason, "This site is blocked.")
        page = f"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Blocked</title>
<style>
:root{{--bg:#f6f6f4;--card:#fff;--fg:#1d1d1b;--muted:#6b6b66;--line:#e2e2dd;--accent:#b3261e}}
@media (prefers-color-scheme:dark){{:root{{--bg:#141413;--card:#1e1e1c;--fg:#ebebe6;--muted:#9c9c95;--line:#33332f;--accent:#f2827a}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,sans-serif;
  min-height:100vh;display:grid;place-items:center;padding:16px;box-sizing:border-box}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:32px;max-width:28rem;width:100%}}
.icon{{width:44px;height:44px;border-radius:50%;background:var(--accent);color:#fff;display:grid;place-items:center;
  font-size:24px;font-weight:700;margin-bottom:16px}}
h1{{font-size:1.5rem;margin:0 0 6px}} .host{{font-weight:600;overflow-wrap:anywhere}}
p{{margin:8px 0}} .muted{{color:var(--muted);font-size:.9rem}}
</style>
<div class="card"><div class="icon">✕</div>
<h1>Blocked</h1>
<p><span class="host">{html.escape(host)}</span></p>
<p>{html.escape(why)}</p>
{f'<p class="muted">Rule: {html.escape(name or msg)}</p>' if msg else ''}
</div></html>"""
        self._send(200, page, "text/html")


def main():
    global PASSWORD
    ap = argparse.ArgumentParser(description="LeechProxy configuration UI")
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--password", default=os.environ.get("LEECHPROXY_PASSWORD"),
                    help="require HTTP basic auth (any username) for the UI/API")
    args = ap.parse_args()
    PASSWORD = args.password
    os.makedirs(core.DATA_DIR, exist_ok=True)
    threading.Thread(target=refresh_all_loop, daemon=True).start()
    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"LeechProxy UI on http://{args.bind}:{args.port}/  (data: {core.DATA_DIR})")
    srv.serve_forever()


if __name__ == "__main__":
    main()
