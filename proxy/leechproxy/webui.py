"""Web configuration UI + JSON API for LeechProxy.

    python3 -m leechproxy.webui [--bind 127.0.0.1] [--port 8080] [--password SECRET]

Endpoints (UI/API are behind --password if given; the LeechBlock and blocked-page
endpoints are not, since browsers and Squid call them unattended):
  GET  /                              config UI
  GET  /api/state                     lists + today's usage + LeechBlock reports
  POST /api/lists                     create list            (JSON body)
  PUT  /api/lists/<id>                replace list           (JSON body)
  DELETE /api/lists/<id>              delete list
  POST /api/lists/<id>/refresh        re-download subscribed blocklists
  POST /api/lists/<id>/reset          reset today's proxy-counted usage
  POST /api/import/leechblock         import a LeechBlock options export (raw body)
  POST /api/leechblock/report         time report from LeechBlock (proxyReportURL option)
  GET  /leechblock/sites/<id>         list as LeechBlock sites (for "Load sites from URL")
  GET  /leechblock/set/<n>            all lists linked to LeechBlock set n ($S in sitesURL)
  GET  /blocked                       block page for Squid deny_info
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

from . import core, leechblock

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
_lock = threading.Lock()  # serialize config read-modify-write
_engine = core.Engine()
PASSWORD = None


def state():
    now = dt.datetime.now()
    day = now.strftime("%Y-%m-%d")
    cfg = core.load_config()
    lists = []
    for raw in cfg["lists"]:
        l = core.validate_list(raw)
        blocked, reason, used = _engine.list_status(l, now)
        l["status"] = {
            "blocked": blocked,
            "reason": reason,
            "used_minutes": used,
            "proxy_minutes": core.proxy_minutes(l["id"], day),
            "leechblock_minutes": core.leechblock_minutes(l["leechblock_set"], day),
        }
        l["source_info"] = [core.source_info(u) for u in l["sources"]]
        lists.append(l)
    return {
        "now": now.isoformat(timespec="seconds"),
        "lists": lists,
        "hosts": [{"host": h, "minutes": m} for h, m in core.host_stats(day)],
        "leechblock_reports": core.leechblock_reports(day),
    }


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

    def log_message(self, fmt, *args):
        if not self.path.startswith("/api/leechblock/report"):
            super().log_message(fmt, *args)

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
        if parts[:2] == ["leechblock", "sites"] and len(parts) == 3:
            return self._lb_sites(lambda l: l["id"] == parts[2].removesuffix(".txt"), q)
        if parts[:2] == ["leechblock", "set"] and len(parts) == 3 and parts[2].isdigit():
            return self._lb_sites(lambda l: l["leechblock_set"] == int(parts[2]), q)
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
        if parts == ["api", "leechblock", "report"]:
            try:
                n = core.record_leechblock_report(self.client_address[0], self._json())
            except (ValueError, AttributeError) as e:
                return self._send(400, {"error": str(e)})
            return self._send(200, {"ok": True, "sets": n})
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
                    core.reset_usage(lst["id"], dt.date.today().isoformat())
                    return self._send(200, {"ok": True})
            if parts == ["api", "import", "leechblock"]:
                lists, warnings = leechblock.import_options(self._body())
                with _lock:
                    cfg = core.load_config()
                    # Re-importing replaces lists previously imported for the same set number
                    linked = {l["leechblock_set"] for l in lists}
                    cfg["lists"] = [l for l in cfg["lists"] if not (l.get("imported") and l.get("leechblock_set") in linked)]
                    cfg["lists"] += lists
                    saved = core.save_config(cfg)
                return self._send(200, {"imported": len(lists), "warnings": warnings, "lists": saved["lists"]})
        except (ValueError, json.JSONDecodeError) as e:
            return self._send(400, {"error": str(e)})
        self._send(404, {"error": "not found"})

    def do_PUT(self):
        parts, _ = self._path()
        if not self._authed():
            return
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

    def _lb_sites(self, pred, q):
        lists = [core.validate_list(l) for l in core.load_config()["lists"]]
        lists = [l for l in lists if pred(l)]
        if not lists:
            return self._send(404, "", "text/plain")
        with_sources = q.get("sources", ["0"])[0] == "1"
        out = []
        for l in lists:
            extra = []
            if with_sources:
                for u in l["sources"]:
                    try:
                        with open(core.source_cache_file(u)) as f:
                            extra += [x.strip() for x in f if x.strip()]
                    except FileNotFoundError:
                        pass
            out.append(leechblock.sites_for_leechblock(l, extra))
        self._send(200, "".join(out), "text/plain")

    def _blocked_page(self, q):
        host = html.escape(q.get("host", [""])[0])
        msg = html.escape(q.get("msg", [""])[0])
        page = f"""<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Blocked</title><style>body{{font:16px system-ui;margin:15vh auto;max-width:32rem;padding:0 16px;
color:#222;background:#fafafa}}h1{{font-size:1.6rem}}code{{background:#eee;padding:2px 4px}}
@media (prefers-color-scheme:dark){{body{{background:#161616;color:#ddd}}code{{background:#333}}}}</style>
<h1>Site blocked</h1><p><code>{host}</code> is blocked by LeechProxy.</p><p>{msg}</p>"""
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
