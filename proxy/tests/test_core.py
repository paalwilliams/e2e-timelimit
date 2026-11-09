import datetime as dt
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TMP = tempfile.mkdtemp()
os.environ["LEECHPROXY_DATA"] = TMP

from leechproxy import acl_helper, core, webui  # noqa: E402

MON_10 = dt.datetime(2026, 11, 9, 10, 0)  # a Monday


def setup_lists(*lists, users=()):
    core.save_config({"lists": list(lists), "users": list(users)})
    with core.db() as c:
        for t in ("usage2", "hosts2", "devices"):
            c.execute(f"DELETE FROM {t}")


class EngineTest(unittest.TestCase):
    def test_always_blocked_matches_subdomains(self):
        setup_lists({"name": "social", "domains": ["reddit.com"]})
        e = core.Engine()
        self.assertTrue(e.check("old.reddit.com", MON_10)[0])
        self.assertTrue(e.check("reddit.com", MON_10)[0])
        self.assertFalse(e.check("notreddit.com", MON_10)[0])
        self.assertFalse(e.check("151.101.1.140", MON_10)[0])

    def test_allow_exception(self):
        setup_lists({"name": "g", "domains": ["google.com"], "allow": ["docs.google.com"]})
        e = core.Engine()
        self.assertTrue(e.check("mail.google.com", MON_10)[0])
        self.assertFalse(e.check("docs.google.com", MON_10)[0])

    def test_periods_and_days(self):
        setup_lists({"name": "w", "domains": ["x.com"], "periods": ["0900-1700"], "days": ["mon"]})
        e = core.Engine()
        self.assertTrue(e.check("x.com", MON_10)[0])
        self.assertFalse(e.check("x.com", MON_10.replace(hour=18))[0])
        self.assertFalse(e.check("x.com", MON_10 + dt.timedelta(days=1))[0])  # Tuesday

    def test_period_wrapping_midnight(self):
        self.assertTrue(core.in_period(["2200-0600"], MON_10.replace(hour=23)))
        self.assertTrue(core.in_period(["2200-0600"], MON_10.replace(hour=3)))
        self.assertFalse(core.in_period(["2200-0600"], MON_10))

    def test_limit_counts_distinct_minutes(self):
        setup_lists({"name": "yt", "domains": ["youtube.com"], "limit_minutes": 2})
        e = core.Engine()
        for s in (0, 10, 50):  # same minute counted once
            self.assertFalse(e.check("www.youtube.com", MON_10.replace(second=s))[0])
        self.assertFalse(e.check("youtube.com", MON_10.replace(minute=1))[0])
        blocked, name, reason = e.check("youtube.com", MON_10.replace(minute=2))
        self.assertEqual((blocked, reason), (True, "limit"))

    def test_reload_on_change(self):
        setup_lists({"name": "a", "domains": ["a.com"]})
        e = core.Engine()
        self.assertTrue(e.check("a.com", MON_10)[0])
        setup_lists({"name": "a", "domains": ["a.com"], "enabled": False})
        os.utime(core.config_path(), ns=(1, 1))  # force a different mtime
        self.assertFalse(e.check("a.com", MON_10)[0])

    def test_source_lists(self):
        url = "https://example.invalid/hosts"
        os.makedirs(core.sources_dir(), exist_ok=True)
        doms = core.parse_blocklist("# c\n0.0.0.0 ads.example.net\n127.0.0.1 localhost\ntracker.org\n||adserv.io^\n")
        self.assertEqual(doms, {"ads.example.net", "tracker.org", "adserv.io"})
        with open(core.source_cache_file(url), "w") as f:
            f.write("\n".join(doms))
        setup_lists({"name": "ads", "sources": [url]})
        self.assertTrue(core.Engine().check("x.tracker.org", MON_10)[0])

    def test_validation(self):
        with self.assertRaises(ValueError):
            core.validate_list({"periods": ["9-17"]})
        with self.assertRaises(ValueError):
            core.validate_list({"domains": ["bad domain!"]})
        l = core.validate_list({"domains": ["https://www.Reddit.com/r/x", "*.foo.org"]})
        self.assertEqual(l["domains"], ["reddit.com", "foo.org"])


class UsersTest(unittest.TestCase):
    USERS = [{"id": "alice", "name": "Alice", "devices": [{"label": "phone", "mac": "A4-83-E7-12-34-56"}]},
             {"id": "bob", "name": "Bob", "devices": [{"label": "laptop", "ip": "192.168.1.30"}]}]

    def test_list_for_specific_user(self):
        setup_lists({"name": "games", "domains": ["roblox.com"], "users": ["bob"]}, users=self.USERS)
        e = core.Engine()
        self.assertTrue(e.check("roblox.com", MON_10, ip="192.168.1.30")[0])
        self.assertFalse(e.check("roblox.com", MON_10, mac="a4:83:e7:12:34:56", ip="192.168.1.31")[0])
        self.assertFalse(e.check("roblox.com", MON_10, ip="192.168.1.99")[0])  # unknown device

    def test_mac_beats_ip_and_limits_are_per_user(self):
        setup_lists({"name": "yt", "domains": ["youtube.com"], "limit_minutes": 1}, users=self.USERS)
        e = core.Engine()
        # Alice's phone on Bob's old IP is still Alice
        self.assertFalse(e.check("youtube.com", MON_10, mac="a4:83:e7:12:34:56", ip="192.168.1.30")[0])
        self.assertEqual(e.check("youtube.com", MON_10.replace(minute=1), mac="a4:83:e7:12:34:56")[2], "limit")
        self.assertFalse(e.check("youtube.com", MON_10.replace(minute=1), ip="192.168.1.30")[0])  # Bob unaffected
        # Unknown devices each get their own allowance
        self.assertFalse(e.check("youtube.com", MON_10, ip="192.168.1.50")[0])
        self.assertTrue(e.check("youtube.com", MON_10.replace(minute=2), ip="192.168.1.50")[0])
        self.assertFalse(e.check("youtube.com", MON_10.replace(minute=2), ip="192.168.1.51")[0])

    def test_validation(self):
        with self.assertRaises(ValueError):
            core.validate_config({"users": [{"name": "A", "devices": [{"ip": "1.2.3.4"}]},
                                            {"name": "B", "devices": [{"ip": "1.2.3.4"}]}]})
        with self.assertRaises(ValueError):
            core.validate_user({"name": "A", "devices": [{"mac": "nope"}]})
        cfg = core.validate_config({"users": [], "lists": [{"name": "x", "users": ["gone"]}]})
        self.assertEqual(cfg["lists"][0]["users"], [])


class HelperTest(unittest.TestCase):
    def test_protocol(self):
        setup_lists({"name": "social", "domains": ["reddit.com"]})
        e = core.Engine()
        ip, mac = "192.168.1.20", "a4:83:e7:12:34:56"
        self.assertTrue(acl_helper.handle(e, f"7 {ip} {mac} www.reddit.com 151.101.1.140").startswith("7 OK message="))
        self.assertEqual(acl_helper.handle(e, f"8 {ip} - - www.reddit.com").split()[1], "OK")   # explicit CONNECT
        self.assertEqual(acl_helper.handle(e, f"9 {ip} {mac} - 151.101.1.140"), "9 ERR")         # intercepted, no SNI yet
        self.assertEqual(acl_helper.handle(e, f"1 {ip} - example.com 1.2.3.4"), "1 ERR")
        self.assertEqual(acl_helper.handle(e, f"{ip} - reddit.com -").split()[0], "OK")         # no concurrency
        self.assertEqual({d["mac"] for d in core.recent_devices()}, {mac, None})


class WebTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = webui.ThreadingHTTPServer(("127.0.0.1", 0), webui.Handler)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def req(self, method, path, body=None, raw=False):
        data = None if body is None else (body.encode() if raw else json.dumps(body).encode())
        r = urllib.request.Request(self.base + path, data=data, method=method)
        with urllib.request.urlopen(r) as resp:
            ct = resp.headers["Content-Type"]
            out = resp.read().decode()
            return json.loads(out) if ct.startswith("application/json") else out

    def test_crud(self):
        setup_lists()
        l = self.req("POST", "/api/lists", {"name": "Test", "domains": ["a.com"]})["list"]
        st = self.req("GET", "/api/state")
        self.assertEqual(st["lists"][0]["status"][0]["blocked"], True)
        u = self.req("POST", "/api/users", {"name": "Kid", "devices": [{"ip": "127.0.0.1"}]})["user"]
        self.req("PUT", f"/api/users/{u['id']}", {"name": "Kid", "devices": [{"ip": "127.0.0.1"}, {"mac": "aa:bb:cc:dd:ee:ff"}]})
        st = self.req("GET", "/api/state")
        self.assertEqual([x["label"] for x in st["lists"][0]["status"]], ["Kid"])
        self.assertEqual(len(st["users"][0]["devices"]), 2)
        r = self.req("PUT", f"/api/lists/{l['id']}", {"name": "Test2", "domains": ["a.com", "b.com"]})
        self.assertEqual(r["list"]["domains"], ["a.com", "b.com"])
        self.req("DELETE", f"/api/lists/{l['id']}")
        self.req("DELETE", f"/api/users/{u['id']}")
        self.assertEqual(self.req("GET", "/api/state")["users"], [])
        self.assertEqual(len(self.req("GET", "/api/state")["lists"]), 0)
        self.assertIn("<title>LeechProxy</title>", self.req("GET", "/"))
        page = self.req("GET", "/blocked?host=%3Cx%3E&msg=Video%20(limit)")
        self.assertIn("&lt;x&gt;", page)
        self.assertIn("used up today", page)


if __name__ == "__main__":
    unittest.main()
