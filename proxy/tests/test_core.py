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

from leechproxy import acl_helper, core, leechblock, webui  # noqa: E402

MON_10 = dt.datetime(2026, 11, 9, 10, 0)  # a Monday


def setup_lists(*lists):
    core.save_config({"lists": list(lists)})
    if os.path.exists(core.db_path()):
        with core.db() as c:
            c.execute("DELETE FROM usage"); c.execute("DELETE FROM hosts"); c.execute("DELETE FROM lbreports")


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

    def test_leechblock_report_counts(self):
        setup_lists({"name": "yt", "domains": ["youtube.com"], "limit_minutes": 30, "leechblock_set": 2})
        e = core.Engine()
        midnight = dt.datetime.combine(MON_10.date(), dt.time()).timestamp()
        core.record_leechblock_report("10.0.0.5", {"sets": [{"set": 2, "periodStart": midnight, "periodSecs": 1500}]}, MON_10)
        self.assertFalse(e.check("youtube.com", MON_10)[0])
        core.record_leechblock_report("10.0.0.6", {"sets": [{"set": 2, "periodStart": midnight, "periodSecs": 400}]}, MON_10)
        self.assertEqual(e.check("youtube.com", MON_10)[2], "limit")  # 25 + 6 min across two browsers
        # A stale period (yesterday) doesn't count
        core.record_leechblock_report("10.0.0.6", {"sets": [{"set": 2, "periodStart": midnight - 86400, "periodSecs": 9999}]}, MON_10)
        self.assertFalse(e.check("youtube.com", MON_10)[0])

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


class HelperTest(unittest.TestCase):
    def test_protocol(self):
        setup_lists({"name": "social", "domains": ["reddit.com"]})
        e = core.Engine()
        self.assertTrue(acl_helper.handle(e, "7 www.reddit.com 151.101.1.140").startswith("7 OK message="))
        self.assertEqual(acl_helper.handle(e, "8 - www.reddit.com").split()[1], "OK")   # explicit CONNECT
        self.assertEqual(acl_helper.handle(e, "9 - 151.101.1.140"), "9 ERR")            # intercepted, no SNI yet
        self.assertEqual(acl_helper.handle(e, "1 example.com 1.2.3.4"), "1 ERR")
        self.assertEqual(acl_helper.handle(e, "reddit.com -").split()[0], "OK")          # no concurrency


class LeechBlockImportTest(unittest.TestCase):
    EXPORT = "\n".join([
        "numSets=3",
        "setName1=Social%20media",
        "sites1=+old.reddit.com facebook.com reddit.com twitter.com/home ~cats",
        "times1=0900-1700",
        "limitMins1=30",
        "limitPeriod1=86400",
        "days1=62",            # Mon-Fri
        "conjMode1=false",
        "sites2=",
        "setName3=",
        "sites3=youtube.com",
        "limitMins3=",
        "days3=127",
    ])

    def test_import(self):
        lists, warnings = leechblock.import_options(self.EXPORT)
        self.assertEqual(len(lists), 2)
        a, b = lists
        self.assertEqual(a["name"], "Social media")
        self.assertEqual(sorted(a["domains"]), ["facebook.com", "reddit.com"])
        self.assertEqual(a["allow"], ["old.reddit.com"])
        self.assertEqual(a["periods"], ["0900-1700"])
        self.assertEqual(a["limit_minutes"], 30)
        self.assertEqual(a["days"], ["mon", "tue", "wed", "thu", "fri"])
        self.assertEqual(a["leechblock_set"], 1)
        self.assertTrue(any("twitter.com/home" in w for w in warnings))
        self.assertEqual(b["name"], "LeechBlock set 3")
        self.assertEqual(b["days"], core.DAYS)
        core.validate_list(a); core.validate_list(b)

    def test_json_export(self):
        js = json.dumps({"numSets": "1", "sites1": "x.com", "days1": [True] * 7, "setName1": "X"})
        lists, _ = leechblock.import_options(js)
        self.assertEqual(lists[0]["domains"], ["x.com"])

    def test_sites_output(self):
        txt = leechblock.sites_for_leechblock({"domains": ["b.com", "a.com"], "allow": ["x.a.com"]}, ["c.com"])
        self.assertEqual(txt, "a.com\nb.com\nc.com\n+x.a.com\n")


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

    def test_crud_import_and_sites(self):
        setup_lists()
        l = self.req("POST", "/api/lists", {"name": "Test", "domains": ["a.com"]})["list"]
        st = self.req("GET", "/api/state")
        self.assertEqual(st["lists"][0]["status"]["blocked"], True)
        self.req("PUT", f"/api/lists/{l['id']}", {"name": "Test2", "domains": ["a.com", "b.com"], "leechblock_set": 4})
        self.assertEqual(self.req("GET", f"/leechblock/sites/{l['id']}"), "a.com\nb.com\n")
        self.assertEqual(self.req("GET", "/leechblock/set/4"), "a.com\nb.com\n")
        r = self.req("POST", "/api/import/leechblock", LeechBlockImportTest.EXPORT, raw=True)
        self.assertEqual(r["imported"], 2)
        r = self.req("POST", "/api/import/leechblock", LeechBlockImportTest.EXPORT, raw=True)  # re-import replaces
        self.assertEqual(len(r["lists"]), 3)
        self.req("POST", "/api/leechblock/report", {"sets": [{"set": 1, "periodStart": 0, "periodSecs": 5}]})
        self.assertEqual(len(self.req("GET", "/api/state")["leechblock_reports"]), 1)
        self.req("DELETE", f"/api/lists/{l['id']}")
        self.assertEqual(len(self.req("GET", "/api/state")["lists"]), 2)
        self.assertIn("<title>LeechProxy</title>", self.req("GET", "/"))
        self.assertIn("&lt;x&gt;", self.req("GET", "/blocked?host=%3Cx%3E"))


if __name__ == "__main__":
    unittest.main()
