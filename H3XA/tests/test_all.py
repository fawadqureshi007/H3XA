import json, sys, tempfile, time, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from h3xa import engine as eng
from h3xa.adapters import (GHunt, H8mail, Holehe, Osintgram, SpiderFoot, Tookie, UserRecon, UserScanner)
from h3xa.adapters.base import Adapter
from h3xa.config import Config
from h3xa.correlate import build_case, combine, summarize
from h3xa.models import AdapterResult, Finding, Pivot, Target
from h3xa.report import to_html, to_json, to_markdown
from h3xa.runner import run
from h3xa.util import detect_kind, platform_key

CFG = Config()
TMP = Path(tempfile.mkdtemp())
T_MAIL = Target("email", "jane@example.com")
T_USER = Target("username", "janedoe")


class Util(unittest.TestCase):
    def test_kind(self):
        for v, k in [("a@b.co", "email"), ("1.2.3.4", "ip"), ("example.com", "domain"),
                     ("+923001234567", "phone"), ("Jane Doe", "name"), ("janedoe", "username")]:
            self.assertEqual(detect_kind(v), k, v)

    def test_platform_key(self):
        self.assertEqual(platform_key("https://www.instagram.com/x"), "instagram")
        self.assertEqual(platform_key("instagram.com"), "instagram")
        self.assertEqual(platform_key("Instagram"), "instagram")
        self.assertEqual(platform_key("https://x.com/a"), "twitter")
        self.assertEqual(platform_key("https://foo.bbc.co.uk/"), "bbc")


class Parsers(unittest.TestCase):
    def test_user_scanner(self):
        rows = [{"status": "Registered", "site_name": "Instagram", "url": "", "category": "social",
                 "extra": {"full_name": "Jane D", "contact_email": "jane.work@corp.com"}, "media": {}},
                {"status": "Not Registered", "site_name": "X"}, {"status": "Error", "site_name": "Y"},
                {"status": "Skipped", "site_name": "Z"}]
        r = UserScanner(CFG, TMP).parse(rows, T_MAIL)
        acc = [f for f in r.findings if f.category == "account"]
        self.assertEqual(len(acc), 1)
        self.assertEqual(acc[0].platform, "instagram")
        self.assertEqual(r.checked, 4)
        self.assertTrue(any(f.kind == "name" and f.value == "Jane D" for f in r.findings))
        self.assertEqual([(p.value, p.trust) for p in acc[0].pivots], [("jane.work@corp.com", "verified")])
        self.assertIn("1 modules errored", r.message)

    def test_hudson(self):
        txt = "Infection #1:\n - Stealer Family: RedLine\n - Date Compromised: 2023-01-01\n - Operating System: Win10\n - Computer Name: PC1\n"
        f = UserScanner(CFG, TMP).parse_hudson(txt, T_MAIL)
        self.assertEqual(f[0].value, "RedLine")

    def test_holehe(self):
        rows = [{"name": "github", "domain": "github.com", "exists": True, "rateLimit": False, "method": "register",
                 "emailrecovery": "j***@g***.com", "phoneNumber": None, "others": {"FullName": "Jane Doe"}},
                {"name": "x", "domain": "x.com", "exists": False, "rateLimit": True},
                {"name": "y", "domain": "y.com", "exists": False, "rateLimit": False, "error": True}]
        r = Holehe(CFG, TMP).parse(rows, T_MAIL)
        self.assertEqual([f.platform for f in r.findings if f.category == "account"], ["github"])
        kinds = {f.kind for f in r.findings if f.category == "identity"}
        self.assertEqual(kinds, {"recovery_email", "name"})
        self.assertIn("rate-limited", r.message)

    def test_h8mail_redacts_and_pivots(self):
        doc = {"targets": [{"target": "jane@example.com", "pwn_num": 2, "data": [
            ["HIBP3:Adobe"], ["SCYLLA_USERNAME:jdoe", "SCYLLA_PASSWORD:hunter2", "SCYLLA_EMAIL:jd2@example.org", "SCYLLA_SOURCE:collection1"]]}]}
        r = H8mail(CFG, TMP).parse(doc, T_MAIL)
        blob = json.dumps([f.to_dict() for f in r.findings])
        self.assertNotIn("hunter2", blob)
        br = [f for f in r.findings if f.category == "breach"]
        self.assertEqual(len(br), 2)
        self.assertTrue(any(p.value == "jd2@example.org" for f in br for p in f.pivots))
        self.assertEqual(br[1].data["credential_fields"], 1)

    def test_ghunt(self):
        doc = {"PROFILE_CONTAINER": {"profile": {"personId": "1234", "names": {"PROFILE": {"fullname": "Jane Doe"}},
               "profilePhotos": {"PROFILE": {"url": "https://lh3/x", "isDefault": False}},
               "inAppReachability": {"PROFILE": {"apps": ["Maps", "Photos"]}}}, "play_games": None,
               "maps": {"stats": {"reviews": 3}}, "calendar": None}}
        r = GHunt(CFG, TMP).parse(doc, T_MAIL)
        self.assertTrue(any(f.platform == "google" for f in r.findings))
        self.assertTrue(any(f.kind == "google_id" and f.value == "1234" for f in r.findings))

    def test_ghunt_applies(self):
        g = GHunt(CFG, TMP)
        self.assertTrue(g.applies(Target("email", "a@gmail.com"), []))
        self.assertFalse(g.applies(T_MAIL, []))
        prior = [Finding("holehe", "jane@example.com", "email", "account", platform="google")]
        self.assertTrue(g.applies(T_MAIL, prior))

    def test_tookie_userrecon_spiderfoot(self):
        r = Tookie(CFG, TMP).parse([{"url": "https://github.com/janedoe", "found": True, "status": 200},
                                    {"url": "https://a.com/janedoe", "found": False}], T_USER)
        self.assertEqual(len(r.findings), 1)
        r = UserRecon(CFG, TMP).parse(["https://www.facebook.com/janedoe", ""], T_USER)
        self.assertEqual(r.findings[0].platform, "facebook")
        ev = [{"type": "EMAILADDR", "data": "info@example.com", "module": "sfp_x"},
              {"type": "IP_ADDRESS", "data": "1.2.3.4", "module": "sfp_dns"},
              {"type": "ROOT", "data": "x"},
              {"type": "ACCOUNT_EXTERNAL_OWNED", "data": "Twitter (Category: social)\n<SFURL>https://twitter.com/jane</SFURL>", "module": "sfp_account"}]
        r = SpiderFoot(CFG, TMP).parse(ev, Target("domain", "example.com"))
        cats = sorted(f.category for f in r.findings)
        self.assertEqual(cats, ["account", "identity", "infra"])
        self.assertEqual([f for f in r.findings if f.category == "account"][0].platform, "twitter")

    def test_osintgram(self):
        doc = {"info": {"full_name": "Jane D", "biography": "mail jane@x.org", "public_email": "jane@biz.com",
                        "bio_links": [{"url": "https://jane.dev"}]}, "about": {"country": "PK"}, "_api_calls": 5}
        r = Osintgram(CFG, TMP).parse(doc, T_USER)
        self.assertEqual({p.value for p in r.findings[0].pivots}, {"jane@biz.com", "jane@x.org"})
        og = Osintgram(CFG, TMP)
        prior = [Finding("tookie", "janedoe", "username", "account", platform="instagram")]
        self.assertTrue(og.applies(T_USER, prior))
        self.assertFalse(og.applies(T_USER, []))


class Correlation(unittest.TestCase):
    def test_combine(self):
        self.assertAlmostEqual(combine([0.8, 0.8]), 0.96)

    def test_dedupe_across_tools(self):
        fs = [Finding("user-scanner", "janedoe", "username", "account", platform="github", via="username", weight=.8, url="https://github.com/janedoe"),
              Finding("tookie", "janedoe", "username", "account", platform="github", via="username", weight=.6, url="https://github.com/janedoe"),
              Finding("tookie", "janedoe", "username", "account", platform="reddit", via="username", weight=.6),
              # name-vs-domain mismatch resolved by alt key
              Finding("user-scanner", "janedoe", "username", "account", platform="hackernews", via="username", weight=.8, data={"alt_keys": ["ycombinator"]}),
              Finding("tookie", "janedoe", "username", "account", platform="ycombinator", via="username", weight=.6)]
        case = build_case(["janedoe"], [T_USER], [], fs)
        by = {a.platform: a for a in case.accounts}
        self.assertEqual(len(case.accounts), 3)
        self.assertEqual(by["github"].tools, ["tookie", "user-scanner"])
        self.assertGreater(by["github"].confidence, 0.9)
        self.assertLess(by["reddit"].confidence, 0.7)
        self.assertEqual(len(by["ycombinator"].tools), 2)


class Fake(Adapter):
    needs_python = False
    def check(self): pass

class FakeUS(Fake):
    name, kinds, weight = "user-scanner", ("email", "username"), .8
    def run(self, t):
        f = self.mk(t, "account", title="Instagram", platform="instagram", via=t.kind)
        if t.kind == "email":
            f.pivots.append(Pivot("username", "janedoe", "verified"))
            f.pivots.append(Pivot("email", "junk@spam.com", "scraped"))
        return AdapterResult([f], checked=100)

class FakeTookie(Fake):
    name, kinds, weight = "tookie", ("username",), .6
    def run(self, t):
        return AdapterResult([self.mk(t, "account", title="instagram", platform="instagram", via="username")])

class FakeIG(Fake):
    name, kinds, phase = "osintgram", ("username",), 2
    applies = Osintgram.applies
    opts = {}
    def run(self, t):
        return AdapterResult([self.mk(t, "account", title="Instagram", platform="instagram", via="username", weight=.98),
                              self.mk(t, "identity", kind="name", value="Jane Doe")])

class Boom(Fake):
    name, kinds = "holehe", ("email",)
    def run(self, t): raise RuntimeError("kaboom")


class EngineE2E(unittest.TestCase):
    def test_pivot_cooperation_and_report(self):
        orig = dict(eng.ALL)
        eng.ALL.clear(); eng.ALL.update({"user-scanner": FakeUS, "tookie": FakeTookie, "osintgram": FakeIG, "holehe": Boom})
        try:
            logs = []
            e = eng.Engine(CFG, ["user-scanner", "tookie", "osintgram", "holehe"], TMP, logs.append)
            case = e.scan([eng.make_seed("jane@example.com")])
        finally:
            eng.ALL.clear(); eng.ALL.update(orig)
        keys = [t.key for t in case.targets]
        self.assertEqual(keys, ["email:jane@example.com", "username:janedoe"])   # verified pivot yes, scraped no
        self.assertEqual(case.targets[1].depth, 1)
        # phase 2 ran only because tookie/user-scanner found instagram for the handle
        self.assertTrue(any(r.tool == "osintgram" and r.status == "ok" for r in case.runs))
        # one tool crashing does not kill the case
        self.assertTrue(any(r.tool == "holehe" and r.status == "error" for r in case.runs))
        ig = [a for a in case.accounts if a.platform == "instagram" and a.subject == "janedoe"][0]
        self.assertEqual(sorted(ig.tools), ["osintgram", "tookie", "user-scanner"])
        self.assertLess(ig.confidence, 0.99)
        s = summarize(case)
        self.assertEqual(s["runs_failed"], 1)
        h, m, j = to_html(case), to_markdown(case), json.loads(to_json(case))
        self.assertIn("Instagram", h); self.assertIn("kaboom", h); self.assertIn("| Instagram", m)
        self.assertEqual(j["summary"]["targets"], 2)

    def test_html_escapes(self):
        f = Finding("t", "<script>alert(1)</script>", "username", "account", title="<img src=x onerror=1>", platform="p", via="username")
        h = to_html(build_case(["x"], [Target("username", f.subject)], [], [f]))
        self.assertNotIn("<script>alert(1)", h); self.assertNotIn("<img src=x", h)


class Runner(unittest.TestCase):
    def test_timeout_kills(self):
        t = time.time()
        r = run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1)
        self.assertTrue(r.timed_out); self.assertLess(time.time() - t, 6)

    def test_ok(self):
        r = run([sys.executable, "-c", "import sys; print(sys.stdin.read())"], input_text="hi")
        self.assertEqual(r.out.strip(), "hi")



class Plumbing(unittest.TestCase):
    """Real adapter -> real subprocess -> stub tool that writes output the way tookie does."""
    def test_tookie_via_subprocess(self):
        v = Path(tempfile.mkdtemp())
        (v / "tookie").mkdir()
        (v / "tookie" / "brib.py").write_text(
            "import sys,json\nu=sys.argv[sys.argv.index('-u')+1]\n"
            "json.dump([{'url':'https://github.com/'+u,'found':True,'status':200}],open(u+'.json','w'))\n")
        cfg = Config({"general": {"vendor_dir": str(v)}, "python": {"tookie": sys.executable}})
        ad = Tookie(cfg, TMP)
        ad.check()
        res = ad.run(T_USER)
        self.assertEqual(res.findings[0].platform, "github")
        cfg2 = Config({"general": {"vendor_dir": str(v)}})   # no interpreter configured
        from h3xa.models import Unavailable
        with self.assertRaises(Unavailable):
            Tookie(cfg2, TMP).check()



class PhoneStub(unittest.TestCase):
    """PhoneInfo against a stub of the phonenumbers API (real lib is installed by the launcher)."""
    def test_phone(self):
        import types
        m = types.ModuleType("phonenumbers")
        class Ex(Exception): pass
        class Fmt: E164, INTERNATIONAL = 0, 1
        class Typ: MOBILE = FIXED_LINE = FIXED_LINE_OR_MOBILE = VOIP = TOLL_FREE = PREMIUM_RATE = 9
        m.NumberParseException, m.PhoneNumberFormat, m.PhoneNumberType = Ex, Fmt, Typ
        m.parse = lambda raw, region: ("num", raw, region)
        m.is_valid_number = lambda n: n[2] != "XX" and n[1] != "+1"
        m.format_number = lambda n, f: n[1] if f == 0 else "+92 300 1234567"
        m.number_type = lambda n: 9
        g, ca, tz = types.ModuleType("g"), types.ModuleType("c"), types.ModuleType("t")
        g.description_for_number = lambda n, l: "Karachi"; g.country_name_for_number = lambda n, l: "Pakistan"
        ca.name_for_number = lambda n, l: "Jazz"; tz.time_zones_for_number = lambda n: ("Asia/Karachi", "Etc/Unknown")
        m.geocoder, m.carrier, m.timezone = g, ca, tz
        sys.modules.update({"phonenumbers": m, "phonenumbers.geocoder": g, "phonenumbers.carrier": ca, "phonenumbers.timezone": tz})
        try:
            ad = __import__("h3xa.adapters", fromlist=["PhoneInfo"]).PhoneInfo(CFG, TMP)
            ad.check()
            r = ad.run(Target("phone", "03001234567", hints={"region": "pk"}))
            kinds = {f.kind: f.value for f in r.findings}
            self.assertEqual(kinds["location"], "Karachi, Pakistan")
            self.assertEqual(kinds["carrier"], "Jazz")
            self.assertEqual(kinds["timezone"], "Asia/Karachi")
            self.assertIn("phone", kinds)
            bad = ad.run(Target("phone", "+1", hints={}))
            self.assertIn("not valid", bad.message)
        finally:
            for k in ("phonenumbers", "phonenumbers.geocoder", "phonenumbers.carrier", "phonenumbers.timezone"):
                sys.modules.pop(k, None)


class ReqCheck(unittest.TestCase):
    def test_pypdf2_import_name_keeps_case(self):
        from h3xa import reqcheck
        self.assertEqual(reqcheck.import_name_for("PyPDF2"), "PyPDF2")

    def test_relax_drops_only_upper_bound(self):
        from h3xa import reqcheck
        self.assertEqual(reqcheck.relax("pyOpenSSL>=21.0.0,<22"), "pyOpenSSL>=21.0.0")
        self.assertEqual(reqcheck.relax("lxml>=4.9.2,<5"), "lxml>=4.9.2")
        self.assertEqual(reqcheck.relax("requests>=2.28.2,<3"), "requests>=2.28.2")
        self.assertEqual(reqcheck.relax("six"), "six")

    def test_bulk_file_relaxes_problem_pins(self):
        import tempfile
        from h3xa import reqcheck
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "r.txt"
            src.write_text("lxml>=4.9.2,<5\ncryptography>=3.4.8,<4\npyOpenSSL>=21.0.0,<22\nMako>=1.2.4,<2\n")
            out = reqcheck.filtered_requirements(src, Path(d) / "b.txt").read_text().split()
            self.assertEqual(out, ["lxml>=4.9.2", "cryptography>=3.4.8", "pyOpenSSL>=21.0.0", "Mako>=1.2.4,<2"])

    def test_unused_pygexf_is_skipped(self):
        import tempfile
        from h3xa import reqcheck
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "requirements.txt"
            src.write_text("requests>=2\npygexf>=0.2.2,<0.3\nPyPDF2>=1.28.6,<2\n")
            out = reqcheck.filtered_requirements(src, Path(d) / "bulk.txt").read_text()
            self.assertNotIn("pygexf", out)
            self.assertIn("PyPDF2", out)
            missing = reqcheck.missing_packages(sys.executable, src)
            self.assertNotIn("pygexf", [m[1] for m in missing])


if __name__ == "__main__":
    unittest.main(verbosity=1)
