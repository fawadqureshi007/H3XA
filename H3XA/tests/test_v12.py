"""Tests for the 1.2 features: retries, cancel, report writing + verification, CSV/HTML safety, doctor."""
import csv, io, json, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_all as T
from h3xa import engine as eng, doctor, report
from h3xa.config import Config
from h3xa.correlate import build_case, summarize
from h3xa.models import AdapterError, AdapterResult, Finding, Target, ToolRun


class Flaky(T.Fake):
    name, kinds = "holehe", ("email",)
    calls = 0
    def run(self, t):
        type(self).calls += 1
        if type(self).calls == 1:
            raise AdapterError("no output (rc=1): connection reset by peer")
        return AdapterResult([self.mk(t, "account", title="GitHub", platform="github", via="email")])


class Hard(T.Fake):
    name, kinds = "holehe", ("email",)
    calls = 0
    def run(self, t):
        type(self).calls += 1
        raise AdapterError("timed out after 5s")


def run_engine(adapter, cfg=None, seeds=None):
    orig = dict(eng.ALL)
    eng.ALL.clear(); eng.ALL["holehe"] = adapter
    try:
        events = []
        e = eng.Engine(cfg or Config(), ["holehe"], T.TMP, on_event=lambda ev, **kw: events.append(ev))
        case = e.scan(seeds or [eng.make_seed("a@b.co")])
        return case, events
    finally:
        eng.ALL.clear(); eng.ALL.update(orig)


class EngineBehaviour(unittest.TestCase):
    def test_transient_failure_is_retried_once(self):
        Flaky.calls = 0
        case, events = run_engine(Flaky)
        r = case.runs[0]
        self.assertEqual((r.status, r.attempts, Flaky.calls), ("ok", 2, 2))
        self.assertIn("retry", events)
        self.assertEqual(len(case.accounts), 1)

    def test_timeout_is_not_retried(self):
        Hard.calls = 0
        case, _ = run_engine(Hard)
        self.assertEqual((case.runs[0].status, Hard.calls), ("error", 1))

    def test_retries_can_be_disabled(self):
        Flaky.calls = 0
        cfg = Config(); cfg.data["general"]["retries"] = 0
        case, _ = run_engine(Flaky, cfg)
        self.assertEqual((case.runs[0].status, case.runs[0].attempts), ("error", 1))

    def test_case_meta_and_events(self):
        Flaky.calls = 5
        case, events = run_engine(Flaky)
        self.assertTrue(case.meta["case_id"].startswith("H3XA-"))
        self.assertEqual(events[:3], ["target", "start", "done"])

    def test_cancel_stops_before_next_target(self):
        orig = dict(eng.ALL); eng.ALL.clear(); eng.ALL["holehe"] = T.FakeUS
        try:
            e = eng.Engine(Config(), ["holehe"], T.TMP)
            e.cancel()
            case = e.scan([eng.make_seed("a@b.co")])
        finally:
            eng.ALL.clear(); eng.ALL.update(orig)
        self.assertEqual(case.runs, [])
        self.assertTrue(case.meta["cancelled"])

    def test_unknown_module_is_a_clear_error(self):
        with self.assertRaises(ValueError):
            eng.Engine(Config(), ["nope"], T.TMP)


def sample():
    return doctor._sample_case()


class Reports(unittest.TestCase):
    def test_all_formats_written_and_verified(self):
        with tempfile.TemporaryDirectory() as d:
            rr = report.write_reports(sample(), Path(d), "t")
            self.assertTrue(rr.ok, rr.checks + rr.errors)
            self.assertEqual(sorted(p.suffix for p in rr.paths), [".csv", ".html", ".json", ".md"])
            self.assertEqual(list(Path(d).glob("*.tmp")), [])          # atomic write left nothing behind

    def test_truncated_html_is_detected(self):
        with tempfile.TemporaryDirectory() as d:
            case = sample()
            p = Path(d) / "x.html"
            p.write_text(report.to_html(case)[:5000], encoding="utf-8")
            ok, detail = report.verify_report(p, case, "html")
            self.assertFalse(ok); self.assertTrue(detail)

    def test_bad_json_and_csv_detected(self):
        with tempfile.TemporaryDirectory() as d:
            case = sample()
            j = Path(d) / "x.json"; j.write_text("{broken", encoding="utf-8")
            self.assertFalse(report.verify_report(j, case, "json")[0])
            c = Path(d) / "x.csv"; c.write_text(report.to_csv(case).splitlines()[0] + "\r\n", encoding="utf-8")
            self.assertFalse(report.verify_report(c, case, "csv")[0])

    def test_csv_formula_injection_neutralised(self):
        rows = list(csv.reader(io.StringIO(report.to_csv(sample()))))
        self.assertTrue(all(cell[:1] not in "=+-@" for r in rows for cell in r if cell))

    def test_html_escapes_everything_hostile(self):
        h = report.to_html(sample())
        self.assertNotIn("<img src=x", h); self.assertNotIn("<b>op</b>", h)
        self.assertNotIn('href="javascript:', h)
        self.assertEqual(h.count("<script>"), 1)

    def test_markdown_table_cells_escaped(self):
        self.assertNotIn("a|b", report.to_markdown(sample()))

    def test_no_secret_in_any_format(self):
        case = sample()
        blob = report.to_html(case) + report.to_json(case) + report.to_markdown(case) + report.to_csv(case)
        self.assertNotIn("SECRET-VALUE-123", blob)

    def test_empty_case_still_valid_and_flagged(self):
        case = build_case(["nobody"], [Target("username", "nobody")], [], [], "2026-01-01T00:00:00", "2026-01-01T00:00:01", {"case_id": "X"})
        with tempfile.TemporaryDirectory() as d:
            rr = report.write_reports(case, Path(d), "e")
            self.assertTrue(rr.ok, rr.checks + rr.errors)
        self.assertIn("No module ran", report.to_html(case))

    def test_partial_coverage_is_stated(self):
        case = build_case(["a"], [Target("username", "a")],
                          [ToolRun("tookie", "username:a", "ok", 1, 0), ToolRun("ghunt", "username:a", "needs_auth")], [])
        self.assertIn("Partial coverage", report.to_html(case))

    def test_unknown_format_reported_not_crashing(self):
        with tempfile.TemporaryDirectory() as d:
            rr = report.write_reports(sample(), Path(d), "t", ["html", "pdf"])
            self.assertEqual([p.suffix for p in rr.paths], [".html"])
            self.assertEqual(rr.errors[0][0], "pdf")

    def test_unwritable_folder_reported(self):
        with tempfile.NamedTemporaryFile() as f:
            rr = report.write_reports(sample(), Path(f.name) / "sub", "t")
            self.assertTrue(rr.errors and not rr.ok)

    def test_aliases_and_dedup(self):
        with tempfile.TemporaryDirectory() as d:
            rr = report.write_reports(sample(), Path(d), "t", ["markdown", "md", "HTML"])
            self.assertEqual(sorted(p.suffix for p in rr.paths), [".html", ".md"])


class Doctor(unittest.TestCase):
    def test_every_module_has_fixture_and_contract(self):
        from h3xa.adapters import ALL
        from h3xa import selftest_data as D
        for n in ALL:
            if n != "phoneinfo":
                self.assertIn(n, D.FIXTURES, n); self.assertIn(n, D.CONTRACTS, n)

    def test_parsers_pass_on_builtin_samples(self):
        from h3xa.adapters import ALL
        for n in ALL:
            if n == "phoneinfo":
                continue
            cs = {c.name: c for c in doctor.check_module(n, Config(), T.TMP)}
            self.assertEqual(cs["parser"].status, "pass", f"{n}: {cs['parser'].detail}")

    def test_report_checks_all_pass(self):
        bad = [c for c in doctor.check_reports() if c.status != "pass"]
        self.assertEqual(bad, [])

    def test_doctor_catches_a_broken_parser(self):
        from h3xa.adapters import ALL, tookie
        orig = tookie.Tookie.parse
        tookie.Tookie.parse = lambda self, rows, t: AdapterResult()
        try:
            cs = {c.name: c for c in doctor.check_module("tookie", Config(), T.TMP)}
        finally:
            tookie.Tookie.parse = orig
        self.assertEqual(cs["parser"].status, "fail")

    def test_doctor_catches_contract_drift(self):
        cfg = Config({"general": {"vendor_dir": tempfile.mkdtemp()}})
        v = Path(cfg.vendor_dir) / "tookie"; v.mkdir()
        (v / "brib.py").write_text("nothing relevant")
        cs = {c.name: c for c in doctor.check_module("tookie", cfg, T.TMP)}
        self.assertEqual(cs["contract"].status, "fail")

    def test_live_probe_runs_through_real_subprocess(self):
        v = Path(tempfile.mkdtemp()); (v / "tookie").mkdir()
        (v / "tookie" / "brib.py").write_text(
            "import sys,json\nu=sys.argv[sys.argv.index('-u')+1]\n"
            "json.dump([{'url':'https://github.com/'+u,'found':True,'status':200}],open(u+'.json','w'))\n")
        cfg = Config({"general": {"vendor_dir": str(v)}, "python": {"tookie": sys.executable}})
        c = doctor.check_live("tookie", cfg, Target("username", "someone"), T.TMP, 30)
        self.assertEqual(c.status, "pass", c.detail)
        c2 = doctor.check_live("tookie", Config({"general": {"vendor_dir": str(v)}}), Target("username", "someone"), T.TMP, 30)
        self.assertEqual(c2.status, "warn")                               # no interpreter -> reported, not crashed
        self.assertEqual(doctor.check_live("tookie", cfg, Target("email", "a@b.co"), T.TMP, 30).status, "skip")

    def test_verdict_buckets(self):
        v = doctor.verdict([doctor.Check("A", "install", "pass"), doctor.Check("A", "parser", "pass"),
                            doctor.Check("B", "install", "fail"), doctor.Check("C", "parser", "fail"),
                            doctor.Check("D", "install", "pass"), doctor.Check("D", "access", "warn")])
        self.assertEqual((v["ready_modules"], v["needs_setup"], v["broken_modules"], v["needs_attention"]),
                         (["A"], ["B"], ["C"], ["D"]))
        self.assertFalse(v["ok"])


class PhoneGuard(unittest.TestCase):
    def test_empty_namespace_package_is_not_ready(self):
        import types
        from h3xa.util import phonenumbers_ok
        sys.modules["phonenumbers"] = types.ModuleType("phonenumbers")     # looks imported but has no parse()
        try:
            self.assertFalse(phonenumbers_ok())
        finally:
            sys.modules.pop("phonenumbers", None)


if __name__ == "__main__":
    unittest.main(verbosity=1)
