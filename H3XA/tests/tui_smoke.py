"""Drives the real TUI with piped keystrokes and fake tools. Prints the raw screen."""
import io, os, sys, types
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("TERM", "xterm")
import test_all as T
from h3xa import engine as eng, tui
from h3xa.models import AdapterResult, Pivot
from h3xa.adapters.phoneinfo import PhoneInfo

class FakeHolehe(T.Fake):
    name, kinds, weight = "holehe", ("email",), .75
    def run(self, t):
        fs = [self.mk(t, "account", title="Instagram", platform="instagram", via="email", url="https://instagram.com"),
              self.mk(t, "account", title="Spotify", platform="spotify", via="email"),
              self.mk(t, "identity", kind="recovery_email", value="j***@g***.com", weight=.7)]
        return AdapterResult(fs, checked=120, message="4 modules rate-limited")

class FakeGH(T.Fake):
    name, kinds, phase = "ghunt", ("email",), 2
    def applies(self, t, prior): return t.kind == "email"
    def run(self, t):
        return AdapterResult([self.mk(t, "account", title="Google", platform="google", via="email", weight=.97),
            self.mk(t, "identity", kind="name", value="Jane Doe", weight=.9),
            self.mk(t, "identity", kind="location", title="Maps", value="Dubai, UAE", weight=.6)])

class FakeH8(T.Fake):
    name, kinds = "h8mail", ("email",)
    def run(self, t):
        return AdapterResult([self.mk(t, "breach", kind="breach", title="Adobe (2013)", weight=.75, data={"credential_fields": 1})])

class Missing(T.Fake):
    name, kinds = "spiderfoot", ("domain",)
    def check(self):
        from h3xa.models import Unavailable
        raise Unavailable("no Python env; run setup")

fake = {"user-scanner": T.FakeUS, "holehe": FakeHolehe, "h8mail": FakeH8, "ghunt": FakeGH, "tookie": T.FakeTookie,
        "osintgram": T.FakeIG, "spiderfoot": Missing}
for k in ("user-scanner","holehe","h8mail","ghunt","tookie","osintgram","spiderfoot"):
    pass
for d in (eng.ALL, tui.ALL):
    d.clear(); d.update(fake)
tui.DESC.setdefault("phoneinfo", "x")
cfg = tui.Config()
cfg.data["general"]["output_dir"] = "/tmp/h3xa_reports"
cfg.data["general"]["retries"] = 0
st = tui.State(cfg)
sys.stdin = io.StringIO("1\njane@example.com\n\n\n\nTester\nlab test\n\n\n0\n")  # scan, target, keep type, no extras, standard, operator, purpose, start, back, exit
tui.menu(st)
