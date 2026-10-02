"""Self-test ("doctor"): proves, module by module, what works - and says plainly what does not.

Layers (cheapest first; each can fail independently so the cause is obvious):
  1. install   - source folder present, private Python env present, requirements importable
  2. contract  - the CLI flags / functions our adapter relies on still exist in the vendored source
  3. parser    - the adapter turns a built-in sample of the tool's real output into findings
                 (also asserts secrets are never carried into findings)
  4. access    - credentials the module needs for live use are present (warn, not fail)
  5. live      - OPTIONAL (`--live TARGET`): actually run the module against a target you choose
  6. reports   - build a case from the samples, write every format, re-read and validate each one,
                 and prove hostile input is neutralised

Status values: pass | warn | fail | skip.   Exit code of `h3xa doctor` is 1 if anything failed.
"""
from __future__ import annotations
import copy
import json
import os
import socket
import sys
import tempfile
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Callable

from . import selftest_data as D
from .adapters import ALL
from .branding import display
from .config import Config
from .correlate import build_case
from .engine import Engine, make_seed
from .models import AdapterError, Finding, MissingRequirement, Target, ToolRun
from .report import FORMATS, write_reports
from .util import detect_kind

PASS, WARN, FAIL, SKIP = "pass", "warn", "fail", "skip"


@dataclass
class Check:
    group: str          # "Environment" | module label | "Reports"
    name: str
    status: str
    detail: str = ""
    seconds: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


def _timed(group: str, name: str, fn: Callable[[], tuple[str, str]]) -> Check:
    t0 = time.time()
    try:
        status, detail = fn()
    except Exception as e:   # a check that crashes is itself a failure, never a crash of the doctor
        status, detail = FAIL, f"check crashed: {type(e).__name__}: {e}"
    return Check(group, name, status, detail, round(time.time() - t0, 2))


# ----------------------------------------------------------------------------- environment
def check_environment(cfg: Config, net: bool = False) -> list[Check]:
    g, out = "Environment", []
    v = sys.version_info
    out.append(_timed(g, "Python version", lambda: (PASS, f"{v.major}.{v.minor}.{v.micro}") if v >= (3, 11)
                      else (WARN, f"{v.major}.{v.minor} - 3.11+ needed to read h3xa.toml")))

    def outdir():
        d = cfg.output_dir
        d.mkdir(parents=True, exist_ok=True)
        probe = d / ".h3xa_write_test"
        probe.write_text("ok")
        probe.unlink()
        return PASS, f"{d} is writable"
    out.append(_timed(g, "Reports folder", outdir))

    def vendor():
        n = sum(1 for t in D.CONTRACTS if cfg.src(t).is_dir())
        return (PASS if n == len(D.CONTRACTS) else WARN), f"{n}/{len(D.CONTRACTS)} module sources unpacked in {cfg.vendor_dir}"
    out.append(_timed(g, "Module sources", vendor))

    def phonelib():
        from .util import phonenumbers_ok
        if not phonenumbers_ok():
            return WARN, "real phonenumbers library not available - PhoneID unavailable (installed on first run)"
        return PASS, "phonenumbers available"
    out.append(_timed(g, "Phone library", phonelib))

    if net:
        def online():
            for host in ("1.1.1.1", "8.8.8.8"):
                try:
                    socket.create_connection((host, 443), timeout=4).close()
                    return PASS, f"reached {host}:443"
                except OSError:
                    continue
            return FAIL, "no outbound connection - live scans will fail"
        out.append(_timed(g, "Internet access", online))
    return out


# ----------------------------------------------------------------------------- one module
def _access(name: str, ad, cfg: Config) -> tuple[str, str]:
    if name == "ghunt":
        return (PASS, "Google session found") if ad._creds_ok() else (WARN, "not logged in - run: <venv>/bin/ghunt login")
    if name == "osintgram":
        has = bool(os.environ.get("HIKERAPI_TOKEN")) or any(
            (cfg.src("osintgram") / "config" / f).exists() for f in ("credentials.ini", "credentials.json"))
        return (PASS, "credentials found") if has else (WARN, "no HikerAPI token / instagrapi session found")
    if name == "h8mail":
        return (PASS, "API-key config set") if cfg.get("h8mail", "config") else (WARN, "no API keys configured - fewer breach sources")
    return PASS, "no credentials needed"


def check_module(name: str, cfg: Config, tmp: Path) -> list[Check]:
    label, ad, out = display(name), ALL[name](cfg, tmp), []

    def install():
        try:
            ad.check()
        except MissingRequirement as e:
            return WARN, f"{e} (repair: menu [2] Module status)"
        except AdapterError as e:
            return FAIL, str(e)
        return PASS, "source + private environment + packages OK"
    c_install = _timed(label, "install", install)
    out.append(c_install)

    def contract():
        rules = D.CONTRACTS.get(name)
        if not rules:
            return SKIP, "built-in module (no external source)"
        if not cfg.src(ad.dir).is_dir():
            return SKIP, "source not unpacked"
        bad = []
        for rel, needle in rules:
            f = cfg.src(ad.dir) / rel
            if not f.is_file():
                bad.append(f"{rel} missing")
            elif needle not in f.read_text(encoding="utf-8", errors="replace"):
                bad.append(f"{needle} not in {rel}")
        if bad:
            return FAIL, "vendored version no longer matches the adapter: " + "; ".join(bad[:3])
        return PASS, f"{len(rules)} expectations match the vendored source"
    out.append(_timed(label, "contract", contract))

    def parser():
        if name == "phoneinfo":
            from .util import phonenumbers_ok
            if not phonenumbers_ok():
                return SKIP, "phonenumbers library missing or broken (see install check)"
            import phonenumbers
            tgt = Target("phone", D.PHONE_SAMPLE)
            res = ad.parse_number(phonenumbers.parse(D.PHONE_SAMPLE, None), tgt)
            kinds = {f.kind for f in res.findings}
            if "phone" not in kinds:
                return FAIL, "no normalised number produced"
            return PASS, "kinds: " + ", ".join(sorted(kinds))
        tgt, sample, need = D.FIXTURES[name]
        res = ad.parse(sample, tgt)
        cats = {f.category for f in res.findings}
        if need - cats:
            return FAIL, f"missing categories: {', '.join(sorted(need - cats))} (got {', '.join(sorted(cats)) or 'nothing'})"
        blob = json.dumps([f.to_dict() for f in res.findings], default=str)
        if "SECRET-VALUE-123" in blob:
            return FAIL, "a credential value leaked into findings"
        return PASS, f"{len(res.findings)} findings from sample ({', '.join(sorted(cats))})"
    out.append(_timed(label, "parser", parser))

    out.append(_timed(label, "access", lambda: _access(name, ad, cfg)))
    return out


# ----------------------------------------------------------------------------- live probe
def check_live(name: str, cfg: Config, target: Target, tmp: Path, timeout: int) -> Check:
    label = display(name)
    probe_cfg = Config(copy.deepcopy(cfg.data), cfg.path)
    probe_cfg.data["pivot"]["depth"] = 0
    probe_cfg.data["general"]["retries"] = 0
    probe_cfg.data["timeouts"] = {**probe_cfg.data.get("timeouts", {}), name: timeout}
    ad = ALL[name](probe_cfg, tmp)
    applicable = ad.applies(target, []) if ad.phase == 1 else target.kind in ad.kinds
    if not applicable:
        return Check(label, "live", SKIP, f"does not take a {target.kind} target")
    run: dict = {}

    def on_event(ev, **kw):
        if ev == "done":
            run["r"] = kw["run"]
    t0 = time.time()
    try:
        # phase-2 modules only run when told to (instagram hint) so the probe really exercises them
        t = Target(target.kind, target.value, hints={**target.hints, "instagram": True} if name == "osintgram" else target.hints)
        Engine(probe_cfg, [name], tmp, on_event=on_event).scan([t])
    except Exception as e:
        return Check(label, "live", FAIL, f"{type(e).__name__}: {e}", round(time.time() - t0, 1))
    r: ToolRun | None = run.get("r")
    secs = round(time.time() - t0, 1)
    if r is None:
        return Check(label, "live", SKIP, "module did not run for this target", secs)
    if r.status == "ok":
        return Check(label, "live", PASS, f"{r.findings} findings in {r.seconds}s" + (f" ({r.message})" if r.message else ""), secs)
    if r.status in ("needs_auth", "unavailable", "skipped"):
        return Check(label, "live", WARN, f"{r.status}: {r.message}", secs)
    return Check(label, "live", FAIL, f"{r.status}: {r.message}", secs)


# ----------------------------------------------------------------------------- reports
def _sample_case() -> tuple:
    """A case built from every module's sample output + one hostile finding + varied run statuses."""
    findings, targets, runs = [], [Target("email", D.T_MAIL.value), Target("username", D.T_USER.value, 1, "email:" + D.T_MAIL.value, "sample pivot"),
                                   Target("domain", D.T_DOMAIN.value)], []
    for name, (tgt, sample, _) in D.FIXTURES.items():
        res = ALL[name](Config(), Path(tempfile.gettempdir())).parse(sample, tgt)
        findings += res.findings
        runs.append(ToolRun(name, tgt.key, "ok", 1.2, len(res.findings), res.checked, res.message))
    from .util import phonenumbers_ok
    if phonenumbers_ok():
        import phonenumbers
        t = Target("phone", D.PHONE_SAMPLE)
        res = ALL["phoneinfo"](Config(), Path(tempfile.gettempdir())).parse_number(phonenumbers.parse(D.PHONE_SAMPLE, None), t)
        findings += res.findings
        targets.append(t)
        runs.append(ToolRun("phoneinfo", t.key, "ok", 0.1, len(res.findings)))
    runs += [ToolRun("ghunt", "email:x@y.z", "needs_auth", 0.0, 0, None, "not logged in"),
             ToolRun("tookie", "username:x", "timeout", 900.0, 0, None, "timed out after 900s"),
             ToolRun("holehe", "email:x@y.z", "error", 3.0, 0, None, "no output", 2)]
    findings.append(Finding("tookie", D.HOSTILE_TITLE, "username", "account", title=D.HOSTILE_TITLE, platform="evil",
                            via="username", url="javascript:alert(1)", weight=0.6))
    findings.append(Finding("spiderfoot", D.HOSTILE_VALUE, "domain", "identity", kind="name", title=D.HOSTILE_PIPE,
                            value=D.HOSTILE_VALUE, weight=0.5))
    findings.append(Finding("spiderfoot", D.HOSTILE_VALUE, "domain", "note", title=D.HOSTILE_PIPE, value=D.HOSTILE_PIPE, weight=0.5))
    targets.append(Target("username", D.HOSTILE_TITLE))
    seeds = [targets[0].value, D.HOSTILE_TITLE]
    return build_case(seeds, targets, runs, findings, "2026-01-01T10:00:00", "2026-01-01T10:03:25",
                      {"case_id": "H3XA-SELFTEST", "operator": "<b>op</b>", "purpose": "self-test", "profile": "standard",
                       "modules": [display(n) for n in D.FIXTURES]})


def check_reports() -> list[Check]:
    g, out = "Reports", []
    case = _sample_case()
    with tempfile.TemporaryDirectory(prefix="h3xa-selftest-") as d:
        t0 = time.time()
        res = write_reports(case, Path(d), "selftest", FORMATS)
        for fmt in FORMATS:
            err = next((m for f, m in res.errors if f == fmt), None)
            chk = next(((ok, det) for f, ok, det in res.checks if f == fmt), None)
            if err:
                out.append(Check(g, fmt.upper(), FAIL, err))
            elif chk:
                out.append(Check(g, fmt.upper(), PASS if chk[0] else FAIL, chk[1]))
            else:
                out.append(Check(g, fmt.upper(), FAIL, "not written"))
        out[-len(FORMATS)].seconds = round(time.time() - t0, 2)

        def hostile():
            problems = []
            html_t = (Path(d) / "selftest.html").read_text(encoding="utf-8") if (Path(d) / "selftest.html").exists() else ""
            if "<img src=x" in html_t or "<b>op</b>" in html_t:
                problems.append("HTML not escaped")
            if 'href="javascript:' in html_t:
                problems.append("javascript: link emitted")
            csv_t = (Path(d) / "selftest.csv").read_text(encoding="utf-8") if (Path(d) / "selftest.csv").exists() else ""
            import csv as _csv, io as _io
            if any(cell[:1] in ("=", "+", "-", "@") for row in _csv.reader(_io.StringIO(csv_t)) for cell in row):
                problems.append("CSV formula not neutralised")
            md_t = (Path(d) / "selftest.md").read_text(encoding="utf-8") if (Path(d) / "selftest.md").exists() else ""
            if "a|b" in md_t:
                problems.append("Markdown pipe not escaped")
            js = (Path(d) / "selftest.json").read_text(encoding="utf-8") if (Path(d) / "selftest.json").exists() else ""
            if "SECRET-VALUE-123" in html_t + csv_t + md_t + js:
                problems.append("credential value present in a report")
            return (FAIL, "; ".join(problems)) if problems else (PASS, "HTML/CSV/Markdown injection and secret leakage blocked")
        out.append(_timed(g, "Hostile input", hostile))
    return out


# ----------------------------------------------------------------------------- orchestration
def run_doctor(cfg: Config, tools: list[str] | None = None, live: str | None = None, net: bool = False,
               live_timeout: int = 180, on_check: Callable[[Check], None] | None = None,
               on_step: Callable[[str], None] | None = None) -> list[Check]:
    tmp = Path(tempfile.mkdtemp(prefix="h3xa-doctor-"))
    results: list[Check] = []

    def add(items):
        for c in ([items] if isinstance(items, Check) else items):
            results.append(c)
            if on_check:
                on_check(c)

    step = on_step or (lambda s: None)
    step("environment")
    add(check_environment(cfg, net))
    names = [t for t in (tools or list(ALL)) if t in ALL]
    for n in names:
        step(f"checking {display(n)}")
        add(check_module(n, cfg, tmp))
    if live:
        target = make_seed(live)
        for n in names:
            step(f"live probe: {display(n)} (up to {live_timeout}s)")
            add(check_live(n, cfg, target, tmp, live_timeout))
    step("report pipeline")
    add(check_reports())
    return results


def verdict(checks: list[Check]) -> dict:
    """Roll the checks up per module: ready | needs_attention (works, but credentials/keys missing)
    | needs_setup (not installed yet) | broken (installed but parser/contract check failed)."""
    n = {s: sum(1 for c in checks if c.status == s) for s in (PASS, WARN, FAIL, SKIP)}
    groups: dict = {}
    for c in checks:
        groups.setdefault(c.group, []).append(c)
    ready, attention, setup, broken = [], [], [], []
    for g, cs in groups.items():
        if g in ("Environment", "Reports"):
            continue
        by = {c.name: c for c in cs}
        if any(by[k].status == FAIL for k in ("contract", "parser") if k in by):
            broken.append(g)
        elif any(c.status == FAIL for c in cs if c.name == "install"):
            setup.append(g)
        elif any(c.status == FAIL for c in cs):          # a live probe failed
            broken.append(g)
        elif any(c.status == WARN for c in cs):
            attention.append(g)
        else:
            ready.append(g)
    return {**n, "ready_modules": ready, "needs_attention": attention, "needs_setup": setup,
            "broken_modules": broken, "ok": n[FAIL] == 0, "exit_code": 0 if n[FAIL] == 0 else 1}


def to_json(checks: list[Check]) -> str:
    return json.dumps({"verdict": verdict(checks), "checks": [c.to_dict() for c in checks]}, indent=2, ensure_ascii=False)
