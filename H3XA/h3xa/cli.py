from __future__ import annotations
import argparse, sys, tempfile, time
from pathlib import Path

from . import __version__
from .adapters import ALL
from .config import Config
from .correlate import summarize
from .engine import Engine, make_seed
from .report import FORMATS, write_reports
from .util import safe_name


def _scan(a) -> int:
    cfg = Config.load(a.config)
    for k, v in (("depth", a.depth), ("derive_username", a.derive_username or None)):
        if v is not None:
            cfg.data["pivot"][k] = v
    if a.no_pivot:
        cfg.data["pivot"]["depth"] = 0
    if a.allow_loud:
        cfg.data["user-scanner"]["allow_loud"] = cfg.data["holehe"]["allow_loud"] = True
    if a.hudson:
        cfg.data["user-scanner"]["hudson"] = True
    if a.sf_mode:
        cfg.data["spiderfoot"]["mode"] = a.sf_mode
    profile = a.profile or cfg.get("general", "profile")
    tools = a.tools.split(",") if a.tools else cfg.tools_for_profile(profile)
    if profile == "deep" and not a.tools:
        cfg.data["pivot"]["depth"] = max(cfg.data["pivot"]["depth"], 2)
    tools = [t for t in tools if t not in (a.exclude.split(",") if a.exclude else [])]
    if any(k == "spiderfoot" for k in tools) and a.spiderfoot_all:
        cfg.data["spiderfoot"]["kinds"] = ["domain", "ip", "phone", "name", "email", "username"]
    if a.retries is not None:
        cfg.data["general"]["retries"] = a.retries
    if a.timeout:
        cfg.data["general"]["timeout"] = a.timeout
    if a.parallel:
        cfg.data["general"]["max_parallel"] = a.parallel
    log = (lambda s: None) if a.quiet else (lambda s: print(s, file=sys.stderr))
    log(f"h3xa {__version__} - profile={profile} tools={','.join(tools)} pivot-depth={cfg['pivot']['depth']}")
    seeds = [make_seed(v, a.type, instagram=a.instagram) for v in a.targets]
    tmp = Path(tempfile.mkdtemp(prefix="h3xa-"))
    meta = {"operator": a.operator or cfg["report"]["operator"], "purpose": a.purpose or cfg["report"]["purpose"],
            "profile": profile}
    try:
        case = Engine(cfg, tools, tmp, log).scan(seeds, meta)
    except ValueError as e:                      # unknown module name etc.
        print(f"error: {e}", file=sys.stderr)
        return 2
    base = a.name or safe_name("_".join(s.value for s in seeds))[:50] + time.strftime("_%Y%m%d_%H%M%S")
    fmts = [f for f in (a.format or ",".join(cfg["report"]["formats"])).split(",") if f.strip()]
    rr = write_reports(case, Path(a.out) if a.out else cfg.output_dir, base, fmts)
    s = summarize(case)
    print(f"\n{s['accounts']} accounts ({s['accounts_multi_tool']} confirmed by 2+ tools), "
          f"{s['breaches']} breach records, {s['identity_clues']} identity clues; "
          f"{s['runs_ok']}/{s['tool_runs']} module runs ok.")
    for p in rr.paths:
        ok, detail = next(((o, d) for f, o, d in rr.checks if f == p.suffix[1:]), (True, ""))
        print(f"report: {p}  [{'verified: ' + detail if ok else 'VERIFICATION FAILED: ' + detail}]")
    for f, m in rr.errors:
        print(f"report {f}: NOT WRITTEN - {m}", file=sys.stderr)
    if s["tool_runs"] and s["runs_ok"] == 0:
        print("warning: no module completed - the report contains no collected data (run `h3xa doctor`).", file=sys.stderr)
        return 3
    return 0 if rr.ok else 4


def _setup(a) -> int:
    from . import setup_tools as st
    cfg = Config.load(a.config)
    if a.zips:
        st.extract(Path(a.zips), cfg)
    if not a.no_install:
        from .branding import display
        only = a.only.split(",") if a.only else None
        for k, v in st.install_with_progress(cfg, only, label=display).items():
            print(f"{display(k):<13} {v}")
    return 0


def _status(a) -> int:
    cfg = Config.load(a.config)
    for name, cls in ALL.items():
        ad = cls(cfg, Path(tempfile.gettempdir()))
        try:
            ad.check()
            print(f"{name:<13} ready")
        except Exception as e:
            print(f"{name:<13} NOT READY - {e}")
    return 0


def _doctor(a) -> int:
    from . import doctor
    cfg = Config.load(a.config)
    icon = {"pass": "PASS", "warn": "WARN", "fail": "FAIL", "skip": "skip"}
    shown = {"g": ""}

    def show(c):
        if a.json:
            return
        if c.group != shown["g"]:
            shown["g"] = c.group
            print(f"\n[{c.group}]")
        print(f"  {icon[c.status]:<4}  {c.name:<14} {c.detail}")
    checks = doctor.run_doctor(cfg, a.only.split(",") if a.only else None, a.live, a.net, a.live_timeout, on_check=show)
    if a.json:
        print(doctor.to_json(checks))
    else:
        v = doctor.verdict(checks)
        print(f"\n{v['pass']} passed, {v['warn']} warnings, {v['fail']} failed, {v['skip']} skipped")
        for k, t in (("ready_modules", "ready"), ("needs_attention", "work but need credentials/keys"),
                     ("needs_setup", "not installed (run `h3xa setup`)"), ("broken_modules", "BROKEN")):
            if v[k]:
                print(f"  {t}: {', '.join(v[k])}")
    return doctor.verdict(checks)["exit_code"]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="h3xa", description="Unified OSINT orchestrator")
    p.add_argument("--config", help="path to h3xa.toml")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="run tools against one or more targets and build a report")
    s.add_argument("targets", nargs="+", help="email / username / domain / IP / phone / 'First Last'")
    s.add_argument("--type", choices=["email", "username", "domain", "ip", "phone", "name"], help="force target type")
    s.add_argument("-p", "--profile", choices=["quick", "standard", "deep"])
    s.add_argument("--tools", help="comma list, overrides profile")
    s.add_argument("--exclude", help="comma list of tools to skip")
    s.add_argument("--depth", type=int, help="pivot depth (0 = no follow-up targets)")
    s.add_argument("--no-pivot", action="store_true")
    s.add_argument("--derive-username", action="store_true", help="also try e-mail local-part as username (weak lead)")
    s.add_argument("--instagram", action="store_true", help="treat username as an Instagram handle (runs Osintgram)")
    s.add_argument("--allow-loud", action="store_true", help="include modules that may notify the target")
    s.add_argument("--hudson", action="store_true", help="query Hudson Rock (sends identifier to a third party)")
    s.add_argument("--sf-mode", choices=["passive", "footprint", "investigate", "all"])
    s.add_argument("--spiderfoot-all", action="store_true", help="let SpiderFoot take e-mail/username targets too")
    s.add_argument("-o", "--out", help="output directory")
    s.add_argument("-n", "--name", help="report base name")
    s.add_argument("--format", help="comma list from html,json,md,csv (default: from config, all four)")
    s.add_argument("--operator", help="your name/team, printed on the report cover")
    s.add_argument("--purpose", help="purpose / authorisation, printed on the report cover")
    s.add_argument("--retries", type=int, help="re-run a module this many times after a transient failure")
    s.add_argument("--timeout", type=int, help="seconds allowed per module run")
    s.add_argument("--parallel", type=int, help="modules run at once")
    s.add_argument("-q", "--quiet", action="store_true")
    s.set_defaults(fn=_scan)

    u = sub.add_parser("setup", help="unpack zips into vendor/ and install each tool in its own venv")
    u.add_argument("--zips", help="folder containing the tool .zip files")
    u.add_argument("--only", help="comma list of tools")
    u.add_argument("--no-install", action="store_true")
    u.set_defaults(fn=_setup)

    dd = sub.add_parser("doctor", help="self-test every module and the report pipeline (exit 1 if anything failed)")
    dd.add_argument("--only", help="comma list of modules")
    dd.add_argument("--live", metavar="TARGET", help="also run each fitting module against this target (use your own)")
    dd.add_argument("--live-timeout", type=int, default=180, help="seconds per live probe")
    dd.add_argument("--net", action="store_true", help="also test outbound internet access")
    dd.add_argument("--json", action="store_true", help="machine-readable output")
    dd.set_defaults(fn=_doctor)
    t = sub.add_parser("status", help="show which tools are ready")
    t.set_defaults(fn=_status)
    tu = sub.add_parser("tui", help="interactive terminal interface (default)")
    tu.set_defaults(fn=lambda a: __import__("h3xa.tui", fromlist=["run"]).run(a.config))
    a = p.parse_args(argv)
    if not getattr(a, "fn", None):
        return __import__("h3xa.tui", fromlist=["run"]).run(a.config)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
