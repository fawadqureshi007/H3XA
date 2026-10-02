"""H3XA terminal interface. Pure stdlib (ANSI colours) so it runs from a double-click."""
from __future__ import annotations

import datetime as dt
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from pathlib import Path

from . import __version__
from .adapters import ALL
from .branding import display, display_list
from .config import ROOT, TOOLS, Config
from .correlate import Case, build_case, label, summarize
from .engine import Engine, make_seed
from .models import MissingRequirement, Target
from .progress import Spinner
from .report import FORMATS, write_reports
from .runner import kill_all
from .util import detect_kind, safe_name, strip_ansi

# ----------------------------------------------------------------------------- ANSI
def _init_terminal() -> None:
    if os.name == "nt":
        os.system("")  # enables VT/ANSI processing on Windows 10+
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def c(code, text) -> str:
    return f"\033[38;5;{code}m{text}\033[0m"


def bold(t) -> str:
    return f"\033[1m{t}\033[0m"


def dim(t) -> str:
    return f"\033[2m{t}\033[0m"


CY, VI, MG, GR, YE, RD, GY, WH = 51, 99, 201, 46, 220, 203, 244, 255

_H = ["██╗  ██╗", "██║  ██║", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"]
_3 = ["██████╗ ", "╚════██╗", " █████╔╝", " ╚═══██╗", "██████╔╝", "╚═════╝ "]
_X = ["██╗  ██╗", "╚██╗██╔╝", " ╚███╔╝ ", " ██╔██╗ ", "██╔╝ ██╗", "╚═╝  ╚═╝"]
_A = [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"]
LOGO_ROWS = [51, 45, 39, 63, 99, 135]           # cyan -> violet gradient


def logo() -> str:
    out = []
    for i in range(6):
        row = f"{_H[i]} {_3[i]} {_X[i]} {_A[i]}"
        out.append("   " + c(LOGO_ROWS[i], row))
    return "\n".join(out)


def banner(cfg: Config | None = None) -> None:
    clear()
    print()
    print(logo())
    print()
    print("   " + c(CY, "◆") + " " + bold(c(WH, "ALL-IN-ONE OSINT FRAMEWORK")) + c(GY, f"   v{__version__}"))
    print("   " + c(VI, "⚡ ") + bold(c(GY, "powered by ")) + bold(c(MG, "CodenSec")))
    print("   " + c(VI, "─" * 74))
    print()


def intro() -> None:
    """One-time animated splash shown only when the program starts."""
    clear()
    print()
    print(logo())
    print()
    tag = "P O W E R E D   B Y   C O D E N S E C"
    pulse = [CY, 45, 39, 63, 99, MG, 201, MG, 99, 63]
    line = "   "
    sys.stdout.write(line)
    sys.stdout.flush()
    for i, ch in enumerate(tag):
        sys.stdout.write(c(pulse[i % len(pulse)], ch) if ch != " " else " ")
        sys.stdout.flush()
        time.sleep(0.012)
    print("\n")
    time.sleep(0.5)


def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def width() -> int:
    return max(60, min(shutil.get_terminal_size((100, 30)).columns, 120))


def trunc(s, n) -> str:
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


def vislen(s: str) -> int:
    return len(strip_ansi(s))


def box(title: str, lines: list[str], color=VI) -> None:
    """A bordered panel so a group of related lines (target entry, module setup ...)
    reads as one clear block instead of scattered loose text."""
    w = max(50, width() - 6)
    head = f"─ {title} "
    print("   " + c(color, "╭" + head + "─" * max(1, w - vislen(head)) + "╮"))
    for ln in lines:
        gap = max(0, (w - 2) - vislen(ln))
        print("   " + c(color, "│") + " " + ln + " " * gap + " " + c(color, "│"))
    print("   " + c(color, "╰" + "─" * w + "╯"))


def conf_bar(conf: float, n: int = 10) -> str:
    filled = round(conf * n)
    col = GR if conf >= 0.85 else YE if conf >= 0.6 else GY
    return c(col, "█" * filled) + c(238, "░" * (n - filled)) + " " + c(col, f"{conf:.2f}")


def section(title: str, count: int | None = None) -> None:
    extra = f" {c(GY, f'({count})')}" if count is not None else ""
    print("\n   " + bold(c(CY, "▌ " + title.upper())) + extra)
    print("   " + c(238, "─" * (width() - 6)))


def ask(prompt: str) -> str:
    try:
        return input("   " + c(MG, "❯ ") + prompt + " ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit(0)


# ----------------------------------------------------------------------------- state
DESC = {
    "user-scanner": "accounts on 1000+ sites (email + username)",
    "holehe":       "which sites an email is registered on + recovery hints",
    "h8mail":       "breach & leak exposure of an email",
    "ghunt":        "Google account: name, photo, services, Maps activity",
    "tookie":       "username on 260+ sites (2nd opinion)",
    "userrecon":    "legacy username check (extra corroboration)",
    "spiderfoot":   "domain / IP / phone / name intel, geo, infrastructure",
    "osintgram":    "Instagram profile, bio links, account country",
    "phoneinfo":    "number validity, region, carrier, time zone (offline)",
}
CONDITIONAL = {
    "ghunt": "auto: runs if a Google account is indicated",
    "osintgram": "auto: runs if the handle is found on Instagram",
}


class State:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.depth = cfg["pivot"]["depth"]
        self.allow_loud = False
        self.name_guesses = True
        self.tools = list(ALL)                       # every module is selectable; the mode narrows it per scan
        self.formats = [f for f in cfg["report"]["formats"] if f in FORMATS] or list(FORMATS)
        self.operator = cfg["report"]["operator"]
        self.purpose = cfg["report"]["purpose"]
        self.case_info_done = bool(self.operator or self.purpose)
        self.tmp = Path(tempfile.mkdtemp(prefix="h3xa-"))


# ----------------------------------------------------------------------------- first run
def ensure_installed(cfg: Config) -> None:
    from . import setup_tools as st
    zips = ROOT / "zips"
    need_unpack = any(not cfg.src(t).is_dir() for t in TOOLS) and zips.is_dir()
    todo = [t for t, (_, m) in TOOLS.items() if m != "none" and cfg.src(t).is_dir() and not cfg.venv_python(t)]
    from .util import phonenumbers_ok
    need_phone = not phonenumbers_ok()
    did = need_unpack or todo or need_phone
    if did:
        section("First-run setup")
    if need_unpack:
        print("   " + c(YE, "◐ ") + "unpacking bundled modules ...")
        st.extract(zips, cfg, log=lambda s: print("     " + c(GY, s)))
    if todo:
        print("   " + c(YE, f"◐ {len(todo)} module(s) still need their private environment: ") + display_list(todo))
        if ask("Install now? needs internet, ~1-3 minutes (installs in parallel) [Y/n]").lower() in ("", "y", "yes"):
            print()
            res = st.install_with_progress(cfg, todo, label=display)
            bad = {k: v for k, v in res.items() if not v.startswith("ok")}
            for k, v in bad.items():
                print("   " + c(RD, "✖ ") + f"{display(k):<13} {trunc(v, 90)}")
            if not bad:
                print("   " + c(GR, "✔ ") + "all modules installed")
    if need_phone:
        print("   " + c(YE, "◐ ") + "installing phonenumbers (offline phone analysis) ...")
        import importlib, shutil as _sh
        libs = ROOT / "libs"
        stub = libs / "phonenumbers"
        if stub.is_dir() and not (stub / "__init__.py").exists():      # empty leftover folder shadows the real package
            _sh.rmtree(stub, ignore_errors=True)
        sys.modules.pop("phonenumbers", None)
        r = subprocess.run([sys.executable, "-m", "pip", "install", "-q", "--target", str(libs), "phonenumbers"],
                           capture_output=True, text=True)
        if str(libs) not in sys.path:
            sys.path.insert(0, str(libs))
        importlib.invalidate_caches()
        if phonenumbers_ok():
            print("   " + c(GR, "✔ ") + "phonenumbers ready")
        else:
            tail = (r.stderr or r.stdout or "").strip().splitlines()[-1:] or ["unknown error"]
            print("   " + c(RD, "✖ ") + f"phonenumbers could not be installed (PhoneID disabled): {trunc(tail[0], 80)}")
    if did:
        input("\n   " + dim("press Enter to continue ..."))


# ----------------------------------------------------------------------------- plan
def offer_repair(name: str, ad, err: MissingRequirement) -> bool:
    """A module's own venv is missing one or more packages it needs (usually a partial
    requirements.txt install on this machine - one broken package silently took others
    down with it). Ask once, right in the terminal, whether to install them now - the
    person can always say no and the scan just runs without that module."""
    count = len(err.all_missing)
    names = ", ".join(err.all_missing[:8]) + ("..." if count > 8 else "")
    plural = "package" if count == 1 else f"{count} packages"
    print("   " + c(YE, f"◐ {display(name)} needs {plural} that "
                        f"didn't finish installing on this machine: {names}"))
    eta = "~10-20s" if count <= 2 else "up to a couple minutes"
    if ask(f"Install now? needs internet, {eta} [Y/n/skip]").lower() not in ("", "y", "yes"):
        print("   " + c(GY, f"skipped - {display(name)} won't run this scan"))
        return False
    with Spinner(c(GY, f"installing {trunc(names, 60)}")):
        fixed, tail = ad.install_missing()
    if fixed:
        print("   " + c(GR, f"✔ fixed - {display(name)} is ready"))
        return True
    print("   " + c(RD, f"✖ still not working: {trunc(tail, 200) or 'see reports for details'}"))
    return False


def build_plan(st: State, seeds, tools=None):
    """One row per module: (name, state, note). state: run | auto | missing | na.
    A module is 'na' when none of the seeds is a kind it can take; 'missing' when it cannot run now."""
    seeds = seeds if isinstance(seeds, list) else [seeds]
    rows = []
    for name, cls in ALL.items():
        if tools is not None and name not in tools:
            continue
        ad = cls(st.cfg, st.tmp)
        fits = any((ad.applies(t, []) if ad.phase == 1 else t.kind in ad.kinds) for t in seeds)
        if not fits:
            rows.append((name, "na", ""))
            continue
        state, note = ("auto" if name in CONDITIONAL else "run"), CONDITIONAL.get(name, DESC.get(name, ""))
        try:
            ad.check()
        except MissingRequirement as e:
            rows.append((name, state, note) if offer_repair(name, ad, e) else (name, "missing", str(e)))
            continue
        except Exception as e:
            rows.append((name, "missing", str(e)))
            continue
        rows.append((name, state, note))
    return rows


def show_plan(rows) -> int:
    section("Execution plan")
    runnable = 0
    w = max(50, width() - 6)
    name_w = 13
    lines = []
    for name, state, note in rows:
        if state == "na":
            continue
        if state == "run":
            icon, col, tag = "✔", GR, ""
            runnable += 1
        elif state == "auto":
            icon, col, tag = "◐", CY, ""
            runnable += 1
        else:
            icon, col, tag = "✖", RD, "not ready — "
            note = str(note)
        budget = max(10, (w - 2) - 2 - name_w - vislen(c(RD, tag)))
        lines.append(f"{c(col, icon)} {bold(f'{display(name):<{name_w}}')} "
                     f"{c(RD, tag)}{c(GY, trunc(note, budget))}")
    box("EXECUTION PLAN", lines or [c(GY, "nothing runnable")], color=CY if runnable else RD)
    skipped = [n for n, s, _ in rows if s == "na"]
    if skipped:
        print("   " + c(238, "– not applicable to this target type: " + display_list(skipped)))
    return runnable


# ----------------------------------------------------------------------------- live scan
STATUS_ICON = {
    "ok": ("✔", GR), "error": ("✖", RD), "timeout": ("⏱", RD),
    "unavailable": ("◐", YE), "needs_auth": ("⚿", YE), "skipped": ("⊘", GY),
}


class ScanBoard:
    """Live scan dashboard. Finished module runs scroll up as permanent lines; a pinned block at
    the bottom shows overall progress and every module currently running with its own timer.
    Driven by the engine's structured events; falls back to plain lines when not on a terminal."""
    FR = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, engine: Engine):
        self.e, self.t0 = engine, time.time()
        self.active: dict = {}                   # (module, target) -> [label, target, started, attempt]
        self.done = self.found = self.leads = self.expected = 0
        self.tty = bool(getattr(sys.stdout, "isatty", lambda: False)())
        self._lock, self._stop, self._lines, self._i = threading.RLock(), threading.Event(), 0, 0
        self._th = threading.Thread(target=self._loop, daemon=True)

    # ---- lifecycle
    def start(self):
        if self.tty:
            sys.stdout.write("\033[?25l")
            self._th.start()

    def stop(self):
        self._stop.set()
        if self.tty:
            self._th.join(timeout=1)
            with self._lock:
                self._erase()
            sys.stdout.write("\033[?25h")
            sys.stdout.flush()

    def _loop(self):
        while not self._stop.is_set():
            with self._lock:
                self._erase()
                self._draw()
            time.sleep(0.12)

    # ---- drawing (only ever called with the lock held)
    def _erase(self):
        if self._lines:
            sys.stdout.write(f"\033[{self._lines}F\033[J")
            self._lines = 0

    def _draw(self):
        self._i += 1
        sp = self.FR[self._i % len(self.FR)]
        w = width() - 6
        n = 14 if w < 80 else 22
        pct = self.done / self.expected if self.expected else 0.0
        pct = min(pct, 0.99) if self.active else min(pct, 1.0)
        fill = int(round(n * pct))
        el = int(time.time() - self.t0)
        pct_txt, runs_txt = f"{int(pct * 100):>3}%", f"{self.done}/{self.expected}"
        tm = f"{el // 60}:{el % 60:02d}"
        head = (f"   {c(CY, sp)} {c(CY, '█' * fill)}{c(238, '░' * (n - fill))} {c(CY, pct_txt)}  "
                f"{c(WH, runs_txt)} {c(GY, 'runs')} · {c(GR, str(self.found))} {c(GY, 'findings')} · "
                f"{c(MG, str(self.leads))} {c(GY, 'leads')} · {c(GY, tm)}")
        lines = [head]
        rows = sorted(self.active.values(), key=lambda r: r[2])
        for label, target, t0, attempt in rows[:8]:
            s = int(time.time() - t0)
            room = max(10, w - 44)
            lab, tg, tm2 = bold(f"{label:<13}"), c(GY, f"{trunc(target, room):<{room}}"), c(GY, f"{s // 60}:{s % 60:02d}")
            lines.append(f"     {c(MG, sp)} {lab} {tg} {tm2}" + (c(YE, f"  retry #{attempt}") if attempt > 1 else ""))
        if len(rows) > 8:
            lines.append("     " + c(GY, f"… +{len(rows) - 8} more running"))
        sys.stdout.write("\n".join("\033[2K" + ln for ln in lines) + "\n")
        sys.stdout.flush()
        self._lines = len(lines)

    def _commit(self, text: str):
        if self.tty:
            self._erase()
            sys.stdout.write("\033[2K" + text + "\n")
            self._draw()
        else:
            print(text, flush=True)

    # ---- engine events
    def _n_for(self, t: Target) -> int:
        return sum(1 for a in self.e.adapters if (a.applies(t, []) if a.phase == 1 else t.kind in a.kinds))

    def event(self, ev: str, **kw):
        with self._lock:
            if ev == "target":
                t = kw["target"]
                self.expected += self._n_for(t)
                self._commit("\n   " + c(VI, "▸") + " " + bold(c(CY, f"{t.kind}: {t.value}"))
                             + (c(GY, f"   (depth {t.depth}: {t.reason})") if t.depth else ""))
            elif ev == "lead":
                t = kw["target"]
                self._commit("     " + c(MG, "↳ new lead: ") + c(MG, f"{t.kind} {t.value}") + c(GY, f"  ← {trunc(t.reason, 50)}"))
            elif ev == "start":
                self.active[(kw["module"], kw["target"])] = [kw["label"], kw["target"], time.time(), 1]
            elif ev == "retry":
                row = self.active.get((kw["module"], kw["target"]))
                if row:
                    row[3] = kw["attempt"]
            elif ev == "done":
                self.active.pop((kw["module"], kw["target"]), None)
                r = kw["run"]
                self.done += 1
                self.found += r.findings
                icon, col = STATUS_ICON.get(r.status, ("•", GY))
                label = kw["label"]
                tgt = trunc(r.target.split(":", 1)[-1], 24)
                name_col, tgt_col = bold(f"{label:<13}"), c(GY, f"{tgt:<24}")
                stat = c(GY, f"{r.findings:>3} found · {r.seconds:.1f}s")
                m = f"   {c(col, icon)} {name_col} {tgt_col} {stat}"
                msg = r.message if r.status != "ok" else ""
                if r.attempts > 1:
                    msg = (msg + " " if msg else "") + f"(tried {r.attempts}x)"
                if msg:
                    m += "  " + c(col if r.status != "ok" else 238, trunc(msg, max(10, width() - 70)))
                self._commit(m)


def run_scan(st: State, seeds: list[Target], tools: list[str], depth: int, meta: dict) -> tuple[Case, bool]:
    """Run the scan with the live board. Returns (case, aborted). Ctrl+C stops cleanly with partial results."""
    st.cfg.data["pivot"]["depth"] = depth
    eng = Engine(st.cfg, tools, st.tmp)
    board = ScanBoard(eng)
    eng.on_event = board.event
    holder: dict = {}
    started = dt.datetime.now().isoformat(timespec="seconds")

    def work():
        try:
            holder["case"] = eng.scan(seeds, meta)
        except Exception as e:  # pragma: no cover
            holder["err"] = e

    th = threading.Thread(target=work, daemon=True)
    print()
    board.start()
    th.start()
    aborted = False
    try:
        while th.is_alive():
            th.join(0.2)
    except KeyboardInterrupt:
        aborted = True
        eng.cancel()
        kill_all()
        th.join(8)
    board.stop()
    if aborted:
        print("   " + c(YE, "stopped by user - showing partial results"))
        return eng.make_case(seeds, started, meta), True
    if "err" in holder:
        raise holder["err"]
    return holder["case"], False


# ----------------------------------------------------------------------------- results
from .branding import KIND_LABEL, KIND_ORDER  # noqa: E402


def show_results(case: Case) -> None:
    s = summarize(case)
    section("Summary")
    box = [("Targets", s["targets"], CY), ("Accounts", s["accounts"], GR), ("2+ modules agree", s["accounts_multi_tool"], GR),
           ("Breaches", s["breaches"], RD if s["breaches"] else GY), ("Clues", s["identity_clues"], MG),
           ("Modules ok", f"{s['runs_ok']}/{s['tool_runs']}", YE)]
    print("   " + "   ".join(f"{c(col, bold(str(v)))} {c(GY, k)}" for k, v, col in box))

    # accounts
    section("Accounts found", len(case.accounts))
    if not case.accounts:
        print("   " + c(GY, "none"))
    w = width()
    for a in case.accounts[:40]:
        url = a.urls[0] if a.urls else ""
        via = c(CY, "email") if a.via == "email" else c(VI, "user ")
        print(f"   {via} {bold(f'{trunc(a.title, 18):<18}')} {conf_bar(a.confidence)}  {c(GY, f'{len(a.tools)}×')} "
              f"{c(GY, trunc(url or a.subject, w - 52))}")
    if len(case.accounts) > 40:
        print("   " + c(GY, f"… and {len(case.accounts) - 40} more in the report"))

    # identity / location / phone
    section("Identity, phone & location clues", len(case.identity))
    if not case.identity:
        print("   " + c(GY, "none"))
    by: dict = {}
    for i in case.identity:
        by.setdefault(i["kind"], []).append(i)
    for kind in KIND_ORDER + [k for k in by if k not in KIND_ORDER]:
        for i in by.get(kind, [])[:8]:
            src = display_list(i["tools"])
            print(f"   {c(MG, f'{KIND_LABEL.get(kind, kind):<24}')} {bold(trunc(i['value'], w - 52))} {c(GY, '← ' + src)}")

    # breaches
    if case.breaches:
        section("Breach & exposure", len(case.breaches))
        for b in case.breaches[:15]:
            print(f"   {c(RD, '!')} {b['title']} {c(GY, '(' + b['subject'] + ' · ' + display_list(b['tools']) + ')')}")
        print("   " + c(GY, "passwords/hashes are counted, never shown or stored"))

    if case.infra:
        section("Infrastructure", len(case.infra))
        for i in case.infra[:10]:
            kd = f"{i['kind']:<22}"
            print(f"   {c(GY, kd)} {trunc(i['value'], w - 34)}")
        if len(case.infra) > 10:
            print("   " + c(GY, f"… {len(case.infra) - 10} more in the report"))

    # pivots
    piv = [t for t in case.targets if t.depth]
    if piv:
        section("Auto-discovered follow-up targets", len(piv))
        for t in piv:
            print(f"   {c(MG, '↳')} {t.kind}: {bold(t.value)} {c(GY, '— ' + t.reason)}")

    # module status
    section("Module status")
    for r in case.runs:
        col = {"ok": GR, "error": RD, "timeout": RD}.get(r.status, YE)
        note = f" {c(GY, trunc(r.message, w - 60))}" if r.message else ""
        print(f"   {c(col, f'{r.status:<11}')} {display(r.tool):<13} {c(GY, trunc(r.target, 28)):<40} {r.findings:>3} found{note}")


# ----------------------------------------------------------------------------- flows
KINDS = ("email", "username", "phone", "name", "domain", "ip")
MODES = [("quick", "Quick", "main e-mail / username / phone checks only, no lead-following"),
         ("standard", "Standard", "every module that fits the target; follows verified leads"),
         ("deep", "Deep", "all modules incl. legacy corroboration; follows leads 2 levels deep"),
         ("custom", "Custom", "you choose exactly which modules run")]


def open_path(p: Path) -> None:
    """Open a file or folder with the system's default application."""
    try:
        if p.suffix.lower() in (".html", ".htm"):
            webbrowser.open(p.resolve().as_uri())
        elif os.name == "nt":
            os.startfile(str(p))                              # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.run(["open", str(p)], check=False)
        else:
            subprocess.run(["xdg-open", str(p)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        print("   " + c(YE, f"could not open automatically - path: {p}"))


def choose_type(value: str) -> tuple[str, dict]:
    """Detect the target type, let the operator correct it (e.g. 'jane.doe' is a username, not a domain)."""
    kind = detect_kind(value)
    print("   " + c(GY, "detected type: ") + bold(c(CY, kind)))
    ov = ask("Enter = correct, or type the right type (" + " / ".join(KINDS) + "):").lower()
    if ov in KINDS and ov != kind:
        kind = ov
        print("   " + c(GY, "type set to: ") + bold(c(CY, kind)))
    hints: dict = {}
    if kind == "phone" and not value.strip().startswith("+"):
        hints["region"] = ask("Number has no +country code. Country letters (e.g. PK, IN, US, GB):")
    return kind, hints


def extra_identifiers(seed: Target) -> list[Target]:
    """Other identifiers the operator already knows for the SAME person - the strongest way to make a
    name search useful, since a bare name alone matches thousands of people."""
    if seed.kind in ("domain", "ip"):
        return []
    raw = ask("Also known about the same person? e-mail / username / phone, comma-separated (Enter = none):")
    out: list[Target] = []
    for part in [p.strip() for p in raw.split(",") if p.strip()]:
        k = detect_kind(part)
        hints: dict = {}
        if k == "phone" and not part.startswith("+"):
            hints["region"] = ask(f"Country letters for {part} (e.g. PK):")
        t = Target(k, part, 0, seed.key, "given by the operator for the same person", hints=hints)
        if t.key != seed.key and t.key not in {x.key for x in out}:
            out.append(t)
    if out:
        print("   " + c(GR, "✔ ") + "added: " + ", ".join(f"{t.kind} {t.value}" for t in out))
    return out


def choose_mode(st: State, seeds: list[Target]):
    """Returns (profile_key, tools_or_None, depth) or None to cancel. tools None = ask the custom picker."""
    section("Scan mode")
    default = "standard"
    lines = []
    for i, (key, name, desc) in enumerate(MODES, 1):
        mods = "" if key == "custom" else f"{len(st.cfg.tools_for_profile(key))} modules · "
        tag = c(GR, "  ← default") if key == default else ""
        lines.append(f"{c(CY, f'[{i}]')} {bold(f'{name:<9}')} {c(GY, mods + desc)}{tag}")
    box("HOW THOROUGH?", lines)
    while True:
        o = ask("Mode [1-4, Enter = Standard, 0 = cancel]:").lower()
        if o in ("0", "q", "cancel", "back"):
            return None
        pick = default if o == "" else next((k for i, (k, n, _) in enumerate(MODES, 1) if o in (str(i), k, n.lower())), None)
        if pick:
            break
        print("   " + c(YE, "choose 1, 2, 3 or 4"))
    depth = {"quick": 0, "standard": st.depth, "deep": max(st.depth, 2), "custom": st.depth}[pick]
    tools = None if pick == "custom" else st.cfg.tools_for_profile(pick)
    return pick, tools, depth


def pick_modules(rows) -> list[str]:
    """Interactive checklist. Only modules that fit the target are listed; modules that cannot run now are shown but locked."""
    avail = [(n, s, note) for n, s, note in rows if s != "na"]
    chosen = {n for n, s, _ in avail if s in ("run", "auto")}
    while True:
        section("Choose modules")
        for i, (n, s, note) in enumerate(avail, 1):
            num = c(CY, f"{i:>2}")
            if s in ("run", "auto"):
                mark = c(GR, "[x]") if n in chosen else c(GY, "[ ]")
                print(f"   {mark} {num}  {bold(f'{display(n):<13}')} {c(GY, trunc(note, width() - 30))}")
            else:
                print(f"   {c(RD, '[-]')} {num}  {c(GY, f'{display(n):<13}')} {c(RD, 'not ready - ' + trunc(note, width() - 44))}")
        o = ask("Toggle by number(s) e.g. '1 3', a = all ready, n = none, Enter = continue:").lower()
        if o in ("a", "all"):
            chosen = {n for n, s, _ in avail if s in ("run", "auto")}
        elif o in ("n", "none"):
            chosen = set()
        elif o == "":
            if chosen:
                return [n for n, _, _ in avail if n in chosen]
            print("   " + c(YE, "select at least one module"))
        else:
            for tok in o.replace(",", " ").split():
                if tok.isdigit() and 1 <= int(tok) <= len(avail):
                    n, s, _ = avail[int(tok) - 1]
                    if s in ("run", "auto"):
                        chosen ^= {n}


def case_info(st: State) -> None:
    """Asked once per session; goes on the report cover so every report records who ran it and why."""
    if st.case_info_done:
        return
    section("Case details (optional - printed on the report)")
    print("   " + c(GY, "Use only on yourself, with the person's consent, or within a lawful engagement."))
    st.operator = ask("Your name / team (Enter = skip):")
    st.purpose = ask("Purpose / authorisation, e.g. 'client engagement #12' (Enter = skip):")
    st.case_info_done = True


def show_report_status(rr) -> None:
    section("Reports")
    for p in rr.paths:
        fmt = p.suffix[1:]
        ok, detail = next(((o, d) for f, o, d in rr.checks if f == fmt), (True, ""))
        print(f"   {c(GR, '✔') if ok else c(RD, '✖')} {bold(f'{fmt.upper():<5}')} {c(WH, str(p))}")
        if detail:
            print("         " + c(GY if ok else RD, ("verified: " if ok else "VERIFICATION FAILED: ") + detail))
    for f, m in rr.errors:
        print(f"   {c(RD, '✖')} {bold(f'{f.upper():<5}')} {c(RD, 'not written - ' + str(m))}")


def all_in_one(st: State, preset: str = "") -> None:
    banner()
    section("NEW SCAN")
    if not preset:
        box("TARGET", [
            c(GY, "Enter anything: H3XA detects what it is and runs the modules that fit."),
            "",
            c(GY, "e.g.  ") + c(WH, "jane@gmail.com") + c(GY, "   ") + c(WH, "+923001234567") + c(GY, "   ")
            + c(WH, "janedoe") + c(GY, "   ") + c(WH, "Jane Doe") + c(GY, "   ") + c(WH, "example.com")
            + c(GY, "   ") + c(WH, "8.8.8.8"),
            c(GY, "Name searches work best together with an e-mail / username / phone you already know."),
        ])
        print()
    value = preset or ask("Target:")
    if not value:
        return
    kind, hints = choose_type(value)
    seed = Target(kind, value.strip(), hints=hints)
    seeds = [seed] + extra_identifiers(seed)

    mode = choose_mode(st, seeds)
    if mode is None:
        return
    profile, tools, depth = mode
    if kind == "name" and st.name_guesses and not any(t.kind in ("username", "email") for t in seeds[1:]):
        parts = [p for p in value.lower().replace("-", " ").split() if p.isalpha()]
        if len(parts) >= 2:
            f, l = parts[0], parts[-1]
            for u in dict.fromkeys([f + l, f + "." + l, f + "_" + l, f[0] + l]):
                seeds.append(Target("username", u, 1, seed.key, "username guess from name (weak)", trust=0.4))
            print("   " + c(YE, f"name → also trying {len(seeds) - 1} username guesses (low confidence)"))

    section("Checking modules")
    rows = build_plan(st, seeds, tools)
    if profile == "custom":
        picked = pick_modules(rows)
        tools = picked
        rows = [r for r in rows if r[0] in picked or r[1] == "na"]
    else:
        tools = [n for n, s, _ in rows if s != "na"]
    if show_plan(rows) == 0:
        print("\n   " + c(RD, "No module is ready for this target. Use [2] Module status to set up / repair, or [4] Self-test."))
        input("\n   press Enter ...")
        return
    runnable = [n for n, s, _ in rows if s in ("run", "auto")]
    case_info(st)
    if ask(f"Start {profile} scan with {len(runnable)} module(s)? [Y/n]").lower() not in ("", "y", "yes"):
        return
    meta = {"operator": st.operator, "purpose": st.purpose, "profile": profile}
    case, aborted = run_scan(st, seeds, runnable, depth, meta)
    base = safe_name(f"{kind}_{value}")[:50] + time.strftime("_%Y%m%d_%H%M%S")
    rr = write_reports(case, st.cfg.output_dir, base, st.formats)
    show_results(case)
    show_report_status(rr)
    html_path = next((p for p in rr.paths if p.suffix == ".html"), rr.paths[0] if rr.paths else None)
    while True:
        o = ask("[O] open report   [F] open reports folder   [Enter] back to menu:").lower()
        if o == "o" and html_path:
            open_path(html_path)
        elif o == "f":
            open_path(st.cfg.output_dir)
        else:
            break


def reports_screen(st: State) -> None:
    banner()
    section("Saved reports")
    d = st.cfg.output_dir
    files = sorted(d.glob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True)[:15] if d.is_dir() else []
    if not files:
        print("   " + c(GY, f"no reports yet in {d}"))
    for i, p in enumerate(files, 1):
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(p.stat().st_mtime))
        print(f"   {c(CY, f'[{i:>2}]')} {c(GY, when)}  {bold(trunc(p.stem, width() - 36))} {c(GY, f'{p.stat().st_size // 1024 + 1} KB')}")
    while True:
        o = ask("number = open · F = open folder · Enter = back:").lower()
        if o.isdigit() and 1 <= int(o) <= len(files):
            open_path(files[int(o) - 1])
        elif o == "f":
            open_path(d)
        else:
            return


DOC_ICON = {"pass": (GR, "✔"), "warn": (YE, "◐"), "fail": (RD, "✖"), "skip": (GY, "–")}


def doctor_screen(st: State) -> None:
    from . import doctor
    banner()
    section("Self-test")
    print("   " + c(GY, "Checks every module (install · source contract · parser) and the whole report pipeline,"))
    print("   " + c(GY, "then tells you exactly what works. A live probe really runs each module against a target you choose."))
    live = ask("Live probe target (your own e-mail / username, Enter = skip live probe):")
    net = ask("Also test internet access? [y/N]").lower() in ("y", "yes")
    print()
    state = {"group": ""}

    def show(chk) -> None:
        if chk.group != state["group"]:
            state["group"] = chk.group
            print("\n   " + bold(c(CY, chk.group)))
        col, icon = DOC_ICON[chk.status]
        print(f"     {c(col, icon)} {chk.name:<15} {c(GY if chk.status == 'pass' else col, trunc(chk.detail, width() - 30))}")

    def step(txt: str) -> None:
        sys.stdout.write("\r\033[K   " + c(GY, "… " + txt))
        sys.stdout.flush()

    checks = doctor.run_doctor(st.cfg, live=live or None, net=net, on_check=show, on_step=step)
    sys.stdout.write("\r\033[K")
    v = doctor.verdict(checks)
    lines = [f"{c(GR, '✔')} {v['pass']} passed   {c(YE, '◐')} {v['warn']} warnings   {c(RD, '✖')} {v['fail']} failed   {c(GY, '–')} {v['skip']} skipped"]
    if v["ready_modules"]:
        lines.append(c(GR, "ready: ") + ", ".join(v["ready_modules"]))
    if v["needs_attention"]:
        lines.append(c(YE, "work, but missing credentials/keys: ") + ", ".join(v["needs_attention"]))
    if v["needs_setup"]:
        lines.append(c(YE, "not installed yet → open [2] Module status: ") + ", ".join(v["needs_setup"]))
    if v["broken_modules"]:
        lines.append(c(RD, "BROKEN (installed but a check failed): ") + ", ".join(v["broken_modules"]))
    print()
    box("RESULT", lines, color=GR if v["ok"] else RD)
    input("\n   press Enter ...")


def tool_status(st: State) -> None:
    banner()
    section("Module status")
    fixable: list[tuple[str, object, MissingRequirement]] = []
    needs_setup: list[str] = []
    for name, cls in ALL.items():
        ad = cls(st.cfg, st.tmp)
        try:
            ad.check()
            print(f"   {c(GR, '●')} {bold(f'{display(name):<13}')} {c(GR, 'ready')}   {c(GY, DESC[name])}")
        except MissingRequirement as e:
            print(f"   {c(YE, '○')} {bold(f'{display(name):<13}')} {c(YE, 'needs a package')} {c(GY, trunc(str(e), 55))}")
            fixable.append((name, ad, e))
        except Exception as e:
            msg = str(e)
            no_env = ad.dir in TOOLS and "no Python env" in msg
            print(f"   {c(RD, '○')} {bold(f'{display(name):<13}')} {c(RD, 'not ready')} {c(GY, trunc(msg, 60))}")
            if no_env:
                needs_setup.append(name)
    print("\n   " + c(GY, "GAccountID needs a one-time login; InstaLens needs its own API token or session; "
                          "BreachRadar finds more with API keys configured."))
    if needs_setup:
        names = ", ".join(display(n) for n in needs_setup)
        if ask(f"{len(needs_setup)} module(s) have no private Python env yet ({names}). "
               "Set it up now? needs internet, several minutes [Y/n]").lower() in ("", "y", "yes"):
            from . import setup_tools as st_
            print()
            for k, v in st_.install_with_progress(st.cfg, needs_setup, label=display).items():
                if not v.startswith("ok"):
                    print("   " + c(RD, "✖ ") + f"{display(k):<13} {trunc(v, 90)}")
    if fixable:
        names = ", ".join(display(n) for n, _, _ in fixable)
        if ask(f"{len(fixable)} module(s) just need a missing package ({names}). Install now? [Y/n]").lower() in ("", "y", "yes"):
            for name, ad, err in fixable:
                with Spinner(f"fixing {display(name)}"):
                    fixed, tail = ad.install_missing()
                tag = c(GR, "✔ fixed") if fixed else c(RD, f"✖ still failing: {trunc(tail, 80)}")
                print(f"   {bold(display(name))}: {tag}")
    input("\n   press Enter ...")


def settings(st: State) -> None:
    """Accepts a number OR a word, with an optional value: `1`, `depth 2`, `formats html,csv`, `timeout 600`, `back`."""
    while True:
        banner()
        section("Settings (this session)")
        g = st.cfg.data["general"]
        print(f"   [1] Pivot depth ............ {bold(c(CY, st.depth))}  {c(GY, '0 = only what you typed; 1-3 = also scan leads found (e-mails/usernames)')}")
        print(f"   [2] Loud modules ........... {bold(c(RD if st.allow_loud else GR, 'ON' if st.allow_loud else 'off'))}  {c(GY, 'ON = may trigger notification mails to the target')}")
        print(f"   [3] Name → username guesses  {bold(c(CY, 'ON' if st.name_guesses else 'off'))}")
        print(f"   [4] Report formats ......... {bold(c(CY, ', '.join(st.formats)))}  {c(GY, 'html, json, md, csv')}")
        print(f"   [5] Time limit per module .. {bold(c(CY, str(g['timeout']) + 's'))}")
        print(f"   [6] Modules in parallel .... {bold(c(CY, g['max_parallel']))}")
        print(f"   [7] Retries on failure ..... {bold(c(CY, g['retries']))}  {c(GY, 'a module that fails for a network reason is tried again')}")
        print(f"   [8] Case details ........... {c(GY, trunc((st.operator or '-') + ' / ' + (st.purpose or '-'), 50))}")
        print(f"   [0] Back   {c(GY, 'shortcuts: depth 2 · loud · guess · formats csv · timeout 600 · parallel 6 · retries 2 · case')}")
        raw = ask("Choose:").lower().split()
        o = raw[0] if raw else "0"
        arg = " ".join(raw[1:])
        if o in ("1", "depth", "d"):
            v = arg or ask("Depth 0-3:")
            if v.isdigit() and 0 <= int(v) <= 3:
                st.depth = int(v)
        elif o in ("2", "loud", "l"):
            st.allow_loud = not st.allow_loud
            st.cfg.data["user-scanner"]["allow_loud"] = st.cfg.data["holehe"]["allow_loud"] = st.allow_loud
        elif o in ("3", "guess", "g", "names"):
            st.name_guesses = not st.name_guesses
        elif o in ("4", "formats", "format", "f"):
            v = arg or ask("Formats, comma-separated from html,json,md,csv (current: " + ",".join(st.formats) + "):")
            chosen = [x.strip() for x in v.replace(" ", ",").split(",") if x.strip() in FORMATS]
            if chosen:
                st.formats = list(dict.fromkeys(chosen))
        elif o in ("5", "timeout", "t"):
            v = arg or ask("Seconds per module (30-7200):")
            if v.isdigit() and 30 <= int(v) <= 7200:
                g["timeout"] = int(v)
        elif o in ("6", "parallel", "p"):
            v = arg or ask("Modules at once (1-8):")
            if v.isdigit() and 1 <= int(v) <= 8:
                g["max_parallel"] = int(v)
        elif o in ("7", "retries", "retry", "r"):
            v = arg or ask("Retries 0-3:")
            if v.isdigit() and 0 <= int(v) <= 3:
                g["retries"] = int(v)
        elif o in ("8", "case", "c"):
            st.operator = ask("Your name / team:")
            st.purpose = ask("Purpose / authorisation:")
            st.case_info_done = True
        else:
            return


def _ready_count(st: State) -> tuple[int, int]:
    ok = 0
    for name, cls in ALL.items():
        try:
            cls(st.cfg, st.tmp).check()
            ok += 1
        except Exception:
            pass
    return ok, len(ALL)


MENU_ALIASES = {
    "scan": ("1", "scan", "all", "all-in-one", "run", "start", "s"),
    "status": ("2", "status", "modules", "m", "check", "setup", "repair", "install"),
    "settings": ("3", "settings", "set", "config", "cfg"),
    "doctor": ("4", "selftest", "self-test", "doctor"),
    "reports": ("5", "reports"),
    "help": ("?", "h", "help"),
    "exit": ("0", "q", "quit", "exit", "bye"),
}


def _resolve(word: str) -> str | None:
    w = word.lower()
    for action, names in MENU_ALIASES.items():
        if w in names:
            return action
    return None


def show_help() -> None:
    banner()
    section("Help")
    box("QUICK USE", [
        c(WH, "Type a number or a word at the menu:") + c(GY, "  1/scan · 2/status · 3/settings · 4/selftest · 5/reports · ?/help · 0/quit"),
        c(WH, "Or just paste a target") + c(GY, " (email, username, phone, domain, IP, name) and H3XA scans it."),
        c(WH, "Each scan asks: ") + c(GY, "type check → other known identifiers → mode (quick/standard/deep/custom) → plan → live scan."),
        c(WH, "Something not working? ") + c(GY, "[4] Self-test checks every module and report format and says exactly what to fix."),
        c(WH, "Missing a module? ") + c(GY, "'status' (or 'setup') installs what is missing - in parallel, with live progress."),
        c(WH, "Ctrl+C during a scan ") + c(GY, "stops it and still saves a report of what was found so far."),
    ])
    input("\n   " + dim("press Enter ..."))


def menu(st: State) -> None:
    ready = None
    while True:
        banner()
        if ready is None:
            ready = _ready_count(st)
        okn, total = ready
        rc = GR if okn == total else YE if okn else RD
        print("   " + c(rc, "●") + f" {bold(c(rc, f'{okn}/{total}'))} modules ready"
              + c(GY, f"   ·   pivot depth {st.depth}   ·   loud {'ON' if st.allow_loud else 'off'}"
                      f"   ·   reports → {trunc(st.cfg.output_dir, 40)}"))
        print()
        print("   " + c(GR, bold("[1]")) + "  " + bold(c(WH, "⚡ NEW SCAN")) + c(GY, "        give a target - choose Quick / Standard / Deep / Custom"))
        print("   " + c(CY, "[2]") + "  Module status / setup" + (c(YE, "   ← some modules need installing") if okn < total else ""))
        print("   " + c(CY, "[3]") + "  Settings")
        print("   " + c(CY, "[4]") + "  Self-test            " + c(GY, "verify every module + report format"))
        print("   " + c(CY, "[5]") + "  Saved reports")
        print("   " + c(CY, "[?]") + "  Help")
        print("   " + c(CY, "[0]") + "  Exit")
        print()
        print("   " + c(GY, "tip: type a number, a word (scan, status ...), or paste a target directly"))
        o = ask("Select:")
        action = _resolve(o)
        if action == "scan":
            all_in_one(st)
        elif action == "status":
            tool_status(st)
            ready = None
        elif action == "settings":
            settings(st)
        elif action == "doctor":
            doctor_screen(st)
            ready = None
        elif action == "reports":
            reports_screen(st)
        elif action == "help":
            show_help()
        elif action == "exit":
            print("\n   " + c(VI, "bye ◆ H3XA") + "\n")
            return
        elif o:                                   # anything else is treated as a target
            all_in_one(st, preset=o)


def run(config_path: str | None = None) -> int:
    _init_terminal()
    cfg = Config.load(config_path)
    intro()
    ensure_installed(cfg)
    menu(State(cfg))
    return 0
