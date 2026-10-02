from __future__ import annotations
import datetime as dt
import hashlib
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from .adapters import ALL
from .branding import display
from .config import Config
from .correlate import Case, build_case
from .models import (AdapterError, Finding, Pivot, Target, ToolRun)
from .util import detect_kind

# Failures worth one more try (network hiccup, tool crashed before writing output).
# Timeouts, missing setup and missing credentials are never retried - they would fail again.
_TRANSIENT = ("no output", "unparseable", "connection", "temporar", "reset by peer",
              "unreachable", "429", "502", "503", "504", "ssl")


def new_case_id(seeds) -> str:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    h = hashlib.sha1("|".join(s.key for s in seeds).encode()).hexdigest()[:4].upper()
    return f"H3XA-{stamp}-{h}"


class Engine:
    """Runs adapters against targets, follows verified leads, and reports progress through
    two channels: `log(str)` (plain text, used by the CLI) and `on_event(kind, **info)`
    (structured, used by the terminal UI). Events: start, done, retry, target, lead."""

    def __init__(self, cfg: Config, tools: list[str], tmp_root: Path,
                 log: Callable[[str], None] = lambda s: None,
                 on_event: Callable[..., None] | None = None):
        self.cfg, self.log = cfg, log
        self.on_event = on_event or (lambda event, **info: None)
        unknown = [t for t in tools if t not in ALL]
        if unknown:
            raise ValueError(f"unknown module(s): {', '.join(unknown)} (available: {', '.join(ALL)})")
        self.tools = list(tools)
        self.adapters = [ALL[t](cfg, tmp_root) for t in tools]
        self.findings: list[Finding] = []
        self.runs: list[ToolRun] = []
        self.targets: list[Target] = []
        self._lock = threading.Lock()
        self.running: set[str] = set()
        self.cancelled = threading.Event()

    def cancel(self) -> None:
        """Ask the scan to stop after the module runs already in flight (the UI also kills them)."""
        self.cancelled.set()

    def _emit(self, event: str, **info) -> None:
        try:
            self.on_event(event, **info)
        except Exception:      # a broken UI callback must never break a scan
            pass

    # ---- one adapter on one target -------------------------------------------
    @staticmethod
    def _transient(message: str) -> bool:
        m = (message or "").lower()
        return any(k in m for k in _TRANSIENT)

    def _exec(self, ad, target: Target) -> list[Finding]:
        t0 = time.time()
        run = ToolRun(ad.name, target.key, "ok")
        found: list[Finding] = []
        max_attempts = 1 + max(0, int(self.cfg.get("general", "retries", 1) or 0))
        with self._lock:
            self.running.add(display(ad.name))
        self._emit("start", module=ad.name, label=display(ad.name), target=target.value, target_kind=target.kind)
        attempts = 0
        while True:
            attempts += 1
            found, run.status, run.message, run.checked = [], "ok", "", None
            try:
                ad.check()
                res = ad.run(target)
                found, run.checked, run.message = res.findings, res.checked, res.message
            except AdapterError as e:
                run.status, run.message = e.status, str(e)
            except Exception as e:  # never let one tool kill the case
                run.status, run.message = "error", f"{type(e).__name__}: {e}"
            if (run.status == "error" and attempts < max_attempts and self._transient(run.message)
                    and not self.cancelled.is_set()):
                self._emit("retry", module=ad.name, label=display(ad.name), target=target.value,
                           attempt=attempts + 1, reason=run.message)
                continue
            break
        run.attempts = attempts
        run.seconds = round(time.time() - t0, 1)
        run.findings = len(found)
        with self._lock:
            self.running.discard(display(ad.name))
            self.runs.append(run)
            self.findings.extend(found)
        msg = run.message if run.status != "ok" else ""
        if attempts > 1:
            msg = (msg + " " if msg else "") + f"(tried {attempts}x)"
        self.log(f"  [{run.status:<11}] {display(ad.name):<13} {target.value}  ({run.findings} findings, {run.seconds}s)"
                 + (f" - {msg}" if msg else ""))
        self._emit("done", module=ad.name, label=display(ad.name), target=target.value, run=run)
        return found

    def scan_target(self, target: Target) -> list[Finding]:
        mine: list[Finding] = []
        p1 = [a for a in self.adapters if a.phase == 1 and a.applies(target, [])]
        if p1 and not self.cancelled.is_set():
            with ThreadPoolExecutor(max_workers=max(1, int(self.cfg.get("general", "max_parallel", 4)))) as ex:
                for fl in ex.map(lambda a: self._exec(a, target), p1):
                    mine += fl
        # phase 2: adapters that decide, from phase-1 results, whether they are worth running
        p2 = [a for a in self.adapters if a.phase == 2 and a.applies(target, mine + self._for(target))]
        for a in p2:
            if self.cancelled.is_set():
                break
            mine += self._exec(a, target)
        return mine

    def _for(self, target):
        with self._lock:
            return [f for f in self.findings if f.subject == target.value]

    # ---- pivoting -------------------------------------------------------------
    def derive(self, target: Target, findings: list[Finding]) -> list[Target]:
        pc = self.cfg["pivot"]
        out: dict[str, Target] = {}

        def policy(kind, trust):
            mode = pc.get({"email": "emails", "username": "usernames"}.get(kind, ""), "none")
            return mode == "all" or (mode == "verified" and trust in ("verified", "derived"))

        for f in findings:
            for pv in f.pivots:
                if pv.kind not in ("email", "username") or not policy(pv.kind, pv.trust):
                    continue
                t = Target(pv.kind, pv.value.strip(), target.depth + 1, target.key,
                           f"{display(f.tool)} exposed {pv.kind} on {f.title or f.platform or 'result'}",
                           trust=target.trust * (0.85 if pv.trust == "verified" else 0.6))
                out.setdefault(t.key, t)
        if pc.get("derive_username") and target.kind == "email":
            u = target.value.split("@")[0]
            t = Target("username", u, target.depth + 1, target.key,
                       "local-part of e-mail (weak guess)", trust=target.trust * 0.5)
            out.setdefault(t.key, t)
        return list(out.values())

    # ---- main loop ------------------------------------------------------------
    def scan(self, seeds: list[Target], meta: dict | None = None) -> Case:
        started = dt.datetime.now().isoformat(timespec="seconds")
        pc = self.cfg["pivot"]
        seen: set[str] = set()
        queue = list(seeds)
        while queue and len(seen) < max(pc["max_targets"], len(seeds)) and not self.cancelled.is_set():
            t = queue.pop(0)
            if t.key in seen:
                continue
            seen.add(t.key)
            self.targets.append(t)
            self.log(f"\n== {t.kind}: {t.value}" + (f"   (depth {t.depth}: {t.reason})" if t.depth else ""))
            self._emit("target", target=t)
            got = self.scan_target(t)
            if t.depth < pc["depth"]:
                for n in self.derive(t, got):
                    if n.key not in seen and n.key not in {q.key for q in queue}:
                        self.log(f"   + new lead: {n.kind} {n.value}  <- {n.reason}")
                        self._emit("lead", target=n)
                        queue.append(n)
        return self.make_case(seeds, started, meta)

    def make_case(self, seeds: list[Target], started: str = "", meta: dict | None = None) -> Case:
        """Build the case from whatever has been collected so far (also used for partial results)."""
        m = {"case_id": new_case_id(seeds), "modules": [display(t) for t in self.tools],
             "cancelled": self.cancelled.is_set()}
        m.update(meta or {})
        return build_case([s.value for s in seeds], self.targets, self.runs, self.findings,
                          started or dt.datetime.now().isoformat(timespec="seconds"),
                          dt.datetime.now().isoformat(timespec="seconds"), meta=m)


def make_seed(value: str, kind: str | None = None, instagram: bool = False) -> Target:
    return Target(kind or detect_kind(value), value.strip(), hints={"instagram": True} if instagram else {})
