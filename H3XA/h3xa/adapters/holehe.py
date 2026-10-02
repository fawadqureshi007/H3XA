from __future__ import annotations
from pathlib import Path
from ..models import AdapterError, AdapterResult, Target
from ..util import clean_dict, load_json_lenient, platform_key, strip_ansi
from .base import Adapter

BRIDGE = Path(__file__).resolve().parent.parent / "bridges" / "holehe_bridge.py"


class Holehe(Adapter):
    name = "holehe"
    dir = "holehe"
    kinds = ("email",)
    weight = 0.75

    def run(self, target: Target) -> AdapterResult:
        wd = self.workdir()
        out = wd / "holehe.json"
        cmd = [self.py(), BRIDGE, target.value, str(out),
               str(self.opts.get("timeout", 12)), "1" if self.opts.get("allow_loud") else "0"]
        r = self.exec(cmd, cwd=wd)
        if not out.exists():
            raise AdapterError(f"no output (rc={r.rc}): {strip_ansi(r.err or r.out)[-300:]}")
        return self.parse(load_json_lenient(out.read_text(encoding="utf-8")) or [], target)

    def parse(self, rows, target: Target) -> AdapterResult:
        res = AdapterResult(checked=len(rows))
        limited = errored = 0
        for row in rows:
            if row.get("rateLimit"):
                limited += 1
                continue
            if row.get("error"):
                errored += 1
                continue
            if row.get("exists") is not True:
                continue
            dom = row.get("domain") or row.get("name") or ""
            res.findings.append(self.mk(
                target, "account", title=row.get("name", dom), url=f"https://{dom}" if dom else "",
                platform=platform_key(dom), via="email",
                data={"method": row.get("method", ""), "alt_keys": [platform_key(row.get("name", ""))]}))
            for k, kind in (("emailrecovery", "recovery_email"), ("phoneNumber", "recovery_phone")):
                if row.get(k):
                    res.findings.append(self.mk(target, "identity", kind=kind, title=dom,
                                                value=str(row[k]), weight=0.7,
                                                data={"masked": True}))
            for k, v in clean_dict(row.get("others") or {}).items():
                kind = {"fullname": "name", "date, time of the creation": "created"}.get(k.lower())
                if kind:
                    res.findings.append(self.mk(target, "identity", kind=kind, title=dom,
                                                value=str(v), weight=0.7))
        notes = []
        if limited:
            notes.append(f"{limited} modules rate-limited")
        if errored:
            notes.append(f"{errored} modules errored")
        res.message = "; ".join(notes)
        return res
