from __future__ import annotations
import json
from ..models import AdapterError, AdapterResult, Target
from ..util import load_json_lenient, platform_key, safe_name, strip_ansi
from .base import Adapter


class Tookie(Adapter):
    name = "tookie"
    dir = "tookie"
    kinds = ("username",)
    weight = 0.60     # status-code / error-text heuristics (+control-response check)

    def run(self, target: Target) -> AdapterResult:
        wd = self.workdir()
        cmd = [self.py(), self.src / "brib.py", "-u", target.value, "-o", "json",
               "-t", str(self.opts.get("threads", 20))]
        r = self.exec(cmd, cwd=wd)
        out = wd / f"{safe_name(target.value)}.json"
        cands = [out] + list(wd.glob("*.json"))
        f = next((c for c in cands if c.exists()), None)
        if not f:
            # tookie writes nothing when it finds nothing
            if r.rc == 0:
                return AdapterResult(message="no hits")
            raise AdapterError(f"no output (rc={r.rc}): {strip_ansi(r.err or r.out)[-300:]}")
        return self.parse(load_json_lenient(f.read_text(encoding="utf-8")) or [], target)

    def parse(self, rows, target: Target) -> AdapterResult:
        res = AdapterResult(checked=len(rows) or None)
        for row in rows:
            if not row.get("found"):
                continue
            url = row.get("url", "")
            res.findings.append(self.mk(target, "account", title=platform_key(url), url=url,
                                        platform=platform_key(url), via="username",
                                        data={"http_status": row.get("status")}))
        return res
