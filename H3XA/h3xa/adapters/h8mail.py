from __future__ import annotations
import re
from ..models import AdapterError, AdapterResult, Pivot, Target
from ..util import load_json_lenient, strip_ansi
from .base import Adapter

# h8mail labels whose value is a secret: we count them, never carry the value into reports
_SECRET = re.compile(r"(PASS|PASSWORD|HASH|HASHSALT)$")
_SOURCE = re.compile(r"(_SOURCE|_PUB_SRC|^HIBP3)$")
_RELATED = re.compile(r"(RELATED|_EMAIL)$")
_USER = re.compile(r"_USERNAME$")


class H8mail(Adapter):
    name = "h8mail"
    dir = "h8mail"
    kinds = ("email",)
    weight = 0.70
    needs_python = True

    def run(self, target: Target) -> AdapterResult:
        wd = self.workdir()
        out = wd / "h8.json"
        exe = self.cfg.venv_bin(self.dir, "h8mail")
        cmd = [exe, "-t", target.value, "-j", out] if exe else [self.py(), "-m", "h8mail", "-t", target.value, "-j", out]
        if self.opts.get("config"):
            cmd += ["-c", self.opts["config"]]
        r = self.exec(cmd, cwd=wd)
        if not out.exists():
            raise AdapterError(f"no output (rc={r.rc}): {strip_ansi(r.err or r.out)[-300:]}")
        return self.parse(load_json_lenient(out.read_text(encoding="utf-8")) or {}, target)

    def parse(self, doc, target: Target) -> AdapterResult:
        res = AdapterResult()
        for t in doc.get("targets", []):
            if str(t.get("target", "")).lower() != target.value.lower():
                continue
            groups = t.get("data") or []
            secrets = 0
            for grp in groups:
                rec = {}
                for item in grp:
                    label, _, val = str(item).partition(":")
                    rec.setdefault(label, []).append(val)
                sources = [v for l, vs in rec.items() if _SOURCE.search(l) for v in vs]
                secrets_here = sum(len(vs) for l, vs in rec.items() if _SECRET.search(l))
                secrets += secrets_here
                title = sources[0] if sources else "Breach record"
                if title == "N/A" and not secrets_here and not rec:
                    continue
                f = self.mk(target, "breach", kind="breach", title=title, weight=0.75,
                            data={"labels": sorted(rec), "credential_fields": secrets_here,
                                  "secrets_redacted": bool(secrets_here)})
                for l, vs in rec.items():
                    if _RELATED.search(l):
                        for v in vs:
                            f.pivots.append(Pivot("email", v.lower(), "verified"))
                    elif _USER.search(l):
                        for v in vs:
                            res.findings.append(self.mk(target, "identity", kind="username", title=title,
                                                        value=v, weight=0.65))
                            f.pivots.append(Pivot("username", v, "scraped"))
                res.findings.append(f)
            res.message = (f"{t.get('pwn_num', 0)} breach hits; "
                           f"{secrets} credential fields seen (redacted)") if groups else "no breach data (add API keys via [h8mail].config for more sources)"
        return res
