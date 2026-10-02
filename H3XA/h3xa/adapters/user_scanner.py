from __future__ import annotations
import json, re
from ..models import AdapterError, AdapterResult, Pivot, Target
from ..util import clean_dict, find_emails, load_json_lenient, platform_key, strip_ansi
from .base import Adapter

_CLUE_KEYS = {
    "name": "name", "full_name": "name", "display_name": "name", "fullname": "name",
    "location": "location", "country": "location", "city": "location",
    "bio": "bio", "biography": "bio", "description": "bio",
    "avatar": "photo", "avatar_url": "photo", "profile_pic": "photo", "image": "photo",
    "website": "link", "url": "link", "blog": "link",
}


class UserScanner(Adapter):
    name = "user-scanner"
    dir = "user-scanner"
    kinds = ("email", "username")
    weight = 0.80

    def _flags(self):
        o = self.opts
        f = []
        if o.get("allow_loud"):
            f.append("--allow-loud")
        if not o.get("nsfw", True):
            f.append("--no-nsfw")
        if o.get("concurrency"):
            f += ["-C", str(o["concurrency"])]
        return f

    def run(self, target: Target) -> AdapterResult:
        wd = self.workdir()
        out = wd / "us.json"
        flag = "-e" if target.kind == "email" else "-u"
        # --cross-scan is deliberately NOT used: h3xa does its own pivoting so that
        # every tool benefits from a lead, not only user-scanner.
        cmd = [self.py(), "-m", "user_scanner", flag, target.value, "-o", out, "--all", *self._flags()]
        r = self.exec(cmd, cwd=wd)
        if not out.exists():
            raise AdapterError(f"no output produced (rc={r.rc}): {strip_ansi(r.err or r.out)[-300:]}")
        rows = load_json_lenient(out.read_text(encoding="utf-8", errors="replace")) or []
        res = self.parse(rows, target)
        if self.opts.get("hudson"):
            try:
                res.findings += self._hudson(target, wd)
            except AdapterError as e:
                res.message = f"hudson: {e}"
        return res

    # -- parsing (pure, unit-tested) ------------------------------------------
    def parse(self, rows, target: Target) -> AdapterResult:
        res = AdapterResult(checked=len(rows))
        errors = skipped = 0
        for row in rows:
            st = str(row.get("status", "")).lower()
            if st == "error":
                errors += 1
                continue
            if st == "skipped":
                skipped += 1
                continue
            if st not in ("found", "registered"):
                continue
            site = row.get("site_name") or ""
            url = row.get("url") or ""
            extra = clean_dict({**(row.get("extra") or {}), **(row.get("media") or {})})
            key = platform_key(url) or platform_key(site)
            f = self.mk(target, "account", title=site, url=url, platform=key,
                        via="email" if target.kind == "email" else "username",
                        weight=0.88 if extra else self.weight,
                        data={"category": row.get("category", ""), "alt_keys": [platform_key(site)],
                              **({"profile": extra} if extra else {})})
            res.findings.append(f)
            for k, v in extra.items():
                kind = _CLUE_KEYS.get(k.lower())
                if kind and isinstance(v, (str, int)) and str(v).strip():
                    res.findings.append(self.mk(target, "identity", kind=kind, title=site,
                                                value=str(v).strip(), url=url, weight=0.7))
            for path, em in find_emails(extra):
                trust = "verified" if "email" in path.lower() else "scraped"
                f.pivots.append(Pivot("email", em, trust))
        notes = []
        if errors:
            notes.append(f"{errors} modules errored")
        if skipped:
            notes.append(f"{skipped} skipped (loud modules; enable allow_loud to include)")
        res.message = "; ".join(notes)
        return res

    def _hudson(self, target, wd):
        flag = "-e" if target.kind == "email" else "-u"
        r = self.exec([self.py(), "-m", "user_scanner", flag, target.value, "--hudson"],
                      cwd=wd, input_text="y\n", timeout=120)
        return self.parse_hudson(strip_ansi(r.out), target)

    def parse_hudson(self, text: str, target: Target):
        out = []
        blocks = re.split(r"Infection #\d+:", text)[1:]
        for b in blocks:
            g = lambda label: (re.search(rf"{label}:\s*(.+)", b) or [None, ""])[1].strip()
            out.append(self.mk(target, "breach", kind="infostealer", title="Infostealer infection (Hudson Rock)",
                               value=g("Stealer Family"), weight=0.9,
                               data={"date": g("Date Compromised"), "os": g("Operating System"),
                                     "computer_name": g("Computer Name")}))
        return out
