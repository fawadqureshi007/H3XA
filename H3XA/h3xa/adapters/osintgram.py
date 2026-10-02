from __future__ import annotations
from pathlib import Path
from ..models import AdapterError, AdapterResult, NeedsAuth, Pivot, Target
from ..util import EMAIL_RE, clean_dict, load_json_lenient, strip_ansi
from .base import Adapter

BRIDGE = Path(__file__).resolve().parent.parent / "bridges" / "osintgram_bridge.py"


class Osintgram(Adapter):
    name = "osintgram"
    dir = "osintgram"
    kinds = ("username",)
    phase = 2
    weight = 0.95
    # No critical_imports list needed - base.Adapter.check() verifies every package in
    # vendor/osintgram/requirements.txt automatically (fastapi, uvicorn, instagrapi, ...).

    def applies(self, target, prior) -> bool:
        if target.kind != "username":
            return False
        if target.hints.get("instagram"):
            return True
        # tool cooperation: another tool found this handle on Instagram
        return any(f.category == "account" and f.platform == "instagram" and f.subject == target.value
                   and f.tool != self.name for f in prior)

    def run(self, target: Target) -> AdapterResult:
        wd = self.workdir()
        out = wd / "ig.json"
        o = self.opts
        cmd = [self.py(), BRIDGE, self.src, target.value, out, str(o.get("limit_posts", 30)),
               "1" if o.get("followers") else "0", "1" if o.get("followings") else "0"]
        env = {"INSTAGRAM_BACKEND": o["backend"]} if o.get("backend") else {}
        r = self.exec(cmd, cwd=self.src, env=env)
        doc = load_json_lenient(out.read_text(encoding="utf-8")) if out.exists() else None
        if not doc:
            raise AdapterError(f"no output (rc={r.rc}): {strip_ansi(r.err or r.out)[-300:]}")
        if doc.get("_fatal"):
            msg = doc["_fatal"]
            if "No backend configured" in msg or "HikerAPI selected" in msg or "credentials" in msg.lower():
                raise NeedsAuth("Osintgram needs a HikerAPI token (HIKERAPI_TOKEN) or an instagrapi "
                                "session - see vendor/osintgram/config/credentials.ini.example")
            raise AdapterError(msg)
        return self.parse(doc, target)

    def parse(self, doc, target: Target) -> AdapterResult:
        res = AdapterResult(message=f"{doc.get('_api_calls', '?')} API calls")
        info = doc.get("info") or {}
        about = doc.get("about") or {}
        if not info:
            return res
        url = f"https://www.instagram.com/{target.value}/"
        prof = clean_dict({**info, **{f"about_{k}": v for k, v in about.items()}})
        res.findings.append(self.mk(target, "account", title="Instagram", url=url, platform="instagram",
                                    via="username", weight=0.98, data={"alt_keys": []}))
        res.findings.append(self.mk(target, "profile", title="Instagram profile", url=url, weight=0.95,
                                    data=prof))
        if info.get("full_name"):
            res.findings.append(self.mk(target, "identity", kind="name", title="Instagram",
                                        value=info["full_name"], weight=0.85))
        if about.get("country"):
            res.findings.append(self.mk(target, "identity", kind="location", title="Instagram (account country)",
                                        value=about["country"], weight=0.8))
        if info.get("profile_pic_url_hd"):
            res.findings.append(self.mk(target, "identity", kind="photo", title="Instagram",
                                        value=info["profile_pic_url_hd"], url=info["profile_pic_url_hd"], weight=0.9))
        for l in info.get("bio_links", []) or []:
            if l.get("url"):
                res.findings.append(self.mk(target, "identity", kind="link", title="Instagram bio link",
                                            value=l["url"], url=l["url"], weight=0.9))
        pivots = []
        for key in ("public_email", "email"):
            if info.get(key):
                pivots.append(Pivot("email", str(info[key]).lower(), "verified"))
        for e in EMAIL_RE.findall(info.get("biography") or ""):
            pivots.append(Pivot("email", e.lower(), "scraped"))
        if info.get("public_phone_number") or info.get("contact_phone_number"):
            res.findings.append(self.mk(target, "identity", kind="phone", title="Instagram business contact",
                                        value=str(info.get("public_phone_number") or info.get("contact_phone_number")),
                                        weight=0.9))
        for i, k in enumerate(("hashtags", "places", "posting_times")):
            if doc.get(k):
                res.findings.append(self.mk(target, "note", title=f"Instagram {k.replace('_', ' ')}",
                                            weight=0.9, data={k: doc[k]}))
        if res.findings:
            res.findings[0].pivots = pivots
        return res
