from __future__ import annotations
import os
from pathlib import Path
from ..models import AdapterError, AdapterResult, NeedsAuth, Skipped, Target
from ..util import dig, load_json_lenient, strip_ansi
from .base import Adapter

GOOGLE_DOMAINS = {"gmail.com", "googlemail.com"}


class GHunt(Adapter):
    name = "ghunt"
    dir = "ghunt"
    kinds = ("email",)
    phase = 2
    weight = 0.95

    def applies(self, target, prior) -> bool:
        if target.kind != "email":
            return False
        if self.opts.get("always"):
            return True
        if target.value.split("@")[-1].lower() in GOOGLE_DOMAINS:
            return True
        # tool cooperation: another tool already saw a Google account for this address
        return any(f.category == "account" and f.platform == "google" and f.subject == target.value
                   for f in prior)

    def _creds_ok(self) -> bool:
        home = Path(os.environ.get("HOME", "~")).expanduser()
        return any(p.exists() for p in (home / ".malfrats/ghunt/creds.m", Path.cwd() / ".malfrats/ghunt/creds.m"))

    def run(self, target: Target) -> AdapterResult:
        if not self._creds_ok():
            raise NeedsAuth("GHunt is not logged in - run: <venv>/bin/ghunt login")
        wd = self.workdir()
        out = wd / "ghunt.json"
        exe = self.cfg.venv_bin(self.dir, "ghunt")
        cmd = [exe, "email", target.value, "--json", out] if exe else \
              [self.py(), "-m", "ghunt", "email", target.value, "--json", out]
        r = self.exec(cmd, cwd=wd)
        if not out.exists():
            tail = strip_ansi(r.out + r.err)[-300:]
            if "does not match a public Google Account" in tail:
                return AdapterResult(message="no public Google account for this address")
            raise AdapterError(f"no output (rc={r.rc}): {tail}")
        return self.parse(load_json_lenient(out.read_text(encoding="utf-8")) or {}, target)

    def parse(self, doc, target: Target) -> AdapterResult:
        res = AdapterResult()
        cont = doc.get("PROFILE_CONTAINER")
        if not cont:
            res.message = "no PROFILE container returned"
            return res
        prof = cont.get("profile") or {}
        gaia = prof.get("personId") or ""
        name = dig(prof, "names", "PROFILE", "fullname")
        photo = dig(prof, "profilePhotos", "PROFILE", "url")
        default_photo = dig(prof, "profilePhotos", "PROFILE", "isDefault", default=True)
        apps = dig(prof, "inAppReachability", "PROFILE", "apps", default=[]) or []
        data = {"gaia_id": gaia, "google_services": apps,
                "workspace_user": dig(prof, "extendedData", "gplusData", "isEntrepriseUser")}
        res.findings.append(self.mk(target, "account", title="Google", platform="google", via="email",
                                    url="https://www.google.com", weight=0.97, data=data))
        res.findings.append(self.mk(target, "profile", title="Google account", weight=0.95,
                                    data={k: v for k, v in {**data, "name": name, "photo": photo}.items() if v}))
        if gaia:
            res.findings.append(self.mk(target, "identity", kind="google_id", title="Google",
                                        value=str(gaia), weight=0.97))
        if name:
            res.findings.append(self.mk(target, "identity", kind="name", title="Google", value=name, weight=0.9))
        if photo and not default_photo:
            res.findings.append(self.mk(target, "identity", kind="photo", title="Google", value=photo, url=photo, weight=0.9))
        pg = cont.get("play_games")
        if pg and isinstance(pg, dict):
            u = pg.get("name") or pg.get("username")
            if u:
                res.findings.append(self.mk(target, "identity", kind="username", title="Google Play Games",
                                            value=str(u), weight=0.85))
        stats = dig(cont, "maps", "stats")
        if stats:
            res.findings.append(self.mk(target, "note", title="Google Maps contributions", weight=0.9,
                                        data={"stats": stats}))
        if cont.get("calendar"):
            res.findings.append(self.mk(target, "note", title="Public Google Calendar exposed", weight=0.9))
        return res
