from __future__ import annotations
import shutil
from ..models import AdapterError, AdapterResult, Target, Unavailable
from ..util import platform_key, safe_name
from .base import Adapter


class UserRecon(Adapter):
    """Legacy bash script (~75 sites, grep-based detection). Every site it checks is also
    covered by user-scanner/tookie, so it is only used as low-weight corroboration
    and only in the `deep` profile."""
    name = "userrecon"
    dir = "userrecon"
    kinds = ("username",)
    weight = 0.35
    needs_python = False

    def check(self):
        super().check()
        if not shutil.which("bash") or not shutil.which("curl"):
            raise Unavailable("needs bash and curl on PATH")

    def run(self, target: Target) -> AdapterResult:
        wd = self.workdir()
        r = self.exec(["bash", self.src / "userrecon.sh"], cwd=wd, input_text=target.value + "\n")
        f = wd / f"{safe_name(target.value)}.txt"
        if not f.exists():
            if r.rc in (0, 1):
                return AdapterResult(message="no hits")
            raise AdapterError(f"rc={r.rc}: {r.err[-200:]}")
        return self.parse(f.read_text(errors="replace").splitlines(), target)

    def parse(self, lines, target: Target) -> AdapterResult:
        res = AdapterResult()
        for ln in lines:
            ln = ln.strip()
            if ln.startswith("http"):
                k = platform_key(ln)
                res.findings.append(self.mk(target, "account", title=k, url=ln, platform=k, via="username"))
        return res
