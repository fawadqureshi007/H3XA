from __future__ import annotations
import tempfile
from pathlib import Path

from ..config import Config
from ..models import (AdapterError, AdapterResult, Finding, MissingRequirement, Target, Unavailable)
from ..reqcheck import missing_packages as _missing_from_requirements
from ..runner import CmdResult, run

# Requirements-file verification is a handful of subprocesses per module - cheap once,
# wasteful if repeated for every pivot target in a single run (e.g. 4 derived username
# guesses would otherwise re-check SpiderFoot's ~26 packages 4 times over). Cached per
# module dir for the life of the process; invalidated after a repair attempt.
_verify_cache: dict[str, list[tuple[str, str, str]]] = {}


class Adapter:
    """One wrapper per external tool. The tool's source stays untouched in vendor/."""
    name = ""
    dir = ""                 # folder under vendor/
    kinds: tuple = ()        # target kinds this adapter can take
    phase = 1                # 1 = always; 2 = conditional on what phase 1 found
    weight = 0.6             # default reliability of this tool's positives
    needs_python = True
    # Fallback for "pkg"-installed modules with no requirements.txt of their own: import
    # names that must work for the module to run at all.
    critical_imports: tuple = ()
    critical_pip: dict = {}

    def __init__(self, cfg: Config, tmp_root: Path):
        self.cfg = cfg
        self.tmp_root = tmp_root

    # -- helpers ------------------------------------------------------------
    @property
    def opts(self) -> dict:
        return self.cfg.data.get(self.name, {})

    @property
    def src(self) -> Path:
        return self.cfg.src(self.dir)

    def py(self) -> Path:
        p = self.cfg.venv_python(self.dir)
        if not p:
            raise Unavailable(f"no Python env for {self.name}; run `h3xa setup` "
                              f"or set [python] {self.dir} in h3xa.toml")
        return p

    def check(self) -> None:
        if not self.src.is_dir():
            raise Unavailable(f"{self.dir} not found in {self.cfg.vendor_dir}; run `h3xa setup`")
        if not self.needs_python:
            return
        py = self.py()
        req_file = self.src / "requirements.txt"
        if req_file.exists():
            missing = self._cached_missing(py, req_file)
            if missing:
                raw, pkg, imp = missing[0]
                raise MissingRequirement(pkg, imp, all_missing=[m[1] for m in missing])
        elif self.critical_imports:
            missing = self.missing_imports(py)
            if missing:
                imp = missing[0]
                raise MissingRequirement(self.critical_pip.get(imp, imp), imp,
                                          all_missing=[self.critical_pip.get(m, m) for m in missing])

    def _cached_missing(self, py, req_file: Path) -> list[tuple[str, str, str]]:
        if self.dir not in _verify_cache:
            _verify_cache[self.dir] = _missing_from_requirements(py, req_file)
        return _verify_cache[self.dir]

    def invalidate_cache(self) -> None:
        _verify_cache.pop(self.dir, None)

    def missing_imports(self, py=None) -> list[str]:
        """Fallback path for modules with no requirements.txt (pkg-installed): which of
        critical_imports fail to import right now."""
        py = py or self.py()
        missing = []
        for mod in self.critical_imports:
            r = run([str(py), "-c", f"import {mod}"], timeout=20)
            if r.rc != 0:
                missing.append(mod)
        return missing

    def install_missing(self, py=None) -> tuple[bool, str]:
        """Best-effort repair: install whatever's currently missing, one package at a
        time so a single stubborn dependency can't block the rest. Returns
        (all_fixed, note_for_display)."""
        import subprocess
        py = py or self.py()
        req_file = self.src / "requirements.txt"

        if req_file.exists():
            missing = _missing_from_requirements(py, req_file)
            if not missing:
                self.invalidate_cache()
                return True, ""
            still_broken, why = [], {}
            for raw, pkg, imp in missing:
                from ..reqcheck import relax
                ok = False
                for spec in dict.fromkeys([raw, relax(raw)]):     # pinned first, then without the "<" ceiling
                    r = subprocess.run([str(py), "-m", "pip", "install", "-q", "--disable-pip-version-check",
                                        "--prefer-binary", spec], capture_output=True, text=True)
                    if r.returncode == 0:
                        chk = subprocess.run([str(py), "-c", f"import {imp}"], capture_output=True, text=True)
                        ok = chk.returncode == 0
                        if not ok:
                            why[pkg] = f"installed but `import {imp}` fails: " + (chk.stderr.strip().splitlines() or [""])[-1][:100]
                    else:
                        lines = [l for l in (r.stderr or r.stdout or "").strip().splitlines() if l.strip()]
                        why[pkg] = lines[-1][:120] if lines else "pip failed"
                    if ok:
                        break
                if not ok:
                    still_broken.append(pkg)
            self.invalidate_cache()
            if not still_broken:
                return True, f"installed {len(missing)} package(s) individually"
            return False, "still broken: " + "; ".join(f"{k} ({why[k]})" for k in still_broken)

        # no requirements.txt -> fall back to the static critical_imports list
        missing = self.missing_imports(py)
        if not missing:
            return True, ""
        pkgs = [self.critical_pip.get(m, m) for m in missing]
        r = subprocess.run([str(py), "-m", "pip", "install", "-q"] + pkgs,
                            capture_output=True, text=True)
        still_missing = self.missing_imports(py)
        self.invalidate_cache()
        return (not still_missing), (r.stderr or r.stdout or "")[-400:]

    def workdir(self) -> Path:
        self.tmp_root.mkdir(parents=True, exist_ok=True)
        return Path(tempfile.mkdtemp(prefix=f"{self.name}-", dir=self.tmp_root))

    def exec(self, cmd, cwd=None, env=None, input_text=None, timeout=None) -> CmdResult:
        t = (timeout or (self.cfg.data.get("timeouts") or {}).get(self.name)
             or self.cfg.get("general", "timeout", 900))
        r = run(cmd, cwd=cwd, env=env, timeout=t, input_text=input_text)
        if r.timed_out:
            raise AdapterError(f"timed out after {t}s")
        return r

    # -- interface ----------------------------------------------------------
    def applies(self, target: Target, prior: list[Finding]) -> bool:
        return target.kind in self.kinds

    def run(self, target: Target) -> AdapterResult:  # pragma: no cover
        raise NotImplementedError

    def mk(self, target: Target, category: str, **kw) -> Finding:
        kw.setdefault("weight", self.weight)
        return Finding(tool=self.name, subject=target.value, subject_kind=target.kind,
                       category=category, trust=target.trust, **kw)
