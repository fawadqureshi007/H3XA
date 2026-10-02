"""`h3xa setup`: unpack the 8 zips into vendor/ and give each tool its own venv,
so their conflicting dependency pins never collide.

Speed: the tools install IN PARALLEL (each has its own venv, so they cannot clash), pip
is run with its slow extras turned off (no version check, prefer wheels, no prompts), and
its output is streamed so the UI can show real progress instead of a silent wait.
"""
from __future__ import annotations
import math, os, shutil, subprocess, sys, tempfile, threading, venv, zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import reqcheck
from .config import TOOLS, Config

MAX_WORKERS = 4

_PIP_ENV = {
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    "PIP_NO_INPUT": "1",
    "PIP_PROGRESS_BAR": "off",
    "PYTHONUTF8": "1",
}
_PIP_FAST = ["--disable-pip-version-check", "--prefer-binary", "--progress-bar", "off"]


class _Null:
    """Stand-in when no progress UI is attached (CLI pipes, tests)."""
    def set(self, *a, **k): ...
    def done(self, *a, **k): ...


def extract(zips_dir: Path, cfg: Config, log=print) -> list[str]:
    done = []
    for z in sorted(zips_dir.glob("*.zip")):
        for canon, (prefix, _) in TOOLS.items():
            if z.name.lower().startswith(prefix.lower()):
                dest = cfg.src(canon)
                if dest.exists():
                    log(f"  = {canon}: already in {dest}")
                    break
                with tempfile.TemporaryDirectory() as t:
                    zipfile.ZipFile(z).extractall(t)
                    top = [p for p in Path(t).iterdir()]
                    root = top[0] if len(top) == 1 and top[0].is_dir() else Path(t)
                    cfg.vendor_dir.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(root, dest)
                log(f"  + {canon}: {z.name} -> {dest}")
                done.append(canon)
                break
    return done


# ----------------------------------------------------------------------------- pip, streamed
def _pip(args: list[str], on_line=None, timeout: int = 1800) -> tuple[int, str]:
    """Run pip, feeding each output line to on_line as it arrives. Returns (rc, tail)."""
    env = dict(os.environ)
    env.update(_PIP_ENV)
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                encoding="utf-8", errors="replace", bufsize=1, env=env)
    except Exception as e:
        return 1, f"{type(e).__name__}: {e}"
    timer = threading.Timer(timeout, proc.kill)
    timer.start()
    tail: list[str] = []
    try:
        for ln in proc.stdout:                       # type: ignore[union-attr]
            ln = ln.rstrip()
            tail.append(ln)
            del tail[:-40]
            if on_line:
                on_line(ln)
        proc.wait()
    finally:
        timer.cancel()
    return proc.returncode, "\n".join(tail)


def _stream_pct(base: float, span: float, total: int | None, progress, canon: str):
    """Turn pip's own lines ("Collecting x", "Installing collected packages") into a
    progress value. With a known package count the bar is exact-ish; without one it
    approaches `base+span` smoothly instead of lying about a total."""
    seen = {"n": 0}

    def on_line(ln: str):
        if ln.startswith("Collecting "):
            seen["n"] += 1
            name = ln.split()[1].split(";")[0]
            frac = (min(1.0, seen["n"] / total) if total else 1 - math.exp(-seen["n"] / 5)) * 0.8
            progress.set(canon, "downloading", base + span * frac, name)
        elif ln.startswith("Installing collected packages"):
            progress.set(canon, "installing", base + span * 0.88, "building / copying packages")
        elif ln.startswith("Successfully installed"):
            progress.set(canon, pct=base + span * 0.97)
    return on_line


# ----------------------------------------------------------------------------- public API
def install(cfg: Config, only: list[str] | None = None, log=print, progress=None,
            workers: int = MAX_WORKERS) -> dict:
    """Install every tool's private venv, in parallel. `progress` (an InstallProgress or
    anything with set()/done()) gets live updates; otherwise per-step text goes to `log`."""
    names = [c for c in TOOLS if not only or c in only]
    results: dict[str, str] = {}
    prog = progress or _Null()

    def job(canon: str) -> tuple[str, str]:
        lg = (lambda s: prog.set(canon, detail=s.strip())) if progress else log
        try:
            res = _install_one(cfg, canon, TOOLS[canon][1], lg, prog)
        except Exception as e:                                   # one tool must never kill the batch
            res = f"FAILED: {type(e).__name__}: {e}"
        prog.done(canon, res.startswith("ok"), res)
        return canon, res

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(names) or 1))) as pool:
        for canon, res in pool.map(job, names):
            results[canon] = res
    return {k: results[k] for k in names}


def install_with_progress(cfg: Config, only: list[str] | None = None, label=lambda k: k) -> dict:
    """install() with the animated multi-row display (plain lines when not on a terminal)."""
    from .progress import InstallProgress
    names = [c for c in TOOLS if not only or c in only]
    with InstallProgress(names, label=label) as prog:
        return install(cfg, only, progress=prog)


# ----------------------------------------------------------------------------- one tool
def _install_one(cfg: Config, canon: str, method: str, log, prog) -> str:
    src = cfg.src(canon)
    if not src.is_dir():
        return "missing source"
    if method == "none":
        return "ok (no python deps; needs bash+curl)"
    env = cfg.venv_dir / canon
    try:
        if not (env / "bin/python").exists() and not (env / "Scripts/python.exe").exists():
            prog.set(canon, "creating environment", 4, "venv")
            venv.EnvBuilder(with_pip=True).create(env)
        py = cfg.venv_python(canon)
        if not py:
            return ("FAILED: venv was created but no python interpreter was found inside it - "
                    "your Python install may be missing 'ensurepip' (common with the Microsoft "
                    f"Store build on Windows). Try: {sys.executable} -m venv {env} --without-pip, "
                    "or install Python from python.org instead.")
    except Exception as e:
        return f"FAILED: could not create venv ({type(e).__name__}: {e})"
    prog.set(canon, "environment ready", 10)
    if method == "req":
        return _install_requirements(canon, py, src, log, prog)
    return _install_pkg(canon, py, src, log, prog)


def _install_pkg(canon: str, py: Path, src: Path, log, prog=None) -> str:
    """'pkg' tools (holehe, h8mail, GHunt, user-scanner) are installed as a single
    pip package - their own setup.py/pyproject resolves their deps as one unit, so
    pip's exit code is a reliable signal here (unlike a loose requirements.txt)."""
    prog = prog or _Null()
    args = [str(py), "-m", "pip", "install", *_PIP_FAST, str(src)]
    if canon == "holehe":
        args += ["trio", "httpx"]        # used by our bridge
    prog.set(canon, "downloading", 12)
    rc, tail = _pip(args, _stream_pct(12, 86, None, prog, canon))
    return "ok" if rc == 0 else "FAILED: " + tail[-300:]


def _install_requirements(canon: str, py: Path, src: Path, log, prog=None) -> str:
    """'req' tools (SpiderFoot, Osintgram, tookie) list ~10-30 independently pinned
    packages in requirements.txt. On some machines ONE of them fails to build (usually
    an old, unmaintained pin against a newer Python) and the whole bulk command can
    report success while most of the list never actually installed - exactly what
    happened with SpiderFoot's CherryPy/cryptography/lxml/... on Windows/Python 3.13.
    So: try the bulk install for speed, but don't trust its exit code either way -
    verify every single requirement actually imports afterward, and for whatever's
    missing, install that one line individually so one broken package can't take the
    other 25 down with it."""
    prog = prog or _Null()
    req_file = src / "requirements.txt"
    all_reqs = [r for r in reqcheck.parse_requirements(req_file) if not reqcheck.is_unused(r[1])]
    prog.set(canon, "downloading", 12, f"{len(all_reqs)} packages")
    bulk = reqcheck.filtered_requirements(req_file, Path(tempfile.gettempdir()) / f"h3xa-req-{canon}.txt")
    rc, _ = _pip([str(py), "-m", "pip", "install", *_PIP_FAST, "-r", str(bulk)],
                 _stream_pct(12, 70, len(all_reqs) or None, prog, canon), timeout=1800)

    prog.set(canon, "verifying", 84, "checking every package imports")
    missing = reqcheck.missing_packages(py, req_file)
    if not missing:
        return "ok"

    log(f"{len(missing)}/{len(all_reqs)} packages missing after bulk install - fixing one by one")
    fixed, still_broken = [], []
    for i, (raw, pkg, imp) in enumerate(missing, 1):
        prog.set(canon, "repairing", 86 + 12 * i / len(missing), pkg)
        ok = False
        for spec in dict.fromkeys([raw, reqcheck.relax(raw)]):      # pinned first, then without the "<" ceiling
            rc, _ = _pip([str(py), "-m", "pip", "install", *_PIP_FAST, spec])
            if rc == 0:
                chk = subprocess.run([str(py), "-c", f"import {imp}"], capture_output=True, text=True)
                ok = chk.returncode == 0
            if ok:
                break
        (fixed if ok else still_broken).append(pkg)

    if not still_broken:
        return f"ok (bulk install missed {len(fixed)} package(s); installed them individually)"
    return (f"PARTIAL: {len(fixed)}/{len(missing)} repaired individually. Still broken: "
            f"{', '.join(still_broken)} - the module may run with reduced coverage, or fix "
            f"manually: {py} -m pip install {' '.join(still_broken)}")
