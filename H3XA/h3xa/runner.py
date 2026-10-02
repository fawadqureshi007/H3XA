from __future__ import annotations
import os, signal, subprocess, time
from dataclasses import dataclass


_LIVE: set = set()


def kill_all() -> None:
    """Kill every child tool still running (used when the user aborts a scan)."""
    for p in list(_LIVE):
        try:
            os.killpg(p.pid, signal.SIGKILL) if os.name == "posix" else p.kill()
        except Exception:
            pass
    _LIVE.clear()


@dataclass
class CmdResult:
    rc: int
    out: str
    err: str
    seconds: float
    timed_out: bool = False


def _txt(b) -> str:
    if b is None:
        return ""
    return b.decode("utf-8", "replace") if isinstance(b, bytes) else b


def run(cmd: list[str], cwd=None, env=None, timeout: int = 600, input_text: str | None = None) -> CmdResult:
    """Run a command, kill its whole process group on timeout (SpiderFoot forks)."""
    t0 = time.time()
    full_env = dict(os.environ)
    full_env.update(env or {})
    full_env.setdefault("PYTHONIOENCODING", "utf-8")
    full_env.setdefault("PYTHONUNBUFFERED", "1")
    popen_kw = {}
    if os.name == "posix":
        popen_kw["start_new_session"] = True
    try:
        p = subprocess.Popen([str(c) for c in cmd], cwd=cwd, env=full_env,
                             stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, **popen_kw)
    except FileNotFoundError as e:
        return CmdResult(127, "", str(e), time.time() - t0)
    _LIVE.add(p)
    try:
        out, err = p.communicate(input=input_text.encode() if input_text is not None else None, timeout=timeout)
        _LIVE.discard(p)
        return CmdResult(p.returncode, _txt(out), _txt(err), time.time() - t0)
    except subprocess.TimeoutExpired:
        try:
            if os.name == "posix":
                os.killpg(p.pid, signal.SIGKILL)
            else:
                p.kill()
        except ProcessLookupError:
            pass
        out, err = p.communicate()
        _LIVE.discard(p)
        return CmdResult(-9, _txt(out), _txt(err), time.time() - t0, True)
