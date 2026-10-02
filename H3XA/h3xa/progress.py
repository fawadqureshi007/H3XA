"""Live, animated progress for module installs (and a one-line spinner for short jobs).

Pure ANSI, no extra dependency. On a terminal that is not a TTY (pipes, CI) it falls back
to plain one-line-per-event output, so logs stay readable.
"""
from __future__ import annotations

import shutil
import sys
import threading
import time

SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_CY, _GR, _RD, _YE, _GY, _WH, _VI = 51, 46, 203, 220, 244, 255, 99
_GRAD = [39, 45, 51, 87, 123]          # filled-bar gradient (cyan family)


def _c(code: int, t: str) -> str:
    return f"\033[38;5;{code}m{t}\033[0m"


def _fmt_t(sec: float) -> str:
    sec = int(sec)
    return f"{sec // 60}:{sec % 60:02d}"


def _cut(s: str, n: int) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: max(1, n - 1)] + "…"


class _Row:
    __slots__ = ("name", "state", "stage", "target", "shown", "detail", "t0", "t1", "note")

    def __init__(self, name: str):
        self.name = name
        self.state = "wait"            # wait | run | ok | fail
        self.stage = "queued"
        self.target = 0.0              # where the installer says we are (0-100)
        self.shown = 0.0               # eased value actually drawn
        self.detail = ""
        self.t0 = 0.0
        self.t1 = 0.0
        self.note = ""


class InstallProgress:
    """One animated row per module + an overall bar. Thread-safe: installer threads call
    set()/done(); a single render thread owns the terminal."""

    def __init__(self, names, label=lambda k: k, indent: str = "   ", out=None):
        self.out = out or sys.stdout
        self.rows = {n: _Row(n) for n in names}
        self.order = list(names)
        self.label = label
        self.indent = indent
        self.tty = bool(getattr(self.out, "isatty", lambda: False)())
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lines = 0
        self._frame = 0
        self._t0 = time.time()
        self._lw = max((len(label(n)) for n in names), default=8)

    # ---- called by installers
    def set(self, name: str, stage: str | None = None, pct: float | None = None, detail: str | None = None):
        with self._lock:
            r = self.rows[name]
            if r.state == "wait":
                r.state, r.t0 = "run", time.time()
            if stage is not None:
                r.stage = stage
            if pct is not None:
                r.target = max(r.target, min(99.0, float(pct)))   # never move backwards
            if detail is not None:
                r.detail = detail
            if not self.tty and (stage is not None):
                print(f"{self.indent}{self.label(name)}: {r.stage}", file=self.out, flush=True)

    def done(self, name: str, ok: bool, note: str = ""):
        with self._lock:
            r = self.rows[name]
            if r.state == "wait":
                r.t0 = time.time()
            r.state = "ok" if ok else "fail"
            r.stage = "ready" if ok else "failed"
            r.target = 100.0 if ok else r.target
            r.note, r.t1 = note, time.time()
            if not self.tty:
                print(f"{self.indent}{'+' if ok else 'x'} {self.label(name)}: {_cut(note, 100)}", file=self.out, flush=True)

    # ---- lifecycle
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def start(self):
        if not self.tty:
            return
        self.out.write("\033[?25l")                      # hide cursor
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        if not self.tty:
            return
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        with self._lock:
            self._draw(final=True)
        self.out.write("\033[?25h\n")                    # show cursor
        self.out.flush()

    def _loop(self):
        while not self._stop.is_set():
            with self._lock:
                self._draw()
            time.sleep(0.08)

    # ---- drawing
    def _bar(self, pct: float, width: int, color: int) -> str:
        filled = int(round(width * pct / 100.0))
        if color == _GR:
            body = _c(_GR, "█" * filled)
        elif color == _RD:
            body = _c(_RD, "█" * filled)
        else:
            body = "".join(_c(_GRAD[min(len(_GRAD) - 1, i * len(_GRAD) // max(1, width))], "█") for i in range(filled))
        return body + _c(238, "░" * (width - filled))

    def _row_line(self, r: _Row, cols: int) -> str:
        # ease the drawn value toward the target so the bar glides instead of jumping
        r.shown += (r.target - r.shown) * 0.22
        if abs(r.target - r.shown) < 0.2:
            r.shown = r.target
        spin = SPIN[self._frame % len(SPIN)]
        if r.state == "wait":
            icon, col = _c(238, "○"), 238
        elif r.state == "run":
            icon, col = _c(_CY, spin), _CY
        elif r.state == "ok":
            icon, col = _c(_GR, "✔"), _GR
        else:
            icon, col = _c(_RD, "✖"), _RD
        elapsed = (r.t1 or time.time()) - r.t0 if r.t0 else 0
        bar_w = 22
        tail_w = max(10, cols - (self._lw + bar_w + 30))
        if r.state == "ok":
            tail = _c(_GR, "ready") + (_c(_GY, " " + _cut(r.note, tail_w - 6)) if r.note and not r.note.startswith("ok") else "")
        elif r.state == "fail":
            tail = _c(_RD, _cut(r.note, tail_w))
        else:
            tail = _c(_GY, _cut(r.stage + (" · " + r.detail if r.detail else ""), tail_w))
        shown = 100.0 if r.state == "ok" else r.shown
        return (f"{self.indent}{icon} {_c(_WH, self.label(r.name).ljust(self._lw))} "
                f"{self._bar(shown, bar_w, _GR if r.state == 'ok' else _RD if r.state == 'fail' else _CY)} "
                f"{_c(col, f'{int(shown):>3}%')} {_c(_GY, _fmt_t(elapsed))}  {tail}")

    def _draw(self, final: bool = False):
        cols = max(60, shutil.get_terminal_size((100, 30)).columns - 2)
        self._frame += 1
        lines = [self._row_line(self.rows[n], cols) for n in self.order]
        total = len(self.order)
        finished = sum(1 for r in self.rows.values() if r.state in ("ok", "fail"))
        pct = sum(100.0 if r.state in ("ok", "fail") else r.shown for r in self.rows.values()) / max(1, total)
        lines.append(f"{self.indent}{_c(_VI, '─' * 4)} {_c(_WH, 'overall')} "
                     f"{self._bar(pct, 22, _CY)} {_c(_CY, f'{int(pct):>3}%')} "
                     f"{_c(_GY, f'{finished}/{total} done · {_fmt_t(time.time() - self._t0)}')}")
        if self._lines:
            self.out.write(f"\033[{self._lines}F")      # cursor to start of the block
        for ln in lines:
            self.out.write("\033[2K" + ln + "\n")
        self._lines = len(lines)
        self.out.flush()


class Spinner:
    """`with Spinner('installing x'):` - one animated line for a short job."""

    def __init__(self, text: str, indent: str = "   ", out=None):
        self.text, self.indent = text, indent
        self.out = out or sys.stdout
        self.tty = bool(getattr(self.out, "isatty", lambda: False)())
        self._stop = threading.Event()
        self._t: threading.Thread | None = None
        self._t0 = time.time()

    def _loop(self):
        i = 0
        while not self._stop.is_set():
            self.out.write(f"\r\033[2K{self.indent}{_c(_CY, SPIN[i % len(SPIN)])} {self.text} "
                           f"{_c(_GY, _fmt_t(time.time() - self._t0))}")
            self.out.flush()
            i += 1
            time.sleep(0.08)

    def __enter__(self):
        if self.tty:
            self.out.write("\033[?25l")
            self._t = threading.Thread(target=self._loop, daemon=True)
            self._t.start()
        else:
            print(f"{self.indent}{self.text} ...", file=self.out, flush=True)
        return self

    def __exit__(self, *exc):
        if self.tty:
            self._stop.set()
            if self._t:
                self._t.join(timeout=1)
            self.out.write("\r\033[2K\033[?25h")
            self.out.flush()
