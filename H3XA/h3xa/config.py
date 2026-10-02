from __future__ import annotations
import copy, os, sys
from pathlib import Path

try:
    import tomllib  # py3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None

ROOT = Path(__file__).resolve().parent.parent

# canonical vendor folder -> (zip-name prefix, install method)
TOOLS = {
    "user-scanner": ("user-scanner", "pkg"),
    "holehe":       ("holehe", "pkg"),
    "h8mail":       ("h8mail", "pkg"),
    "ghunt":        ("GHunt", "pkg"),
    "tookie":       ("tookie-osint", "req"),
    "spiderfoot":   ("spiderfoot", "req"),
    "osintgram":    ("Osintgram", "req"),
    "userrecon":    ("userrecon", "none"),
}

DEFAULTS = {
    "general": {
        "vendor_dir": "vendor", "venv_dir": ".venvs", "output_dir": "reports",
        "profile": "standard", "timeout": 900, "max_parallel": 4,
        "retries": 1,              # re-run a module once if it failed for a transient reason
    },
    "timeouts": {},                # per-module override in seconds, e.g. spiderfoot = 1800
    "report": {"formats": ["html", "json", "md", "csv"], "operator": "", "purpose": ""},
    "pivot": {
        "depth": 1, "max_targets": 8,
        "emails": "verified",      # verified | all | none
        "usernames": "verified",
        "derive_username": False,  # try e-mail local-part as a username (weak)
    },
    "profiles": {
        "quick":    ["user-scanner", "holehe", "phoneinfo"],
        "standard": ["user-scanner", "holehe", "tookie", "h8mail", "ghunt", "osintgram", "phoneinfo", "spiderfoot"],
        "deep":     ["user-scanner", "holehe", "tookie", "h8mail", "ghunt", "osintgram",
                     "phoneinfo", "spiderfoot", "userrecon"],
    },
    "python": {},                  # tool -> explicit interpreter path
    "user-scanner": {"allow_loud": False, "nsfw": True, "hudson": False, "concurrency": 40},
    "holehe": {"allow_loud": False, "timeout": 12},
    "h8mail": {"config": ""},      # path to an h8mail config holding your API keys
    "ghunt": {"always": False},    # run even if no Google account was indicated
    "tookie": {"threads": 20},
    "spiderfoot": {"mode": "passive", "kinds": ["domain", "ip", "phone", "name"], "max_threads": 3},
    "osintgram": {"backend": "", "limit_posts": 30, "followers": False, "followings": False},
    "userrecon": {},
    "phoneinfo": {},
}


def _merge(a: dict, b: dict) -> dict:
    out = copy.deepcopy(a)
    for k, v in (b or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


class Config:
    def __init__(self, data: dict | None = None, path: Path | None = None):
        self.data = _merge(DEFAULTS, data or {})
        self.path = path

    @classmethod
    def load(cls, path: str | None = None) -> "Config":
        cands = [Path(path)] if path else [Path.cwd() / "h3xa.toml", ROOT / "h3xa.toml"]
        for c in cands:
            if c.is_file():
                if tomllib is None:
                    raise RuntimeError("Python 3.11+ is required to read h3xa.toml")
                with open(c, "rb") as f:
                    return cls(tomllib.load(f), c)
        if path:
            raise FileNotFoundError(path)
        return cls()

    def __getitem__(self, k):
        return self.data[k]

    def get(self, section: str, key: str, default=None):
        return self.data.get(section, {}).get(key, default)

    # ---- paths -------------------------------------------------------------
    def _p(self, p: str) -> Path:
        pp = Path(p).expanduser()
        return pp if pp.is_absolute() else ROOT / pp

    @property
    def vendor_dir(self) -> Path:
        return self._p(self.data["general"]["vendor_dir"])

    @property
    def venv_dir(self) -> Path:
        return self._p(self.data["general"]["venv_dir"])

    @property
    def output_dir(self) -> Path:
        return self._p(self.data["general"]["output_dir"])

    def src(self, tool: str) -> Path:
        return self.vendor_dir / tool

    def venv_python(self, tool: str) -> Path | None:
        explicit = self.data["python"].get(tool)
        if explicit:
            return Path(explicit)
        for rel in ("bin/python", "Scripts/python.exe"):
            p = self.venv_dir / tool / rel
            if p.exists():
                return p
        return None

    def venv_bin(self, tool: str, exe: str) -> Path | None:
        for rel in (f"bin/{exe}", f"Scripts/{exe}.exe"):
            p = self.venv_dir / tool / rel
            if p.exists():
                return p
        return None

    def tools_for_profile(self, profile: str | None = None) -> list[str]:
        return list(self.data["profiles"][profile or self.data["general"]["profile"]])
