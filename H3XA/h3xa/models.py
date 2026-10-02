from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any

# --- target -----------------------------------------------------------------
@dataclass
class Pivot:
    """A lead discovered in a finding that may become a new scan target."""
    kind: str            # email | username | domain | phone | name
    value: str
    trust: str = "scraped"   # verified (tool read it from a structured field) | scraped | derived


@dataclass
class Target:
    kind: str            # email | username | domain | ip | phone | name
    value: str
    depth: int = 0
    parent: str = ""     # "kind:value" of the target that led here
    reason: str = "seed"
    trust: float = 1.0   # confidence multiplier inherited along the pivot chain
    hints: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.value.lower()}"


# --- findings ---------------------------------------------------------------
CATEGORIES = ("account", "breach", "identity", "profile", "infra", "note")


@dataclass
class Finding:
    tool: str
    subject: str                 # target value the finding belongs to
    subject_kind: str
    category: str                # one of CATEGORIES
    kind: str = ""               # subtype: name, location, photo, ip, vuln ...
    title: str = ""
    value: str = ""
    url: str = ""
    platform: str = ""           # normalised platform key (accounts)
    via: str = ""                # email | username  (how the account was matched)
    data: dict = field(default_factory=dict)
    weight: float = 0.5          # reliability of this individual finding (0..1)
    trust: float = 1.0           # inherited from target chain
    pivots: list = field(default_factory=list)   # list[Pivot]

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# --- run bookkeeping --------------------------------------------------------
@dataclass
class ToolRun:
    tool: str
    target: str
    status: str                  # ok | error | timeout | unavailable | needs_auth | skipped
    seconds: float = 0.0
    findings: int = 0
    checked: int | None = None   # number of sites/modules the tool tested
    message: str = ""
    attempts: int = 1            # how many times the module was tried (transient failures are retried)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AdapterResult:
    findings: list[Finding] = field(default_factory=list)
    checked: int | None = None
    message: str = ""


class AdapterError(Exception):
    status = "error"

class NeedsAuth(AdapterError):
    status = "needs_auth"

class Unavailable(AdapterError):
    status = "unavailable"

class Skipped(AdapterError):
    status = "skipped"

class MissingRequirement(Unavailable):
    """A module's environment exists but one or more packages it needs at runtime
    aren't installed (usually because a bulk requirements.txt install partially failed
    on this machine). Carries enough info for the interface to offer a one-key repair
    instead of surfacing a raw traceback."""
    def __init__(self, pip_name: str, import_name: str | None = None, note: str = "",
                 all_missing: list[str] | None = None):
        self.pip_name = pip_name
        self.import_name = import_name or pip_name
        self.note = note
        self.all_missing = all_missing or [pip_name]
        count = len(self.all_missing)
        if count > 1:
            shown = ", ".join(self.all_missing[:6]) + ("..." if count > 6 else "")
            msg = f"needs {count} extra packages that aren't installed ({shown})"
        else:
            msg = f"needs an extra package ('{pip_name}') that isn't installed"
        if note:
            msg += f" - {note}"
        super().__init__(msg)
