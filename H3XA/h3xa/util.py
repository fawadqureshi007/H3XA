from __future__ import annotations
import re, json, ipaddress
from typing import Any, Iterator

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)
PHONE_RE = re.compile(r"^\+?[0-9][0-9 ()\-]{6,18}[0-9]$")
URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.I)

_SLD = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.in", "com.pk", "co.jp", "com.br",
        "co.za", "com.tr", "co.nz", "com.mx", "com.cn", "com.sg", "com.hk", "co.kr", "com.ar"}
_ALIAS = {"x": "twitter", "xcom": "twitter", "lastfm": "last", "googleplay": "google",
          "gmail": "google", "youtu": "youtube", "fb": "facebook", "ig": "instagram",
          "stackoverflow": "stackoverflow", "hotmail": "microsoft", "live": "microsoft",
          "outlook": "microsoft", "office365": "microsoft", "office": "microsoft",
          "mailru": "mail", "vk": "vkontakte"}


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s or "")


def detect_kind(value: str) -> str:
    v = value.strip()
    if EMAIL_RE.fullmatch(v):
        return "email"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if "/" in v:
        try:
            ipaddress.ip_network(v, strict=False)
            return "ip"
        except ValueError:
            pass
    if PHONE_RE.fullmatch(v) and sum(c.isdigit() for c in v) >= 7:
        return "phone"
    if DOMAIN_RE.fullmatch(v):
        return "domain"
    if " " in v:
        return "name"
    return "username"


def platform_key(s: str) -> str:
    """Normalise a URL / hostname / site name to a comparable platform key.

    "https://www.instagram.com/x" -> "instagram", "Instagram" -> "instagram",
    "instagram.com" -> "instagram". Heuristic by design: it is what lets results
    from different tools be recognised as the *same* site.
    """
    s = (s or "").strip().lower()
    if not s:
        return ""
    m = re.match(r"^(?:[a-z][a-z0-9+.\-]*://)?([^/\s?#:@]+)", s)
    host = m.group(1) if m else s
    if re.fullmatch(r"[a-z0-9.\-]+", host) and re.search(r"\.[a-z]{2,}$", host):
        labels = host.split(".")
        if len(labels) >= 3 and ".".join(labels[-2:]) in _SLD:
            base = labels[-3]
        else:
            base = labels[-2]
    else:
        base = re.sub(r"[^a-z0-9]", "", s)
    return _ALIAS.get(base, base)


def walk(obj: Any, path: str = "") -> Iterator[tuple[str, Any]]:
    """Yield (key-path, scalar) pairs for every scalar in a nested structure."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from walk(v, f"{path}[{i}]")
    else:
        yield path, obj


def find_emails(obj: Any) -> list[tuple[str, str]]:
    """(key-path, email) for every e-mail inside obj."""
    out = []
    for p, v in walk(obj):
        if isinstance(v, str):
            for e in EMAIL_RE.findall(v):
                out.append((p, e.lower()))
    return out


def load_json_lenient(text: str) -> Any:
    """json.loads that tolerates log noise before/after the JSON document."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for op, cl in (("[", "]"), ("{", "}")):
        a, b = text.find(op), text.rfind(cl)
        if a != -1 and b > a:
            try:
                return json.loads(text[a:b + 1])
            except json.JSONDecodeError:
                continue
    return None


def dig(obj: Any, *path, default=None):
    """Safe nested lookup over dicts/lists; also reads attributes-as-dicts."""
    cur = obj
    for p in path:
        if isinstance(cur, dict):
            cur = cur.get(p)
        elif isinstance(cur, (list, tuple)) and isinstance(p, int) and -len(cur) <= p < len(cur):
            cur = cur[p]
        else:
            return default
        if cur is None:
            return default
    return cur


def clean_dict(d: dict) -> dict:
    """Drop empty values so reports stay readable."""
    return {k: v for k, v in (d or {}).items() if v not in (None, "", [], {})}


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._@-]", "_", s)[:80]


def phonenumbers_ok() -> bool:
    """True only if the real `phonenumbers` library is importable. An empty folder named
    `phonenumbers` (e.g. a leftover in libs/) imports fine as a namespace package but has no
    functions, which used to make the phone module look ready while it was actually broken."""
    import importlib
    try:
        m = importlib.import_module("phonenumbers")
    except ImportError:
        return False
    return callable(getattr(m, "parse", None)) and getattr(m, "__file__", None) is not None
