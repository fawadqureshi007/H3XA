"""Generic requirements.txt <-> importable-module verification.

Why this exists: a `pip install -r requirements.txt` with ~20-30 independently pinned
packages (SpiderFoot, Osintgram, tookie) is exactly the kind of command where ONE
package failing to build (an old, unmaintained pin against a newer Python, usually)
can silently take the whole batch down on some machines while looking fine on others -
pip's exit code doesn't always tell you which packages actually landed. Instead of
hand-picking 2-3 "critical" packages to check per module (which just moves the
whack-a-mole to a different package each time), this checks and repairs EVERY line
in that module's own requirements.txt, one at a time if needed.
"""
from __future__ import annotations
import re
from pathlib import Path

from .runner import run

# pip package name -> the name you actually `import`. Only needed where they differ;
# anything not listed here falls back to the normalized package name itself.
_RAW_OVERRIDES = {
    "pyyaml": "yaml",
    "beautifulsoup4": "bs4",
    "pyopenssl": "OpenSSL",
    "python-docx": "docx",
    "python-pptx": "pptx",
    "python-whois": "whois",
    "dnspython": "dns",
    "pysocks": "socks",
    "pygexf": "gexf",
    "pillow": "PIL",
    "pycryptodome": "Crypto",
    "cherrypy-cors": "cherrypy_cors",
    "python-dateutil": "dateutil",
    "pyjwt": "jwt",
    "protobuf": "google.protobuf",
    "opencv-python": "cv2",
    "pywin32": "win32api",
    "msgpack-python": "msgpack",
    "ipaddr": "ipaddr",
    "pypdf2": "PyPDF2",      # import name is CASE-SENSITIVE: `import pypdf2` fails even when installed
    "exifread": "exifread",
    "mako": "mako",
    "secure": "secure",
}

# Listed in a tool's requirements.txt but never imported by the tool itself, and known to
# fail to build on current Python versions. Treating them as "required" made a perfectly
# working module show as broken forever (SpiderFoot lists pygexf, but its GEXF export uses
# networkx's own writer). They are skipped when verifying AND when bulk-installing, so one
# dead optional pin can no longer abort the whole `pip install -r`.
UNUSED = {"pygexf"}

# Old upper-bound pins that have NO wheels for current Python (3.12/3.13) and then try to
# compile from source - which fails on a normal Windows box (no C compiler / libxml2 /
# Rust). SpiderFoot pins lxml<5, cryptography<4, pyOpenSSL<22; all three work fine with
# SpiderFoot's code in their current releases, so for these we drop the "<" ceiling and keep
# the lower bound. They are relaxed together because pyOpenSSL and cryptography constrain
# each other (a new pyOpenSSL needs a new cryptography).
RELAX = {"lxml", "pyopenssl", "cryptography"}

_UPPER = re.compile(r"\s*,?\s*(<=?|~=)\s*[^,;\s]+")


def relax(raw: str) -> str:
    """'pyOpenSSL>=21.0.0,<22' -> 'pyOpenSSL>=21.0.0' (drops only the upper bound)."""
    head, sep, tail = raw.partition(";")
    out = _UPPER.sub("", head).strip().rstrip(",")
    return out + (sep + tail if sep else "")


def _normalize(pkg: str) -> str:
    return re.sub(r"[-_.]+", "_", pkg.strip().lower())


_IMPORT_NAME_OVERRIDES = {_normalize(k): v for k, v in _RAW_OVERRIDES.items()}


def import_name_for(pkg: str) -> str:
    norm = _normalize(pkg)
    return _IMPORT_NAME_OVERRIDES.get(norm, norm)


_SPEC_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)")


def parse_requirements(path: Path) -> list[tuple[str, str]]:
    """[(raw_requirement_line, bare_package_name), ...]. Skips comments, blank lines,
    and -r/-e/--index-url style directives (those aren't a single importable package)."""
    out: list[tuple[str, str]] = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _SPEC_RE.match(line)
        if not m:
            continue
        pkg = m.group(1).split("[")[0]  # drop extras, e.g. uvicorn[standard]
        out.append((line, pkg))
    return out


def is_unused(pkg: str) -> bool:
    return _normalize(pkg) in UNUSED


def filtered_requirements(requirements_path: Path, dest: Path) -> Path:
    """Copy of requirements.txt without the UNUSED packages, for the bulk `pip install -r`."""
    keep = []
    for line in requirements_path.read_text(encoding="utf-8", errors="replace").splitlines():
        bare = line.split("#", 1)[0].strip()
        m = _SPEC_RE.match(bare) if bare and not bare.startswith("-") else None
        pkg = m.group(1).split("[")[0] if m else ""
        if m and is_unused(pkg):
            continue
        if m and _normalize(pkg) in {_normalize(r) for r in RELAX}:
            keep.append(relax(bare))
            continue
        keep.append(line)
    dest.write_text("\n".join(keep) + "\n", encoding="utf-8")
    return dest


def missing_packages(py, requirements_path: Path, timeout: int = 20) -> list[tuple[str, str, str]]:
    """[(raw_spec, pkg_name, import_name), ...] for every requirement that doesn't
    currently import in this venv. One subprocess per package (~0.2-0.5s each) -
    callers should cache the result for the life of a run; see adapters/base.py."""
    missing = []
    for raw, pkg in parse_requirements(requirements_path):
        if is_unused(pkg):
            continue
        imp = import_name_for(pkg)
        r = run([str(py), "-c", f"import {imp}"], timeout=timeout)
        if r.rc != 0:
            missing.append((raw, pkg, imp))
    return missing
