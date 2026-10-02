"""H3XA - all-in-one OSINT framework (orchestrates 8 tools, correlates, pivots, reports)."""
import sys as _sys
from pathlib import Path as _Path

__version__ = "1.2.0"
_libs = _Path(__file__).resolve().parent.parent / "libs"      # pip --target libs (phonenumbers)
if _libs.is_dir() and str(_libs) not in _sys.path:
    _sys.path.insert(0, str(_libs))
