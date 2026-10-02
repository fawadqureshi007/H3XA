#!/usr/bin/env bash
# H3XA launcher for Linux / macOS:  chmod +x h3xa.sh && ./h3xa.sh
cd "$(dirname "$0")" || exit 1
export PYTHONUTF8=1
PY=$(command -v python3 || command -v python)
[ -z "$PY" ] && { echo "Python 3.10+ not found"; exit 1; }
"$PY" -c 'import sys; sys.exit(0 if sys.version_info>=(3,10) else 1)' || { echo "Python 3.10+ required"; exit 1; }
exec "$PY" -m h3xa "$@"
