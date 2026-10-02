"""Runs inside holehe's venv. Dumps every module result as JSON (holehe's own CSV
export breaks when rows have differing keys, so we call its modules directly)."""
import json, sys
from types import SimpleNamespace

import httpx
import trio
from holehe.core import get_functions, import_submodules, launch_module


async def main(email, out_path, timeout, allow_loud):
    modules = import_submodules("holehe.modules")
    args = SimpleNamespace(nopasswordrecovery=not allow_loud)
    websites = get_functions(modules, args)
    out = []
    async with httpx.AsyncClient(timeout=timeout) as client:
        async with trio.open_nursery() as nursery:
            for w in websites:
                nursery.start_soon(launch_module, w, email, client, out)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sorted(out, key=lambda i: i.get("name", "")), f, default=str)


if __name__ == "__main__":
    email, out_path, timeout, loud = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4] == "1"
    trio.run(main, email, out_path, timeout, loud)
