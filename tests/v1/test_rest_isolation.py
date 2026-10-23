"""Consumers install traust-core without the [rest] extra: nothing outside rest/ may need it."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
BLOCK = """
import importlib.abc, importlib.util, pkgutil, sys
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in {"fastapi", "starlette", "uvicorn"}:
            raise ModuleNotFoundError(f"No module named {name!r} (blocked)", name=name)
sys.meta_path.insert(0, Block())
import traust_core
for m in pkgutil.walk_packages(traust_core.__path__, "traust_core."):
    if ".rest" not in m.name or m.name.endswith(".rest.server"):
        __import__(m.name)
from traust_core.v1.rest.server import main
try:
    main([])
except SystemExit as e:
    print(e)
"""


def test_core_imports_and_explains_itself_without_the_rest_extra() -> None:
    done = subprocess.run(
        [sys.executable, "-c", BLOCK], capture_output=True, text=True, check=False, cwd=SRC
    )
    assert done.returncode == 0, done.stderr
    assert "pip install 'traust-core[rest]'" in done.stdout
