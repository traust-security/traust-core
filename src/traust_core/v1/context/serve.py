"""The config path handed to spawned server workers.

A multi-worker uvicorn takes an import string, not the app object the
parent built, so each spawned worker rebuilds the app itself — and the
config file it must build from can only cross the process boundary
through the environment. This is the one sanctioned env handoff for
serving, beside `TRAUST_CONFIG_HOME` in home.py.
"""

from __future__ import annotations

import os
from pathlib import Path

_SERVER_CONFIG_ENV = "TRAAST_SERVER_CONFIG"


def hand_config(path: Path) -> None:
    """The parent hands its config file to the workers it is about to spawn."""
    os.environ[_SERVER_CONFIG_ENV] = str(path)


def handed_config() -> Path | None:
    """The config file a spawned worker was handed, if any."""
    raw = os.environ.get(_SERVER_CONFIG_ENV)
    return Path(raw) if raw else None
