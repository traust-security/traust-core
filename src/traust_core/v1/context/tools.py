from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pydantic
import yaml

from traust_core.v1 import contracts
from traust_core.v1.errors import ConfigError, DocumentError
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.tools.adapter import AdapterTool
from traust_core.v1.providers.tools.safe_exec import RECURSION_ENV, SafeExec, profiles_of
from traust_core.v1.providers.tools.toolchain import (
    POPULATE_SECONDS,
    PROBE_ENV,
    Toolchain,
    ToolPin,
)

if TYPE_CHECKING:
    from traust_core.v1.context.context import Context


def scanner_tools(ctx: Context) -> tuple[AdapterTool[Any], ...]:
    """Core's scanner adapters, registered by name by `Context.register_toolchain`."""
    return ()


def load_toolchain(path: Path) -> Toolchain:
    """`external-tools.yaml`'s pins, probed through a runner allowing only the pinned binaries."""
    try:
        pins = {
            pin.name: pin
            for pin in (ToolPin.model_validate(t) for t in _config(path, "external-tools")["tools"])
        }
    except pydantic.ValidationError as e:
        raise ConfigError(f"{path}: {e}") from e
    allowed = {p.name for p in pins.values()} | {
        Path(p.version_cmd[0]).name for p in pins.values() if p.version_cmd
    }
    default_db = Path.home() / ".cache" / "grype" / "db"
    return Toolchain(
        pins,
        ProcessRunner(allowed, keep_env=PROBE_ENV, timeout_seconds=POPULATE_SECONDS),
        grype_db_dir=Path(os.environ.get("GRYPE_DB_CACHE_DIR", default_db)),
    )


def load_safe_exec(path: Path) -> SafeExec:
    """`safe-exec-profiles.yaml`, at the safe-exec depth this process runs in."""
    return SafeExec(
        profiles_of(_config(path, "safe-exec-profiles")),
        depth=int(os.environ.get(RECURSION_ENV, "0")),
    )


def _config(path: Path, schema: str) -> Any:
    try:
        document = yaml.safe_load(path.read_text())
        contracts.validate_config(schema, document)
    except (OSError, yaml.YAMLError, DocumentError) as e:
        raise ConfigError(f"{path}: {e}") from e
    return document
