from __future__ import annotations

import os
from pathlib import Path

import yaml

from traust_core.v1 import contracts
from traust_core.v1.errors import ConfigError, DeploymentConfigMissing

TRAUST_CONFIG_HOME_ENV = "TRAUST_CONFIG_HOME"
TRAUST_CONFIG_HOME_DEFAULT = Path.home() / ".traust" / "config"


def resolve_config_home(config_home: Path | None = None) -> Path | None:
    """`config_home`, else `$TRAUST_CONFIG_HOME`, else `~/.traust/config` when it exists."""
    if config_home is not None:
        return config_home
    if raw := os.environ.get(TRAUST_CONFIG_HOME_ENV):
        return Path(raw).expanduser()
    return TRAUST_CONFIG_HOME_DEFAULT if TRAUST_CONFIG_HOME_DEFAULT.is_dir() else None


def optional_config_path(name: str) -> Path | None:
    """`<config home>/<name>` when the file is there; a feature-gated file may be absent."""
    home = resolve_config_home()
    return home / name if home is not None and (home / name).is_file() else None


def config_path(name: str) -> Path:
    """`<config home>/<name>`, or DeploymentConfigMissing naming the file and the fix."""
    if (path := optional_config_path(name)) is not None:
        return path
    home = resolve_config_home()
    where = (
        str(home)
        if home is not None
        else f"<${TRAUST_CONFIG_HOME_ENV} unset and {TRAUST_CONFIG_HOME_DEFAULT} absent>"
    )
    stem, dot, ext = name.rpartition(".")
    example = f"{stem}.example.{ext}" if dot else f"{name}.example"
    raise DeploymentConfigMissing(
        f"required config file {name!r} not found in {where}. Copy "
        f"config/{example} there as {name!r} and fill it in, or run "
        f"scripts/install_traust."
    )


def config_completeness_audit(*, config_home: Path | None = None) -> tuple[list[str], list[str]]:
    """`(errors, warnings)` for a deployment config home: errors block a production-ready
    deployment, warnings name optional files and fields still to configure."""
    home = resolve_config_home(config_home)
    if home is None:
        return [
            f"no config home: set ${TRAUST_CONFIG_HOME_ENV} or run scripts/install_traust "
            f"(default {TRAUST_CONFIG_HOME_DEFAULT})."
        ], []
    try:
        return contracts.config_completeness_audit(home)
    except (OSError, ValueError, yaml.YAMLError) as e:
        raise ConfigError(f"cannot audit config home {home}: {e}") from e
