from __future__ import annotations

import os
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pydantic
import yaml

from traust_core.v1 import contracts
from traust_core.v1.context.config import Locations
from traust_core.v1.errors import ConfigError, DocumentError, ValidationError
from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.tools.adapter import AdapterTool, resolves
from traust_core.v1.providers.tools.cloud_config import (
    BICEP_VERSION,
    CHECKOV_TIMEOUT,
    PROBE_TIMEOUT,
    CheckovProvider,
)
from traust_core.v1.providers.tools.gitleaks import GITLEAKS_TIMEOUT, Gitleaks
from traust_core.v1.providers.tools.safe_exec import RECURSION_ENV, SafeExec, profiles_of
from traust_core.v1.providers.tools.toolchain import (
    POPULATE_SECONDS,
    PROBE_ENV,
    Toolchain,
    ToolPin,
)
from traust_core.v1.providers.tools.yara import YARA_TIMEOUT, Yara
from traust_core.v1.services.provider_catalog import core_version

if TYPE_CHECKING:
    from traust_core.v1.context.context import Context


def scanner_tools(ctx: Context) -> tuple[AdapterTool[Any], ...]:
    """Core's scanner adapters, registered by name by `Context.register_toolchain`."""
    keep = ctx.config.process.keep_env
    gitleaks = Gitleaks(
        ProcessRunner(["gitleaks", "git"], keep_env=keep, timeout_seconds=GITLEAKS_TIMEOUT),
        ctx.clock,
    )
    yara = Yara(
        ProcessRunner(["yara", "git"], keep_env=keep, timeout_seconds=YARA_TIMEOUT),
        ctx.clock,
        cache_root=Path.home() / ".cache" / "traust-engine",
        harness_version=core_version(),
    )

    def rules() -> Path:
        return gitleaks_config(ctx.config.locations)

    def tool(
        name: str,
        binaries: tuple[str, ...],
        scan: Callable[[Path], AdapterResultArtifact],
        **kw: Any,
    ) -> AdapterTool[Any]:
        return AdapterTool(name, binaries, scan, ctx.clock, lambda: ctx.toolchain, **kw)

    return (
        tool(
            "gitleaks",
            ("gitleaks",),
            lambda w: gitleaks.scan(w, rules(), mode="dir"),
            precondition=lambda: resolves("gitleaks", rules),
        ),
        tool(
            "gitleaks-history",
            ("gitleaks", "git"),
            lambda w: gitleaks.scan(w, rules(), mode="history"),
            precondition=lambda: resolves("gitleaks", rules),
        ),
        tool("yara", ("yara", "git"), lambda w: yara.scan(w)),
    )


def checkov_tool(ctx: Context) -> CheckovProvider:
    """Checkov on runners with its own time budgets; it needs none of the toolchain config."""
    bicep = bicep_candidates()
    keep = ctx.config.process.keep_env
    return CheckovProvider(
        ProcessRunner(["checkov"], keep_env=keep, timeout_seconds=CHECKOV_TIMEOUT),
        ProcessRunner(
            ["checkov", "git", "bicep", *(p.name for p in bicep)],
            keep_env=keep,
            timeout_seconds=PROBE_TIMEOUT,
        ),
        ctx.clock,
        bicep,
    )


def bicep_candidates() -> list[Path]:
    """Where the pinned bicep may be: `$CCA_BICEP`, PATH, then the per-user pinned install dir."""
    found = (os.environ.get("CCA_BICEP"), shutil.which("bicep"))
    home = Path.home() / ".cache" / "cca-tools" / f"bicep-{BICEP_VERSION}" / "bicep"
    return [*(Path(p) for p in found if p), home]


def gitleaks_config(locations: Locations) -> Path:
    """The gitleaks rules `locations.gitleaks_config` names; ValueError when it names none."""
    # PENDING(pack: gitleaks rules): the engine fell back to its bundled gitleaks-default.toml;
    # rule content stays pack config, so the pack sets locations.gitleaks_config to its copy.
    raw = locations.gitleaks_config
    if not raw:
        raise ValueError("gitleaks config required (locations.gitleaks_config)")
    path = locations.gitleaks_config_path()
    if path is None:
        raise ValueError(
            f"locations.gitleaks_config={raw!r} has no local path form "
            "(remote URIs are not supported for gitleaks config)"
        )
    if not path.is_file():
        raise ValueError(f"gitleaks config required (locations.gitleaks_config): no file {path}")
    return path


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


class _LineLoader(yaml.SafeLoader):
    """SafeLoader that records each mapping's source line under `__line__`."""


def _mapping_with_line(
    loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping = loader.construct_mapping(node, deep=deep)
    mapping["__line__"] = node.start_mark.line + 1
    return mapping


_LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping_with_line)


def yaml_documents_with_lines(text: str) -> list[object]:
    """Every document of a YAML text, each mapping carrying its line; ValidationError when it
    doesn't parse (`k8s_hardening.Scanner` cites file:line)."""
    try:
        return list(yaml.load_all(text, Loader=_LineLoader))
    except yaml.YAMLError as e:
        raise ValidationError(f"unparseable YAML: {e}") from e


def _config(path: Path, schema: str) -> Any:
    try:
        document = yaml.safe_load(path.read_text())
        contracts.validate_config(schema, document)
    except (OSError, yaml.YAMLError, DocumentError) as e:
        raise ConfigError(f"{path}: {e}") from e
    return document
