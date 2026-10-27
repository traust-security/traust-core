from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pydantic
import yaml

from traust_core.v1 import contracts
from traust_core.v1.errors import ConfigError, DocumentError
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.config_matrix import YamlLoader
from traust_core.v1.providers.http import HttpFetcher
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.tools import opengrep
from traust_core.v1.providers.tools.adapter import AdapterTool
from traust_core.v1.providers.tools.compliance_sources import (
    CURL_TIMEOUT,
    GH_TIMEOUT,
    GithubAdrSource,
    RedHatDocSource,
)
from traust_core.v1.providers.tools.detection_quality import (
    GIT_TIMEOUT,
    GitCanaryMaterializer,
    OpengrepRulePacks,
)
from traust_core.v1.providers.tools.fleet_fix import (
    AST_GREP_TIMEOUT,
    CLONE_TIMEOUT,
    GitFleetFixApplier,
)
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


def load_rule_pack_supplements(path: Path) -> tuple[opengrep.SupplementalPack, ...]:
    """The supplemental packs `rule-pack-allowlist.yaml` enables."""
    return tuple(opengrep.supplemental_packs(_config(path, "rule-pack-allowlist")["packs"]))


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


def git_fleet_fix(keep_env: Sequence[str], clock: Clock) -> GitFleetFixApplier:
    """The fleet-fix applier, which is also the ast-grep golden runner."""
    return GitFleetFixApplier(
        ProcessRunner(["git"], keep_env=keep_env, timeout_seconds=CLONE_TIMEOUT),
        ProcessRunner(["ast-grep"], keep_env=keep_env, timeout_seconds=AST_GREP_TIMEOUT),
        clock,
    )


def compliance_sources(
    keep_env: Sequence[str], http: HttpFetcher, clock: Clock
) -> tuple[GithubAdrSource, RedHatDocSource]:
    """ADR registers read with gh and raw GitHub files; product docs fetched with curl."""
    gh = ProcessRunner(["gh"], keep_env=keep_env, timeout_seconds=GH_TIMEOUT)
    curl = ProcessRunner(["curl"], keep_env=keep_env, timeout_seconds=CURL_TIMEOUT)
    # NEED(config: product -> docs slug/version): no DocsTarget map yet, so every product's
    # docs lookup is refused by name until one has a home.
    return GithubAdrSource(gh, http, clock), RedHatDocSource(curl, clock, {})


def load_detection_quality(
    keep_env: Sequence[str],
    load: YamlLoader,
    *,
    pack: Path,
    pack_version: str,
    supplements: Callable[[], Sequence[opengrep.SupplementalPack]],
    canary_sources: Path,
    canary_repos: Path,
) -> tuple[OpengrepRulePacks, GitCanaryMaterializer]:
    """The rule-pack source over `pack` and its supplements, and the canary materialiser
    committing `canary_sources` under `canary_repos`."""
    git = ProcessRunner(["git"], keep_env=keep_env, timeout_seconds=GIT_TIMEOUT)
    return (
        OpengrepRulePacks(pack, pack_version, supplements, git, load),
        GitCanaryMaterializer(canary_sources, canary_repos, git, load),
    )


def _config(path: Path, schema: str) -> Any:
    try:
        document = yaml.safe_load(path.read_text())
        contracts.validate_config(schema, document)
    except (OSError, yaml.YAMLError, DocumentError) as e:
        raise ConfigError(f"{path}: {e}") from e
    return document
