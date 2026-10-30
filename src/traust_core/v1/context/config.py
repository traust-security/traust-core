from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import pydantic
import sqlalchemy as sa
import yaml

from traust_core.v1 import contracts
from traust_core.v1.errors import ConfigError, DocumentError
from traust_core.v1.models.inventory import DEFAULT_FORGE_HOSTS
from traust_core.v1.models.operations import Budget, RecordingStartScope
from traust_core.v1.services.findings.rating import RatingConfig
from traust_core.v1.services.findings.review import ReviewConfig
from traust_core.v1.services.identity import IdentityConfig
from traust_core.v1.services.ledger import LedgerConfig
from traust_core.v1.services.remediation import RemediationConfig


class _Model(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid", frozen=True)


def _read_env(name: str | None, field: str) -> str | None:
    if name is None:
        return None
    if (value := os.environ.get(name)) is None:
        raise ConfigError(f"{field} names unset variable {name}")
    return value


class DatabaseConfig(_Model):
    url: str | None = None
    password_env: str | None = None

    def password(self) -> str | None:
        return _read_env(self.password_env, "database.password_env")

    def engine_url(self) -> sa.URL:
        if self.url is None:
            raise ConfigError("database.url is not set")
        try:
            url = sa.make_url(self.url)
        except sa.exc.ArgumentError as e:
            raise ConfigError("database.url is invalid") from e
        return url.set(password=pw) if (pw := self.password()) else url


class ArtifactsConfig(_Model):
    path: Path = Path("artifacts")


class ProcessConfig(_Model):
    allowed_binaries: tuple[str, ...] = ()
    keep_env: tuple[str, ...] = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")
    timeout_seconds: float = 600.0


class HttpConfig(_Model):
    """Retry policy for outbound provider HTTP (RetryPolicy fields)."""

    max_attempts: int = 4
    timeout_seconds: float = 120.0
    backoff_base_seconds: float = 1.0
    max_wait_seconds: float = 60.0
    jitter_seconds: float = 0.5


class LoggingConfig(_Model):
    outputs: tuple[Literal["stderr", "file"], ...] = ("stderr", "file")
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    levels: dict[str, Literal["DEBUG", "INFO", "WARNING", "ERROR"]] = pydantic.Field(
        default_factory=lambda: {"traust_core.rest.access": "INFO"}
    )
    format: Literal["json", "text"] = "json"
    file: Path = Path("logs/traust.log")
    max_bytes: int = pydantic.Field(default=10_000_000, ge=1024)
    backups: int = pydantic.Field(default=5, ge=1)

    @pydantic.field_validator("outputs")
    @classmethod
    def _at_least_one_unique_output(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("logging outputs must not be empty")
        if len(value) != len(set(value)):
            raise ValueError("logging outputs must be unique")
        return value

    @pydantic.field_validator("levels")
    @classmethod
    def _project_loggers_only(cls, value: dict[str, str]) -> dict[str, str]:
        if any(not name.startswith("traust_core.") for name in value):
            raise ValueError("logger level overrides must name traust_core loggers")
        return value


def _local_path(value: str | None) -> Path | None:
    if not value or ("://" in value and not value.startswith("file://")):
        return None
    return Path(value.removeprefix("file://"))


class Locations(_Model):
    """`locations:` in traust.yaml: where the harness reads and writes runtime data."""

    workspace: str | None = None
    analysis_results: str | None = None
    portfolio_graph: str | None = None
    progress_tracker: str | None = None
    rule_drafts: str | None = None
    feeds_cache: str | None = None
    gitleaks_config: str | None = None
    opengrep_rules: str | None = None
    product_definitions: str | None = None
    sarif_tool_uri: str | None = None
    inputs: str | None = None
    mirror_cache: str | None = None

    def _absolute(self, home: Path) -> dict[str, str]:
        # Same rule as traust-contracts' loader: URIs stay as written; `inputs` follows traust's.
        out = {}
        for field in _PATH_FIELDS:
            value = getattr(self, field)
            if value and "://" not in value and not Path(value).is_absolute():
                out[field] = str((home / value).resolve())
        if (inputs := _local_path(self.inputs)) and not inputs.is_absolute():
            out["inputs"] = str((home / inputs).resolve())
        return out

    @staticmethod
    def require(value: Path | None, name: str) -> Path:
        """`value`, or a ConfigError naming the location that is unset (or remote-only)."""
        if value is None:
            raise ConfigError(
                f"{name} not configured: set `locations.{name}` in traust.yaml "
                "(or it is a remote URI with no local form)"
            )
        return value

    def analysis_results_dir(self) -> Path | None:
        return _local_path(self.analysis_results)

    def workspace_dir(self) -> Path:
        return self.require(_local_path(self.workspace), "workspace")

    def inputs_dir(self) -> Path:
        """`inputs` when set, else `<workspace>/inputs`."""
        if not self.inputs:
            return self.workspace_dir() / "inputs"
        return self.require(_local_path(self.inputs), "inputs")

    def progress_tracker_dir(self) -> Path | None:
        return _local_path(self.progress_tracker)

    def feeds_cache_dir(self) -> Path | None:
        return _local_path(self.feeds_cache)

    def gitleaks_config_path(self) -> Path | None:
        return _local_path(self.gitleaks_config)

    def rule_drafts_dir(self) -> Path | None:
        """`rule_drafts` when set, else `<progress_tracker>/metrics/rule-mining/rule-drafts`."""
        if self.rule_drafts:
            return _local_path(self.rule_drafts)
        root = self.progress_tracker_dir()
        return root / "metrics" / "rule-mining" / "rule-drafts" if root else None

    def portfolio_graph_db(self) -> Path | None:
        """`portfolio_graph` when set, else `<analysis_results>/graph/portfolio-graph.db`."""
        if self.portfolio_graph:
            return _local_path(self.portfolio_graph)
        root = self.analysis_results_dir()
        return root / "graph" / "portfolio-graph.db" if root else None

    def findings_db(self) -> Path | None:
        root = self.analysis_results_dir()
        return root / "graph" / "findings.db" if root else None

    def mirror_cache_dir(self, home: Path) -> Path:
        """The git mirror cache root: `mirror_cache` when set, else `<home>/mirrors`. Unlike the
        locations above it has a default, so checkouts work with no configuration."""
        if self.mirror_cache is None:
            return home / "mirrors"
        if (local := _local_path(self.mirror_cache)) is None:
            raise ConfigError("locations.mirror_cache must be a local path")
        return local if local.is_absolute() else home / local


class FeedsConfig(_Model):
    osv_access: Literal["api", "air-gapped"] = "api"  # air-gapped: exported OSV records only


class ExecutionConfig(_Model):
    sandbox: Literal["none", "podman"] = "none"  # how a target's own build and test code runs


class CampaignConfig(_Model):
    tracking_reference: str | None = None  # the issue-tracker key reports cite
    display_name: str | None = None


class OverridesConfig(_Model):
    """What an adopter may point at its own file for. Tool pins, safe-exec profiles and the
    feeds registry are the project's opinions: they ship with traust-core (`SHIPPED`)."""

    rule_pack_allowlist: Path | None = None  # absent: no supplemental rule packs


_SHIPPED_DIR = Path(__file__).parent / "shipped"
SHIPPED_EXTERNAL_TOOLS = _SHIPPED_DIR / "external-tools.yaml"
SHIPPED_SAFE_EXEC_PROFILES = _SHIPPED_DIR / "safe-exec-profiles.yaml"
SHIPPED_FEEDS = _SHIPPED_DIR / "feeds.yaml"


class RecordingConfig(_Model):
    """Server-owned asset capabilities; absent bindings grant no report-recording access."""

    assessment: tuple[str, ...] = ()
    triage: tuple[str, ...] = ()
    validation: tuple[str, ...] = ()
    verification: tuple[str, ...] = ()
    start: tuple[RecordingStartScope, ...] = ()


_PATH_FIELDS = (
    "workspace",
    "analysis_results",
    "portfolio_graph",
    "progress_tracker",
    "rule_drafts",
    "feeds_cache",
    "gitleaks_config",
    "opengrep_rules",
    "mirror_cache",
)


CONFIG_FILE = "traust.yaml"


class Config(_Model):
    """traust.yaml (contracts `traust`): everything an adopter sets; env only for secrets."""

    home: Path = pydantic.Field(default_factory=lambda: Path.home() / ".traust")
    database: DatabaseConfig = DatabaseConfig()
    artifacts: ArtifactsConfig = ArtifactsConfig()
    process: ProcessConfig = ProcessConfig()
    http: HttpConfig = HttpConfig()
    logging: LoggingConfig = LoggingConfig()
    rating: RatingConfig = RatingConfig()
    review: ReviewConfig = ReviewConfig()
    ledger: LedgerConfig | None = None  # absent: no proof chain; decisions are still recorded
    identity: IdentityConfig | None = None  # absent: no caller can be verified
    recording: RecordingConfig = RecordingConfig()
    allowed_repo_hosts: tuple[str, ...] = ()
    forge_hosts: dict[str, str] = pydantic.Field(default_factory=lambda: dict(DEFAULT_FORGE_HOSTS))
    forge_tokens: dict[str, str] = {}  # host -> env var holding its API token; absent: anonymous
    budgets: tuple[Budget, ...] = ()  # monthly spend per lane; absent lanes are never bound
    remediation: RemediationConfig = RemediationConfig()
    locations: Locations = Locations()  # relative paths resolve against traust.yaml's directory
    feeds: FeedsConfig = FeedsConfig()
    execution: ExecutionConfig = ExecutionConfig()
    campaign: CampaignConfig = CampaignConfig()
    overrides: OverridesConfig = OverridesConfig()
    # The top-level keys the traust.yaml file set (the file's own keys, never defaults); the
    # zero-config defaults and hand-built configs set none. Private: the contracts schema owns
    # the public field set. Preflight checks requirements against it.
    _provided: frozenset[str] = pydantic.PrivateAttr(default=frozenset())
    # The home this config was loaded from (None for the zero-config defaults); preflight's
    # completeness audit examines it, not whatever $TRAUST_CONFIG_HOME points at. Private for
    # the same reason as _provided.
    _config_home: Path | None = pydantic.PrivateAttr(default=None)

    @property
    def provided(self) -> frozenset[str]:
        """The top-level keys the traust.yaml file set; preflight checks config requirements
        against it."""
        return self._provided

    @property
    def config_home(self) -> Path | None:
        """The directory this config was loaded from; None when nothing was loaded."""
        return self._config_home

    @pydantic.field_validator("home")
    @classmethod
    def _expand_home(cls, value: Path) -> Path:
        return value.expanduser()

    def forge_token_values(self) -> dict[str, str]:
        return {
            host: value
            for host, name in self.forge_tokens.items()
            if (value := _read_env(name, f"forge_tokens.{host}"))
        }

    def valve_salt(self) -> str | None:
        return _read_env(self.review.valve_salt_env, "review.valve_salt_env")

    def artifacts_path(self) -> Path:
        """Where artifact bytes live: a relative `artifacts.path` is under `home`, never the cwd."""
        path = self.artifacts.path.expanduser()
        return path if path.is_absolute() else self.home / path

    def record_store_url(self) -> sa.URL:
        if self.database.url is not None:
            return self.database.engine_url()
        return sa.URL.create("sqlite", database=str(self.home / "traust.db"))

    @classmethod
    def from_home(cls, home: Path | None) -> Config:
        """`<home>/traust.yaml`; no home or no file keeps the zero-config defaults."""
        path = home / CONFIG_FILE if home is not None else None
        return cls.from_file(path) if path is not None and path.is_file() else cls()

    @classmethod
    def from_file(cls, path: Path) -> Config:
        """A traust.yaml, schema-checked; relative locations and overrides resolve beside it."""
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except (OSError, yaml.YAMLError) as e:
            raise ConfigError(f"cannot read {path}") from e
        try:
            contracts.validate_config("traust", data)
            provided = frozenset(data)
            locations = Locations.model_validate(
                {k: v for k, v in data.pop("locations", {}).items() if k in Locations.model_fields}
            )
            config = cls.model_validate(data)
        except (DocumentError, pydantic.ValidationError) as e:
            raise ConfigError(f"{path}: {e}") from e
        home = path.parent
        overrides = {k: (home / v).resolve() for k, v in config.overrides if v is not None}
        loaded = config.model_copy(
            update={
                "locations": locations.model_copy(update=locations._absolute(home)),
                "overrides": config.overrides.model_copy(update=overrides),
            }
        )
        loaded._provided = provided
        loaded._config_home = home
        return loaded
