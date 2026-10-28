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
from traust_core.v1.models.operations import Budget
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
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "WARNING"
    levels: dict[str, Literal["DEBUG", "INFO", "WARNING", "ERROR"]] = pydantic.Field(
        default_factory=lambda: {"traust_core.rest.access": "INFO"}
    )
    format: Literal["json", "text"] = "json"
    file: Path = Path("logs/traust.log")
    max_bytes: int = pydantic.Field(default=10_000_000, ge=1024)
    backups: int = pydantic.Field(default=5, ge=1)

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
    """`locations.yaml` beside the config file: where the harness reads and writes runtime data."""

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
    # NEED(contracts): `inputs` is read by traust but not named in locations.schema.json.
    inputs: str | None = None

    @classmethod
    def from_home(cls, home: Path) -> Locations:
        """`<home>/locations.yaml`, schema-checked, relative paths made absolute against `home`."""
        path = home / "locations.yaml"
        if not path.is_file():
            return cls()
        try:
            data = yaml.safe_load(path.read_text())
            contracts.validate_config("locations", data)
            raw = cls.model_validate({k: v for k, v in data.items() if k in cls.model_fields})
        except (OSError, yaml.YAMLError, DocumentError, pydantic.ValidationError) as e:
            raise ConfigError(f"cannot read {path}: {e}") from e
        return raw.model_copy(update=raw._absolute(home))

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
                f"{name} not configured: set `{name}` in locations.yaml "
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


_PATH_FIELDS = (
    "workspace",
    "analysis_results",
    "portfolio_graph",
    "progress_tracker",
    "rule_drafts",
    "feeds_cache",
    "gitleaks_config",
    "opengrep_rules",
)


# NEED(config): too busy and too clunky today. Target: one shape, one home, few keys —
# home dir, record store (SQLite default, Postgres optional), blob store (local dir or S3),
# identity. Pack data (catalogs, product maps) is not config; env only for secrets.
class Config(_Model):
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
    allowed_repo_hosts: tuple[str, ...] = ()
    forge_hosts: dict[str, str] = pydantic.Field(default_factory=lambda: dict(DEFAULT_FORGE_HOSTS))
    budgets: tuple[Budget, ...] = ()  # monthly spend per lane; absent lanes are never bound
    remediation: RemediationConfig = RemediationConfig()
    locations: Locations = Locations()  # from locations.yaml beside the config file, never inline

    @pydantic.field_validator("home")
    @classmethod
    def _expand_home(cls, value: Path) -> Path:
        return value.expanduser()

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
    def from_file(cls, path: Path) -> Config:
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except (OSError, yaml.YAMLError) as e:
            raise ConfigError(f"cannot read {path}") from e
        if isinstance(data, dict) and "locations" in data:
            raise ConfigError(f"{path}: locations live in locations.yaml beside it, not inline")
        try:
            return cls.model_validate(data).model_copy(
                update={"locations": Locations.from_home(path.parent)}
            )
        except pydantic.ValidationError as e:
            raise ConfigError(f"{path}: {e}") from e
