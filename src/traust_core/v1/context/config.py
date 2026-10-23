from __future__ import annotations

import os
from pathlib import Path

import pydantic
import sqlalchemy as sa
import yaml

from traust_core.v1.errors import ConfigError
from traust_core.v1.models.inventory import DEFAULT_FORGE_HOSTS
from traust_core.v1.services.findings.rating import RatingConfig
from traust_core.v1.services.identity import IdentityConfig
from traust_core.v1.services.ledger import LedgerConfig


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
            raise ConfigError(f"database.url is invalid: {self.url}") from e
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


# NEED(logging): one logging setup from Config — per-logger levels, JSON or text, stderr + rolling
# file, and a correlation ID set at every entry point and carried on every line (AGENTS.md).
# NEED(config): too busy and too clunky today. Target: one shape, one home, few keys —
# home dir, record store (SQLite default, Postgres optional), blob store (local dir or S3),
# identity. Pack data (catalogs, product maps) is not config; env only for secrets.
class Config(_Model):
    home: Path = pydantic.Field(default_factory=lambda: Path.home() / ".traust")
    database: DatabaseConfig = DatabaseConfig()
    artifacts: ArtifactsConfig = ArtifactsConfig()
    process: ProcessConfig = ProcessConfig()
    http: HttpConfig = HttpConfig()
    rating: RatingConfig = RatingConfig()
    ledger: LedgerConfig | None = None  # absent: no proof chain; decisions are still recorded
    identity: IdentityConfig | None = None  # absent: no caller can be verified
    allowed_repo_hosts: tuple[str, ...] = ()
    forge_hosts: dict[str, str] = pydantic.Field(default_factory=lambda: dict(DEFAULT_FORGE_HOSTS))

    @pydantic.field_validator("home")
    @classmethod
    def _expand_home(cls, value: Path) -> Path:
        return value.expanduser()

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
        try:
            return cls.model_validate(data)
        except pydantic.ValidationError as e:
            raise ConfigError(f"{path}: {e}") from e
