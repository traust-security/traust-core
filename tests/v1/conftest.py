from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from collections.abc import Generator, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.example import repository as example_repository
from traust_core.v1 import contracts
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.providers.base import Readiness
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.forge_api import ForgeApi
from traust_core.v1.providers.local import LocalCheckout
from traust_core.v1.providers.mirror import MirrorCheckout
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.sources import CheckoutRequest
from traust_core.v1.repositories import apply_schema, create_database_engine
from traust_core.v1.repositories.sql import contract_dialect
from traust_core.v1.services.repo_checkout import CheckoutProvider, RepoCheckoutService

PG_URL = os.environ.get("TRAUST_TEST_DATABASE_URL")
SQL_BACKENDS = ["sqlite", pytest.param("postgres", marks=pytest.mark.integration)]
CLOCK = FixedClock(datetime(2026, 10, 5, tzinfo=UTC))


def git(repo: Path, *args: str) -> str:
    """Run git in a test repository; the identity is fixed so commits need no global config."""
    # Under a git hook GIT_DIR points at the repo being pushed: inherited, it would commit there.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    done = subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@example.com", "-c", "user.name=T", *args],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    return done.stdout.strip()


def commit_all(repo: Path, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


class NoArchive:
    """`RepoCheckoutService` serves whole trees through the mirror; the archive seam is never
    asked."""

    name = "unused-archive"

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def checkout(self, request: CheckoutRequest) -> Any:
        raise AssertionError("the forge stand-in serves no kept-file checkouts")

    def release(self, workspace: Any) -> None:
        raise AssertionError("the forge stand-in serves no kept-file checkouts")


class LocalForge(ProcessRunner):
    """The real runner, minus GIT_ALLOW_PROTOCOL on forge reads: git's file transport carries the
    local forge that stands in for the https repository (only a test configures insteadOf)."""

    def run(self, argv: Sequence[str], **kwargs: Any) -> Any:
        env = kwargs.get("env")
        if ("fetch" in argv or "ls-remote" in argv) and env:
            kwargs["env"] = {k: v for k, v in env.items() if k != "GIT_ALLOW_PROTOCOL"}
        return super().run(argv, **kwargs)


class NoCheckouts:
    """A checkout seam no code path of a test that resolves no remote source may reach."""

    def checkout(self, request: Any) -> Any:
        raise AssertionError("nothing should be checked out here")

    def release(self, workspace: Any) -> None:
        raise AssertionError("nothing should be checked out here")


class CheckoutForge:
    """A local bare repository standing in for the forge at `url`, served through
    `RepoCheckoutService`'s mirror: git's `url.<bare>.insteadOf` rewrites the https URL (only a
    test configures it), so no real remote is ever reached."""

    def __init__(self, root: Path, url: str = "https://github.com/o/r") -> None:
        parsed = HttpsRepoUrl.parse(url, [urlsplit(url).hostname or ""])
        self.url = url
        self.bare = root / "forge" / parsed.host / f"{parsed.path}.git"
        self.bare.mkdir(parents=True)
        git(self.bare, "init", "--bare", "-q")
        self._work = root / "forge-work"
        self._work.mkdir()
        git(self._work, "init", "-q")
        self._cache = root / "mirror-cache"
        mirror = self._mirror()
        mirror.mkdir(parents=True)
        git(mirror, "init", "--bare", "-q")
        git(mirror, "config", f"url.{self.bare}.insteadOf", url)

    def commit(self, files: Mapping[str, str | bytes | Path], message: str = "commit") -> GitSha:
        """Write `files` (a Path value: a symlink to it) and push one commit to the forge; that
        commit's sha."""
        for rel, text in files.items():
            path = self._work / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(text, Path):
                path.symlink_to(text)
            else:
                path.write_bytes(text if isinstance(text, bytes) else text.encode())
        sha = commit_all(self._work, message)
        git(self._work, "push", "-q", str(self.bare), "HEAD:refs/heads/main")
        return GitSha.parse(sha)

    def service(self, archive: CheckoutProvider | None = None) -> RepoCheckoutService:
        return RepoCheckoutService(
            archive if archive is not None else NoArchive(),
            MirrorCheckout(LocalForge(("git",)), CLOCK, self._cache, ForgeApi(None, {}, {})),
            LocalCheckout(LocalForge(("git",)), CLOCK),
        )

    def _mirror(self) -> Path:
        parsed = HttpsRepoUrl.parse(self.url, [urlsplit(self.url).hostname or ""])
        return self._cache / parsed.host / f"{parsed.path}.git"


def apply_contract_ddl(engine: Engine, area: contracts.Area) -> None:
    apply_schema(engine, contracts.ddl(area, contract_dialect(engine)))


def apply_contract_db(engine: Engine) -> None:
    apply_schema(engine, contracts.database_ddl(contract_dialect(engine)))


def _engine(kind: str, tmp_path: Path) -> Engine:
    if kind == "postgres" and not PG_URL:
        pytest.skip("TRAUST_TEST_DATABASE_URL not set")
    return create_database_engine(PG_URL if kind == "postgres" else f"sqlite:///{tmp_path}/t.db")


@contextmanager
def database(
    kind: str, tmp_path: Path, metadata: sa.MetaData = example_repository.metadata
) -> Generator[Engine]:
    if kind == "postgres":
        # A fresh database per test: parallel workers must not share traust_test.
        with _fresh_postgres() as eng:
            metadata.create_all(eng)
            try:
                yield eng
            finally:
                eng.dispose()
        return
    eng = _engine(kind, tmp_path)
    metadata.create_all(eng)
    try:
        yield eng
    finally:
        metadata.drop_all(eng)
        eng.dispose()


@contextmanager
def contract_db(kind: str, tmp_path: Path) -> Generator[Engine]:
    """A fresh database holding the whole contracts db (every namespace).

    The DDL runs once per session into a template; each test gets a copy - a file
    copy on SQLite, CREATE DATABASE ... TEMPLATE on Postgres - so tests stay
    isolated without re-bootstrapping 31 tables and their triggers every time.
    """
    if kind == "postgres":
        with _postgres_copy() as eng:
            yield eng
        return
    target = tmp_path / "contract.db"
    shutil.copyfile(_sqlite_template(), target)
    eng = create_database_engine(f"sqlite:///{target}")
    try:
        yield eng
    finally:
        eng.dispose()


@cache
def _sqlite_template() -> Path:
    path = Path(tempfile.mkdtemp(prefix="traust-contract-")) / "template.db"
    eng = create_database_engine(f"sqlite:///{path}")
    apply_contract_db(eng)
    eng.dispose()
    return path


_PG_TEMPLATE = f"traust_contract_tmpl_{os.getpid()}"


def _pg_admin() -> Engine:
    if not PG_URL:
        pytest.skip("TRAUST_TEST_DATABASE_URL not set")
    return sa.create_engine(PG_URL, isolation_level="AUTOCOMMIT")


@cache
def _postgres_template() -> str:
    admin = _pg_admin()
    with admin.connect() as conn:
        conn.exec_driver_sql(f"DROP DATABASE IF EXISTS {_PG_TEMPLATE} WITH (FORCE)")
        conn.exec_driver_sql(f"CREATE DATABASE {_PG_TEMPLATE}")
    admin.dispose()
    eng = create_database_engine(sa.make_url(PG_URL).set(database=_PG_TEMPLATE))
    apply_contract_db(eng)
    eng.dispose()  # a template database must have no open connections to be copied
    return _PG_TEMPLATE


@contextmanager
def _postgres_copy() -> Generator[Engine]:
    template = _postgres_template()
    name = f"traust_contract_{uuid4().hex[:12]}"
    admin = _pg_admin()
    with admin.connect() as conn:
        conn.exec_driver_sql(f"CREATE DATABASE {name} TEMPLATE {template}")
    eng = create_database_engine(sa.make_url(PG_URL).set(database=name))
    try:
        yield eng
    finally:
        eng.dispose()
        with admin.connect() as conn:
            conn.exec_driver_sql(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        admin.dispose()


def pytest_sessionfinish(session: pytest.Session) -> None:
    if PG_URL and _postgres_template.cache_info().currsize:
        admin = _pg_admin()
        with admin.connect() as conn:
            conn.exec_driver_sql(f"DROP DATABASE IF EXISTS {_PG_TEMPLATE} WITH (FORCE)")
        admin.dispose()


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if mark := item.get_closest_marker("todo"):
            item.add_marker(pytest.mark.skip(reason=f"todo({mark.args[0]}): parked"))


@contextmanager
def _fresh_postgres() -> Generator[Engine]:
    name = f"traust_example_{uuid4().hex[:12]}"
    admin = _pg_admin()
    with admin.connect() as conn:
        conn.exec_driver_sql(f"CREATE DATABASE {name} TEMPLATE template0")
    eng = create_database_engine(sa.make_url(PG_URL).set(database=name))
    try:
        yield eng
    finally:
        eng.dispose()
        with admin.connect() as conn:
            conn.exec_driver_sql(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        admin.dispose()


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with database(request.param, tmp_path) as eng:
        yield eng
