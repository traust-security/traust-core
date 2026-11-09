"""PortfolioSync.attach_branch: the door that attaches a branch line to track, resolving its
current head at the forge (the Snyk-style "scan this branch")."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.engine import Engine

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import SHA, Seed
from tests.v1.services.test_portfolio_sync import Forge
from traust_core.v1.models.inventory import RefName
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.sources import SourceError
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService, PortfolioSync

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed

T0 = datetime(2026, 11, 9, tzinfo=UTC)
MOVED = "b" * 40


def attach(engine: Engine, heads: dict[str, str]) -> PortfolioSync:
    uow = SqlTraustUnitOfWork(engine)
    return PortfolioSync(
        PortfolioService(uow, PortfolioPolicy()),
        Forge(heads=heads),  # type: ignore[arg-type]
        clock=FixedClock(T0),
    )


def test_attach_registers_the_lines_current_head(engine: Engine, seed: Seed) -> None:
    repo = seed.repository(url="https://github.com/org/tooling")
    seed.uow.commit()
    ref = attach(engine, {"release-4.16": SHA}).attach_branch(
        repo.id,
        RefName("release-4.16"),  # type: ignore[arg-type]
    )
    assert (ref.name, ref.sha) == ("release-4.16", SHA)
    with SqlTraustUnitOfWork(engine) as uow:
        [line] = uow.repository_refs.list_lines(repo.id)  # type: ignore[arg-type]
    assert line == ref


def test_re_attach_moves_the_line_to_its_new_head(engine: Engine, seed: Seed) -> None:
    repo = seed.repository(url="https://github.com/org/tooling")
    seed.uow.commit()
    service = attach(engine, {"release-4.16": SHA})
    service.attach_branch(repo.id, RefName("release-4.16"))  # type: ignore[arg-type]
    moved = attach(engine, {"release-4.16": MOVED}).attach_branch(
        repo.id,
        RefName("release-4.16"),  # type: ignore[arg-type]
    )
    assert moved.sha == MOVED
    with SqlTraustUnitOfWork(engine) as uow:
        [line] = uow.repository_refs.list_lines(repo.id)  # type: ignore[arg-type]
    assert line == moved


def test_attaching_the_default_branch_marks_the_default_line(engine: Engine, seed: Seed) -> None:
    repo = seed.repository(url="https://github.com/org/tooling")
    seed.repository_ref(repository=repo, name="main", sha=MOVED, is_default=True)
    seed.uow.commit()
    ref = attach(engine, {"main": SHA}).attach_branch(repo.id, RefName("main"))  # type: ignore[arg-type]
    assert ref.is_default is True
    assert ref.sha == SHA


def url_of(repo_url: str) -> HttpsRepoUrl:
    return HttpsRepoUrl.parse(repo_url, ("github.com",))


def test_observe_lines_advances_each_attached_line(engine: Engine, seed: Seed) -> None:
    repo = seed.repository(url="https://github.com/org/tooling")
    seed.repository_ref(repository=repo, name="main", sha=SHA, is_default=True)
    seed.repository_ref(repository=repo, name="dev", sha=MOVED)
    seed.repository_ref(repository=repo, name="release-4.16", sha=MOVED)
    seed.uow.commit()
    report = attach(engine, {"dev": SHA, "release-4.16": MOVED}).observe_lines(
        repo.id,
        url_of("https://github.com/org/tooling"),  # type: ignore[arg-type]
    )
    assert report.observed == (RefName("dev"), RefName("release-4.16"))  # type: ignore[arg-type]
    assert report.unobserved == ()
    with SqlTraustUnitOfWork(engine) as uow:
        lines = {r.name: r.sha for r in uow.repository_refs.list_lines(repo.id)}  # type: ignore[arg-type]
    assert lines == {"main": SHA, "dev": SHA, "release-4.16": MOVED}  # default line untouched


def test_observe_lines_names_a_line_the_forge_wont_answer(engine: Engine, seed: Seed) -> None:
    repo = seed.repository(url="https://github.com/org/tooling")
    seed.repository_ref(repository=repo, name="main", sha=SHA, is_default=True)
    seed.repository_ref(repository=repo, name="release-4.16", sha=MOVED)
    seed.uow.commit()
    gone = SourceError("branch gone", observation_status=ComparisonStatus.UNREACHABLE)
    service = PortfolioSync(
        PortfolioService(SqlTraustUnitOfWork(engine), PortfolioPolicy()),
        Forge(head_error=gone),  # type: ignore[arg-type]
        clock=FixedClock(T0),
    )
    report = service.observe_lines(
        repo.id,
        url_of("https://github.com/org/tooling"),  # type: ignore[arg-type]
    )
    assert report.observed == ()
    assert report.unobserved == (RefName("release-4.16"),)  # type: ignore[arg-type]
