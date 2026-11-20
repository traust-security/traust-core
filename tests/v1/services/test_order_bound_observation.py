from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.observation_support import HEAD, NOW, FakeSource, default_tools
from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import Seed, saved_id
from tests.v1.services.test_exposure_sweep import FakeCheckout, FakeSbomTool
from tests.v1.services.test_operations import LEASE, OPERATOR, W1
from tests.v1.services.test_recording_authority import MovingClock
from traust_core.v1.context.config import Config
from traust_core.v1.context.context import Context
from traust_core.v1.errors import ConflictError
from traust_core.v1.models.artifacts import RepoLivenessArtifact, RepoStateArtifact
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.dependencies import Sbom
from traust_core.v1.models.observation import ForgeFacts
from traust_core.v1.models.operations import AssetName, OrderRequest
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.providers.base import Result
from traust_core.v1.providers.sources import RepoInfo
from traust_core.v1.providers.tools import ToolRequest
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

engine = table_fixtures.engine


class LeaseRace:
    def __init__(self, engine: Engine, home: Path, asset: str, repository_id: UUID) -> None:
        self.clock = MovingClock(NOW)
        context = Context(Config(home=home), clock=self.clock)
        context.__dict__["database"] = engine
        self.services = context.services()
        self.other_connection = context.services().ops
        self.first = self.current = self.other_connection.start(
            OrderRequest(asset=AssetName(asset), priority=1, repository_id=repository_id),
            OPERATOR,
            W1,
            LEASE,
        )
        self.clock.at += timedelta(seconds=1)

    def reclaim(self) -> None:
        self.clock.at = NOW + LEASE
        assert self.other_connection.requeue_expired() == 1
        claim = self.other_connection.claim(W1, LEASE, order_id=saved_id(self.first))
        assert claim is not None and claim.lease_generation == self.first.lease_generation + 1
        self.current = claim


def test_reclaim_during_forge_fetch_rolls_back_observation_and_liveness(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = seed.repository(url="https://github.com/o/repo", public=False)
        base = seed.repository_ref(repository, sha="a" * 40)
        seed.assessment(ref=base, kind=AssessmentKind.SECURE_CODE, occurred_at=NOW - LEASE)
        uow.commit()
    repository_id = saved_id(repository)
    race = LeaseRace(engine, tmp_path, "repo_state", repository_id)
    portfolio = race.services.portfolio
    source = FakeSource()
    portfolio._sources, portfolio._tools = source, default_tools()
    info = source.info

    def reclaim_at_fetch(repo: HttpsRepoUrl) -> Result[RepoInfo]:
        race.reclaim()
        return info(repo)

    def observe(generation: int) -> ForgeFacts:
        return portfolio.record_forge_facts(
            repository_id=repository_id,
            run_order_id=saved_id(race.first),
            worker=W1,
            lease_generation=generation,
        )

    with monkeypatch.context() as patch:
        patch.setattr(source, "info", reclaim_at_fetch)
        with pytest.raises(ConflictError, match="stale lease generation"):
            observe(race.first.lease_generation)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.repositories.get(repository_id) == repository
        assert [ref.id for ref in uow.repository_refs.list_for(repository_id)] == [base.id]
        assert not uow.artifacts.list_imported(RepoLivenessArtifact.schema, limit=1)
        assert not uow.artifacts.list_imported(RepoStateArtifact.schema, limit=1)
    assert observe(race.current.lease_generation).head == HEAD
    calls = source.calls.copy()
    with pytest.raises(ConflictError, match="stale lease generation"):
        observe(race.first.lease_generation)
    assert source.calls == calls


def test_reclaim_during_manifest_scan_rolls_back_all_db_links_and_fences_cache_hits(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        ref = Seed(uow).repository_ref()
        uow.commit()
    race = LeaseRace(engine, tmp_path, "manifest_sbom", ref.repository_id)
    exposure = race.services.exposure
    checkout, tool = FakeCheckout(tmp_path), FakeSbomTool()
    exposure._checkout, exposure._sbom_tool = checkout, tool
    acquire = tool.acquire

    def reclaim_at_scan(request: ToolRequest) -> Result[bytes]:
        race.reclaim()
        return acquire(request)

    def record(generation: int) -> Sbom:
        return exposure.record_manifest_sbom(
            saved_id(ref), run_order_id=saved_id(race.first), worker=W1, lease_generation=generation
        )

    with monkeypatch.context() as patch:
        patch.setattr(tool, "acquire", reclaim_at_scan)
        with pytest.raises(ConflictError, match="stale lease generation"):
            record(race.first.lease_generation)
    assert len(checkout.released) == 1
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.repository_refs.get(saved_id(ref)) == ref
        assert not uow.artifacts.list_imported("sbom", limit=1)
        assert not uow.assessments.list_for_run_order(saved_id(race.first))
    current = record(race.current.lease_generation)
    assert record(race.current.lease_generation) == current
    with pytest.raises(ConflictError, match="stale lease generation"):
        record(race.first.lease_generation)
    assert len(checkout.asked) == len(checkout.released) == 2
    with SqlTraustUnitOfWork(engine) as uow:
        [scan] = uow.assessments.list_for_run_order(saved_id(race.first))
        stored = uow.repository_refs.get(saved_id(ref))
        assert stored.manifest_sbom_assessment_id == scan.id
        assert stored.manifest_sbom_id == current.id
