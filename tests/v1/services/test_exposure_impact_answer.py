"""ExposureService.impact: every tracked ref's outcome for one advisory, its gaps counted,
never silently missing (plan: impact analysis in SCI, layer 2)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed, apart
from tests.v1.services.test_exposure_impact import AT, Lookup, engine
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    AdvisoryRecord,
    AffectedPackage,
    AffectedSpan,
    ImpactState,
    Version,
)
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Readiness, Result
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.providers.tools import ToolRequest
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

__all__ = ["engine"]

CVE = AdvisoryIdentifier("CVE-2026-0001")
LODASH = AdvisoryRecord(
    identifier=CVE,
    source="osv",
    affected=(
        AffectedPackage(
            ecosystem=Ecosystem.NPM,
            name="lodash",
            spans=(AffectedSpan(introduced=Version("0"), fixed=Version("4.17.21")),),
        ),
    ),
)
NOTHING = AdvisoryRecord(
    identifier=AdvisoryIdentifier("CVE-2026-0002"),
    source="osv",
    unmodeled_ecosystems=("alpm",),
)
AFFECTED = json.dumps(
    {"bomFormat": "CycloneDX", "components": [{"purl": "pkg:npm/lodash@4.17.20"}]}
).encode()
FIXED = json.dumps(
    {"bomFormat": "CycloneDX", "components": [{"purl": "pkg:npm/lodash@4.17.21"}]}
).encode()
OTHER_NPM = json.dumps(
    {"bomFormat": "CycloneDX", "components": [{"purl": "pkg:npm/left-pad@1.3.0"}]}
).encode()
GO = json.dumps(
    {"bomFormat": "CycloneDX", "components": [{"purl": "pkg:golang/grpc@1.56.2"}]}
).encode()


class Tool:
    """The SBOM tool, saying whatever the test last loaded."""

    name = "syft"

    def __init__(self) -> None:
        self.raw = AFFECTED

    def check(self) -> Readiness:
        return Readiness(ready=True, detail="")

    def acquire(self, request: ToolRequest) -> Result[bytes]:
        return Result(self.raw, Acquisition(provider="syft", acquired_at=AT, version="1.51.1"))


def exposure(
    engine: Engine, tool: Tool, objects: InMemoryObjectStore, *records: AdvisoryRecord
) -> ExposureService:
    uow = SqlTraustUnitOfWork(engine)
    return ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry[FeedProvider]("feed"),
        objects=objects,
        advisories=Lookup(*(records or (LODASH,))),  # type: ignore[arg-type]
        portfolio=PortfolioService(uow, PortfolioPolicy()),
        sbom_tool=tool,  # type: ignore[arg-type]
        clock=None,
    )


def checkout(root: Path, *, locked: bool) -> Path:
    (root / "ui").mkdir(parents=True)
    (root / "ui" / "package.json").write_text(json.dumps({"dependencies": {"lodash": "^4"}}))
    if locked:
        (root / "ui" / "package-lock.json").write_text('{"lockfileVersion": 3}')
    return root


def ingest(
    engine: Engine,
    tool: Tool,
    objects: InMemoryObjectStore,
    ref: UUID,
    raw: bytes,
    root: Path,
    *,
    locked: bool,
) -> None:
    tool.raw = raw
    exposure(engine, tool, objects).ingest_dependencies(ref, checkout(root, locked=locked))


def default_ref(uow: SqlTraustUnitOfWork, seed: Seed, **kw: object) -> UUID:
    ref = seed.repository_ref(is_default=True, **kw)  # type: ignore[arg-type]
    uow.commit()
    assert ref.id is not None
    return ref.id


def test_every_state_over_the_tracked_fleet(engine: Engine, tmp_path: Path) -> None:
    tool, objects = Tool(), InMemoryObjectStore()
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        affected = default_ref(uow, seed, repository=repo)
        fixed = default_ref(uow, seed)
        not_using = default_ref(uow, seed)
        unresolved = default_ref(uow, seed)
        outside = default_ref(uow, seed)
        default_ref(uow, seed)  # never scanned: no SBOM, its line never scanned either
        unknown = default_ref(uow, seed)
        stale_repo = seed.repository()
        scanned_head = default_ref(uow, seed, repository=stale_repo)
        apart()
        default_ref(uow, seed, repository=stale_repo, sha="b" * 40)  # the head moved past its scan
        shipped = seed.repository_ref(name="release-4.16")
        product = seed.product(slug="ocp")
        seed.component(seed.release(product), shipped)
        uow.commit()
        assert shipped.id is not None

    ingest(engine, tool, objects, affected, AFFECTED, tmp_path / "a", locked=True)
    ingest(engine, tool, objects, fixed, FIXED, tmp_path / "b", locked=True)
    ingest(engine, tool, objects, not_using, OTHER_NPM, tmp_path / "c", locked=True)
    ingest(engine, tool, objects, unresolved, OTHER_NPM, tmp_path / "d", locked=False)
    ingest(engine, tool, objects, outside, GO, tmp_path / "e", locked=True)
    ingest(engine, tool, objects, scanned_head, OTHER_NPM, tmp_path / "f", locked=True)
    ingest(engine, tool, objects, shipped.id, GO, tmp_path / "g", locked=True)
    exposure(engine, tool, objects).ingest_sbom(OTHER_NPM, unknown)

    answer = exposure(engine, tool, objects).impact(CVE)
    assert answer.ecosystems == (Ecosystem.NPM,)
    assert answer.advisory_id is not None
    by_state = {row.state: row for row in answer.rows}
    assert set(by_state) == {
        ImpactState.AFFECTED,
        ImpactState.FIXED,
        ImpactState.NOT_USING,
        ImpactState.UNRESOLVED_MANIFEST,
    }
    [held] = by_state[ImpactState.AFFECTED].held
    assert (held.name, held.version, held.in_range) == ("lodash", Version("4.17.20"), True)
    assert by_state[ImpactState.UNRESOLVED_MANIFEST].reason == "ui/package.json"
    assert by_state[ImpactState.NOT_USING].product_slugs == ()
    assert by_state[ImpactState.AFFECTED].repository_ref_id == affected

    assert answer.counts == {
        ImpactState.AFFECTED: 1,
        ImpactState.FIXED: 1,
        ImpactState.NOT_USING: 1,
        ImpactState.UNRESOLVED_MANIFEST: 1,
        ImpactState.NOT_IN_ECOSYSTEM: 2,  # the go-scanned default head and the shipped commit
        ImpactState.NO_SBOM: 1,
        ImpactState.STALE: 1,  # the moved default head: its line's SBOM is at the earlier commit
        ImpactState.COVERAGE_UNKNOWN: 1,  # the SBOM given as a document, no scan
    }
    assert answer.complete is False
    assert answer.fixable == 2  # the stale and the unscanned default heads; a branch commit isn't
    assert answer.as_of is not None and answer.as_of <= datetime.now(tz=UTC)


def test_a_complete_answer_names_no_gaps(engine: Engine, tmp_path: Path) -> None:
    tool, objects = Tool(), InMemoryObjectStore()
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        affected = default_ref(uow, seed)
        outside = default_ref(uow, seed)
        uow.commit()
    ingest(engine, tool, objects, affected, AFFECTED, tmp_path / "a", locked=True)
    ingest(engine, tool, objects, outside, GO, tmp_path / "b", locked=True)

    answer = exposure(engine, tool, objects).impact(CVE)
    assert answer.complete is True
    assert answer.fixable == 0
    assert answer.counts == {
        ImpactState.AFFECTED: 1,
        ImpactState.NOT_IN_ECOSYSTEM: 1,
    }


def test_products_shipping_each_row(engine: Engine, tmp_path: Path) -> None:
    tool, objects = Tool(), InMemoryObjectStore()
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        head = seed.repository_ref(is_default=True)
        uow.commit()
        assert head.id is not None
        seed.component(seed.release(seed.product(slug="ocp")), head)
        uow.commit()
    ingest(engine, tool, objects, head.id, AFFECTED, tmp_path / "a", locked=True)

    answer = exposure(engine, tool, objects).impact(CVE)
    [row] = answer.rows
    assert row.state is ImpactState.AFFECTED
    assert row.product_slugs == ("ocp",)


def test_an_unknown_advisory_raises_and_a_uuid_answers(engine: Engine, tmp_path: Path) -> None:
    tool, objects = Tool(), InMemoryObjectStore()
    service = exposure(engine, tool, objects)
    with pytest.raises(NotFoundError):
        service.impact(AdvisoryIdentifier("CVE-0000-0000"))
    answer = service.impact(CVE)
    assert answer.advisory_id is not None
    assert service.impact(answer.advisory_id).identifier == CVE


def test_an_advisory_naming_nothing_modelled_answers_empty(engine: Engine) -> None:
    tool, objects = Tool(), InMemoryObjectStore()
    answer = exposure(engine, tool, objects, NOTHING).impact(NOTHING.identifier)
    assert answer.ecosystems == ()
    assert answer.unmodeled_ecosystems == ("alpm",)
    assert answer.rows == ()
    assert answer.counts == {}
    assert answer.complete is True


def test_no_tracked_refs_answer_empty(engine: Engine) -> None:
    tool, objects = Tool(), InMemoryObjectStore()
    answer = exposure(engine, tool, objects).impact(CVE)
    assert answer.rows == ()
    assert answer.counts == {}
    assert answer.complete is True
