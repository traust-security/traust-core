from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError as ModelValidationError
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables import conftest as tables
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import CodeFactsArtifact, CorpusRegistryArtifact
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import ArtifactRef, Provenance
from traust_core.v1.models.corpus import CorpusRegistry, CorpusSubject
from traust_core.v1.models.insight import ExecutiveSummary, LocDashboard, ViewFilter, ViewName
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.vocabulary import OwnershipClass, SourceType
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpec, PublishSpecs

engine = tables.engine
DAY = timedelta(days=1)


def record(ctx: Context, ref_id: UUID, code: int, days: int) -> None:
    doc = CodeFactsArtifact.from_document(
        {
            "artifact": "code-facts",
            "symbols": [],
            "languages": [
                {"name": name, "files": None, "code": lines, "comments": None, "blanks": None}
                for name, lines in (("Python", code), ("Markdown", 20))
            ],
        }
    )
    published = ArtifactPublisher(
        PublishSpecs(PublishSpec(CodeFactsArtifact)),
        ctx.object_store,
        SqlTraustUnitOfWork(ctx.database),
    ).publish_artifact(doc)
    ctx.services().assessment.record(
        doc,
        ref_id,
        AssessmentKind.TOOL_SCAN,
        "tool:fixture",
        "1",
        Provenance(
            run_id=uuid4(),
            source=SourceType.INTERACTIVE,
            occurred_at=T0 + days * DAY,
            artifact=ArtifactRef(
                id=published.artifact_id, name="code-facts", digest=sha256_hex(doc.payload)
            ),
        ),
    )


def test_loc_selects_both_historical_head_and_measurement_without_future_leakage(
    engine: Engine,
    tmp_path: Path,
) -> None:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0 + 10 * DAY))
    ctx.__dict__["database"] = engine
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        early = seed.repository_ref(repo, sha="a" * 40, is_default=True)
        later = seed.repository_ref(repo, sha="b" * 40, is_default=True)
        seed.assessment(early, kind=AssessmentKind.REPO_STATE, occurred_at=T0)
        seed.assessment(later, kind=AssessmentKind.REPO_STATE, occurred_at=T0 + 5 * DAY)
        unknown = seed.repository()
        empty = seed.repository_ref(unknown, is_default=True)
        seed.assessment(empty, kind=AssessmentKind.REPO_STATE, occurred_at=T0)
        uow.commit()
    assert early.id and later.id and empty.id
    record(ctx, early.id, 100, 1)
    record(ctx, early.id, 900, 7)
    record(ctx, later.id, 300, 6)
    record(ctx, empty.id, 0, 8)
    insight = ctx.services().insight
    historical = insight.build(ViewName.LOC, ViewFilter(as_of=T0 + 2 * DAY))
    assert isinstance(historical, LocDashboard)
    assert (historical.code, historical.total) == (100, 120)
    found = {r.repository_id: r for r in historical.repositories}
    assert found[repo.id].repository_ref_id == early.id
    assert found[unknown.id].unmeasured is not None
    assert found[unknown.id].code is None and found[unknown.id].total is None
    assert found[repo.id].languages[1].name == "Markdown"
    executive = insight.build(ViewName.EXECUTIVE_SUMMARY, ViewFilter(as_of=T0 + 2 * DAY))
    assert isinstance(executive, ExecutiveSummary)
    assert {row.language: row.repositories for row in executive.languages} == {
        "Python": 1,
        "unknown": 1,
    }
    current = insight.build(
        ViewName.LOC,
        ViewFilter(
            as_of=T0 + 9 * DAY,
            compare_as_of=T0 + 2 * DAY,
            first_party_divisor=Decimal("2.5"),
        ),
    )
    assert isinstance(current, LocDashboard)
    assert (current.code, current.total, current.first_party_estimate) == (300, 340, 120)
    assert current.comparison is not None
    assert (
        current.comparison.code,
        current.comparison.measured_repositories,
        current.comparison.comparable_repositories,
        current.comparison.code_delta,
        current.comparison.total_delta,
    ) == (100, 1, 1, 200, 200)
    rows = {r.repository_id: r for r in current.repositories}
    assert rows[repo.id].repository_ref_id == later.id
    assert rows[repo.id].code_delta == 200
    assert rows[unknown.id].code == 0 and rows[unknown.id].unmeasured is None
    assert rows[unknown.id].code_delta is None
    assert insight.build(ViewName.LOC, ViewFilter()).first_party_estimate is None


@pytest.mark.parametrize("divisor", ["0", "-1", "NaN", "Infinity"])
def test_calibration_requires_an_explicit_finite_positive_divisor(divisor: str) -> None:
    with pytest.raises(ModelValidationError):
        ViewFilter(first_party_divisor=Decimal(divisor))


def test_loc_rejects_nonpreceding_comparisons(engine: Engine, tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0 + DAY))
    ctx.__dict__["database"] = engine
    with pytest.raises(ValidationError):
        ctx.services().insight.build(
            ViewName.LOC,
            ViewFilter(
                as_of=T0,
                compare_as_of=T0 + DAY,
            ),
        )
    with pytest.raises(ValidationError):
        ctx.services().insight.build(ViewName.LOC, ViewFilter(compare_as_of=T0 + DAY))


def test_corpus_buckets_preserve_registered_membership_without_double_counting_headlines(
    engine: Engine,
    tmp_path: Path,
) -> None:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0 + DAY))
    ctx.__dict__["database"] = engine
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        product = seed.product()
        ref = seed.repository_ref(is_default=True)
        seed.component(seed.release(product), ref)
        seed.assessment(ref, kind=AssessmentKind.REPO_STATE, occurred_at=T0)
        repo = uow.repositories.get(ref.repository_id)
        seed.repository()
        uow.commit()
    registry = CorpusRegistry(
        subjects=(
            CorpusSubject(
                subject_id=str(product.id),
                tree="findings",
                ownership=OwnershipClass.OWNED,
                business_unit="alpha",
            ),
            CorpusSubject(
                subject_id="explicit-repo",
                tree="oss-findings",
                repo_url=repo.url,
                ownership=OwnershipClass.OWNED,
                business_unit="alpha",
            ),
        )
    ).to_artifact()
    ArtifactPublisher(
        PublishSpecs(PublishSpec(CorpusRegistryArtifact)),
        ctx.object_store,
        SqlTraustUnitOfWork(engine),
    ).publish_artifact(registry)
    assert ref.id is not None
    record(ctx, ref.id, 100, 0)
    model = ctx.services().insight.build(ViewName.LOC, ViewFilter())
    assert isinstance(model, LocDashboard)
    assert (model.code, model.total, len(model.repositories)) == (100, 120, 2)
    assert next(r for r in model.repositories if r.repository_id == repo.id).corpus_trees == (
        "findings",
        "oss-findings",
    )
    buckets = {b.tree: b for b in model.corpus_buckets}
    assert (buckets["findings"].code, buckets["oss-findings"].code) == (100, 100)
    assert (buckets[None].repositories, buckets[None].measured) == (1, 0)


def test_no_measurements_never_become_an_estimated_first_party_zero(
    engine: Engine,
    tmp_path: Path,
) -> None:
    ctx = Context(Config(home=tmp_path))
    ctx.__dict__["database"] = engine
    with SqlTraustUnitOfWork(engine) as uow:
        Seed(uow).repository()
        uow.commit()
    model = ctx.services().insight.build(
        ViewName.LOC, ViewFilter(first_party_divisor=Decimal("2.5"))
    )
    assert model.first_party_estimate is None
    assert model.repositories[0].unmeasured is not None
    assert model.repositories[0].code is None and model.repositories[0].total is None
