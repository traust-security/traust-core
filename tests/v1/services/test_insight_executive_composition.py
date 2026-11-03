from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.test_detection_quality import finding, report, target
from tests.v1.services.test_insight_census import register
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.artifacts import (
    ArtifactDocument,
    BenchmarkTargetArtifact,
    CloudConfigAuditArtifact,
    FuzzReportArtifact,
    IsolationReviewArtifact,
    PrivProfileArtifact,
    ThreatModelArtifact,
)
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.detection_quality import BenchmarkFilter
from traust_core.v1.models.insight import (
    ExecutivePanel,
    ExecutiveSummary,
    Scoreboard,
    ViewFilter,
    ViewName,
)
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.vocabulary import OwnershipClass, SourceType
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    AssessmentLog,
    PublishSpec,
    PublishSpecs,
)

DAY = timedelta(days=1)
FIXTURES = Path(__file__).parents[2] / "fixtures"


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0 + 20 * DAY))
    ctx.__dict__["database"] = engine
    return ctx


def attach(
    context: Context,
    uow: SqlTraustUnitOfWork,
    ref: RepositoryRef,
    kind: AssessmentKind,
    document: ArtifactDocument,
    occurred_at: datetime = T0,
    assessor_version: str = "test",
) -> Assessment:
    assessment = Seed(uow).assessment(
        ref, kind=kind, occurred_at=occurred_at, assessor_version=assessor_version
    )
    published = ArtifactPublisher(
        PublishSpecs(PublishSpec(type(document))), context.object_store, uow
    ).publish_artifact(document)
    AssessmentLog(uow).attach(assessment.id, published.artifact_id, sha256_hex(document.payload))
    return assessment


def executive(context: Context, filter: ViewFilter) -> ExecutiveSummary:
    model = context.services().insight.build(ViewName.EXECUTIVE_SUMMARY, filter)
    assert isinstance(model, ExecutiveSummary)
    return model


def test_segment_matrix_is_first_match_additive_and_accounts_for_excluded_and_unmapped(
    context: Context,
    engine: Engine,
    tmp_path: Path,
) -> None:
    root = tmp_path / "inputs"
    root.mkdir()
    (root / "inventory.yaml").write_text(
        "segments:\n  beta: groups\n  alpha: groups\n  ansible: groups\n"
    )
    for segment, names in (("alpha", ("a", "b")), ("beta", ("a",)), ("ansible", ("c",))):
        directory = root / segment
        directory.mkdir()
        (directory / "scope-repos.csv").write_text(
            "URL\n" + "".join(f"https://github.com/example-org/{n}.git\n" for n in names)
        )
    context.register_input_segments(root)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        for name, severity in (("a", "critical"), ("b", "high"), ("c", "medium"), ("d", "low")):
            repo = seed.repository(url=f"https://github.com/example-org/{name}")
            audit = seed.assessment(seed.repository_ref(repo, is_default=True), occurred_at=T0)
            seed.occurrence(seed.finding(repo), audit, severity=severity)
        uow.commit()
    model = executive(context, ViewFilter(by_segment=True))
    cut = model.segments
    assert cut is not None
    assert [(r.segment, r.repositories, r.tally.open.total) for r in cut.rows] == [
        ("beta", 1, 1),
        ("alpha", 1, 1),
        ("unmapped", 1, 1),
    ]
    assert cut.rows[0].tally.open.critical == 1
    assert cut.overlapping == ("https://github.com/example-org/a",)
    assert cut.unmapped == ("https://github.com/example-org/d",)
    assert cut.excluded == ("https://github.com/example-org/c",)
    assert sum(r.repositories for r in cut.rows) + len(cut.excluded) == len(
        model.rollup.repositories
    )
    assert model.rollup.total.open.total == 4
    moved = executive(context, ViewFilter(by_segment=True, exclude_segments=("beta", "ansible")))
    assert moved.segments is not None
    assert moved.segments.rows[0].segment == "alpha"
    assert moved.segments.rows[0].tally.open.total == 2
    assert moved.segments.overlapping == ()
    assert executive(context, ViewFilter()).segments is None


def test_requesting_segments_without_a_source_fails_without_fabricating_a_matrix(
    context: Context,
) -> None:
    with pytest.raises(ConfigError):
        executive(context, ViewFilter(by_segment=True))


def test_advisory_accountability_joins_aliases_and_honors_the_filing_and_resolution_cutoff(
    context: Context,
    engine: Engine,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        advisory = seed.advisory(identifier="CVE-2026-12345")
        alias = seed.advisory(identifier="GHSA-2345-6789-cfgh", alias_of_id=advisory.id)
        repo = seed.repository(url="https://github.com/example-org/svc")
        audit = seed.assessment(seed.repository_ref(repo, is_default=True), occurred_at=T0)
        opened = seed.finding(repo, advisory_id=alias.id, advisory_match="confirmed")
        fixed = seed.finding(repo, advisory_id=advisory.id, advisory_match="confirmed")
        for finding in (opened, fixed):
            seed.occurrence(finding, audit, severity="high")
        seed.finding_external_ref(opened)
        seed.decision(
            fixed,
            validity="confirmed",
            resolution="resolved",
            actor="human:analyst@example.com",
            occurred_at=T0 + DAY,
        )
        uow.commit()
    now = datetime.now(UTC) + DAY
    (row,) = executive(context, ViewFilter(as_of=now)).accountability
    assert (row.advisory, row.findings, row.filed, row.resolved) == ("CVE-2026-12345", 2, 1, 1)
    assert row.affected is None  # no impact analysis, not zero affected commits
    (before,) = executive(context, ViewFilter(as_of=T0 + DAY / 2)).accountability
    assert (before.findings, before.filed, before.resolved) == (2, 0, 0)


def test_optional_panels_read_latest_domain_documents_and_render_the_same_composition(
    context: Context,
    engine: Engine,
) -> None:
    review = json.loads((FIXTURES / "assessments/widget-isolation-review.json").read_text())
    review["metadata"]["service"] = "<script>tenant</script>"
    review["posture"]["overall"] = "weak"
    cloud = CloudConfigAuditArtifact.parse(
        (FIXTURES / "cloud_config/myrepo-cloud-config-audit.json").read_bytes()
    )
    profile = json.loads((FIXTURES / "assessments/widget-operator-priv-profile.json").read_text())
    profile["tier2_required_vs_granted"]["shipped_not_declared_count"] = 7
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url="https://github.com/example-org/myrepo")
        ref = seed.repository_ref(repo, is_default=True)
        attach(
            context,
            uow,
            ref,
            AssessmentKind.ISOLATION_REVIEW_CANONICAL,
            IsolationReviewArtifact.from_document(review),
        )
        review["posture"]["overall"] = "strong"
        attach(
            context,
            uow,
            ref,
            AssessmentKind.ISOLATION_REVIEW_CANONICAL,
            IsolationReviewArtifact.from_document(review),
            T0 + 5 * DAY,
        )
        audit = attach(context, uow, ref, AssessmentKind.CLOUD_CONFIG_CANONICAL, cloud)
        found = seed.finding(repo)
        seed.occurrence(found, audit, severity="critical")
        seed.decision(
            found, validity="confirmed", actor="human:analyst@example.com", occurred_at=T0
        )
        attach(
            context,
            uow,
            ref,
            AssessmentKind.PRIV_PROFILE_CANONICAL,
            PrivProfileArtifact.from_document(profile),
        )
        uow.commit()
    scope = ViewFilter(
        as_of=T0 + DAY, executive_panels=(ExecutivePanel.ISOLATION, ExecutivePanel.IAC)
    )
    built = executive(context, scope)
    assert built.isolation is not None and built.iac is not None
    (isolation,) = built.isolation.reviews
    assert (isolation.posture, isolation.interfaces, isolation.gaps) == ("weak", 1, 1)
    assert built.rollup.as_of == built.isolation.threat_register.as_of == scope.as_of
    assert isolation.dimensions == {"yes": 3, "partial": 1, "na": 1}
    (target,) = built.iac.targets
    assert (target.unsuppressed, target.suppressed, target.needs_review, target.ledgered) == (
        5,
        1,
        1,
        1,
    )
    assert target.severities.critical == 3
    assert built.privileges.surplus_scored == 1
    assert [r.surplus for r in built.top_surplus] == [7]
    later = executive(context, scope.model_copy(update={"as_of": T0 + 6 * DAY}))
    assert later.isolation is not None and later.isolation.reviews[0].posture == "strong"
    rendered = context.services().insight.publish(ViewName.EXECUTIVE_SUMMARY, scope)
    assert rendered.model == built
    assert "&lt;script&gt;tenant&lt;/script&gt;" in rendered.html
    assert "<script>tenant</script>" not in rendered.html
    headings = {
        s.heading
        for s in context.services().insight.report(ViewName.EXECUTIVE_SUMMARY, scope).sections
    }
    assert {
        "Tenant-isolation posture (PEACH)",
        "Declared IaC targets",
        "Top measured RBAC surplus",
    } <= headings
    plain = executive(context, ViewFilter())
    assert (plain.attack, plain.pqc, plain.isolation, plain.iac) == (None, None, None, None)


def test_threat_ownership_cuts_include_zero_threat_models_and_keep_unregistered_explicit(
    context: Context,
    engine: Engine,
) -> None:
    owned = register(context, "owned", OwnershipClass.OWNED)
    upstream = register(context, "upstream", OwnershipClass.UPSTREAM)
    document = json.loads((FIXTURES / "assessments/widget-threat-model.json").read_text())
    threat_count = len(document["threats"])
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url="https://github.com/example-org/svc")
        ref = seed.repository_ref(repo, is_default=True)
        seed.component(seed.release(owned), ref)
        seed.component(seed.release(upstream), ref)
        attach(
            context,
            uow,
            ref,
            AssessmentKind.THREAT_MODEL_CANONICAL,
            ThreatModelArtifact.from_document(document),
        )
        document["threats"] = []
        empty = seed.repository_ref(
            seed.repository(url="https://github.com/example-org/empty"), is_default=True
        )
        attach(
            context,
            uow,
            empty,
            AssessmentKind.THREAT_MODEL_CANONICAL,
            ThreatModelArtifact.from_document(document),
        )
        uow.commit()
    register_model = context.services().insight.build(ViewName.THREAT_REGISTER, ViewFilter())
    by = {cut.ownership: cut for cut in register_model.ownership}
    assert register_model.models == 2
    assert by[OwnershipClass.OWNED].models == by[OwnershipClass.UPSTREAM].models == 1
    assert by[OwnershipClass.OWNED].threats == by[OwnershipClass.UPSTREAM].threats == threat_count
    assert by[None].models == 1 and by[None].threats == 0
    earlier = context.services().insight.build(ViewName.THREAT_REGISTER, ViewFilter(as_of=T0 - DAY))
    assert earlier.models == 0 and all(c.models == 0 for c in earlier.ownership)


def test_scoreboard_composes_real_domain_models_without_turning_unknown_recall_into_zero(
    context: Context,
    engine: Engine,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        ref = seed.repository_ref(repo, is_default=True)
        assessment = seed.assessment(ref, occurred_at=T0)
        found = seed.finding(repo)
        occurrence = seed.occurrence(found, assessment, severity="high")
        seed.location(occurrence, path="src/a.py", language="python")
        seed.finding_cwe(found, seed.cwe(identifier="CWE-89"))
        attach(
            context,
            uow,
            ref,
            AssessmentKind.FUZZ,
            FuzzReportArtifact.parse(
                (FIXTURES / "assessments/widget-fuzz-report.json").read_bytes()
            ),
        )
        uow.commit()
    service = context.services().insight
    board = service.build(ViewName.SCOREBOARD, ViewFilter())
    assert isinstance(board, Scoreboard)
    pinned = ViewFilter(as_of=board.as_of)
    assert board.validation == service.build(ViewName.VALIDATION_FUZZ, pinned)
    assert board.census == service.build(ViewName.CENSUS, pinned)
    assert board.patterns == service.build(ViewName.INSECURE_PATTERNS, pinned)
    assert len(board.validation.targets) == len(board.validation.crashers) == 1
    assert len(board.validation.gaps) == 2
    assert board.census.cuts[0].distinct.high == 1
    assert board.patterns.cuts[0].patterns[0].cwe == "CWE-89"
    assert board.recall is None and board.recall_unavailable is not None
    assert board.maturity is None


def test_attack_and_pqc_are_embedded_models_and_rendered_panels(context: Context) -> None:
    attack = FIXTURES / "insight/attack"
    context.register_attack_catalog(
        attack / "attack-techniques.json", attack / "attack-mapping.json"
    )
    scope = ViewFilter(executive_panels=(ExecutivePanel.ATTACK, ExecutivePanel.PQC))
    model = executive(context, scope)
    service = context.services().insight
    assert model.attack is not None
    assert model.attack.as_of == model.rollup.as_of == T0 + 20 * DAY
    assert model.attack == service.build(ViewName.ATTACK_COVERAGE, ViewFilter())
    assert model.pqc == service.build(ViewName.PQC_PORTFOLIO, ViewFilter())
    rendered = service.publish(ViewName.EXECUTIVE_SUMMARY, scope)
    assert rendered.model == model
    sections = service.report(ViewName.EXECUTIVE_SUMMARY, scope).sections
    assert any(section.heading.startswith("ATT&CK") for section in sections)
    assert any(section.heading.startswith("PQC") for section in sections)


def test_benchmark_scorecards_and_scoreboard_exclude_future_audits(
    context: Context,
    engine: Engine,
) -> None:
    now = datetime.now(UTC)
    context.services().detection_quality.record(
        BenchmarkTargetArtifact.from_document(
            {"version": 1, "updated": now.date().isoformat(), "targets": [target()]}
        ),
        Provenance(run_id=uuid4(), source=SourceType.INTERACTIVE, occurred_at=T0),
    )
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref(seed.repository(url=target()["repo_url"]), is_default=True)
        attach(context, uow, ref, AssessmentKind.BENCHMARK_AUDIT, report(finding()), T0, "early")
        attach(context, uow, ref, AssessmentKind.BENCHMARK_AUDIT, report(), now + 3 * DAY, "future")
        uow.commit()
    cutoff = now + DAY
    service = context.services().detection_quality
    (card,) = service.scorecards(BenchmarkFilter(as_of=cutoff))
    assert card.auditor_versions == ("early",)
    assert (card.overall.detected, card.overall.expected) == (1, 1)
    board = context.services().insight.build(ViewName.SCOREBOARD, ViewFilter(as_of=cutoff))
    assert board.recall == (card,) and board.recall_unavailable is None
    assert len(service.scorecards(BenchmarkFilter(as_of=now + 4 * DAY))) == 2


def test_an_inventory_segment_named_unmapped_does_not_capture_unknown_repositories(
    context: Context,
    engine: Engine,
    tmp_path: Path,
) -> None:
    root = tmp_path / "inputs"
    (root / "unmapped").mkdir(parents=True)
    (root / "unmapped/scope-repos.csv").write_text("URL\nhttps://github.com/example-org/known\n")
    context.register_input_segments(root)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        for name in ("known", "unknown"):
            seed.repository(url=f"https://github.com/example-org/{name}")
        uow.commit()
    cut = executive(context, ViewFilter(by_segment=True)).segments
    assert cut is not None
    assert [(r.segment, r.mapped, r.repositories) for r in cut.rows] == [
        ("unmapped", True, 1),
        ("unmapped", False, 1),
    ]
    assert cut.unmapped == ("https://github.com/example-org/unknown",)
