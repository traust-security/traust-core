"""`AssessmentService.record` as a caller outside core reaches it (`Context.services()`): the
document published when provenance names none, the assessment of its kind on the commit."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError, IntegrityError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import (
    ArtifactDocument,
    CloudConfigAuditArtifact,
    IsolationReviewArtifact,
    PrivProfileArtifact,
    ReportArtifact,
    RepoStateArtifact,
    SecurityAuditArtifact,
    ThreatModelArtifact,
    VulnFindingsArtifact,
)
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    ASSESSMENT_DEGRADED,
    RECORDED_SCHEMAS,
    Assessment,
    AssessmentKind,
)
from traust_core.v1.models.common import ArtifactRef, Provenance
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey
from traust_core.v1.services.artifact_publishing import AssessmentLog, PublishSpec, PublishSpecs

FIXTURES = Path(__file__).parents[2] / "fixtures"
WHEN = datetime(2026, 10, 23, 9, tzinfo=UTC)


def fixture(path: str) -> bytes:
    return (FIXTURES / path).read_bytes()


ISOLATION = IsolationReviewArtifact.parse(fixture("assessments/widget-isolation-review.json"))
REPORT = ReportArtifact.parse(fixture("assessments/widget-audit-report.json"))
PROFILE = PrivProfileArtifact.parse(fixture("assessments/widget-operator-priv-profile.json"))
_threat_body = json.loads(fixture("assessments/widget-threat-model.json"))
THREATS = ThreatModelArtifact.from_document(
    {
        **_threat_body,
        "mitigations": [{**m, "effort": "s"} for m in _threat_body["mitigations"]],
    }
)

RECORDABLE: list[tuple[AssessmentKind, ArtifactDocument]] = [
    (AssessmentKind.SECURE_CODE_CANONICAL, SecurityAuditArtifact.parse(REPORT.payload)),
    (AssessmentKind.CONTAINER, REPORT),
    (AssessmentKind.RPM, SecurityAuditArtifact.parse(REPORT.payload)),
    (AssessmentKind.BENCHMARK_AUDIT, SecurityAuditArtifact.parse(REPORT.payload)),
    (
        AssessmentKind.VULN_SCAN_CANONICAL,
        VulnFindingsArtifact.parse(fixture("assessments/widget-vuln-findings.json")),
    ),
    (AssessmentKind.THREAT_MODEL_CANONICAL, THREATS),
    (AssessmentKind.ISOLATION_REVIEW_CANONICAL, ISOLATION),
    (AssessmentKind.PRIV_PROFILE_CANONICAL, PROFILE),
    (
        AssessmentKind.CLOUD_CONFIG_CANONICAL,
        CloudConfigAuditArtifact.parse(fixture("cloud_config/myrepo-cloud-config-audit.json")),
    ),
]


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path))
    ctx.__dict__["database"] = engine
    return ctx


@pytest.fixture
def ref(engine: Engine) -> UUID:
    with SqlTraustUnitOfWork(engine) as uow:
        saved = Seed(uow).repository_ref()
        uow.commit()
    assert saved.id is not None
    return saved.id


def provenance(artifact: ArtifactRef | None = None) -> Provenance:
    return Provenance(
        run_id=uuid4(), artifact=artifact, source=SourceType.INTERACTIVE, occurred_at=WHEN
    )


def record(
    context: Context,
    doc: ArtifactDocument,
    ref: UUID,
    kind: AssessmentKind,
    artifact: ArtifactRef | None = None,
    status: str = ASSESSMENT_COMPLETED,
) -> Assessment:
    return context.services().assessment.record(
        doc,  # type: ignore[arg-type]
        ref,
        kind,
        "skill:test",
        "0.1.0",
        provenance(artifact),
        status=status,
    )


def publish(context: Context, doc: ArtifactDocument) -> ArtifactRef:
    return context.artifact_publisher(PublishSpecs(PublishSpec(type(doc)))).publish_ref(doc)


def test_every_audit_kind_is_exercised() -> None:
    # tool_scan (code-facts) and repo-state run through record in their owners' tests
    owned = {AssessmentKind.TOOL_SCAN, AssessmentKind.REPO_STATE_CANONICAL}
    assert {k for k, _ in RECORDABLE} == set(RECORDED_SCHEMAS) - owned


@pytest.mark.parametrize(("kind", "doc"), RECORDABLE, ids=[k for k, _ in RECORDABLE])
def test_an_unpublished_document_is_published_and_held_by_the_assessment(
    context: Context, ref: UUID, kind: AssessmentKind, doc: ArtifactDocument
) -> None:
    assessment = record(context, doc, ref, kind)

    assert (assessment.repository_ref_id, assessment.kind, assessment.status) == (
        ref,
        kind,
        ASSESSMENT_COMPLETED,
    )
    assert (assessment.assessor, assessment.assessor_version, assessment.occurred_at) == (
        "skill:test",
        "0.1.0",
        WHEN,
    )
    with SqlTraustUnitOfWork(context.database) as uow:
        [held] = uow.artifacts.list_for_assessment(assessment.id)  # type: ignore[arg-type]
        published = uow.artifacts.find(None, sha256_hex(doc.payload))
    assert (held.kind, held.digest) == (doc.schema, sha256_hex(doc.payload))
    assert published is not None and published.uri == held.uri
    stored = context.object_store.get(context.object_store.stat(ObjectKey.parse(held.uri)))
    assert stored == doc.payload


def test_the_same_run_again_is_the_same_assessment(context: Context, ref: UUID) -> None:
    first = record(context, ISOLATION, ref, AssessmentKind.ISOLATION_REVIEW_CANONICAL)
    again = record(context, ISOLATION, ref, AssessmentKind.ISOLATION_REVIEW_CANONICAL)

    assert again == first
    with SqlTraustUnitOfWork(context.database) as uow:
        assert uow.assessments.list_for_ref(ref) == [first]
        assert len(uow.artifacts.list_for_assessment(first.id)) == 1  # type: ignore[arg-type]


def test_the_same_document_from_a_later_run_is_a_new_assessment(
    context: Context, ref: UUID
) -> None:
    first = record(context, ISOLATION, ref, AssessmentKind.ISOLATION_REVIEW_CANONICAL)
    later = context.services().assessment.record(
        ISOLATION,
        ref,
        AssessmentKind.ISOLATION_REVIEW_CANONICAL,
        "skill:test",
        "0.1.0",
        provenance().model_copy(update={"occurred_at": WHEN + timedelta(days=1)}),
    )

    assert later.id != first.id
    assert (
        context.services().assessment.latest(ref, AssessmentKind.ISOLATION_REVIEW_CANONICAL)
        == later
    )


def test_one_report_recorded_as_two_kinds_is_two_assessments_over_one_published_copy(
    context: Context, ref: UUID
) -> None:
    container = record(context, REPORT, ref, AssessmentKind.CONTAINER)
    rpm = record(context, REPORT, ref, AssessmentKind.RPM)

    assert container.id != rpm.id
    with SqlTraustUnitOfWork(context.database) as uow:
        uris = {
            row.uri
            for a in (container, rpm)
            for row in uow.artifacts.list_for_assessment(a.id)  # type: ignore[arg-type]
        }
    assert len(uris) == 1


def test_a_document_published_earlier_is_recorded_by_its_reference(
    context: Context, ref: UUID
) -> None:
    published = publish(context, PROFILE)

    assessment = record(
        context,
        PROFILE,
        ref,
        AssessmentKind.PRIV_PROFILE_CANONICAL,
        published,
        ASSESSMENT_DEGRADED,
    )

    assert assessment.status == ASSESSMENT_DEGRADED
    with SqlTraustUnitOfWork(context.database) as uow:
        [held] = uow.artifacts.list_for_assessment(assessment.id)  # type: ignore[arg-type]
    assert held.digest == published.digest


def test_a_reference_to_other_bytes_links_nothing(context: Context, ref: UUID) -> None:
    other = publish(context, THREATS)
    claimed = ArtifactRef(id=other.id, name=ISOLATION.name, digest=sha256_hex(ISOLATION.payload))

    with pytest.raises(IntegrityError, match="doc digest"):
        record(context, ISOLATION, ref, AssessmentKind.ISOLATION_REVIEW_CANONICAL, claimed)
    with SqlTraustUnitOfWork(context.database) as uow:
        assert uow.assessments.list_for_ref(ref) == []


@pytest.mark.parametrize(
    ("kind", "doc", "error", "match"),
    [
        (AssessmentKind.FUZZ, ISOLATION, ConfigError, "recorded by their owner's door"),
        (AssessmentKind.TRIAGE, REPORT, ConfigError, "recorded by their owner's door"),
        (
            AssessmentKind.PRIV_PROFILE_CANONICAL,
            THREATS,
            ValidationError,
            "holds a operator-priv-profile",
        ),
        (
            AssessmentKind.SECURE_CODE_CANONICAL,
            ISOLATION,
            ValidationError,
            "holds a report document",
        ),
        (
            AssessmentKind.REPO_STATE_CANONICAL,
            RepoStateArtifact.from_document({"observed_at": WHEN.isoformat(), "status": "ok"}),
            ConfigError,
            "unknown artifact 'repo-state'",
        ),
    ],
    ids=["no-schema-kind", "owned-elsewhere", "wrong-schema", "report-kind-wrong-doc", "unwired"],
)
def test_refused_documents_record_nothing(
    context: Context,
    ref: UUID,
    kind: AssessmentKind,
    doc: ArtifactDocument,
    error: type[Exception],
    match: str,
) -> None:
    with pytest.raises(error, match=match):
        record(context, doc, ref, kind)
    with SqlTraustUnitOfWork(context.database) as uow:
        assert uow.assessments.list_for_ref(ref) == []


def test_an_unknown_commit_publishes_nothing(context: Context) -> None:
    with pytest.raises(NotFoundError):
        record(context, ISOLATION, uuid4(), AssessmentKind.ISOLATION_REVIEW_CANONICAL)
    with SqlTraustUnitOfWork(context.database) as uow:
        assert uow.artifacts.find(None, sha256_hex(ISOLATION.payload)) is None


@pytest.mark.parametrize("published_first", [False, True])
def test_new_threat_mitigation_writes_reject_historical_effort_before_recording(
    context: Context, ref: UUID, published_first: bool
) -> None:
    legacy = ThreatModelArtifact.parse(fixture("assessments/widget-threat-model.json"))
    artifact = publish(context, legacy) if published_first else None
    with pytest.raises(ValidationError):
        record(context, legacy, ref, AssessmentKind.THREAT_MODEL_CANONICAL, artifact)
    with SqlTraustUnitOfWork(context.database) as uow:
        assert uow.assessments.list_for_ref(ref) == []
        if not published_first:
            assert uow.artifacts.find(None, sha256_hex(legacy.payload)) is None


def test_unknown_mitigation_size_is_recordable_without_erasing_external_blocking(
    context: Context, ref: UUID
) -> None:
    body = json.loads(THREATS.payload)
    body["mitigations"][0].update(effort=None, blocked_external=True)
    doc = ThreatModelArtifact.from_document(body)
    saved = record(context, doc, ref, AssessmentKind.THREAT_MODEL_CANONICAL)
    with SqlTraustUnitOfWork(context.database) as uow:
        [held] = uow.artifacts.list_for_assessment(saved.id)
    assert held.id is not None
    restored = context.artifact_publisher(PublishSpecs(PublishSpec(ThreatModelArtifact))).get(
        held.id
    )
    assert restored.payload == doc.payload
    assert restored.mitigations[0].effort is None
    assert restored.mitigations[0].blocked_external is True


def test_stored_historical_threat_model_replays_but_cannot_start_a_new_legacy_run(
    context: Context, ref: UUID
) -> None:
    legacy = ThreatModelArtifact.parse(fixture("assessments/widget-threat-model.json"))
    artifact = publish(context, legacy)
    historical, _ = AssessmentLog(SqlTraustUnitOfWork(context.database)).add(
        Assessment(
            repository_ref_id=ref,
            kind=AssessmentKind.THREAT_MODEL,
            status=ASSESSMENT_COMPLETED,
            assessor="skill:test",
            assessor_version="0.1.0",
            occurred_at=WHEN,
        ),
        artifact.id,
        artifact.digest,
    )
    replay = record(context, legacy, ref, AssessmentKind.THREAT_MODEL_CANONICAL, artifact)
    assert replay.id == historical.id
    assert replay.kind == AssessmentKind.THREAT_MODEL_CANONICAL
    with pytest.raises(ValidationError):
        context.services().assessment.record(
            legacy,
            ref,
            AssessmentKind.THREAT_MODEL_CANONICAL,
            "skill:test",
            "0.1.0",
            provenance().model_copy(update={"occurred_at": WHEN + timedelta(days=1)}),
        )
    with SqlTraustUnitOfWork(context.database) as uow:
        assert [a.id for a in uow.assessments.list_for_ref(ref)] == [historical.id]
    restored = context.artifact_publisher(PublishSpecs(PublishSpec(ThreatModelArtifact))).get(
        artifact.id
    )
    assert restored.payload == legacy.payload
    assert restored.mitigations[0].effort == "S"


def test_mitigation_write_gate_validates_the_actual_bytes_not_a_forged_view(
    context: Context, ref: UUID
) -> None:
    class AlternateThreatDocument(ArtifactDocument, schema=ThreatModelArtifact.schema):
        pass

    legacy = fixture("assessments/widget-threat-model.json")
    forged = AlternateThreatDocument(legacy, json.loads(THREATS.payload))
    assert forged.mitigations[0].effort == "s"
    with pytest.raises(ValidationError):
        record(context, forged, ref, AssessmentKind.THREAT_MODEL_CANONICAL)
    with SqlTraustUnitOfWork(context.database) as uow:
        assert uow.assessments.list_for_ref(ref) == []
        assert uow.artifacts.find(None, sha256_hex(legacy)) is None
