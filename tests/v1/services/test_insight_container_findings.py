from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.test_assessment_record import authored_report
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import SecurityAuditArtifact
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import FindingCandidate, FindingState
from traust_core.v1.models.insight import ContainerFindings, FindingsRollup, ViewFilter, ViewName
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

DAY = timedelta(days=1)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as database:
        yield database


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    context = Context(Config(home=tmp_path), clock=FixedClock(T0 + 20 * DAY))
    context.__dict__["database"] = engine
    return context


def record_container(
    context: Context, ref_id: UUID, image: str, day: int, indices: tuple[int, ...] = (0, 1)
) -> UUID:
    body = json.loads(authored_report().payload)
    body["title"] = f"Container assessment {day}: {image}"
    body["metadata"] = {
        "date": (T0 + day * DAY).date().isoformat(),
        "repository": image,
        "commit": str(day % 10) * 64,
        "audit_profile": "container",
        "scope": image,
    }
    body["findings"] = [body["findings"][i] for i in indices]
    for finding in body["findings"]:
        finding.pop("validation_status", None)
        finding.pop("disposition", None)
        finding.pop("effective_severity", None)
    saved = context.services().assessment.record(
        SecurityAuditArtifact.from_document(body),
        ref_id,
        AssessmentKind.CONTAINER,
        "skill:secure-container-audit",
        "test",
        Provenance(run_id=uuid4(), source=SourceType.INTERACTIVE, occurred_at=T0 + day * DAY),
    )
    assert saved.id is not None
    return saved.id


def test_container_population_is_cumulative_image_scoped_and_decision_driven(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref()
        uow.commit()
    assert ref.id is not None
    first = record_container(context, ref.id, "registry.example:5000/apps/widget@sha256:aaa", 0)
    second = record_container(context, ref.id, "registry.example:5000/apps/widget:release", 1, (0,))
    empty = record_container(context, ref.id, "registry.example:5000/apps/widget@sha256:ccc", 2, ())
    record_container(context, ref.id, "registry.example:5000/apps/other@sha256:ddd", 3, (2,))
    findings = context.services().findings
    initial = findings.occurrences(assessment_id=first)
    assert len(initial) == 2
    repeated = findings.occurrences(assessment_id=second)[0].finding_id
    absent = next(o.finding_id for o in initial if o.finding_id != repeated)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        code = seed.assessment(ref, kind="secure-code", occurred_at=T0 + 4 * DAY)
        original = uow.findings.get(repeated)
        seed.occurrence(original, code, severity="critical")
        seed.occurrence(
            seed.finding(uow.repositories.get(ref.repository_id)), code, severity="high"
        )
        seed.decision(
            original,
            validity="confirmed",
            resolution="resolved",
            actor="human:analyst@example.com",
            occurred_at=T0 + 5 * DAY,
        )
        uow.commit()
    scope = ViewFilter(assessment_id=empty, report_stem="widget-container-audit")
    rendered = context.services().insight.publish(ViewName.CONTAINER_FINDINGS, scope)
    model = rendered.model
    assert isinstance(model, ContainerFindings)
    assert rendered.stem == "widget-container-audit-findings-current"
    assert model.image_repository == "registry.example:5000/apps/widget"
    assert [r.assessment_id for r in model.reports] == [first, second, empty]
    by_id = {row.view.finding.id: row for row in model.findings}
    assert set(by_id) == {repeated, absent}
    assert len(by_id[repeated].occurrences) == 2
    assert by_id[repeated].view.occurrence.assessment_id == second
    assert by_id[repeated].view.effective_severity == "high"
    assert by_id[repeated].view.state() == FindingState.RESOLVED
    assert by_id[absent].view.state() == FindingState.OPEN
    assert model.total.resolved == 1 and model.total.open.total == 1
    assert len(by_id[repeated].history) == 1
    before_decision = context.services().insight.build(
        ViewName.CONTAINER_FINDINGS, scope.model_copy(update={"as_of": T0 + 3 * DAY})
    )
    assert before_decision.total.open.total == 2
    assert before_decision.total.resolved == 0
    assert all(not row.history for row in before_decision.findings)
    payload = json.loads(model.model_dump_json())
    assert {row["view"]["finding"]["id"] for row in payload["findings"]} == set(map(str, by_id))
    report = context.services().insight.report(ViewName.CONTAINER_FINDINGS, scope)
    table = next(section.table for section in report.sections if section.heading == "Findings")
    assert {row[0]: row[3] for row in table.rows} == {
        str(repeated): "resolved",
        str(absent): "open",
    }


def test_container_scope_rejects_code_anchor_missing_stem_and_future_anchor(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref()
        code = seed.assessment(ref, kind="secure-code", occurred_at=T0)
        uow.commit()
    assert ref.id is not None
    container = record_container(context, ref.id, "registry.example/apps/widget@sha256:aaa", 1, ())
    insight = context.services().insight
    for scope in (
        ViewFilter(assessment_id=container),
        ViewFilter(assessment_id=container, report_stem="widget"),
        ViewFilter(assessment_id=code.id, report_stem="widget-container-audit"),
        ViewFilter(assessment_id=container, report_stem="widget-container-audit", as_of=T0),
    ):
        with pytest.raises(ValidationError):
            insight.build(ViewName.CONTAINER_FINDINGS, scope)


def test_category_rollup_diagnoses_documented_and_undocumented_downgrades(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        ref = Seed(uow).repository_ref()
        uow.commit()
    body = json.loads(authored_report().payload)
    body["findings"] = []
    template = json.loads(authored_report().payload)["findings"][0]
    cases = (
        (
            "low",
            8.1,
            "authorization",
            "No stated reason for the reported lower severity in this assessment.",
        ),
        (
            "medium",
            9.8,
            "authorization",
            "Deployment context limits impact; the base score is retained for reference.",
        ),
        (
            "informational",
            4.0,
            "authorization",
            "No explanation accompanies this informational classification in the report.",
        ),
        (
            "informational",
            0.0,
            "authorization",
            "Contextual downgrade documented despite the zero CVSS score in this report.",
        ),
        (
            "high",
            8.1,
            "authorization",
            "The severity agrees with its score and needs no downgrade explanation.",
        ),
        (
            "low",
            9.8,
            "cryptography",
            "No explanation for this lower severity appears in the report description.",
        ),
    )
    for i, (severity, score, category, description) in enumerate(cases):
        entry = {
            **template,
            "id": f"WIDGET-0123456-{i + 1:03d}",
            "title": f"Finding {i}",
            "severity": severity,
            "category": category,
            "description": description,
            "locations": [{"path": f"pkg:generic/item-{i}"}],
            "cvss": {**template["cvss"], "score": score},
        }
        entry.pop("validation_status", None)
        body["findings"].append(entry)
    saved = context.services().assessment.record(
        SecurityAuditArtifact.from_document(body),
        ref.id,
        AssessmentKind.CONTAINER,
        "skill:secure-container-audit",
        "test",
        Provenance(run_id=uuid4(), source=SourceType.INTERACTIVE, occurred_at=T0),
    )
    bindings = context.services().assessment.intake_bindings(saved.id).findings
    assert len(set(bindings.values())) == len(cases)
    scope = ViewFilter(categories=("authorization",))
    model = context.services().insight.build(ViewName.FINDINGS_ROLLUP, scope)
    assert isinstance(model, FindingsRollup)
    diagnostic = model.severity_cvss_mismatches
    assert (diagnostic.documented, diagnostic.undocumented) == (2, 2)
    details = {d.title: d for d in diagnostic.details}
    assert set(details) == {"Finding 0", "Finding 1", "Finding 2", "Finding 3"}
    assert details["Finding 0"].bands_below == 2
    assert details["Finding 1"].cvss_band == "critical"
    assert details["Finding 2"].scored_informational
    assert details["Finding 3"].scored_informational and details["Finding 3"].documented
    assert all(d.category == "authorization" for d in details.values())
    assert model.total.open.total == 5
    fleet = context.services().insight.build(ViewName.FINDINGS_ROLLUP, ViewFilter())
    assert fleet.severity_cvss_mismatches.undocumented == 3
    report = context.services().insight.report(ViewName.FINDINGS_ROLLUP, scope)
    table = next(s.table for s in report.sections if s.heading == "Severity/CVSS diagnostics")
    assert {row[1] for row in table.rows} == set(details)


def test_legacy_unscored_occurrence_reads_cvss_from_its_immutable_report(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        ref = Seed(uow).repository_ref()
        uow.commit()
    body = json.loads(authored_report().payload)
    body["findings"] = [body["findings"][0]]
    body["findings"][0]["severity"] = "low"
    body["findings"][0].pop("validation_status", None)
    doc = SecurityAuditArtifact.from_document(body)
    services = context.services()
    saved = services.assessment.record(
        doc,
        ref.id,
        AssessmentKind.SECURE_CODE_CANONICAL,
        "skill:secure-code-audit",
        "test",
        Provenance(run_id=uuid4(), source=SourceType.INTERACTIVE, occurred_at=T0),
    )
    original = FindingCandidate.of_report(doc.findings, ref.repository_id)[0]
    unscored = FindingCandidate(
        label=original.label,
        repository_id=original.repository_id,
        title=original.title,
        description=original.description,
        cwes=original.cwes,
        category=original.category,
        locations=original.locations,
        reported_severity=original.reported_severity,
    )
    services.findings.intake.accept(saved.id, [unscored])
    [before] = services.findings.occurrences(assessment_id=saved.id)
    assert before.cvss_score is None
    model = services.insight.build(ViewName.FINDINGS_ROLLUP, ViewFilter(categories=("injection",)))
    [diagnostic] = model.severity_cvss_mismatches.details
    assert diagnostic.finding_id == before.finding_id
    assert diagnostic.cvss_score == Decimal("8.1")
    assert diagnostic.score_source == "original_report"
    assert diagnostic.assessment_id == saved.id and diagnostic.occurrence_id == before.id
    assert diagnostic.bands_below == 2 and not diagnostic.documented
    assert services.findings.occurrences(assessment_id=saved.id) == [before]


def test_severity_decision_rationale_documents_only_the_current_time_slice(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref()
        assessment = seed.assessment(ref, occurred_at=T0)
        finding = seed.finding(uow.repositories.get(ref.repository_id))
        seed.occurrence(finding, assessment, severity="high", cvss_score=Decimal("9.8"))
        seed.finding_label(finding, taxonomy="category", label="authorization")
        seed.decision(
            finding,
            severity="low",
            actor="human:analyst@example.com",
            rationale="Deployment context limits this route to authenticated administrators.",
            occurred_at=T0 + DAY,
        )
        uow.commit()
    insight = context.services().insight
    before = insight.build(
        ViewName.FINDINGS_ROLLUP, ViewFilter(categories=("authorization",), as_of=T0)
    )
    assert before.severity_cvss_mismatches.details == ()
    after = insight.build(ViewName.FINDINGS_ROLLUP, ViewFilter(categories=("authorization",)))
    assert after.severity_cvss_mismatches.documented == 1
    assert after.severity_cvss_mismatches.undocumented == 0
    [diagnostic] = after.severity_cvss_mismatches.details
    assert diagnostic.finding_id == finding.id and diagnostic.severity == "low"
    assert diagnostic.bands_below == 3
