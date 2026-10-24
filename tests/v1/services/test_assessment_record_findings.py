"""`AssessmentService.record` of a container or RPM audit: the report's findings are taken in as
findings of the assessment through FindingIntake, as `record_audit` does for cloud-config."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

import pytest

from tests.v1.services import test_assessment_record as recording
from tests.v1.services.test_assessment_record import REPORT, provenance, record
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.artifacts import SecurityAuditArtifact
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs
from traust_core.v1.services.assessment import AssessmentService

engine, context, ref = recording.engine, recording.context, recording.ref

DESCRIPTION = "The image runs its entrypoint as root, so a process escape lands with uid 0 rights."


def finding(label: str, path: str, lines: str | None = None, **changes: Any) -> dict[str, Any]:
    location = {"path": path} | ({"lines": lines} if lines else {})
    return {
        "id": label,
        "title": f"{label} runs as root",
        "severity": "high",
        "cwes": ["CWE-250"],
        "locations": [location],
        "description": DESCRIPTION,
        "remediation": "Set a non-root USER in the image.",
        **changes,
    }


def report(*findings: dict[str, Any]) -> SecurityAuditArtifact:
    return SecurityAuditArtifact.from_document(
        {**json.loads(REPORT.payload), "findings": list(findings)}
    )


AUDIT = report(
    finding("WIDGET-1", "Dockerfile", "12-14", category="insecure-workload-config"),
    finding("WIDGET-2", "usr/lib/widget/plugin.so", severity="low", cwes=["CWE-276", "CWE-732"]),
)


def taken(context: Any, assessment: Assessment) -> dict[str, tuple[str, str, int | None]]:
    """Per finding title: its occurrence's severity and first location on this assessment."""
    assert assessment.id is not None
    with SqlTraustUnitOfWork(context.database) as uow:
        occurrences = uow.occurrences.list_for_assessment(assessment.id)
        findings = {f.id: f for f in uow.findings.list_by_ids([o.finding_id for o in occurrences])}
        out = {}
        for o in occurrences:
            assert o.id is not None
            (place,) = uow.locations.list_for_occurrences([o.id])
            out[findings[o.finding_id].title] = (o.severity, place.path, place.line_start)
    return out


@pytest.mark.parametrize("kind", [AssessmentKind.CONTAINER, AssessmentKind.RPM])
def test_a_container_or_rpm_audit_takes_its_report_findings_in(
    context: Any, ref: UUID, kind: AssessmentKind
) -> None:
    assessment = record(context, AUDIT, ref, kind)
    assert taken(context, assessment) == {
        "WIDGET-1 runs as root": ("high", "Dockerfile", 12),
        "WIDGET-2 runs as root": ("low", "usr/lib/widget/plugin.so", None),
    }


def test_the_report_states_cwes_and_category_on_the_findings(context: Any, ref: UUID) -> None:
    assessment = record(context, AUDIT, ref, AssessmentKind.CONTAINER)
    assert assessment.id is not None
    views = context.services().findings.list_by_ids(
        [o.finding_id for o in _occurrences(context, assessment.id)]
    )
    assert {v.finding.title: (sorted(v.cwes), v.label("category")) for v in views} == {
        "WIDGET-1 runs as root": (["CWE-250"], "insecure-workload-config"),
        "WIDGET-2 runs as root": (["CWE-276", "CWE-732"], None),
    }


def _occurrences(context: Any, assessment_id: UUID) -> list[Any]:
    with SqlTraustUnitOfWork(context.database) as uow:
        return uow.occurrences.list_for_assessment(assessment_id)


def test_recording_the_same_run_again_adds_no_finding(context: Any, ref: UUID) -> None:
    first = record(context, AUDIT, ref, AssessmentKind.CONTAINER)
    again = record(context, AUDIT, ref, AssessmentKind.CONTAINER)
    assert again.id == first.id
    assert first.id is not None
    assert len(_occurrences(context, first.id)) == 2


def test_the_same_finding_in_a_later_audit_is_the_same_finding(context: Any, ref: UUID) -> None:
    first = record(context, AUDIT, ref, AssessmentKind.CONTAINER)
    later = record(
        context, report(finding("WIDGET-9", "Dockerfile", "30")), ref, AssessmentKind.RPM
    )
    assert first.id is not None and later.id is not None
    (rerun,) = _occurrences(context, later.id)
    assert rerun.finding_id in {o.finding_id for o in _occurrences(context, first.id)}


@pytest.mark.parametrize(
    "kind", [AssessmentKind.SECURE_CODE_CANONICAL, AssessmentKind.BENCHMARK_AUDIT], ids=str
)
def test_other_report_kinds_record_the_document_only(
    context: Any, ref: UUID, kind: AssessmentKind
) -> None:
    assessment = record(context, AUDIT, ref, kind)
    assert assessment.id is not None
    assert _occurrences(context, assessment.id) == []


def test_a_report_with_no_findings_takes_nothing_in(context: Any, ref: UUID) -> None:
    assessment = record(context, REPORT, ref, AssessmentKind.CONTAINER)
    assert assessment.id is not None
    assert _occurrences(context, assessment.id) == []


@pytest.mark.parametrize("root", [".", "./", "/"])
def test_a_finding_intake_refuses_records_nothing(context: Any, ref: UUID, root: str) -> None:
    doc = report(finding("WIDGET-1", "Dockerfile"), finding("ROOT", root))
    with pytest.raises(ValidationError, match="no usable location"):
        record(context, doc, ref, AssessmentKind.CONTAINER)
    with SqlTraustUnitOfWork(context.database) as uow:
        assert uow.assessments.list_for_ref(ref) == []


def test_recording_findings_needs_intake(context: Any, ref: UUID) -> None:
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(SecurityAuditArtifact)))
    service = AssessmentService(SqlTraustUnitOfWork(context.database), publisher=publisher)
    with pytest.raises(ConfigError, match="needs finding intake"):
        service.record(AUDIT, ref, AssessmentKind.CONTAINER, "skill:test", "0.1.0", provenance())
    with SqlTraustUnitOfWork(context.database) as uow:
        assert uow.assessments.list_for_ref(ref) == []
