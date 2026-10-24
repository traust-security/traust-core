from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError as ModelValidationError
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.findings.test_intake_boundary import snapshot
from tests.v1.services.test_assessment_scan import SCANNERS, a_ref, provenance
from tests.v1.services.test_assessment_scan import context as context
from tests.v1.services.test_assessment_scan import engine as engine
from traust_core.v1.context import Context
from traust_core.v1.errors import ConfigError, RepositoryError, ValidationError
from traust_core.v1.models.findings import CandidateFormat, Location
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.traust.assessments.location import SqlLocationRepository
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy


def scanner_batch(defect: str | None = None) -> bytes:
    doc = json.loads((SCANNERS / "codeql.sarif").read_bytes())
    run = doc["runs"][0]
    first = run["results"][0]
    second = deepcopy(first)
    physical = second["locations"][0]["physicalLocation"]
    physical["artifactLocation"]["uri"] = "pkg/api/other.go"
    if defect == "no-location":
        second["locations"] = []
    elif defect == "bad-line":
        physical["region"]["startLine"] = "not-a-line"
    elif defect == "zero-line":
        physical["region"]["startLine"] = 0
    elif defect == "empty-function":
        second["locations"][0]["logicalLocations"] = [
            {"kind": "function", "fullyQualifiedName": ""}
        ]
    elif defect == "malformed-cwe":
        second["properties"] = {"tags": ["external/cwe/cwe-123456"]}
    run["results"] = [first, second]
    return json.dumps(doc).encode()


@pytest.mark.parametrize(
    "defect", ["no-location", "bad-line", "zero-line", "empty-function", "malformed-cwe"]
)
def test_invalid_scanner_batch_leaves_no_assessment_or_finding_rows(
    context: Context, engine: Engine, defect: str
) -> None:
    ref = a_ref(engine)
    before = snapshot(engine)
    with pytest.raises((ValidationError, ModelValidationError)):
        context.services().assessment.record_scan(
            ref, scanner_batch(defect), CandidateFormat.SARIF, provenance()
        )
    assert snapshot(engine) == before
    assert before["assessments"] == ()


def test_malformed_scanner_document_leaves_no_assessment(context: Context, engine: Engine) -> None:
    ref = a_ref(engine)
    before = snapshot(engine)
    with pytest.raises(ValidationError, match="not JSON"):
        context.services().assessment.record_scan(
            ref, b"{", CandidateFormat.DEPENDABOT, provenance()
        )
    assert snapshot(engine) == before


def test_empty_scanner_report_records_its_source_and_replays_without_findings(
    context: Context, engine: Engine
) -> None:
    ref, prov = a_ref(engine), provenance()
    services = context.services()
    assessment, accepted = services.assessment.record_scan(
        ref, b"[]", CandidateFormat.DEPENDABOT, prov
    )
    assert (
        assessment.kind,
        assessment.assessor,
        assessment.assessor_version,
        assessment.occurred_at,
    ) == ("scanner", "dependabot", "unversioned", prov.occurred_at)
    assert accepted.findings == {} and accepted.created == ()
    before = snapshot(engine)
    replayed, replay = services.assessment.record_scan(ref, b"[]", CandidateFormat.DEPENDABOT, prov)
    assert replayed == assessment and replay == accepted
    assert snapshot(engine) == before


@pytest.mark.parametrize(
    ("format", "filename", "severity"),
    [
        (CandidateFormat.SARIF, "codeql.sarif", "high"),
        (CandidateFormat.DEPENDABOT, "dependabot-alerts.json", "critical"),
        (CandidateFormat.GOVULNCHECK, "govulncheck.jsonl", "unrated"),
    ],
)
def test_real_scanner_intake_reloads_and_exact_replay_changes_no_rows(
    context: Context, engine: Engine, format: CandidateFormat, filename: str, severity: str
) -> None:
    ref = a_ref(engine)
    raw = (SCANNERS / filename).read_bytes()
    prov = provenance().model_copy(
        update={"occurred_at": datetime(2026, 10, 23, 9, 1, 2, 123456, tzinfo=UTC)}
    )
    services = context.services()
    assessment, first = services.assessment.record_scan(ref, raw, format, prov)
    before = snapshot(engine)
    again, replay = context.services().assessment.record_scan(ref, raw, format, prov)
    assert again == assessment
    assert replay.findings == first.findings
    assert replay.created == ()
    assert snapshot(engine) == before
    assert context.services().assessment.get(assessment.id) == assessment
    assert assessment.repository_ref_id == ref
    [finding_id] = first.created
    view = context.services().findings.get(finding_id)
    assert view.occurrence is not None and view.occurrence.severity == severity
    assert view.effective_severity == (None if severity == "unrated" else severity)
    assert len(view.locations) == 1


def test_failed_replay_keeps_the_original_scanner_assessment_and_rows(
    context: Context, engine: Engine
) -> None:
    ref, prov = a_ref(engine), provenance()
    service = context.services().assessment
    service.record_scan(ref, scanner_batch(), CandidateFormat.SARIF, prov)
    before = snapshot(engine)
    with pytest.raises(ValidationError, match="no usable location"):
        service.record_scan(ref, scanner_batch("no-location"), CandidateFormat.SARIF, prov)
    assert snapshot(engine) == before


def test_a_late_location_write_failure_rolls_back_the_entire_scan(
    context: Context, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    ref = a_ref(engine)
    before = snapshot(engine)
    add = SqlLocationRepository.add
    calls = 0

    def fail_second(repository: SqlLocationRepository, location: Location) -> Location:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RepositoryError("second scanner location failed")
        return add(repository, location)

    monkeypatch.setattr(SqlLocationRepository, "add", fail_second)
    with pytest.raises(RepositoryError, match="second scanner location failed"):
        context.services().assessment.record_scan(
            ref, scanner_batch(), CandidateFormat.SARIF, provenance()
        )
    assert calls == 2
    assert snapshot(engine) == before


def test_scanner_intake_refuses_separate_units_of_work(engine: Engine) -> None:
    ref = a_ref(engine)
    before = snapshot(engine)
    intake = FindingIntake(SqlTraustUnitOfWork(engine), IdentityPolicy(), TaxonomyPolicy())
    service = AssessmentService(SqlTraustUnitOfWork(engine), intake)
    with pytest.raises(ConfigError, match="share a unit of work"):
        service.record_scan(ref, scanner_batch(), CandidateFormat.SARIF, provenance())
    assert snapshot(engine) == before


def test_caught_scanner_failure_marks_the_outer_shared_transaction_rollback_only(
    engine: Engine,
) -> None:
    ref = a_ref(engine)
    before = snapshot(engine)
    unit = SqlTraustUnitOfWork(engine)
    intake = FindingIntake(unit, IdentityPolicy(), TaxonomyPolicy())
    service = AssessmentService(unit, intake)
    with unit:
        Seed(unit).assessment(unit.repository_refs.get(ref))
        with pytest.raises(ValidationError, match="no usable location"):
            service.record_scan(
                ref, scanner_batch("no-location"), CandidateFormat.SARIF, provenance()
            )
        with pytest.raises(RepositoryError, match="rollback-only"):
            unit.commit()
    assert snapshot(engine) == before
