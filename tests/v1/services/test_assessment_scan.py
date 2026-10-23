"""AssessmentService.record_scan: scanner output becomes an assessment and its findings."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import CandidateFormat
from traust_core.v1.models.vocabulary import FindingOrigin, SourceType
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.assessment import AssessmentService

FIXTURES = Path(__file__).parents[2] / "fixtures" / "findings"
SCANNERS = FIXTURES / "scanners"
ORIGIN = FindingOrigin("vuln-scan")
WHEN = datetime(2026, 10, 23, 9, tzinfo=UTC)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path))
    ctx.__dict__["database"] = engine
    return ctx


def a_ref(engine: Engine) -> UUID:
    """A commit to scan, with the CWE catalog entries the scanner fixtures cite."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        for cwe in ("CWE-117", "CWE-354"):
            if uow.cwes.find_by_identifier(cwe) is None:
                seed.cwe(identifier=cwe)
        ref = seed.repository_ref()
        uow.commit()
    assert ref.id is not None
    return ref.id


def provenance() -> Provenance:
    return Provenance(run_id=uuid4(), source=SourceType.VULN_SCAN_REPORT, occurred_at=WHEN)


def test_sarif_becomes_a_scanner_assessment_with_its_findings(
    context: Context, engine: Engine
) -> None:
    ref = a_ref(engine)
    raw = (SCANNERS / "codeql.sarif").read_bytes()
    assessment, intake = context.services().assessment.record_scan(
        ref, raw, CandidateFormat.SARIF, ORIGIN, provenance()
    )
    assert (assessment.kind, assessment.assessor, assessment.assessor_version) == (
        "scanner",
        "CodeQL",
        "2.20.0",
    )
    assert (assessment.repository_ref_id, assessment.status, assessment.occurred_at) == (
        ref,
        "completed",
        WHEN,
    )
    [finding_id] = intake.created
    with SqlTraustUnitOfWork(engine) as uow:
        [occurrence] = uow.occurrences.list_for_assessment(assessment.id)
        [location] = uow.locations.list_for_occurrence(occurrence.id)
    assert (occurrence.finding_id, occurrence.severity, occurrence.rule) == (
        finding_id,
        "high",
        "go/log-injection",
    )
    assert (location.path, location.line_start) == ("pkg/api/handler.go", 42)


def test_an_unrated_scanner_finding_is_taken(context: Context, engine: Engine) -> None:
    raw = (SCANNERS / "govulncheck.jsonl").read_bytes()
    assessment, intake = context.services().assessment.record_scan(
        a_ref(engine), raw, CandidateFormat.GOVULNCHECK, ORIGIN, provenance()
    )
    assert (assessment.assessor, assessment.assessor_version) == ("govulncheck", "v1.1.4")
    with SqlTraustUnitOfWork(engine) as uow:
        [occurrence] = uow.occurrences.list_for_assessment(assessment.id)
    assert occurrence.severity == "unrated" and len(intake.created) == 1


def test_dependabot_has_no_version(context: Context, engine: Engine) -> None:
    raw = (SCANNERS / "dependabot-alerts.json").read_bytes()
    assessment, _ = context.services().assessment.record_scan(
        a_ref(engine), raw, CandidateFormat.DEPENDABOT, ORIGIN, provenance()
    )
    assert (assessment.assessor, assessment.assessor_version) == ("dependabot", "unversioned")


def test_the_same_output_again_adds_nothing(context: Context, engine: Engine) -> None:
    ref, raw, prov = a_ref(engine), (SCANNERS / "codeql.sarif").read_bytes(), provenance()
    first, _ = context.services().assessment.record_scan(
        ref, raw, CandidateFormat.SARIF, ORIGIN, prov
    )
    again, intake = context.services().assessment.record_scan(
        ref, raw, CandidateFormat.SARIF, ORIGIN, prov
    )
    assert again.id == first.id and intake.created == ()


def test_record_scan_needs_intake(engine: Engine) -> None:
    with pytest.raises(ConfigError, match="needs finding intake"):
        AssessmentService(SqlTraustUnitOfWork(engine)).record_scan(
            uuid4(), b"[]", CandidateFormat.DEPENDABOT, ORIGIN, provenance()
        )


def test_a_scan_triaged_end_to_end(context: Context, engine: Engine) -> None:
    """The triage skill's path: scanner output in, prepare, a triage, record."""
    services = context.services()
    raw = (SCANNERS / "codeql.sarif").read_bytes()
    assessment, _ = services.assessment.record_scan(
        a_ref(engine), raw, CandidateFormat.SARIF, ORIGIN, provenance()
    )
    [item] = services.findings.decisions.prepare(assessment.id).items
    doc = json.loads((FIXTURES / "triage" / "triage-report.json").read_text())
    doc["findings"] = [
        {
            "id": "f001",
            "title": item.finding.title,
            "verdict": "true_positive",
            "severity": "high",
            "rationale": "reachable from main at entry.c:53",
            "fingerprint": item.finding.fingerprint,
            "fingerprint_algo": item.finding.fingerprint_algo,
        }
    ]
    [decision] = services.findings.decisions.record(
        assessment.id,
        TriageArtifact.from_document(doc),
        provenance(),
        FIXTURES / "triage" / "canary-target",
    )
    assert (decision.finding_id, decision.validity) == (item.finding.id, "confirmed")
