from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
import sqlalchemy as sa

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.services.findings.test_reads import service as finding_service
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.critical_misses import (
    CampaignFinding,
    CampaignRepositoryReports,
    CampaignTriage,
    CandidateAssessment,
    CandidateIngestion,
    CriticalCandidate,
    CriticalCandidateRow,
    CriticalInstrument,
    CriticalMissCampaign,
    CriticalRouting,
)
from traust_core.v1.models.detection_quality import CriticalMiss, MissReason
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpecs
from traust_core.v1.services.critical_miss_report import (
    build_critical_miss_report,
    render_critical_miss_report,
)
from traust_core.v1.services.detection_quality import DetectionQualityService

NOW = datetime(2026, 10, 20, tzinfo=UTC)
SOURCE = "b-lite/widget-delta.json#0"
DELTA = CriticalCandidate(
    instrument=CriticalInstrument.B_LITE,
    slug="widget",
    title="Critical candidate",
    severity="critical (CVSS 9.9)",
    file="pkg/sink.py",
    cwe="CWE-78",
    source_key=SOURCE,
    evidence_path=SOURCE,
)
BASELINE = CampaignFinding(
    original_id="WIDGET-original-005", paths=("pkg/sink.py",), cwes=("CWE-78",)
)
TRIAGE = CampaignTriage(
    source_key=SOURCE,
    verdict="true_positive",
    true_positive_votes=3,
    false_positive_votes=0,
    confidence=9,
    original_id="WIDGET-original-005",
    evidence_path="fast-track-triage.json",
)


def campaign(
    *candidates: CriticalCandidate,
    triage: tuple[CampaignTriage, ...] = (),
    baseline: tuple[CampaignFinding, ...] = (),
    current: tuple[CampaignFinding, ...] = (),
    baseline_source: str | None = "widget-security-audit.json",
) -> CriticalMissCampaign:
    return CriticalMissCampaign(
        source="campaign",
        candidates=candidates or (DELTA,),
        triage=triage,
        repositories=(
            CampaignRepositoryReports(
                slug="widget",
                baseline_source=baseline_source,
                current_source="widget-findings-current.json",
                baseline=baseline,
                current=current,
            ),
        ),
        sources=("b-lite/widget-delta.json",),
    )


def row(doc: CriticalMissCampaign) -> CriticalCandidateRow:
    return build_critical_miss_report(doc, (), generated_at=NOW).candidates[0]


def test_uningested_probe_and_matrix_candidates_need_no_finding_rows() -> None:
    matrix = DELTA.model_copy(
        update={"instrument": CriticalInstrument.MATRIX, "source_key": "matrix/x#0"}
    )
    high = DELTA.model_copy(update={"severity": "high"})
    result = build_critical_miss_report(
        campaign(DELTA, matrix, high, baseline_source=None),
        (),
        generated_at=NOW,
    )
    assert result.counts.delta_candidates == 2
    assert result.recorded_misses == ()
    assert {r.candidate.instrument for r in result.candidates} == {
        CriticalInstrument.B_LITE,
        CriticalInstrument.MATRIX,
    }
    assert all(r.ingestion == CandidateIngestion.NOT_INGESTED for r in result.candidates)
    assert all(r.routing == CriticalRouting.PENDING_TRIAGE for r in result.candidates)
    assert all(r.requires_human_review for r in result.candidates)
    assert all(r.assessment == CandidateAssessment.UNKNOWN for r in result.candidates)


@pytest.mark.parametrize(
    ("present", "verdict", "included"),
    [
        (True, "missed", True),
        (False, "missed", False),
        (None, "missed", False),
        (True, "detected", False),
        (True, "unclear", False),
        (True, None, False),
        (None, "unclear", False),
        (False, "not_applicable", False),
    ],
)
def test_only_explicit_present_at_audit_missed_replays_enter_the_population(
    present: bool | None,
    verdict: str | None,
    included: bool,
) -> None:
    replay = DELTA.model_copy(
        update={
            "instrument": CriticalInstrument.CVE_REPLAY,
            "present_at_audit": present,
            "audit_verdict": verdict,
        }
    )
    result = build_critical_miss_report(campaign(replay), (), generated_at=NOW)
    assert len(result.candidates) == int(included)
    assert result.counts.cve_replay_missed == int(included)
    assert result.counts.replay_candidates_reviewed == 1
    if included:
        assert result.candidates[0].assessment == CandidateAssessment.MISSED
        assert result.candidates[0].routing == CriticalRouting.MEASURED_NOT_ROUTED
    if present is None or verdict in (None, "unclear"):
        assert result.counts.replay_unknown == 1


@pytest.mark.parametrize(
    ("current", "routing", "validity"),
    [
        ((), CriticalRouting.PENDING_ROUTING, None),
        (
            (CampaignFinding(original_id="WIDGET-original-005", validity="confirmed"),),
            CriticalRouting.NO_COUNTERSIGN_REQUIRED,
            "confirmed",
        ),
        (
            (CampaignFinding(original_id="WIDGET-original-005", validity="not_verified"),),
            CriticalRouting.PENDING_ROUTING,
            "not_verified",
        ),
        (
            (
                CampaignFinding(
                    original_id="WIDGET-original-005",
                    validity="false_positive",
                    refuted_awaiting_signoff=True,
                ),
            ),
            CriticalRouting.AWAITING_COUNTERSIGN,
            "false_positive",
        ),
    ],
)
def test_matched_baselines_route_only_from_actual_current_disposition(
    current: tuple[CampaignFinding, ...],
    routing: CriticalRouting,
    validity: str | None,
) -> None:
    result = row(campaign(triage=(TRIAGE,), baseline=(BASELINE,), current=current))
    assert result.ingestion == CandidateIngestion.INGESTED
    assert result.original_id == "WIDGET-original-005"
    assert result.routing == routing and result.validity == validity
    assert result.triage == TRIAGE


def test_original_id_match_takes_priority_over_inexact_area_identity() -> None:
    baseline = BASELINE.model_copy(update={"paths": ("renamed.py",), "cwes": ("CWE-89",)})
    result = row(campaign(triage=(TRIAGE,), baseline=(baseline,)))
    assert result.ingestion == CandidateIngestion.INGESTED
    assert result.original_id == TRIAGE.original_id


def test_exact_path_and_cwe_match_is_available_without_triage() -> None:
    result = row(campaign(baseline=(BASELINE,)))
    assert result.ingestion == CandidateIngestion.INGESTED
    assert result.original_id == BASELINE.original_id
    assert result.validity is None


def test_same_path_different_cwe_is_review_not_a_miss_or_ingested_finding() -> None:
    other = BASELINE.model_copy(update={"cwes": ("CWE-89",)})
    result = row(campaign(baseline=(other,)))
    assert result.assessment == CandidateAssessment.REVIEW
    assert result.ingestion == CandidateIngestion.NOT_INGESTED
    assert result.routing == CriticalRouting.ADJUDICATION
    assert result.original_id is None


def test_multiple_path_cwe_matches_require_identity_adjudication() -> None:
    other = BASELINE.model_copy(update={"original_id": "WIDGET-original-006"})
    result = row(campaign(baseline=(BASELINE, other)))
    assert result.ingestion == CandidateIngestion.ADJUDICATION
    assert result.assessment == CandidateAssessment.REVIEW
    assert result.routing == CriticalRouting.ADJUDICATION
    assert result.original_id is None


def test_advisory_text_match_is_review_not_synthetic_ingestion() -> None:
    replay = DELTA.model_copy(
        update={
            "instrument": CriticalInstrument.CVE_REPLAY,
            "advisory_id": "CVE-2026-1234",
            "present_at_audit": True,
            "audit_verdict": "missed",
            "file": None,
        }
    )
    finding = BASELINE.model_copy(update={"advisory_ids": ("CVE-2026-1234",)})
    result = row(campaign(replay, baseline=(finding,)))
    assert result.assessment == CandidateAssessment.REVIEW
    assert result.ingestion == CandidateIngestion.NOT_INGESTED
    assert result.routing == CriticalRouting.ADJUDICATION
    assert result.original_id is None


def test_recorded_area_review_stays_separate_from_recorded_misses_and_candidates() -> None:
    recorded = tuple(
        CriticalMiss(
            finding_id=UUID(int=index),
            repository_id=UUID(int=10),
            title="Recorded",
            found_by=UUID(int=20),
            found_at=NOW,
            missed_by=UUID(int=30),
            reason=reason,
        )
        for index, reason in enumerate((MissReason.MISSED, MissReason.AREA_REPORTED), start=1)
    )
    report = build_critical_miss_report(campaign(), recorded, generated_at=NOW)
    assert report.recorded_misses == recorded
    assert report.counts.recorded_missed == 1 and report.counts.recorded_adjudication == 1
    assert report.counts.delta_candidates == 1
    assert report.candidates[0].assessment == CandidateAssessment.CANDIDATE


def test_rendering_is_deterministic_and_escapes_candidate_text() -> None:
    hostile = DELTA.model_copy(update={"title": "Injected|cell\n<script>bad()</script>"})
    report = build_critical_miss_report(
        campaign(hostile), (), generated_at=NOW, harness_version="h-1"
    )
    rendered = render_critical_miss_report(report)
    assert rendered == render_critical_miss_report(report)
    assert "<script>" not in rendered and "\n<script>" not in rendered
    assert "Injected\\|cell &lt;script&gt;" in rendered
    assert NOW.isoformat() in rendered


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_real_service_reports_preintake_candidates_without_writing_findings(
    tmp_path: Path,
    backend: str,
) -> None:
    with contract_db(backend, tmp_path) as engine:
        uow = SqlTraustUnitOfWork(engine)
        findings = finding_service(engine)
        publisher = ArtifactPublisher(PublishSpecs(), InMemoryObjectStore(), uow)
        service = DetectionQualityService(uow, findings, publisher, clock=FixedClock(NOW))
        window = TimeWindow(start=NOW - timedelta(days=1), end=NOW + timedelta(days=1))
        assert service.critical_misses(window) == []
        result = service.critical_miss_report(campaign(), window=window, harness_version="h-1")
        assert result.counts.delta_candidates == 1
        assert result.recorded_misses == ()
        assert result.generated_at == NOW and result.harness_version == "h-1"
        with uow:
            count = sa.select(sa.func.count()).select_from(uow.findings.table)
            assert uow.connection.scalar(count) == 0
        assert service.critical_misses(window) == []
