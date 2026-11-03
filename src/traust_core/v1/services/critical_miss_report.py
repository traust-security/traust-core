from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

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
    CriticalMissCounts,
    CriticalMissReport,
    CriticalRouting,
)
from traust_core.v1.models.detection_quality import CriticalMiss, MissReason
from traust_core.v1.rendering.markdown import MarkdownRenderer, Report, Section, Table


def build_critical_miss_report(
    campaign: CriticalMissCampaign,
    recorded_misses: Sequence[CriticalMiss],
    *,
    generated_at: datetime,
    harness_version: str | None = None,
) -> CriticalMissReport:
    triage = {item.source_key: item for item in campaign.triage}
    repositories = {item.slug: item for item in campaign.repositories}
    critical = [candidate for candidate in campaign.candidates if _critical(candidate)]
    replay = [item for item in critical if item.instrument == CriticalInstrument.CVE_REPLAY]
    candidates = tuple(
        _candidate_row(
            candidate, triage.get(candidate.source_key), repositories.get(candidate.slug)
        )
        for candidate in sorted(critical, key=lambda c: (c.instrument, c.slug, c.source_key))
        if candidate.instrument != CriticalInstrument.CVE_REPLAY
        or (candidate.present_at_audit is True and candidate.audit_verdict == "missed")
    )
    deltas = [
        row for row in candidates if row.candidate.instrument != CriticalInstrument.CVE_REPLAY
    ]
    return CriticalMissReport(
        generated_at=generated_at,
        harness_version=harness_version,
        campaign=campaign.source,
        candidates=candidates,
        recorded_misses=tuple(recorded_misses),
        counts=CriticalMissCounts(
            delta_candidates=len(deltas),
            triage_confirmed=sum(
                row.triage is not None and row.triage.verdict == "true_positive" for row in deltas
            ),
            ingested=sum(row.ingestion == CandidateIngestion.INGESTED for row in candidates),
            cve_replay_missed=sum(
                row.candidate.instrument == CriticalInstrument.CVE_REPLAY for row in candidates
            ),
            replay_candidates_reviewed=len(replay),
            replay_unknown=sum(
                item.present_at_audit is None or item.audit_verdict in (None, "unclear", "unknown")
                for item in replay
            ),
            recorded_missed=sum(item.reason == MissReason.MISSED for item in recorded_misses),
            recorded_adjudication=sum(
                item.reason == MissReason.AREA_REPORTED for item in recorded_misses
            ),
        ),
        sources=campaign.sources,
    )


def _critical(candidate: CriticalCandidate) -> bool:
    return (candidate.severity or "").strip().lower().startswith("critical")


def _candidate_row(
    candidate: CriticalCandidate,
    triage: CampaignTriage | None,
    reports: CampaignRepositoryReports | None,
) -> CriticalCandidateRow:
    assessment = (
        CandidateAssessment.MISSED
        if candidate.instrument == CriticalInstrument.CVE_REPLAY
        else CandidateAssessment.CANDIDATE
    )
    pending = (
        CriticalRouting.MEASURED_NOT_ROUTED
        if candidate.instrument == CriticalInstrument.CVE_REPLAY
        else CriticalRouting.PENDING_TRIAGE
        if triage is None
        else CriticalRouting.PENDING_ROUTING
    )
    row = CriticalCandidateRow(
        candidate=candidate,
        triage=triage,
        assessment=assessment,
        ingestion=CandidateIngestion.NOT_INGESTED,
        routing=pending,
        reason="No baseline resolved; ingestion and original-audit coverage are unknown.",
        baseline_source=reports.baseline_source if reports else None,
        current_source=reports.current_source if reports else None,
    )
    if reports is None or reports.baseline_source is None:
        return (
            row
            if candidate.instrument == CriticalInstrument.CVE_REPLAY
            else row.model_copy(update={"assessment": CandidateAssessment.UNKNOWN})
        )
    matches = [
        item
        for item in reports.baseline
        if triage is not None and triage.original_id == item.original_id
    ]
    if not matches and candidate.file and candidate.cwe:
        matches = [
            item
            for item in reports.baseline
            if candidate.file in item.paths and candidate.cwe in item.cwes
        ]
    if len(matches) > 1:
        return row.model_copy(
            update={
                "assessment": CandidateAssessment.REVIEW,
                "ingestion": CandidateIngestion.ADJUDICATION,
                "routing": CriticalRouting.ADJUDICATION,
                "reason": "Multiple baseline findings match; a human must reconcile original IDs.",
            }
        )
    if not matches:
        area_reported = candidate.file is not None and any(
            candidate.file in item.paths for item in reports.baseline
        )
        advisory_reported = candidate.advisory_id is not None and any(
            candidate.advisory_id.upper() in item.advisory_ids for item in reports.baseline
        )
        if area_reported or advisory_reported:
            return row.model_copy(
                update={
                    "assessment": CandidateAssessment.REVIEW,
                    "routing": CriticalRouting.ADJUDICATION,
                    "reason": "The baseline mentions this area or advisory; "
                    "identity needs adjudication.",
                }
            )
        return row.model_copy(
            update={
                "reason": "No baseline finding matched; this candidate is not ingested.",
            }
        )
    matched = matches[0]
    current = [item for item in reports.current if item.original_id == matched.original_id]
    if len(current) > 1:
        return row.model_copy(
            update={
                "assessment": CandidateAssessment.REVIEW,
                "ingestion": CandidateIngestion.ADJUDICATION,
                "routing": CriticalRouting.ADJUDICATION,
                "original_id": matched.original_id,
                "reason": "Multiple current findings share the matched original ID.",
            }
        )
    state = current[0] if current else None
    return row.model_copy(
        update={
            "ingestion": CandidateIngestion.INGESTED,
            "original_id": matched.original_id,
            "validity": state.validity if state else None,
            "routing": _routing(state),
            "reason": (
                "Matched baseline original ID; current disposition is recorded, not inferred."
                if state
                else "Matched baseline original ID; current disposition is unknown."
            ),
        }
    )


def _routing(current: CampaignFinding | None) -> CriticalRouting:
    if current is not None:
        if current.refuted_awaiting_signoff:
            return CriticalRouting.AWAITING_COUNTERSIGN
        if current.validity == "confirmed":
            return CriticalRouting.NO_COUNTERSIGN_REQUIRED
    return CriticalRouting.PENDING_ROUTING


def render_critical_miss_report(report: CriticalMissReport) -> str:
    counts = report.counts
    sections = [
        Section(
            heading="Scope and summary",
            body=(
                "Candidate worklist only: triage and human countersign own verdicts. "
                "This report neither creates findings nor files tickets. Recorded misses and "
                "pre-intake candidates are separate populations, "
                "not an additive vulnerability total.\n\n"
                f"Critical delta candidates: {counts.delta_candidates}\n\n"
                f"Triage-confirmed delta candidates: {counts.triage_confirmed}\n\n"
                f"Candidates matched to baseline findings: {counts.ingested}\n\n"
                f"Critical present-at-audit replay misses: {counts.cve_replay_missed}\n\n"
                f"Critical replay rows reviewed: {counts.replay_candidates_reviewed}; "
                f"unknown coverage/verdict: {counts.replay_unknown}\n\n"
                f"Recorded misses: {counts.recorded_missed}; "
                f"recorded adjudication cases: {counts.recorded_adjudication}"
            ),
        )
    ]
    columns = (
        "Repo",
        "Candidate",
        "CWE",
        "Assessment",
        "Triage",
        "Triage original ID",
        "Matched ID",
        "Ingestion",
        "Validity",
        "Countersign / routing",
        "Evidence",
        "Reason",
    )
    for instrument in CriticalInstrument:
        rows = tuple(
            (
                row.candidate.slug,
                row.candidate.title,
                row.candidate.cwe or "—",
                row.assessment.value,
                _triage_label(row.triage),
                (row.triage.original_id if row.triage else None) or "—",
                row.original_id or "—",
                row.ingestion.value,
                row.validity or "—",
                row.routing.value,
                row.candidate.evidence_path,
                row.reason,
            )
            for row in report.candidates
            if row.candidate.instrument == instrument
        )
        sections.append(
            Section(
                heading=f"Instrument: {instrument.value}",
                body="No qualifying critical candidates." if not rows else "",
                table=Table(columns=columns, rows=rows),
            )
        )
    sections.append(
        Section(
            heading="Recorded findings (separate population)",
            table=Table(
                columns=(
                    "Finding ID",
                    "Repository ID",
                    "Title",
                    "Assessment",
                    "Validity",
                    "Found by",
                    "Earlier audit",
                ),
                rows=tuple(
                    (
                        str(item.finding_id),
                        str(item.repository_id),
                        item.title,
                        item.reason.value,
                        item.validity or "—",
                        str(item.found_by),
                        str(item.missed_by),
                    )
                    for item in report.recorded_misses
                ),
            ),
        )
    )
    sections.append(
        Section(
            heading="Generation provenance",
            table=Table(
                columns=("Campaign", "Harness version"),
                rows=((report.campaign, report.harness_version or "—"),),
            ),
        )
    )
    return (
        MarkdownRenderer()
        .render(
            Report(
                title="Critical Misses — Campaign Candidate Worklist",
                generated_at=report.generated_at,
                sections=tuple(sections),
                sources=report.sources,
            )
        )
        .decode("utf-8")
    )


def _triage_label(triage: CampaignTriage | None) -> str:
    if triage is None:
        return "untriaged (awaiting fast-track)"
    tp = triage.true_positive_votes
    fp = triage.false_positive_votes
    votes = f"; votes {tp if tp is not None else '—'}-{fp if fp is not None else '—'}"
    confidence = f"; confidence {triage.confidence}" if triage.confidence is not None else ""
    return f"{triage.verdict or 'unknown'}{votes}{confidence}"
