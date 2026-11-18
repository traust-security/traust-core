from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.providers.test_cve_replay import NOW, SHA, OsvFixture, advisory
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.findings.test_reads import service as finding_service
from tests.v1.services.test_detection_quality import Bench, finding, report
from tests.v1.services.test_detection_quality import bench as bench
from tests.v1.services.test_detection_quality import engine as engine
from traust_core.v1.errors import (
    ConfigError,
    ForbiddenError,
    IntegrityError,
    NotFoundError,
    ServiceError,
    ValidationError,
)
from traust_core.v1.models.artifacts import (
    BenchmarkTargetArtifact,
    CveReplayArtifact,
    SecurityAuditArtifact,
)
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.models.cve_replay import CveReplaySnapshot, CveReplayVerdict
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.objects.store import ObjectKey, ObjectRef
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    AssessmentLog,
    PublishSpec,
    PublishSpecs,
)
from traust_core.v1.services.detection_quality import DetectionQualityService
from traust_core.v1.services.exposure import ExposureService

HUMAN = Principal(
    identity="reviewer",
    display="Reviewer",
    kind=ActorKind.HUMAN,
    verified_by=IdentitySource.LOCAL_USER,
)
EVIDENCE = "git show audited-sha:pkg/archive/extract.go; unsafe extraction confirmed"


def bound_report(bench: Bench, *findings: dict[str, Any], **updates: Any) -> SecurityAuditArtifact:
    with bench.uow as uow:
        repository = uow.repositories.get(bench.ref.repository_id)
    return report(
        *findings,
        metadata={
            "date": "2026-07-18",
            "scope": "Whole repository",
            "repository": repository.url,
            "commit": bench.ref.sha,
            **updates.pop("metadata", {}),
        },
        **updates,
    )


def quality(bench: Bench, engine: Engine, osv: OsvFixture | None) -> DetectionQualityService:
    findings = finding_service(engine)
    publisher = ArtifactPublisher(
        PublishSpecs(
            PublishSpec(BenchmarkTargetArtifact),
            PublishSpec(SecurityAuditArtifact),
            PublishSpec(CveReplayArtifact),
        ),
        bench.publisher._objects,
        bench.uow,
    )
    return DetectionQualityService(
        bench.uow,
        findings,
        publisher,
        clock=FixedClock(NOW),
        exposure=ExposureService(
            bench.uow,
            findings.intake,
            feeds=ProviderRegistry("feed"),
            objects=bench.publisher._objects,
            advisories=osv.lookup if osv is not None else None,
            clock=FixedClock(NOW),
        ),
    )


def snapshot_rows(bench: Bench) -> list[tuple[Assessment, bytes]]:
    log = AssessmentLog(bench.uow)
    return [
        (assessment, bench.publisher.payload(artifact.id))
        for assessment, artifact in log.documents(
            log.list_of(AssessmentKind.CVE_REPLAY), [CveReplayArtifact.schema]
        )
    ]


def test_monitor_discovers_external_candidates_without_claiming_presence_or_intaking_findings(
    bench: Bench, engine: Engine
) -> None:
    audit = bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    occurrences = bench.rows()[2]
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory()]})
        result = quality(bench, engine, osv).cve_replay()
        restored = quality(bench, engine, osv)
        rerun = restored.cve_replay()
        [candidate] = restored.cve_replay_candidates().candidates
    assert candidate.audit_id == audit
    assert candidate.repository_ref_id == bench.ref.id
    assert candidate.audited_commit == bench.ref.sha
    assert candidate.present_at_audit is None
    assert candidate.audit_verdict == CveReplayVerdict.UNCLEAR
    assert candidate.requires_human_review is True
    assert result.audited_reports == result.queried_commits == 1
    assert result.trends.rows == ()
    assert rerun.checks == ()
    assert rerun.candidates.candidates == (candidate,)
    [watermark] = result.watermarks
    assert watermark.audit_id == audit and watermark.checked_at == NOW
    [(assessment, payload)] = snapshot_rows(bench)
    assert assessment.repository_ref_id == bench.ref.id
    assert assessment.baseline_assessment_id == audit
    assert CveReplaySnapshot.model_validate_json(payload).audit.audit_id == audit
    assert bench.rows()[2] == occurrences


@pytest.mark.parametrize("section", ["findings", "negative_results", "metadata"])
def test_replay_reads_only_original_findings_and_negative_results(
    bench: Bench, engine: Engine, section: str
) -> None:
    if section == "findings":
        doc = bound_report(
            bench,
            finding(
                description=(
                    "CVE-2026-99901 affects unsafe archive extraction "
                    "when an attacker controls an untrusted archive."
                )
            ),
        )
    elif section == "negative_results":
        doc = bound_report(
            bench,
            negative_results=[
                {"area": "archive", "files": "pkg/archive", "result": "CVE-2026-99901 checked"}
            ],
        )
    else:
        doc = bound_report(
            bench,
            executive_summary={
                "prose": (
                    "CVE-2026-99901 is contextual background about another component; "
                    "this summary does not establish that the finding was detected."
                )
            },
        )
    audit = bench.audit(doc, AssessmentKind.SECURE_CODE_CANONICAL)
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory()]})
        [check] = quality(bench, engine, osv).cve_replay().checks
    assert check.audit_id == audit
    assert check.audit_verdict == (
        CveReplayVerdict.UNCLEAR if section == "metadata" else CveReplayVerdict.DETECTED
    )


def test_later_query_failure_preserves_all_prior_snapshots_and_retry_reaches_new_audit(
    bench: Bench, engine: Engine
) -> None:
    bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory()]})
        service = quality(bench, engine, osv)
        service.cve_replay()
        before = snapshot_rows(bench)
        with bench.uow as uow:
            repository = uow.repositories.get(bench.ref.repository_id)
            second = Seed(uow).repository_ref(repository, sha="b" * 40)
            uow.commit()
        second_bench = replace(bench, ref=second)
        second_audit = second_bench.audit(
            bound_report(second_bench), AssessmentKind.SECURE_CODE_CANONICAL
        )
        osv.responses[("b" * 40, "")] = (503, {"error": "fixture unavailable"})
        with pytest.raises(ServiceError):
            service.cve_replay()
        assert snapshot_rows(bench) == before
        osv.responses[("b" * 40, "")] = (200, {"vulns": [advisory()]})
        retried = service.cve_replay()
    assert second_audit in {r.audit_id for r in retried.candidates.candidates}
    assert len(retried.watermarks) == 2
    assert retried.trends.rows == ()


def test_failed_later_page_never_records_initial_snapshot(bench: Bench, engine: Engine) -> None:
    bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory()], "next_page_token": "broken"})
        osv.responses[(SHA, "broken")] = (503, {"error": "second page failed"})
        with pytest.raises(ServiceError):
            quality(bench, engine, osv).cve_replay()
    assert snapshot_rows(bench) == []


def test_publication_not_modification_controls_discovery_and_unknown_dates_do_not_advance(
    bench: Bench, engine: Engine
) -> None:
    bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (
            200,
            {
                "vulns": [
                    advisory(published="2026-01-01T00:00:00Z", modified="2026-11-02T12:00:00Z"),
                    advisory(id="GO-2026-99902", aliases=[]),
                ]
            },
        )
        service = quality(bench, engine, osv)
        assert [row.advisory_id for row in service.cve_replay().checks] == ["GO-2026-99902"]
        before = snapshot_rows(bench)
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory(published=None)]})
        service._clock = FixedClock(NOW.replace(day=4))
        with pytest.raises(ValidationError, match="publication"):
            service.cve_replay()
        assert snapshot_rows(bench) == before


@pytest.mark.parametrize("presence", [None, False, True])
def test_oracle_records_human_adjudication_without_advancing_source_watermark(
    bench: Bench, engine: Engine, presence: bool | None
) -> None:
    audit = bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    with OsvFixture() as osv:
        osv.records["CVE-2026-99901"] = advisory()
        service = quality(bench, engine, osv)
        check = service.cve_replay_oracle(
            audit,
            "CVE-2026-99901",
            present_at_audit=presence,
            principal=HUMAN if presence is not None else None,
            presence_evidence=EVIDENCE if presence is not None else None,
        )
        assert check.present_at_audit is presence
        assert check.reviewer == (HUMAN.ref if presence is not None else None)
        assert check.trend_eligible is (presence is True)
        restored = quality(bench, engine, osv)
        assert len(restored.cve_replay_trends().rows) == (1 if presence is True else 0)
        [(_, payload)] = snapshot_rows(bench)
        assert CveReplaySnapshot.model_validate_json(payload).watermark is None
        assert osv.requests == []


@pytest.mark.parametrize(
    "kind,verified",
    [
        (ActorKind.MACHINE, IdentitySource.DATABASE),
        (ActorKind.HUMAN, None),
    ],
)
def test_agent_or_unverified_text_identity_cannot_confirm_presence(
    bench: Bench, engine: Engine, kind: ActorKind, verified: IdentitySource | None
) -> None:
    audit = bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    principal = HUMAN.model_copy(update={"kind": kind, "verified_by": verified})
    with OsvFixture() as osv:
        with pytest.raises(ForbiddenError):
            quality(bench, engine, osv).cve_replay_oracle(
                audit,
                "CVE-2026-99901",
                present_at_audit=True,
                principal=principal,
                presence_evidence=EVIDENCE,
            )
        assert osv.requests == []
    assert snapshot_rows(bench) == []


def test_oracle_requires_evidence_and_allows_human_correction_at_same_clock_time(
    bench: Bench, engine: Engine
) -> None:
    audit = bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    with OsvFixture() as osv:
        osv.records["CVE-2026-99901"] = advisory()
        service = quality(bench, engine, osv)
        with pytest.raises(ValidationError):
            service.cve_replay_oracle(
                audit,
                "CVE-2026-99901",
                present_at_audit=True,
                principal=HUMAN,
            )
        service.cve_replay_oracle(
            audit,
            "CVE-2026-99901",
            present_at_audit=True,
            principal=HUMAN,
            presence_evidence=EVIDENCE,
        )
        assert len(service.cve_replay_trends().rows) == 1
        service.cve_replay_oracle(
            audit,
            "CVE-2026-99901",
            present_at_audit=False,
            principal=HUMAN,
            presence_evidence="source inspection confirms vulnerable code absent",
        )
        assert service.cve_replay_trends().rows == ()
        assert service.cve_replay_candidates().candidates == ()
        revisions = [
            CveReplaySnapshot.model_validate_json(payload).revision
            for _, payload in snapshot_rows(bench)
        ]
        assert sorted(revisions) == [1, 2]


def test_oracle_refuses_non_audit_missing_assessment_and_unknown_advisory(
    bench: Bench, engine: Engine
) -> None:
    non_audit = bench.audit(bound_report(bench), AssessmentKind.BENCHMARK_AUDIT)
    audit = bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    with OsvFixture() as osv:
        service = quality(bench, engine, osv)
        for assessment in (non_audit, UUID(int=999)):
            with pytest.raises(NotFoundError):
                service.cve_replay_oracle(assessment, "CVE-2026-99901")
        with pytest.raises(NotFoundError):
            service.cve_replay_oracle(audit, "CVE-2026-99901")
    assert snapshot_rows(bench) == []


def test_oracle_adjudicates_only_advisories_published_inside_the_replay_window(
    bench: Bench, engine: Engine
) -> None:
    audit = bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    with bench.uow as uow:
        audited_at = uow.assessments.get(audit).occurred_at
    with OsvFixture() as osv:
        osv.records["CVE-2026-99901"] = advisory(published=None)
        service = quality(bench, engine, osv)
        with pytest.raises(ValidationError, match="publication must be known"):
            service.cve_replay_oracle(
                audit,
                "CVE-2026-99901",
                present_at_audit=False,
                principal=HUMAN,
                presence_evidence=EVIDENCE,
            )
        osv.records["CVE-2026-99901"] = advisory(
            published=audited_at.isoformat().replace("+00:00", "Z")
        )
        with pytest.raises(ValidationError, match="strictly after the audit"):
            service.cve_replay_oracle(
                audit,
                "CVE-2026-99901",
                present_at_audit=False,
                principal=HUMAN,
                presence_evidence=EVIDENCE,
            )
        osv.records["CVE-2026-99901"] = advisory(published="2099-01-01T00:00:00Z")
        with pytest.raises(ValidationError, match="no later than now"):
            service.cve_replay_oracle(
                audit,
                "CVE-2026-99901",
                present_at_audit=False,
                principal=HUMAN,
                presence_evidence=EVIDENCE,
            )
    assert snapshot_rows(bench) == []


@pytest.mark.parametrize("since", [datetime(2026, 10, 1), datetime(2099, 1, 1, tzinfo=UTC)])
def test_invalid_watermark_fails_before_network_or_snapshot_write(
    bench: Bench, engine: Engine, since: datetime
) -> None:
    with OsvFixture() as osv, pytest.raises(ValidationError):
        quality(bench, engine, osv).cve_replay(since)
    assert osv.requests == []
    assert snapshot_rows(bench) == []


def test_empty_monitor_has_no_synthetic_snapshot_and_unconfigured_provider_is_refused(
    bench: Bench, engine: Engine
) -> None:
    with OsvFixture() as osv:
        run = quality(bench, engine, osv).cve_replay()
        assert run.audited_reports == run.queried_commits == 0
        assert run.candidates.candidates == run.trends.rows == ()
    assert snapshot_rows(bench) == []
    with pytest.raises(ConfigError):
        quality(bench, engine, None).cve_replay()


def test_historical_secure_code_kind_replays_original_bound_report(
    bench: Bench, engine: Engine
) -> None:
    doc = bound_report(bench)
    published = bench.publisher.publish_artifact(doc)
    historical, artifact = AssessmentLog(bench.uow).add(
        Assessment(
            repository_ref_id=bench.ref.id,
            kind=AssessmentKind.SECURE_CODE,
            status="completed",
            assessor="skill:secure-code-audit",
            assessor_version="historical-harness",
            occurred_at=NOW.replace(day=1),
        ),
        published.artifact_id,
        sha256_hex(doc.payload),
    )
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory()]})
        [check] = quality(bench, engine, osv).cve_replay().checks
    assert check.audit_id == historical.id
    assert check.report_artifact_id == artifact.id
    assert bench.publisher.get(artifact.id).payload == doc.payload


def test_corrupt_recorded_snapshot_is_not_silently_reset(bench: Bench, engine: Engine) -> None:
    bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory()]})
        service = quality(bench, engine, osv)
        service.cve_replay()
        log = AssessmentLog(bench.uow)
        [(_, artifact)] = log.documents(
            log.list_of(AssessmentKind.CVE_REPLAY), [CveReplayArtifact.schema]
        )
        key = ObjectKey.parse(artifact.uri)
        bench.publisher._objects.put(key, b"not-json")
        with pytest.raises(IntegrityError):
            service.cve_replay_candidates()
        assert bench.publisher._objects.get(bench.publisher._objects.stat(key)) == b"not-json"


def test_explicit_watermark_boundary_is_inclusive_to_avoid_dropping_delayed_records(
    bench: Bench, engine: Engine
) -> None:
    bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    since = datetime(2026, 11, 2, 12, tzinfo=UTC)
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory()]})
        service = quality(bench, engine, osv)
        result = service.cve_replay(since)
    assert [row.advisory_id for row in result.checks] == ["CVE-2026-99901"]
    assert len(result.watermarks) == 1
    [(_, payload)] = snapshot_rows(bench)
    assert CveReplaySnapshot.model_validate_json(payload).watermark == NOW


def test_new_audit_of_same_commit_has_independent_discovery_watermark(
    bench: Bench, engine: Engine
) -> None:
    first = bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory()]})
        service = quality(bench, engine, osv)
        service.cve_replay()
        doc = bound_report(bench)
        published = bench.publisher.publish_artifact(doc)
        second, _ = AssessmentLog(bench.uow).add(
            Assessment(
                repository_ref_id=bench.ref.id,
                kind=AssessmentKind.SECURE_CODE_CANONICAL,
                status="completed",
                assessor="skill:secure-code-audit",
                assessor_version="second-audit",
                occurred_at=datetime(2026, 10, 20, tzinfo=UTC),
            ),
            published.artifact_id,
            sha256_hex(doc.payload),
        )
        result = service.cve_replay()
    assert len(result.candidates.candidates) == 2
    assert {row.audit_id for row in result.watermarks} == {first, second.id}
    assert [row.audit_id for row in result.checks] == [second.id]


def test_exact_oracle_retry_does_not_append_duplicate_snapshot(
    bench: Bench, engine: Engine
) -> None:
    audit = bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    with OsvFixture() as osv:
        osv.records["CVE-2026-99901"] = advisory()
        service = quality(bench, engine, osv)
        first = service.cve_replay_oracle(
            audit,
            "CVE-2026-99901",
            present_at_audit=True,
            principal=HUMAN,
            presence_evidence=EVIDENCE,
        )
        second = service.cve_replay_oracle(
            audit,
            "CVE-2026-99901",
            present_at_audit=True,
            principal=HUMAN,
            presence_evidence=EVIDENCE,
        )
    assert first == second
    assert len(snapshot_rows(bench)) == 1


def test_monitor_cannot_overwrite_verified_human_presence_with_external_discovery(
    bench: Bench, engine: Engine
) -> None:
    audit = bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    with OsvFixture() as osv:
        osv.records["CVE-2026-99901"] = advisory()
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory()]})
        service = quality(bench, engine, osv)
        human = service.cve_replay_oracle(
            audit,
            "CVE-2026-99901",
            present_at_audit=True,
            principal=HUMAN,
            presence_evidence=EVIDENCE,
        )
        result = service.cve_replay()
    assert result.trends.rows == (human,)
    assert result.candidates.candidates == (human,)
    assert result.checks[0].present_at_audit is None


def test_an_unchanged_replay_does_not_republish_per_run(bench: Bench, engine: Engine) -> None:
    """A re-run with a moving clock and no newly published advisories republishes nothing:
    the skip is the checks' equality, not a watermark that always advances to now (a later
    prior watermark is refused, so requiring watermark equality made the skip fire only on a
    same-instant retry — every run wrote a new artifact and CVE_REPLAY assessment per audit,
    each embedding the full accumulated checks list)."""
    bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory()]})
        service = quality(bench, engine, osv)
        first = service.cve_replay()
        assert len(first.checks) == 1
        after_first = snapshot_rows(bench)
        assert len(after_first) == 1
        service._clock = FixedClock(NOW.replace(day=4))
        second = service.cve_replay()
    # nothing newly classified (the same_advisory fast path skips the
    # already-checked advisory), the accumulated state is unchanged, and no
    # snapshot row was republished for the watermark alone
    assert second.checks == ()
    assert second.candidates.candidates == first.candidates.candidates
    assert snapshot_rows(bench) == after_first


def test_cve_replay_reads_the_report_corpus_once(bench: Bench, engine: Engine) -> None:
    """The audits a caller already fetched are threaded into the snapshot read:
    `_cve_audits()` reads and parses every SECURE_CODE report payload from the
    object store, and cve_replay used to pay for it twice (once directly, once
    inside `_cve_snapshots`)."""
    bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    with OsvFixture() as osv:
        service = quality(bench, engine, osv)
        original = service._cve_audits
        calls = []

        def counted():
            calls.append(1)
            return original()

        service._cve_audits = counted
        service.cve_replay()
    assert len(calls) == 1


def test_successful_empty_commit_answer_records_watermark_without_candidates(
    bench: Bench, engine: Engine
) -> None:
    audit = bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    with OsvFixture() as osv:
        run = quality(bench, engine, osv).cve_replay()
    assert run.checks == ()
    assert run.candidates.candidates == run.trends.rows == ()
    assert run.watermarks[0].audit_id == audit
    assert run.watermarks[0].checked_at == NOW


def test_successful_empty_answer_does_not_hide_late_visible_pre_watermark_advisory(
    bench: Bench, engine: Engine
) -> None:
    audit = bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    with OsvFixture() as osv:
        first = quality(bench, engine, osv).cve_replay()
        assert first.checks == ()
        assert first.watermarks[0].checked_at == NOW
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory()]})
        restored = quality(bench, engine, osv)
        restored._clock = FixedClock(NOW.replace(day=4))
        result = restored.cve_replay()
        before_retry = snapshot_rows(bench)
        retry = restored.cve_replay()
    [check] = result.checks
    assert check.audit_id == audit
    assert check.published_at is not None and check.published_at < NOW
    assert check.present_at_audit is None
    assert result.candidates.candidates == (check,)
    assert result.watermarks[0].checked_at == NOW.replace(day=4)
    assert retry.checks == ()
    assert retry.candidates == result.candidates
    assert snapshot_rows(bench) == before_retry
    assert len(before_retry) == 2


def test_explicit_since_still_filters_late_visible_advisories_after_a_successful_check(
    bench: Bench, engine: Engine
) -> None:
    bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    since = datetime(2026, 11, 2, 12, tzinfo=UTC)
    with OsvFixture() as osv:
        service = quality(bench, engine, osv)
        service.cve_replay()
        osv.responses[(SHA, "")] = (
            200,
            {
                "vulns": [
                    advisory(id="GO-2026-99900", aliases=[], published="2026-11-02T11:59:59Z"),
                    advisory(),
                    advisory(id="GO-2026-99902", aliases=[], published="2026-11-02T12:00:01Z"),
                ]
            },
        )
        service._clock = FixedClock(NOW.replace(day=4))
        filtered = service.cve_replay(since)
        unfiltered = service.cve_replay()
    assert {check.advisory_id for check in filtered.checks} == {
        "CVE-2026-99901",
        "GO-2026-99902",
    }
    assert [check.advisory_id for check in unfiltered.checks] == ["GO-2026-99900"]
    assert len(unfiltered.candidates.candidates) == 3


def test_advisory_at_previous_successful_check_time_is_inclusive_and_retry_is_idempotent(
    bench: Bench, engine: Engine
) -> None:
    bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    with OsvFixture() as osv:
        service = quality(bench, engine, osv)
        service.cve_replay()
        osv.responses[(SHA, "")] = (
            200,
            {"vulns": [advisory(published=NOW.isoformat())]},
        )
        [check] = service.cve_replay().checks
        before_retry = snapshot_rows(bench)
        service.cve_replay()
    assert check.published_at == NOW
    assert len(before_retry) == 2
    assert snapshot_rows(bench) == before_retry


@pytest.mark.parametrize(
    "metadata",
    [
        {"repository": "https://github.com/org/another-repository"},
        {"commit": "b" * 40},
        {"commit": ""},
    ],
)
@pytest.mark.parametrize("oracle", [False, True])
def test_mismatched_original_report_binding_refuses_before_any_source_or_snapshot_io(
    bench: Bench,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    metadata: dict[str, object],
    oracle: bool,
) -> None:
    bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    doc = bound_report(bench, metadata=metadata)
    audit = bench.audit(doc, AssessmentKind.SECURE_CODE_CANONICAL)
    before = bench.rows()

    def unexpected_io(*args: object, **kwargs: object) -> None:
        pytest.fail("an unbound original report must refuse before source or snapshot I/O")

    with OsvFixture() as osv:
        monkeypatch.setattr(osv.lookup, "for_commit", unexpected_io)
        monkeypatch.setattr(osv.lookup, "record", unexpected_io)
        service = quality(bench, engine, osv)
        monkeypatch.setattr(service._publisher, "publish_artifact", unexpected_io)
        with pytest.raises(ValidationError, match="original report repository and commit"):
            if oracle:
                service.cve_replay_oracle(audit, "CVE-2026-99901")
            else:
                service.cve_replay()
        assert osv.requests == []
    assert bench.rows() == before
    assert snapshot_rows(bench) == []


def test_advisory_published_exactly_at_audit_is_not_post_audit_discovery(
    bench: Bench, engine: Engine
) -> None:
    audit = bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    recorded = AssessmentLog(bench.uow).get(audit)
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (
            200,
            {"vulns": [advisory(published=recorded.occurred_at.isoformat())]},
        )
        run = quality(bench, engine, osv).cve_replay()
    assert run.checks == ()


def test_stale_oracle_publication_conflicts_without_overwriting_a_human_successor(
    bench: Bench, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_core.v1.errors import ConflictError
    from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

    audit = bench.audit(bound_report(bench), AssessmentKind.SECURE_CODE_CANONICAL)
    objects = bench.publisher._objects
    put = objects.put
    interleaved = False
    with OsvFixture() as osv:
        osv.records["CVE-2026-99901"] = advisory()
        first = quality(replace(bench, uow=SqlTraustUnitOfWork(engine)), engine, osv)
        second = quality(replace(bench, uow=SqlTraustUnitOfWork(engine)), engine, osv)

        def publish_with_successor(key: ObjectKey, data: bytes) -> ObjectRef:
            nonlocal interleaved
            if str(key).startswith("artifacts/cve-replay/") and not interleaved:
                interleaved = True
                second.cve_replay_oracle(
                    audit,
                    "CVE-2026-99901",
                    present_at_audit=False,
                    principal=HUMAN,
                    presence_evidence="Human verified source is not affected",
                )
            return put(key, data)

        monkeypatch.setattr(objects, "put", publish_with_successor)
        with pytest.raises(ConflictError, match="changed"):
            first.cve_replay_oracle(
                audit,
                "CVE-2026-99901",
                present_at_audit=True,
                principal=HUMAN,
                presence_evidence=EVIDENCE,
            )
        assert first.cve_replay_candidates().candidates == ()
        assert first.cve_replay_trends().rows == ()
        assert len(snapshot_rows(bench)) == 1
        monkeypatch.setattr(objects, "put", put)
        retried = first.cve_replay_oracle(
            audit,
            "CVE-2026-99901",
            present_at_audit=True,
            principal=HUMAN,
            presence_evidence=EVIDENCE,
        )
    assert first.cve_replay_trends().rows == (retried,)
    revisions = [
        CveReplaySnapshot.model_validate_json(payload).revision
        for _, payload in snapshot_rows(bench)
    ]
    assert sorted(revisions) == [1, 2]
