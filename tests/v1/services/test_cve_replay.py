from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from sqlalchemy.engine import Engine

from tests.v1.providers.test_osv_commit_replay import NOW, SHA, OsvFixture, advisory
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.findings.test_reads import service as finding_service
from tests.v1.services.test_detection_quality import (
    Bench,
    finding,
    report,
)
from tests.v1.services.test_detection_quality import (
    bench as bench,
)
from tests.v1.services.test_detection_quality import (
    engine as engine,
)
from traust_core.v1.errors import NotFoundError, ServiceError, ValidationError
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.models.cve_replay import CveReplayVerdict
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.objects.store import ObjectKey
from traust_core.v1.services.artifact_publishing import AssessmentLog
from traust_core.v1.services.detection_quality import DetectionQualityService

STATE = ObjectKey("detection-quality/cve-replay/state.json")


def quality(
    bench: Bench, engine: Engine, osv: OsvFixture, objects: InMemoryObjectStore
) -> DetectionQualityService:
    return DetectionQualityService(
        bench.uow,
        finding_service(engine),
        bench.publisher,
        clock=FixedClock(NOW),
        objects=objects,
        osv=osv.lookup,
    )


def test_first_monitor_discovers_new_advisory_from_real_recorded_audit_without_findings(
    bench: Bench, engine: Engine
) -> None:
    audit_id = bench.audit(report(), AssessmentKind.SECURE_CODE_CANONICAL)
    counts = bench.rows()
    objects = InMemoryObjectStore()
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory()]})
        service = quality(bench, engine, osv, objects)
        result = service.cve_replay()
        restored = quality(bench, engine, osv, objects)
        rerun = restored.cve_replay()
        queued = restored.cve_replay_candidates()
        trends = restored.cve_replay_trends()
    assert result.audited_reports == result.queried_commits == 1
    [check] = result.checks
    assert check.audit_id == audit_id
    assert check.repository_ref_id == bench.ref.id
    assert check.audited_commit == bench.ref.sha
    assert check.present_at_audit is True
    assert check.audit_verdict == CveReplayVerdict.MISSED
    assert check.requires_human_review is True
    assert [r.audit_id for r in queued.candidates] == [audit_id]
    assert trends.rows == queued.candidates
    assert rerun.checks == ()
    assert len(rerun.candidates.candidates) == len(rerun.trends.rows) == 1
    assert result.watermarks == {f"osv:commit:{SHA}": NOW}
    assert bench.rows() == counts


def test_recorded_findings_and_negative_results_are_read_without_finding_intake(
    bench: Bench, engine: Engine
) -> None:
    audit_id = bench.audit(
        report(
            finding(
                description="CVE-2026-99901 affects the archive extraction handler, which joins "
                "an untrusted entry path to the destination without enforcing that boundary."
            )
        ),
        AssessmentKind.SECURE_CODE_CANONICAL,
    )
    counts = bench.rows()
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory()]})
        result = quality(bench, engine, osv, InMemoryObjectStore()).cve_replay()
    [check] = result.checks
    assert check.audit_id == audit_id
    assert check.audit_verdict == CveReplayVerdict.DETECTED
    assert check.matched_advisory_ids == ("CVE-2026-99901",)
    assert result.candidates.candidates == result.trends.rows == ()
    assert bench.rows() == counts


def test_later_commit_failure_keeps_prior_watermarks_and_candidates_byte_for_byte(
    bench: Bench, engine: Engine
) -> None:
    bench.audit(report(), AssessmentKind.SECURE_CODE_CANONICAL)
    objects = InMemoryObjectStore()
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory()]})
        service = quality(bench, engine, osv, objects)
        service.cve_replay()
        before = objects.get(objects.stat(STATE))
        with bench.uow as uow:
            repository = uow.repositories.get(bench.ref.repository_id)
            second = Seed(uow).repository_ref(repository, sha="b" * 40)
            uow.commit()
        second_audit = replace(bench, ref=second).audit(
            report(), AssessmentKind.SECURE_CODE_CANONICAL
        )
        osv.responses[("b" * 40, "")] = (503, {"error": "offline fixture failure"})
        with pytest.raises(ServiceError):
            service.cve_replay()
        assert objects.get(objects.stat(STATE)) == before
        osv.responses[("b" * 40, "")] = (200, {"vulns": [advisory()]})
        retried = service.cve_replay()
    assert len(retried.candidates.candidates) == len(retried.trends.rows) == 2
    assert second_audit in {r.audit_id for r in retried.trends.rows}
    assert set(retried.watermarks) == {f"osv:commit:{SHA}", f"osv:commit:{'b' * 40}"}


def test_http_pagination_failure_never_creates_initial_monitor_state(
    bench: Bench, engine: Engine
) -> None:
    bench.audit(report(), AssessmentKind.SECURE_CODE_CANONICAL)
    objects = InMemoryObjectStore()
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory()], "next_page_token": "broken"})
        osv.responses[(SHA, "broken")] = (503, {"error": "second page failed"})
        with pytest.raises(ServiceError):
            quality(bench, engine, osv, objects).cve_replay()
    assert not objects.exists(STATE)


def test_new_advisory_selection_uses_publication_after_audit_not_modification_date(
    bench: Bench, engine: Engine
) -> None:
    bench.audit(report(), AssessmentKind.SECURE_CODE_CANONICAL)
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (
            200,
            {
                "vulns": [
                    advisory(published="2026-09-01T00:00:00Z"),
                    advisory(id="GO-2026-99902", aliases=[], published="2026-11-02T12:00:00Z"),
                ]
            },
        )
        result = quality(bench, engine, osv, InMemoryObjectStore()).cve_replay()
    assert [r.advisory_id for r in result.checks] == ["GO-2026-99902"]


@pytest.mark.parametrize("presence", [None, False, True])
def test_oracle_preserves_unknown_or_human_presence_when_commit_query_does_not_match(
    bench: Bench, engine: Engine, presence: bool | None
) -> None:
    audit_id = bench.audit(report(), AssessmentKind.SECURE_CODE_CANONICAL)
    objects = InMemoryObjectStore()
    with OsvFixture() as osv:
        osv.records["CVE-2026-99901"] = advisory()
        check = quality(bench, engine, osv, objects).cve_replay_oracle(
            audit_id, "CVE-2026-99901", present_at_audit=presence
        )
    assert check.present_at_audit is presence
    assert check.audit_verdict == (
        CveReplayVerdict.NOT_APPLICABLE if presence is False else CveReplayVerdict.MISSED
    )
    assert check.trend_eligible is (presence is True)
    assert not objects.exists(STATE)


def test_oracle_commit_hit_is_external_presence_evidence_not_benchmark_admission(
    bench: Bench, engine: Engine
) -> None:
    audit_id = bench.audit(report(), AssessmentKind.SECURE_CODE_CANONICAL)
    with OsvFixture() as osv:
        osv.records["CVE-2026-99901"] = advisory()
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory()]})
        check = quality(bench, engine, osv, InMemoryObjectStore()).cve_replay_oracle(
            audit_id, "CVE-2026-99901"
        )
    assert check.present_at_audit is True
    assert check.requires_human_review is True
    assert check.audit_verdict == CveReplayVerdict.MISSED


def test_oracle_refuses_non_audit_assessment_and_unknown_advisory(
    bench: Bench, engine: Engine
) -> None:
    non_audit = bench.audit(report(), AssessmentKind.BENCHMARK_AUDIT)
    audit = bench.audit(report(), AssessmentKind.SECURE_CODE_CANONICAL)
    with OsvFixture() as osv:
        service = quality(bench, engine, osv, InMemoryObjectStore())
        with pytest.raises(NotFoundError):
            service.cve_replay_oracle(non_audit, "CVE-2026-99901")
        with pytest.raises(NotFoundError):
            service.cve_replay_oracle(audit, "CVE-2026-99901")


@pytest.mark.parametrize("since", [datetime(2026, 10, 1), datetime(2099, 1, 1, tzinfo=UTC)])
def test_invalid_source_watermark_fails_before_network_or_state_write(
    bench: Bench, engine: Engine, since: datetime
) -> None:
    objects = InMemoryObjectStore()
    with OsvFixture() as osv, pytest.raises(ValidationError):
        quality(bench, engine, osv, objects).cve_replay(since)
    assert osv.requests == []
    assert not objects.exists(STATE)


def test_corrupt_persisted_state_is_not_silently_reset(bench: Bench, engine: Engine) -> None:
    from pydantic import ValidationError as ModelValidationError

    objects = InMemoryObjectStore()
    objects.put(STATE, b"not json")
    with OsvFixture() as osv, pytest.raises(ModelValidationError):
        quality(bench, engine, osv, objects).cve_replay()
    assert objects.get(objects.stat(STATE)) == b"not json"


def test_historical_secure_code_spelling_replays_the_original_bound_report(
    bench: Bench, engine: Engine
) -> None:
    doc = report()
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
    assert historical.id is not None and artifact.id is not None
    counts = bench.rows()
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory()]})
        result = quality(bench, engine, osv, InMemoryObjectStore()).cve_replay()
    [check] = result.checks
    assert check.audit_id == historical.id
    assert check.report_artifact_id == artifact.id
    assert bench.publisher.get(artifact.id).payload == doc.payload
    assert check.requires_human_review is True
    assert bench.rows() == counts
