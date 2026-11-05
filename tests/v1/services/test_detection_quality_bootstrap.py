from __future__ import annotations

from uuid import UUID

import pytest

from tests.v1.services.findings.test_reads import service as finding_service
from tests.v1.services.test_detection_quality_regression_pairs import (
    FIX,
    PRE,
    Ledger,
)
from tests.v1.services.test_detection_quality_regression_pairs import (
    engine as engine,
)
from tests.v1.services.test_detection_quality_regression_pairs import (
    ledger as ledger,
)
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import BenchmarkTargetArtifact
from traust_core.v1.models.findings import Validity
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpecs
from traust_core.v1.services.detection_quality import DetectionQualityService


def quality(ledger: Ledger) -> DetectionQualityService:
    uow = SqlTraustUnitOfWork(ledger.engine)
    return DetectionQualityService(
        uow,
        finding_service(ledger.engine),
        ArtifactPublisher(PublishSpecs(), InMemoryObjectStore(), uow),
    )


def test_bootstrap_harvests_confirmed_fix_evidence_without_admitting_or_recording(
    ledger: Ledger,
) -> None:
    finding_id = ledger.finding()
    service = quality(ledger)
    doc = service.bootstrap_benchmark()
    (target,) = doc.targets
    assert (target.pre_fix_sha, target.fix_commit) == (PRE, FIX)
    assert target.provenance == "self_replay"
    assert target.admitted is False
    assert target.expected[0].source_finding == str(finding_id)
    assert target.evidence.excerpt == "Commit bbbbbbb quotes the argument"
    assert str(finding_id) in target.evidence.ref
    assert service._publisher.latest_imported(BenchmarkTargetArtifact) is None


def test_bootstrap_excludes_non_truth_unresolved_unfixed_and_unlocated_findings(
    ledger: Ledger,
) -> None:
    wanted = ledger.finding("cmd/valid.go")
    ledger.finding("cmd/fp.go", validity="false_positive")
    ledger.finding("cmd/open.go", resolved=False)
    ledger.finding("cmd/no-fix.go", fixed=False)
    ledger.finding("cmd/unlocated.go", located=False)
    weakness_id = ledger.finding("cmd/hardening.go")
    with ledger.uow as uow:
        weakness = uow.findings.get(weakness_id)
        uow.findings.update(weakness.model_copy(update={"kind": "weakness"}))
        uow.commit()
    targets = quality(ledger).bootstrap_benchmark().targets
    assert [target.expected[0].source_finding for target in targets] == [str(wanted)]


def test_bootstrap_limit_and_held_out_split_are_stable_and_do_not_use_row_order(
    ledger: Ledger, monkeypatch: pytest.MonkeyPatch
) -> None:
    for index in range(8):
        ledger.finding(f"cmd/file-{index}.go")
    service = quality(ledger)
    fixes = service._findings.fixes(Validity.CONFIRMED)
    expected = [
        f"bt-self-{sha256_hex(fix.view.finding.fingerprint.encode())}"
        for fix in sorted(fixes, key=lambda fix: fix.view.finding.fingerprint)
    ][:3]
    first = service.bootstrap_benchmark(limit=3)
    monkeypatch.setattr(service._findings, "fixes", lambda _: list(reversed(fixes)))
    again = service.bootstrap_benchmark(limit=3)
    assert [target.id for target in first.targets] == expected
    assert [target.id for target in again.targets] == expected
    assert len(first.targets) == 3
    for target in first.targets:
        with ledger.uow as uow:
            finding = uow.findings.get(UUID(target.expected[0].source_finding))
        identity = sha256_hex(finding.fingerprint.encode())
        assert target.id == f"bt-self-{identity}"
        assert target.held_out is (int(identity[:8], 16) % 5 == 0)
        assert target.admitted is False
    assert [target.held_out for target in again.targets] == [
        target.held_out for target in first.targets
    ]


def test_bootstrap_deduplicates_paths_from_distinct_recorded_spans(ledger: Ledger) -> None:
    finding_id = ledger.finding()
    with ledger.uow as uow:
        [occurrence] = uow.occurrences.list_for_finding(finding_id)
        ledger.seed.location(occurrence, path="cmd/run.go", line_start=30, line_end=32)
        uow.commit()
    [target] = quality(ledger).bootstrap_benchmark().targets
    [expected] = target.expected
    assert expected.source_finding == str(finding_id)
    assert len(expected.paths) == 1
    assert "cmd/run.go" in expected.paths


@pytest.mark.parametrize("limit", [0, -1])
def test_bootstrap_refuses_an_invalid_limit(ledger: Ledger, limit: int) -> None:
    with pytest.raises(ValidationError, match="positive"):
        quality(ledger).bootstrap_benchmark(limit=limit)
