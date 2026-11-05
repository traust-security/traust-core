from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock
from uuid import uuid4

import pytest

from tests.v1.conftest import CheckoutForge
from tests.v1.providers.tools.test_rule_calibration import RULE, ScannerProcess
from traust_core.v1.context.documents import yaml_documents
from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.detection_quality import TruePositive
from traust_core.v1.models.findings import SubjectRef
from traust_core.v1.models.rule_calibration import CalibrationStatus, RuleCalibrationRequest
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.providers.base import Readiness, Result
from traust_core.v1.providers.sources import CheckoutRequest
from traust_core.v1.providers.tools import rule_calibration
from traust_core.v1.providers.tools.rule_calibration import OpengrepCalibration
from traust_core.v1.services.detection_quality import DetectionQualityService
from traust_core.v1.services.portfolio import Inventory
from traust_core.v1.services.rule_calibration import scan_pack


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple:
    monkeypatch.setattr(rule_calibration, "on_path", lambda _: Readiness(ready=True))
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "demo.yaml").write_text(RULE)
    forge = CheckoutForge(tmp_path)
    sha = forge.commit({"src/a.py": "danger(user_input)\n"})
    subject = SubjectRef(
        repository_id=uuid4(), repository_ref_id=uuid4(), repository_url=forge.url, sha=str(sha)
    )
    tp = TruePositive(
        finding_id=uuid4(),
        repository_id=subject.repository_id,
        repository_ref_id=subject.repository_ref_id,
        cwe="CWE-78",
        severity="high",
        language="python",
        paths=("src/a.py",),
        title="synthetic sink",
    )
    inventory = Mock(spec=Inventory)
    inventory.subject.return_value = subject
    checkouts = Mock(wraps=forge.service())
    raw = {
        "results": [
            {
                "check_id": "demo",
                "path": path,
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"message": "sink", "metadata": {"cwe": ["CWE-78"]}, "lines": "danger(x)"},
            }
            for path in ("src/a.py", "src/novel.py")
        ],
        "paths": {"scanned": ["src/a.py"]},
    }
    process = ScannerProcess(json.dumps(raw).encode())
    scanner = OpengrepCalibration(pack, lambda: (), checkouts, process, yaml_documents)
    return scanner, checkouts, inventory, tp, subject


def test_live_calibration_checks_out_the_confirmed_commit_and_emits_review_samples(
    setup: tuple,
) -> None:
    scanner, checkouts, inventory, tp, subject = setup
    result = scan_pack(scanner, checkouts, inventory, RuleCalibrationRequest(), [tp, tp])
    assert result.status is CalibrationStatus.COMPLETED
    assert len(result.checkouts) == 1
    assert result.checkouts[0].subject == subject
    assert result.checkouts[0].scan.complete
    assert [r.rediscovered for r in result.review_sample] == [False, True]
    checkouts.checkout.assert_called_once()
    assert str(checkouts.checkout.call_args.args[0].ref) == subject.sha
    checkouts.release.assert_called_once()
    assert not checkouts.release.call_args.args[0].path.exists()


def test_checkout_failure_is_a_failed_result_not_a_clean_zero_hit_scan(setup: tuple) -> None:
    scanner, checkouts, inventory, tp, _ = setup
    checkouts.checkout.side_effect = ServiceError("corpus commit unavailable")
    result = scan_pack(scanner, checkouts, inventory, RuleCalibrationRequest(), [tp])
    assert result.status is CalibrationStatus.FAILED
    assert result.checkouts[0].scan is None
    assert "corpus commit unavailable" in result.checkouts[0].reason
    assert result.summary["commits_failed"] == 1
    checkouts.release.assert_not_called()


def test_scanner_failure_releases_checkout_and_keeps_failure_reason(setup: tuple) -> None:
    scanner, checkouts, inventory, tp, _ = setup
    scanner._runner.raw = b"not JSON"
    result = scan_pack(scanner, checkouts, inventory, RuleCalibrationRequest(), [tp])
    assert result.status is CalibrationStatus.FAILED
    assert "no JSON" in result.checkouts[0].reason
    checkouts.release.assert_called_once()


def test_wrong_checkout_commit_is_never_scored(setup: tuple) -> None:
    scanner, checkouts, inventory, tp, subject = setup
    acquired = checkouts._mock_wraps.checkout(
        CheckoutRequest(
            repo=HttpsRepoUrl.parse(subject.repository_url, ["github.com"]),
            ref=GitSha.parse(subject.sha),
        )
    )
    checkouts.checkout.return_value = Result(
        acquired.data.model_copy(update={"sha": GitSha.parse("b" * 40)}), acquired.acquisition
    )
    outcome = scan_pack(scanner, checkouts, inventory, RuleCalibrationRequest(), [tp])
    assert outcome.status is CalibrationStatus.FAILED
    assert "wrong corpus commit" in outcome.checkouts[0].reason
    checkouts.release.assert_called_once()


def test_missing_commit_is_counted_as_skipped_not_silently_dropped(setup: tuple) -> None:
    scanner, checkouts, inventory, tp, _ = setup
    unpinned = tp.model_copy(update={"finding_id": uuid4(), "repository_ref_id": None})
    result = scan_pack(scanner, checkouts, inventory, RuleCalibrationRequest(), [tp, unpinned])
    assert result.status is CalibrationStatus.DEGRADED
    assert result.skipped[0].finding_id == unpinned.finding_id
    assert result.summary["findings_skipped"] == 1


def test_empty_confirmed_corpus_is_refused(setup: tuple) -> None:
    scanner, checkouts, inventory, _, _ = setup
    with pytest.raises(ValidationError, match="confirmed true positives"):
        scan_pack(scanner, checkouts, inventory, RuleCalibrationRequest(), [])
    checkouts.checkout.assert_not_called()


def test_fixture_mode_never_reads_inventory_or_acquires_corpus_checkouts(setup: tuple) -> None:
    scanner, checkouts, inventory, _, _ = setup
    (scanner._pack / "tests").mkdir()
    (scanner._pack / "tests" / "a.py").write_text("danger(user_input)\n")
    result = scan_pack(scanner, checkouts, inventory, RuleCalibrationRequest(fixtures=True), [])
    assert result.status is CalibrationStatus.COMPLETED
    inventory.subject.assert_not_called()
    checkouts.checkout.assert_not_called()


@pytest.mark.parametrize("kwargs", [{"limit": 0}, {"limit": -1}, {"timeout": 0}])
def test_nonpositive_calibration_limits_are_boundary_errors(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        RuleCalibrationRequest(**kwargs)


def test_public_service_scores_live_scans_with_existing_calibration_arithmetic(
    setup: tuple,
) -> None:
    scanner, checkouts, inventory, tp, _ = setup
    publisher = Mock()
    service = DetectionQualityService(
        Mock(), Mock(), publisher, calibration=scanner, checkouts=checkouts
    )
    service._inventory = inventory
    service._corpus = Mock(return_value=[tp])
    service._true_positives = Mock(return_value=(frozenset({"src/a.py"}), frozenset({"CWE-78"})))
    result = service.calibrate_pack(RuleCalibrationRequest(rules=str(scanner._pack)))
    assert result.status is CalibrationStatus.COMPLETED
    assert result.calibration.scanned == 1
    assert result.calibration.tp_files == 1
    assert result.calibration.rediscoveries == 1
    assert result.calibration.rules[0].novel == 1
    assert publisher.mock_calls == []


def test_public_fixture_service_never_loads_confirmed_findings(setup: tuple) -> None:
    scanner, checkouts, inventory, _, _ = setup
    (scanner._pack / "tests").mkdir()
    (scanner._pack / "tests" / "a.py").write_text("danger(user_input)\n")
    service = DetectionQualityService(
        Mock(), Mock(), Mock(), calibration=scanner, checkouts=checkouts
    )
    service._inventory = inventory
    service._corpus = Mock(side_effect=AssertionError("fixtures must not read the TP corpus"))
    result = service.calibrate_pack(RuleCalibrationRequest(fixtures=True, rules=str(scanner._pack)))
    assert result.status is CalibrationStatus.COMPLETED
    service._corpus.assert_not_called()


def test_limit_skips_additional_commits_explicitly(setup: tuple) -> None:
    scanner, checkouts, inventory, tp, _ = setup
    another = tp.model_copy(update={"finding_id": uuid4(), "repository_ref_id": uuid4()})
    result = scan_pack(
        scanner, checkouts, inventory, RuleCalibrationRequest(limit=1), [tp, another]
    )
    assert result.status is CalibrationStatus.DEGRADED
    assert result.skipped[0].finding_id == another.finding_id
    assert result.skipped[0].reason == "calibration commit limit"
    checkouts.checkout.assert_called_once()
