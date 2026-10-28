"""The validation-lane benchmark: its worklist, scoring and release trigger. Ported from
traust-engine tests/test_benchmark_plan.py and tests/test_benchmark_trigger_paths.py, and traust
tests/test_target_attestation.py::TestValidationBenchmark (traust-engine 0b483d7)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.validation_benchmark import (
    TRIGGER_PATHS,
    BenchmarkScore,
    BenchmarkTrigger,
    BenchmarkVariant,
    BenchmarkWorklist,
    ValidationBenchmark,
    ValidationRun,
)

NOW = datetime(2026, 10, 27, tzinfo=UTC)
CLAIM = {
    "title": "A proposed RBAC exposure",
    "severity": "high",
    "cvss": 8.0,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "cwes": ["CWE-269"],
    "category": "authorization",
}


def bench(n: int = 2, floors: bool = True) -> ValidationBenchmark:
    doc: dict[str, Any] = {
        "version": 1,
        "namespace": "validation-benchmark",
        "fixtures": [
            {
                "id": f"BENCH-00{i}",
                "claim": CLAIM,
                "probe_class": "rbac",
                "controls_hint": "Compare the vulnerable fixture with its safe twin.",
                "vuln_manifest": f"rbac-{i}.vuln.yaml",
                "safe_manifest": f"rbac-{i}.safe.yaml",
                "expected": {"vuln": "confirmed", "safe": "refuted"},
            }
            for i in range(1, n + 1)
        ],
    }
    if floors:
        doc["floors"] = {"confirm_recall": 0.9, "refute_precision": 0.9, "severity_within": 1.0}
    return ValidationBenchmark.model_validate(doc)


def test_the_worklist_carries_claims_and_leaves_validity_unanswered() -> None:
    worklist = BenchmarkWorklist.of(bench(1), NOW)
    [claim] = worklist.model_dump(mode="json")["findings"]
    assert "validation_status" not in claim
    assert claim["id"] == "BENCH-001" and claim["cvss_score"] == 8.0
    assert claim["locations"] == [{"path": "benchmark/fixtures/rbac-1.vuln.yaml"}]
    assert "probe class rbac" in claim["description"]
    assert worklist.metadata.benchmark and worklist.metadata.namespace == "validation-benchmark"


def run(verdict: str, flag: str | None = None, est: float | None = None) -> ValidationRun:
    return ValidationRun.model_validate(
        {
            "validated_findings": [
                {
                    "source_id": f"bench/BENCH-00{i}",
                    "verdict": verdict,
                    "soundness_flag": flag,
                    "severity_validation": None
                    if est is None
                    else {"demonstrated": {}, "demonstrated_score_estimate": 8.0 + est},
                }
                for i in (1, 2)
            ]
        }
    )


@pytest.mark.parametrize(
    ("validated", "variant", "metric", "value", "severity"),
    [
        (run("confirmed"), BenchmarkVariant.VULN, "confirm_recall", 1.0, None),
        # a flagged confirmation is a miss: soundness, not the verdict string, decides
        (
            run("confirmed", flag="environment_invalid"),
            BenchmarkVariant.VULN,
            "confirm_recall",
            0.0,
            None,
        ),
        (
            run("refuted", variant := None) if False else run("refuted"),
            BenchmarkVariant.SAFE,
            "refute_precision",
            1.0,
            None,
        ),
        (run("confirmed", est=0.5), BenchmarkVariant.VULN, "confirm_recall", 1.0, 1.0),
        (run("confirmed", est=2.5), BenchmarkVariant.VULN, "confirm_recall", 1.0, 0.0),
        (ValidationRun(), BenchmarkVariant.VULN, "confirm_recall", 0.0, None),
    ],
)
def test_scoring(
    validated: ValidationRun,
    variant: BenchmarkVariant,
    metric: str,
    value: float,
    severity: float | None,
) -> None:
    score = BenchmarkScore.of(bench(), validated, variant)
    assert (getattr(score, metric), score.value, score.severity_accuracy) == (
        value,
        value,
        severity,
    )
    assert score.n == 2 and len(score.rows) == 2


def test_a_missing_verdict_is_scored_missing() -> None:
    score = BenchmarkScore.of(bench(), ValidationRun(), BenchmarkVariant.VULN)
    assert {r.got for r in score.rows} == {"missing"}


def test_an_empty_benchmark_has_no_score() -> None:
    score = BenchmarkScore.of(bench(0), ValidationRun(), BenchmarkVariant.VULN)
    assert (score.n, score.confirm_recall) == (0, None)


@pytest.mark.parametrize(
    ("benchmark", "message"),
    [
        (bench(floors=False), "no floors"),
        (
            ValidationBenchmark.model_validate(
                {
                    **bench(1).model_dump(),
                    "fixtures": [{**bench(1).fixtures[0].model_dump(), "expected": {}}],
                }
            ),
            "expects no",
        ),
    ],
)
def test_an_unscorable_benchmark_is_refused(benchmark: ValidationBenchmark, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        BenchmarkScore.of(benchmark, run("confirmed"), BenchmarkVariant.VULN)


def test_trigger_paths_follow_the_mono_checkout_layout() -> None:
    assert "traust/harnessing/5-validate/validate-findings/" in TRIGGER_PATHS
    assert "traust/src/traust/cli/build_cumulative.py" in TRIGGER_PATHS
    stale = (
        "harnessing/5-validate/validate-core-ocp/",
        "harnessing/5-validate/validate-operator-live/",
        "harnessing/4-triage/track-findings/scripts/build_cumulative.py",
        "traust-contracts/schemas/v1/validation.schema.json",
    )
    assert not any(p in TRIGGER_PATHS for p in stale)


@pytest.mark.parametrize(
    ("changed", "paths"),
    [
        ([], ()),
        (["traust/README.md", "traust-core/src/x.py"], ()),
        (
            [
                "traust/src/traust/cli/attest_target.py",
                "traust/harnessing/5-validate/validate-findings/SKILL.md",
                "traust/src/traust/cli/attest_target.py",
            ],
            (
                "traust/harnessing/5-validate/validate-findings/SKILL.md",
                "traust/src/traust/cli/attest_target.py",
            ),
        ),
    ],
)
def test_the_trigger_names_each_changed_validation_lane_path(
    changed: list[str], paths: tuple[str, ...]
) -> None:
    assert BenchmarkTrigger.of("v1.0", changed).paths == paths
