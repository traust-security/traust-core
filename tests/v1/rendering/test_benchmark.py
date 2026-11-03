from __future__ import annotations

from uuid import UUID

from traust_core.v1.context.benchmark import benchmark_markdown, scorecards_markdown
from traust_core.v1.models.detection_quality import (
    BenchmarkRun,
    BenchmarkTargetId,
    ExpectedMatch,
    InjectionResult,
    MatchTier,
    SkippedTarget,
    Stability,
    TargetScore,
)

KEY = UUID("00000000-0000-0000-0000-000000000001")


def run() -> BenchmarkRun:
    return BenchmarkRun(
        answer_key_id=KEY,
        manifest_version=7,
        auditor_versions=("audit-1",),
        targets=(
            TargetScore(
                target_id=BenchmarkTargetId("bt-dev"),
                provenance="self_replay",
                language="python",
                held_out=False,
                findings_emitted=4,
                matches=(
                    ExpectedMatch(
                        cwe="CWE-89", severity="high", tier=MatchTier.FINGERPRINT, matched="F1"
                    ),
                    ExpectedMatch(
                        cwe="CWE-78", severity="critical", tier=MatchTier.ADVISORY_ID, matched="F2"
                    ),
                    ExpectedMatch(
                        cwe="CWE-79", severity="medium", tier=MatchTier.PATH_CWE, matched="F3"
                    ),
                    ExpectedMatch(
                        cwe="CWE-89", severity="high", tier=MatchTier.REVIEW, matched="F4"
                    ),
                ),
            ),
            TargetScore(
                target_id=BenchmarkTargetId("bt-held"),
                provenance="cve_replay",
                language="unspecified",
                held_out=True,
                findings_emitted=0,
                matches=(ExpectedMatch(cwe="CWE-22", severity="low", tier=MatchTier.MISSED),),
            ),
            TargetScore(
                target_id=BenchmarkTargetId("bt-canary"),
                provenance="seeded",
                language="go",
                held_out=False,
                findings_emitted=1,
                injection=InjectionResult(
                    injection_class="instruction",
                    detected=True,
                    reported=True,
                    tokens_found=("obedience-marker",),
                    neutralized=False,
                ),
            ),
        ),
        skipped=(SkippedTarget(target_id=BenchmarkTargetId("bt-skip"), reason="wrong clone"),),
        stability=(Stability(target_id=BenchmarkTargetId("bt-dev"), jaccard=0.75),),
    )


def test_typed_run_preserves_strict_recall_and_review_population() -> None:
    out = benchmark_markdown(run())
    assert f"| {KEY} | 7 |" in out
    assert "| Targets scored | 3 |" in out
    assert "| Targets skipped | 1 |" in out
    assert "| Expected findings | 5 |" in out
    assert "| Strict detections | 3 |" in out
    assert "| Strict recall | 60.0% |" in out
    assert "| Near misses requiring adjudication \\(excluded from detections\\) | 1 |" in out
    assert "| bt-dev | CWE-89 | high | review | F4 |" in out
    adjudication = out.split("## Near misses / adjudication\n", 1)[1].split("## Injection", 1)[0]
    assert "| bt-dev | CWE-89 | high | F4 |" in adjudication
    assert "F1" not in adjudication and "bt-held" not in adjudication
    assert "| bt-held | CWE-22 | low | missed | none |" in out
    assert "| bt-skip | wrong clone |" in out


def test_every_cut_uses_the_typed_scorecard_denominator() -> None:
    out = benchmark_markdown(run())
    for heading in ("CWE", "Severity", "Provenance", "Language", "Development / held-out split"):
        assert f"### Recall by {heading}\n" in out
    for row in (
        "| CWE-89 | 1 | 2 | 50.0% |",
        "| high | 1 | 2 | 50.0% |",
        r"| self\_replay | 3 | 4 | 75.0% |",
        "| python | 3 | 4 | 75.0% |",
        "| development | 3 | 4 | 75.0% |",
        r"| held\_out | 0 | 1 | 0.0% |",
        "| unspecified | 0 | 1 | 0.0% |",
    ):
        assert row in out


def test_injection_obedience_and_stability_are_not_lost_in_summary() -> None:
    out = benchmark_markdown(run())
    assert "| Injection canaries passed | 0 |" in out
    assert "| Injection attempts reported | 1 |" in out
    assert "| Injection pass rate | 0.0% |" in out
    assert (
        "| bt-canary | instruction | True | True | obedience-marker | False | True | False |" in out
    )
    assert "| Mean rerun Jaccard | 0.750 |" in out
    assert "| bt-dev | 0.750 |" in out
    assert "| bt-dev | self\\_replay | python | development | 4 | 3 | 4 |" in out


def test_empty_run_reports_unknown_metrics_not_zero() -> None:
    out = benchmark_markdown(BenchmarkRun(answer_key_id=KEY, manifest_version=1))
    assert "| Strict recall | not measured |" in out
    assert "| Injection pass rate | not measured |" in out
    assert "| Mean rerun Jaccard | not measured |" in out
    assert "## Skipped targets\n\nNone." in out


def test_recorded_scorecards_keep_populations_separate_and_label_unavailable_detail() -> None:
    first = run().scorecard()
    second = first.model_copy(update={"auditor_versions": ("audit-2",)})
    out = scorecards_markdown([first, second])
    assert "## Scorecard 1\n" in out and "## Scorecard 2\n" in out
    assert "| Auditor versions | audit-1 |" in out
    assert "| Auditor versions | audit-2 |" in out
    assert out.count("| Strict recall | 60.0% |") == 2
    assert "not present in aggregate scorecards" in out
    assert "| bt-skip |" not in out
    assert "No recorded benchmark scorecards matched" in scorecards_markdown([])


def test_all_untrusted_fields_are_literal_markdown_without_forged_rows() -> None:
    hostile = "[act](https://evil.invalid)<img src=x>\n|forged\u202e"
    source = run()
    target = source.targets[0].model_copy(
        update={
            "target_id": BenchmarkTargetId(hostile),
            "language": hostile,
            "matches": (
                ExpectedMatch(cwe=hostile, severity="high", tier=MatchTier.REVIEW, matched=hostile),
            ),
            "injection": InjectionResult(
                injection_class=hostile,
                detected=True,
                reported=False,
                tokens_found=(hostile,),
                neutralized=True,
            ),
        }
    )
    source = source.model_copy(
        update={
            "targets": (target,),
            "skipped": (SkippedTarget(target_id=BenchmarkTargetId(hostile), reason=hostile),),
            "stability": (Stability(target_id=BenchmarkTargetId(hostile), jaccard=1.0),),
            "auditor_versions": (hostile,),
        }
    )
    out = benchmark_markdown(source)
    assert "[act](" not in out and "<img" not in out
    assert "\u202e" not in out and "\n|forged" not in out
    assert r"\[act\]\(https://evil.invalid\)&lt;img src=x&gt; \|forged" in out
    assert "<img" not in scorecards_markdown([source.scorecard()])
