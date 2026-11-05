from __future__ import annotations

from collections.abc import Sequence

from traust_core.v1.models.detection_quality import BenchmarkRun, MatchTier, Recall, Scorecard
from traust_core.v1.rendering.markdown import markdown_table


def _rate(value: float | None) -> str:
    return "not measured" if value is None else f"{value:.1%}"


def _table(columns: tuple[str, ...], rows: Sequence[tuple[str, ...]]) -> list[str]:
    return [*markdown_table(columns, rows), ""] if rows else ["None.", ""]


def _scorecard(card: Scorecard) -> list[str]:
    lines = [
        *_table(
            ("Population / metric", "Value"),
            [
                ("Auditor versions", ", ".join(card.auditor_versions) or "not supplied"),
                ("Targets scored", str(card.targets_scored)),
                ("Targets skipped", str(card.targets_skipped)),
                ("Expected findings", str(card.overall.expected)),
                ("Strict detections", str(card.overall.detected)),
                ("Strict recall", _rate(card.overall.recall)),
                (
                    "Near misses requiring adjudication (excluded from detections)",
                    str(card.near_misses),
                ),
                ("Injection canaries", str(card.injection.total)),
                ("Injection canaries passed", str(card.injection.passed)),
                ("Injection attempts reported", str(card.injection.reported)),
                ("Injection pass rate", _rate(card.injection.pass_rate)),
                (
                    "Mean rerun Jaccard",
                    "not measured" if card.mean_stability is None else f"{card.mean_stability:.3f}",
                ),
            ],
        ),
        "Strict recall counts fingerprint, advisory-ID/path and CWE/path matches only. "
        "Near misses remain human adjudication items, not detections. Skipped targets do not "
        "enter the scored expected-finding denominator. Zero expected findings means recall "
        "is not measured, not zero.",
        "",
    ]
    for heading, cut in (
        ("CWE", card.by_cwe),
        ("Severity", card.by_severity),
        ("Provenance", card.by_provenance),
        ("Language", card.by_language),
        ("Development / held-out split", card.by_split),
    ):
        lines += [f"### Recall by {heading}", ""]
        lines += _table(
            (heading, "Detected", "Expected", "Strict recall"),
            [
                (label, str(r.detected), str(r.expected), _rate(r.recall))
                for label, r in cut.items()
            ],
        )
    return lines


def benchmark_markdown(run: BenchmarkRun) -> str:
    """Render one typed run, including review items and the skipped population."""
    lines = ["# Detection-recall benchmark", "", "## Scorecard", ""]
    lines += _table(
        ("Answer key", "Manifest version"), [(str(run.answer_key_id), str(run.manifest_version))]
    )
    lines += _scorecard(run.scorecard())
    lines += ["## Target population", ""]
    lines += _table(
        ("Target", "Provenance", "Language", "Split", "Findings emitted", "Detected", "Expected"),
        [
            (
                t.target_id,
                str(t.provenance),
                t.language,
                "held_out" if t.held_out else "development",
                str(t.findings_emitted),
                str(Recall.of(t.matches).detected),
                str(len(t.matches)),
            )
            for t in run.targets
        ],
    )
    lines += ["## Expected-finding matches", ""]
    lines += _table(
        ("Target", "CWE", "Severity", "Match tier", "Matched finding"),
        [
            (t.target_id, m.cwe, m.severity, str(m.tier), m.matched or "none")
            for t in run.targets
            for m in t.matches
        ],
    )
    lines += [
        "## Near misses / adjudication",
        "",
        "Review these without changing strict recall.",
        "",
    ]
    lines += _table(
        ("Target", "CWE", "Severity", "Candidate finding"),
        [
            (t.target_id, m.cwe, m.severity, m.matched or "none")
            for t in run.targets
            for m in t.matches
            if m.tier == MatchTier.REVIEW
        ],
    )
    lines += ["## Injection canaries", ""]
    lines += _table(
        (
            "Target",
            "Class",
            "Detected",
            "Reported",
            "Obedience tokens",
            "Neutralized",
            "Obeyed",
            "Passed",
        ),
        [
            (
                t.target_id,
                t.injection.injection_class,
                str(t.injection.detected),
                str(t.injection.reported),
                ", ".join(t.injection.tokens_found) or "none",
                str(t.injection.neutralized),
                str(t.injection.obeyed),
                str(t.injection.passed),
            )
            for t in run.targets
            if t.injection is not None
        ],
    )
    lines += ["## Rerun stability", ""]
    lines += _table(
        ("Target", "Jaccard"), [(s.target_id, f"{s.jaccard:.3f}") for s in run.stability]
    )
    lines += ["## Skipped targets", ""]
    lines += _table(("Target", "Reason"), [(s.target_id, s.reason) for s in run.skipped])
    return "\n".join(lines)


def scorecards_markdown(cards: Sequence[Scorecard]) -> str:
    """Render recorded-audit aggregates without inventing unavailable per-target detail."""
    lines = [
        "# Detection-recall benchmark — recorded scorecards",
        "",
        "Recorded benchmark audits only. Each scorecard is one auditor-version population; "
        "canary and seeded scratch runs are not recorded. Per-target matches, adjudication "
        "candidates, skip reasons, injection signals and rerun pairs are not present in "
        "aggregate scorecards; use runs-dir scoring for those details.",
        "",
    ]
    for index, card in enumerate(cards, start=1):
        lines += [f"## Scorecard {index}", "", *_scorecard(card)]
    if not cards:
        lines += ["No recorded benchmark scorecards matched the requested population.", ""]
    return "\n".join(lines)
