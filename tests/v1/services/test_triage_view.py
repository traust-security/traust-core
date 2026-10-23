"""The triage report (from traust's TestRenderTriage, fabdb13) and hostile text in reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.rendering import MarkdownRenderer
from traust_core.v1.services.insight import TriageView

TRIAGE = Path(__file__).parents[2] / "fixtures" / "findings" / "triage" / "triage-report.json"


def document(edit: Any = None) -> dict[str, Any]:
    doc = json.loads(TRIAGE.read_text())
    if edit:
        edit(doc)
    return doc


def render(doc: dict[str, Any] | None = None) -> str:
    artifact = TriageArtifact.from_document(doc or document())
    return MarkdownRenderer().render(TriageView().report(artifact)).decode()


def test_sections_in_order() -> None:
    md = render()
    headings = (
        "## Summary",
        "## Act on these",
        "## Hardening backlog",
        "## Undetermined",
        "## Dropped",
    )
    positions = [md.index(h) for h in headings]
    assert positions == sorted(positions)


def test_confirmed_entry() -> None:
    md = render()
    assert "### [HIGH] Heap overflow in parse_alpha (f001)" in md
    assert "votes 3T/0H/0F/0C" in md
    assert "`entry.c:25` | memory-safety | claimed HIGH | confidence 9.0/10" in md


def test_confirmed_findings_most_severe_then_most_confident_first() -> None:
    def more(doc: dict[str, Any]) -> None:
        tp = doc["findings"][0]
        doc["findings"] += [
            {**tp, "id": "f010", "title": "Low and sure", "severity": "low", "confidence": 10.0},
            {**tp, "id": "f011", "title": "High and unsure", "severity": "high", "confidence": 5.0},
            {
                **tp,
                "id": "f012",
                "title": "Critical issue",
                "severity": "critical",
                "confidence": 1.0,
            },
        ]

    md = render(document(more))
    assert [md.index(t) for t in ("(f012)", "(f001)", "(f011)", "(f010)")] == sorted(
        md.index(t) for t in ("(f012)", "(f001)", "(f011)", "(f010)")
    )


def test_hardening_is_not_dropped() -> None:
    md = render()
    assert "f006" not in md.split("## Dropped")[1]
    assert "NOT false positives" in md


def test_undetermined_shown_and_omitted_when_none() -> None:
    assert "f007" in render().split("## Undetermined")[1].split("## Dropped")[0]

    def none(doc: dict[str, Any]) -> None:
        doc["findings"] = [f for f in doc["findings"] if f["verdict"] != "undetermined"]

    assert "## Undetermined" not in render(document(none))


def test_dropped_carries_the_rule_and_duplicates() -> None:
    def dup(doc: dict[str, Any]) -> None:
        doc["findings"].append(
            {
                "id": "f009",
                "title": "Same heap overflow",
                "verdict": "duplicate",
                "duplicate_of": "f001",
            }
        )

    md = render(document(dup))
    assert "already_handled (rule 2)" in md
    assert "duplicate of f001" in md


def test_empty_sections_say_so() -> None:
    def only_undetermined(doc: dict[str, Any]) -> None:
        doc["findings"] = [f for f in doc["findings"] if f["verdict"] == "undetermined"]

    md = render(document(only_undetermined))
    assert "_No confirmed findings._" in md
    assert md.split("## Dropped")[1].strip().startswith("_None._")


def test_summary_and_context() -> None:
    md = render()
    assert (
        "4 in: 1 confirmed (0 critical / 1 high / 0 medium / 0 low / 0 informational), 1 hardening"
        in md
    )
    assert "harness 0.26.0-abc1234; completed 2026-07-11" in md
    assert "_Generated 2026-07-11T00:00:00+00:00_" in md


def test_deterministic() -> None:
    assert render() == render()


def test_hostile_text_cannot_add_rows_headings_or_markup() -> None:
    def hostile(doc: dict[str, Any]) -> None:
        hard = next(f for f in doc["findings"] if f["verdict"] == "hardening")
        hard["title"] = "gap\n## Injected heading\n| fake | row |\u202e"
        hard["file"] = "deploy/`evil`.yaml"
        tp = doc["findings"][0]
        tp["title"] = "overflow\n# H1\x07"

    md = render(document(hostile))
    assert "\n## Injected heading" not in md
    assert "\n# H1" not in md
    assert "| gap ## Injected heading \\| fake \\| row \\| |" in md
    assert "`deploy/evil.yaml:19`" in md
    assert "\u202e" not in md and "\x07" not in md
