"""The triage verdict-citation lint, ported from traust's test_triage_tooling.py (fabdb13)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import SecurityAuditArtifact, TriageArtifact
from traust_core.v1.providers.sources import WorkspaceFiles
from traust_core.v1.services.findings.citations import VerdictCitations, citations
from traust_core.v1.services.lint import Lint, LintAction, LintContext

TRIAGE = Path(__file__).parents[3] / "fixtures" / "findings" / "triage"
TARGET = TRIAGE / "canary-target"


def report(**changes: dict[str, Any]) -> TriageArtifact:
    doc = json.loads((TRIAGE / "triage-report.json").read_text())
    for f in doc["findings"]:
        f.update(changes.get(f["id"], {}))
    return TriageArtifact.from_document(doc)


def lint(doc: TriageArtifact, root: Path = TARGET) -> list[tuple[str, str, LintAction]]:
    report_ = Lint({TriageArtifact: [VerdictCitations()]}).run(
        doc, LintContext(files=WorkspaceFiles(root))
    )
    return [(v.item, v.message, v.action) for v in report_.violations]


def test_citations_from_links_and_rationale_once_each() -> None:
    found = citations(
        ("pkg/a.go:12", "https://x.io/a.go:1", "None found"),
        "guard at pkg/a.go:12 and helper.py:9-14; ratio 3:1 at 10:30",
    )
    assert found == [("pkg/a.go", 12, "first_links"), ("helper.py", 9, "rationale")]


def test_clean_verdicts_pass_against_the_canary_target() -> None:
    assert lint(report()) == []


def test_a_dismissal_on_invented_evidence_asks_for_a_fresh_vote() -> None:
    doc = report(
        f005={
            "rationale": "guard exists at entry.c:9999 before use.",
            "first_links": ["lib/imaginary.c:12"],
        }
    )
    found = lint(doc)
    assert {(item, action) for item, _, action in found} == {("f005", LintAction.RE_VOTE)}
    messages = " ".join(m for _, m, _ in found)
    assert "first_links: lib/imaginary.c:12: file not found" in messages
    assert "rationale: entry.c:9999: line out of range" in messages


def test_a_broken_true_positive_citation_asks_for_review() -> None:
    doc = report(f001={"first_links": ["lib/imaginary.c:12"], "rationale": "reachable"})
    assert lint(doc) == [
        (
            "f001",
            "first_links: lib/imaginary.c:12: file not found under the checkout",
            LintAction.REVIEW,
        )
    ]


def test_duplicates_are_not_linted() -> None:
    doc = report(f001={"verdict": "duplicate", "duplicate_of": "f005", "first_links": ["nope.c:1"]})
    assert lint(doc) == []


@pytest.mark.parametrize(
    "cited",
    [
        "./entry.c:47",
        "src/entry.c:47",
        "canary-target/entry.c:47",
        "deployment.yaml:19",
    ],
)
def test_lenient_resolution(cited: str) -> None:
    assert lint(report(f005={"first_links": [cited], "rationale": None})) == []


def test_suffix_match_reports_the_best_match_when_out_of_range(tmp_path: Path) -> None:
    for d in ("a/pkg", "b/pkg"):
        (tmp_path / d).mkdir(parents=True)
        (tmp_path / d / "scope.go").write_text("x\n" * (3 if d == "a/pkg" else 5))
    doc = report(
        f005={"first_links": ["pkg/scope.go:9"], "rationale": None},
        f001={"first_links": [], "rationale": None},
        f006={"first_links": [], "rationale": None},
    )
    assert lint(doc, tmp_path) == [
        (
            "f005",
            "first_links: pkg/scope.go:9: line out of range (5-line file (best suffix match of 2))",
            LintAction.RE_VOTE,
        )
    ]


def test_hyphen_tail_match_and_skipped_directories(tmp_path: Path) -> None:
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "server-jwt-args-patch.yaml").write_text("a\nb\n")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.c").write_text("a\n")
    files = WorkspaceFiles(tmp_path)
    assert files.matches("deploy/jwt-args-patch.yaml") == [
        tmp_path.resolve() / "deploy" / "server-jwt-args-patch.yaml"
    ]
    assert files.matches("lib.c") == []


def test_resolution_never_leaves_the_checkout(tmp_path: Path) -> None:
    (tmp_path / "repo").mkdir()
    (tmp_path / "secret.c").write_text("x\n")
    assert WorkspaceFiles(tmp_path / "repo").resolve("../secret.c") is None


def test_the_rule_needs_a_checkout_and_a_triage() -> None:
    rule = VerdictCitations()
    with pytest.raises(ValidationError, match="needs the target checkout"):
        rule.check(report(), LintContext())
    audit = object.__new__(SecurityAuditArtifact)
    with pytest.raises(ValidationError, match="checks triage artifacts"):
        rule.check(audit, LintContext(files=WorkspaceFiles(TARGET)))


def test_an_artifact_with_no_rules_passes() -> None:
    assert Lint({}).run(report(), LintContext()).passed


def test_check_is_the_skill_door(tmp_path: Path) -> None:
    decisions = Context(Config(home=tmp_path)).services().findings.decisions
    bad = report(f001={"first_links": ["lib/imaginary.c:12"]})
    assert decisions.check(report(), TARGET).passed
    assert [v.item for v in decisions.check(bad, TARGET).violations] == ["f001"]
