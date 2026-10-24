"""Verification rules, ported table-driven from traust
tests/test_emit_verification_ledger_events.py, tests/test_scanner_differential.py,
tests/test_build_verify_sweep.py and the engine's cross_validate_verification."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.artifacts import VerificationArtifact
from traust_core.v1.models.dependencies import FixUptakeState, Version
from traust_core.v1.models.remediation import (
    PropagationEvidence,
    ScanFact,
    SweepEntry,
    SweepSkip,
    SweepTier,
    VerifySweep,
    check_verification,
    propagated,
    regression_candidates,
    scanner_differential,
    verdict_statement,
)
from traust_core.v1.models.vocabulary import Ecosystem, VerificationVerdict

FIXTURE = Path(__file__).parents[2] / "fixtures" / "remediation" / "verification-report.json"
RULE = "traust-python-injection-subprocess-shell"
# The legacy fixture's one fact: the rule fires on app.py before the patch, nothing after.
BASE = [ScanFact(rule=RULE, path="app.py", line=7)]


def raw() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text())


def doc(raw_doc: dict[str, Any]) -> VerificationArtifact:
    return VerificationArtifact.from_document(raw_doc)


# verdict -> statement


@pytest.mark.parametrize(
    ("verdict", "propagation", "validity", "resolution"),
    [
        ("resolved", None, None, "resolved"),
        ("resolved", "consumed", None, "resolved"),
        ("new_approach", None, None, "resolved"),
        ("partially_resolved", None, None, None),
        ("partially_resolved", "pending", None, "open"),
        ("partially_resolved", "consumed", None, None),
        ("unresolved", None, None, "open"),
        ("regression", None, None, "open"),
        ("risk_accepted", None, None, "risk_accepted"),
        ("false_positive", None, "false_positive", None),
    ],
)
def test_a_verdict_says_a_validity_or_a_resolution(
    verdict: str, propagation: str | None, validity: str | None, resolution: str | None
) -> None:
    assert verdict_statement(VerificationVerdict(verdict), propagation) == (validity, resolution)


def test_an_unknown_verdict_is_refused() -> None:
    with pytest.raises(ValueError):
        verdict_statement(VerificationVerdict("banana"))


# report consistency


def test_the_fixture_is_consistent() -> None:
    assert check_verification(doc(raw())) == []


CROSS = {"fix_repo": "https://github.com/example-org/library", "propagation": "pending"}


def _verdict(r: dict[str, Any], verdict: str) -> None:
    r["summary"]["by_verdict"] = dict.fromkeys(r["summary"]["by_verdict"], 0) | {verdict: 1}
    r["verified_findings"][0]["verdict"] = verdict


def _duplicate(r: dict[str, Any]) -> None:
    r["verified_findings"].append(r["verified_findings"][0])
    r["summary"]["total_findings"] = 2
    r["summary"]["by_verdict"]["resolved"] = 2


def _unattributed_fix(r: dict[str, Any]) -> None:
    r["verified_findings"][0]["remediation_commits"] = []
    r["commit_timeline"] = []


BROKEN: dict[str, Any] = {
    "duplicate id": _duplicate,
    "pending resolved": lambda r: r["verified_findings"][0].update(cross_repo=CROSS),
    "same-repo cross_repo": lambda r: r["verified_findings"][0].update(
        cross_repo={"fix_repo": r["metadata"]["repository"] + "/", "propagation": "consumed"}
    ),
    "unattributed with commits": lambda r: r["verified_findings"][0].update(unattributed=True),
    "fixed without attribution": _unattributed_fix,
    "fp without rationale": lambda r: _verdict(r, "false_positive"),
    "accepted without rationale": lambda r: _verdict(r, "risk_accepted"),
    "partial without residual risk": lambda r: _verdict(r, "partially_resolved"),
    "short sha mismatch": lambda r: r["verified_findings"][0]["remediation_commits"][0].update(
        short_sha="1234567"
    ),
    "total mismatch": lambda r: r["summary"].update(total_findings=2),
    "by_verdict mismatch": lambda r: r["summary"]["by_verdict"].update(resolved=0, unresolved=1),
    "regressions mismatch": lambda r: r["summary"].update(regressions=0),
    "timeline sha mismatch": lambda r: r["commit_timeline"][0].update(sha="1234567"),
    "timeline unknown finding": lambda r: r["commit_timeline"][0].update(addresses=["OTHER"]),
    "timeline out of order": lambda r: r["commit_timeline"].append(
        {**r["commit_timeline"][0], "date": "2026-10-22T10:00:00+00:00"}
    ),
}


@pytest.mark.parametrize(
    ("case", "said"),
    [
        ("duplicate id", "duplicate verified_findings original_id"),
        ("pending resolved", "propagation pending"),
        ("same-repo cross_repo", "fix_repo is this repository"),
        ("unattributed with commits", "unattributed but remediation_commits"),
        ("fixed without attribution", "needs remediation_commits or unattributed"),
        ("fp without rationale", "'false_positive' needs disposition_rationale"),
        ("accepted without rationale", "'risk_accepted' needs disposition_rationale"),
        ("partial without residual risk", "needs residual_risk"),
        ("short sha mismatch", "is not a prefix of"),
        ("total mismatch", "summary.total_findings"),
        ("by_verdict mismatch", "summary.by_verdict.resolved"),
        ("regressions mismatch", "summary.regressions"),
        ("timeline sha mismatch", "commit_timeline[0]: 1234567 is not a prefix"),
        ("timeline unknown finding", "names unknown finding OTHER"),
        ("timeline out of order", "out of chronological order"),
    ],
)
def test_an_inconsistent_report_is_refused(case: str, said: str) -> None:
    r = raw()
    BROKEN[case](r)
    with pytest.raises(ValidationError, match=re.escape(said)):
        check_verification(doc(r))


def test_soft_inconsistencies_are_warnings() -> None:
    r = raw()
    _verdict(r, "new_approach")
    r["commit_timeline"][0]["full_sha"] = "89abcdef" + "1" * 32
    r["regressions"][0]["id"] = "EXAMPLE_SERVICE-1234567-REG-001"
    warned = check_verification(doc(r))
    assert [w.split(":")[0].split(" ")[0] for w in warned] == [
        "verified_findings[0]",
        "remediation",
        "commit_timeline",
        "regression",
    ]


def test_a_pending_partial_fix_is_consistent() -> None:
    r = raw()
    _verdict(r, "partially_resolved")
    r["verified_findings"][0].update(
        residual_risk="the product still pins the vulnerable library version", cross_repo=CROSS
    )
    assert check_verification(doc(r)) == []


def test_regressions_become_candidates_at_their_first_line() -> None:
    repository_id = uuid4()
    r = raw()
    r["regressions"][0]["locations"].append({"path": "README.md"})
    (c,) = regression_candidates(doc(r), repository_id)
    assert (c.label, c.repository_id, c.reported_severity, c.cwes) == (
        "EXAMPLE_SERVICE-89abcde-REG-001",
        repository_id,
        "low",
        ("CWE-209",),
    )
    assert [(s.path, s.line) for s in c.locations] == [
        ("pkg/upload/handler.go", 61),
        ("README.md", None),
    ]


# scanner differential


def item(base: list[ScanFact] | None, patched: list[ScanFact] | None, **selector: Any) -> Any:
    rule, path = selector.get("rule", RULE), selector.get("path")
    return scanner_differential("opengrep 1.25.0", {(rule, path)}, base, patched, "fa4b872", "b")


def test_a_cleared_fact_proves_and_says_its_ceiling() -> None:
    got = item(BASE, [])
    assert got.outcome == "proves"
    assert "does not establish the fix is correct" in got.patched_observation
    assert got.base_observation and got.kind == "scanner_differential"


def test_a_fact_still_firing_fails_to_prove() -> None:
    got = item(BASE, BASE)
    assert got.outcome == "fails_to_prove"
    assert "has not cleared its own backing evidence" in got.patched_observation


@pytest.mark.parametrize(
    ("base", "patched", "selector", "said"),
    [
        ([], [], {}, "does not fire on the unpatched revision"),
        (None, [], {}, "no opengrep 1.25.0 scan of the base revision"),
        (BASE, None, {}, "no opengrep 1.25.0 scan of the patched revision"),
        (BASE, [], {"rule": "some-other-rule"}, "does not fire on the unpatched revision"),
        (BASE, [], {"rule": None}, "not scanner-backed"),
    ],
)
def test_no_differential_is_not_attempted(
    base: list[ScanFact] | None, patched: list[ScanFact] | None, selector: Any, said: str
) -> None:
    got = item(base, patched, **selector)
    assert got.outcome.startswith("not_attempted: ") and said in got.outcome
    assert got.base_observation is None and got.deterministic_steps.startswith("skipped: ")


def test_the_selector_ignores_line_numbers() -> None:
    moved = [BASE[0].model_copy(update={"line": 47})]
    assert item(BASE, moved).outcome == "fails_to_prove"


def test_a_path_selector_alone_works() -> None:
    assert item(BASE, [], rule=None, path="app.py").outcome == "proves"


def test_more_than_three_facts_are_summarised() -> None:
    many = [ScanFact(rule=RULE, path=f"m{i}.py") for i in range(5)]
    got = scanner_differential("opengrep", {(RULE, None)}, many, many, "r", "b")
    assert "(+2 more)" in got.base_observation and f"{RULE} in m0.py" in got.base_observation


# propagation


def evidence(*states: FixUptakeState) -> list[PropagationEvidence]:
    return [
        PropagationEvidence(ecosystem=Ecosystem.GO, name=f"m{i}", fixed=Version("v1"), state=s)
        for i, s in enumerate(states)
    ]


C, P, A, N = (
    FixUptakeState.CONSUMED,
    FixUptakeState.PENDING,
    FixUptakeState.MODULE_ABSENT,
    FixUptakeState.NOT_OBSERVED,
)


@pytest.mark.parametrize(
    ("states", "status"),
    [
        ((C,), "consumed"),
        ((C, C), "consumed"),
        ((C, A), "consumed"),
        ((P,), "pending"),
        ((C, P), "pending"),
        ((A, P), "pending"),
        ((A,), "module_absent"),
        ((A, A), "module_absent"),
    ],
)
def test_propagation_rolls_up_its_packages(states: tuple[FixUptakeState, ...], status: str) -> None:
    assert propagated(evidence(*states)) == status


@pytest.mark.parametrize("states", [(), (N,), (C, N)])
def test_propagation_needs_an_sbom(states: tuple[FixUptakeState, ...]) -> None:
    with pytest.raises(NotFoundError, match="no SBOM"):
        propagated(evidence(*states))


# sweep tiers


def entry(**over: Any) -> SweepEntry:
    values = {
        "repository_id": uuid4(),
        "head_sha": "b" * 40,
        "pinned_sha": "a" * 40,
        "open_findings": 1,
    }
    return SweepEntry(**{**values, **over}).classified()


@pytest.mark.parametrize(
    ("over", "tier", "skip"),
    [
        ({"claims": 2, "criticals": 3}, SweepTier.CLAIMED, None),
        ({"criticals": 1}, SweepTier.CRITICAL, None),
        ({"highs": 2}, SweepTier.HIGH, None),
        ({}, SweepTier.OTHER, None),
        ({"pinned_sha": "b" * 40}, None, SweepSkip.HEAD_UNCHANGED),
        ({"pinned_sha": "b" * 40, "claims": 1}, SweepTier.CLAIMED, None),
        ({"verified_at_head": True, "claims": 1}, None, SweepSkip.ALREADY_VERIFIED),
        ({"head_sha": None, "claims": 1}, None, SweepSkip.UNOBSERVED),
        ({"pinned_sha": None, "highs": 1}, SweepTier.HIGH, None),
        ({"open_findings": 0}, None, SweepSkip.NOTHING_OPEN),
        ({"open_findings": 0, "claims": 1}, SweepTier.CLAIMED, None),
    ],
)
def test_a_repository_is_tiered_or_skipped(
    over: dict[str, Any], tier: SweepTier | None, skip: SweepSkip | None
) -> None:
    got = entry(**over)
    assert (got.tier, got.skip) == (tier, skip)


def test_the_sweep_queues_by_tier_then_criticals_then_highs() -> None:
    entries = [
        SweepEntry(repository_id=uuid4(), head_sha="h", open_findings=1, **over)
        for over in (
            {"highs": 1},
            {"criticals": 1, "highs": 1},
            {"criticals": 2},
            {"claims": 1},
            {"verified_at_head": True},
        )
    ]
    sweep = VerifySweep.of(entries)
    assert [(e.tier, e.criticals, e.highs) for e in sweep.queued] == [
        ("T1", 0, 0),
        ("T2", 2, 0),
        ("T2", 1, 1),
        ("T3", 0, 1),
    ]
    assert [e.skip for e in sweep.skipped] == ["already_verified"]
