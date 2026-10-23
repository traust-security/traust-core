"""Patch evidence and work-item steps, ported from traust tests/test_mutation_evidence.py and
tests/test_property_evidence.py (verdicts pinned to real mewt 4.0.0 output)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pydantic
import pytest

from traust_core.v1.errors import ConflictError
from traust_core.v1.models.remediation import (
    EvidenceItem,
    WorkItem,
    furthest,
    mutation_evidence,
    property_evidence,
    resolution_for,
)
from traust_core.v1.models.vocabulary import PatchEvidenceKind, RemediationStatus

FIXTURES = Path(__file__).parents[2] / "fixtures" / "remediation"
UNCAUGHT = (FIXTURES / "mewt-status-uncaught.json").read_bytes()
ALL_CAUGHT = (FIXTURES / "mewt-status-all-caught.json").read_bytes()


def mewt(path: str = "./pkg/x/x.go", **counts: int) -> bytes:
    row = dict.fromkeys(("tested", "untested", "caught", "uncaught", "timeout", "skipped"), 0)
    return json.dumps({"targets": [{"path": path, **row, **counts}]}).encode()


def mutation(
    status: bytes | None, rc: int = 0, target: str = "./pkg/calc", **kw: str
) -> EvidenceItem:
    return mutation_evidence(
        target, rc, kw.get("version", "mewt 4.0.0"), "/tmp/c.log", status, kw.get("boundary", "")
    )


@pytest.mark.parametrize(
    ("status", "rc", "outcome", "patched"),
    [
        (UNCAUGHT, 0, "fails_to_prove", "2 uncaught"),
        (ALL_CAUGHT, 0, "proves", "19 caught, 0 uncaught"),
        (
            mewt(total_mutants=10, tested=4, caught=4, skipped=6),
            0,
            "fails_to_prove",
            "not every mutant was run",
        ),
        (mewt(total_mutants=5, tested=5, caught=4, timeout=1), 0, "fails_to_prove", "1 timed out"),
        (
            mewt(total_mutants=5, tested=5, caught=3),
            0,
            "not_attempted: mewt status did not account for every generated mutant",
            None,
        ),
        (ALL_CAUGHT, 124, "not_attempted: campaign exceeded its timeout", None),
        (None, 1, "not_attempted: mewt exited 1 and produced no readable status json", None),
        (None, 0, "not_attempted: mewt produced no readable status json", None),
        (b"not json at all", 0, "not_attempted: mewt status json was unparseable", None),
        (b"[1, 2]", 0, "not_attempted: mewt status json was unparseable", None),
        (
            mewt("./p/p_test.go", total_mutants=3),
            0,
            "not_attempted: mewt generated no mutants for ./pkg/calc",
            None,
        ),
    ],
)
def test_mutation_verdicts(
    status: bytes | None, rc: int, outcome: str, patched: str | None
) -> None:
    item = mutation(status, rc)
    assert item.outcome == outcome
    if patched is None:
        assert (item.base_observation, item.patched_observation) == (None, None)
        assert item.deterministic_steps.startswith("skipped: ")
    else:
        assert patched in (item.patched_observation or "")
        assert item.base_observation and item.deterministic_steps == "ran"


def test_test_file_mutants_are_excluded_from_the_claim() -> None:
    base = mutation(UNCAUGHT).base_observation or ""
    assert base.startswith("19 mutant(s)")
    assert "1 test-file target(s) excluded" in base


@pytest.mark.parametrize(
    ("version", "tool"), [("mewt 4.0.0", "mewt 4.0.0"), ("4.0.0", "mewt 4.0.0"), ("", "mewt")]
)
def test_the_tool_label_is_not_double_prefixed(version: str, tool: str) -> None:
    assert mutation(ALL_CAUGHT, version=version).tool == tool


@pytest.mark.parametrize("boundary", ["podman", "attested:konflux-job"])
def test_the_boundary_is_recorded_in_the_command(boundary: str) -> None:
    assert f"[boundary: {boundary}]" in (mutation(ALL_CAUGHT, boundary=boundary).command or "")
    item = property_evidence("t.py", "abc", 1, 0, boundary=boundary)
    assert f"[boundary: {boundary}]" in (item.command or "")


def test_the_boundary_is_optional() -> None:
    assert "[boundary:" not in (mutation(ALL_CAUGHT).command or "")
    assert property_evidence("t.py", "abc", 1, 0).command == "pytest t.py"


@pytest.mark.parametrize(
    ("base_rc", "patched_rc", "outcome", "says"),
    [
        (1, 0, "proves", "on the patched revision the property passed"),
        (1, 1, "fails_to_prove", "still finds a counterexample"),
        (0, 0, "fails_to_prove", "it also held before the patch"),
        (0, 1, "fails_to_prove", "it also held before the patch"),
        (5, 0, "not_attempted: pytest collected no tests from t.py", None),
        (124, 0, "not_attempted: property run exceeded its timeout", None),
        (0, 124, "not_attempted: property run exceeded its timeout", None),
        (2, 0, "not_attempted: the base revision's run was interrupted", None),
        (1, 3, "not_attempted: the patched revision's run hit an internal pytest error", None),
        (4, 0, "not_attempted: the base revision's run was a pytest usage error", None),
        (1, 9, "not_attempted: the patched revision's run exited 9", None),
    ],
)
def test_property_verdicts(base_rc: int, patched_rc: int, outcome: str, says: str | None) -> None:
    item = property_evidence("t.py", "abc123", base_rc, patched_rc, base_log="b.log")
    assert item.outcome.startswith(outcome)
    assert item.kind == PatchEvidenceKind.PROPERTY
    if says is None:
        assert item.base_observation is None
    else:
        assert says in (item.patched_observation or "")
        assert item.base_observation and "(abc123)" in item.base_observation


def test_a_proof_claim_without_both_observations_is_refused() -> None:
    with pytest.raises(pydantic.ValidationError, match="needs both"):
        EvidenceItem(kind=PatchEvidenceKind.MUTATION, outcome="proves", base_observation="x")
    with pytest.raises(pydantic.ValidationError):
        EvidenceItem(kind=PatchEvidenceKind.MUTATION, outcome="maybe")


def item(status: str) -> WorkItem:
    return WorkItem(
        work_item_id=uuid4(),
        repository_ref_id=uuid4(),
        finding_ids=(uuid4(),),
        status=RemediationStatus(status),
        opened_at=datetime(2026, 10, 23, tzinfo=UTC),
    )


@pytest.mark.parametrize(
    ("now", "to"),
    [
        ("candidate", "forked"),
        ("candidate", "checks_failed"),
        ("patched", "checks_passed"),
        ("checks_failed", "revalidated_still_vulnerable"),
        ("pr_opened", "merged"),
        ("checks_passed", "abandoned"),
    ],
)
def test_a_work_item_moves_forward(now: str, to: str) -> None:
    assert item(now).advance(RemediationStatus(to)).status == to


@pytest.mark.parametrize(
    ("now", "to"),
    [
        ("patched", "forked"),
        ("checks_failed", "checks_passed"),
        ("merged", "abandoned"),
        ("abandoned", "candidate"),
        ("merged", "pr_opened"),
    ],
)
def test_a_work_item_never_moves_back_or_past_the_end(now: str, to: str) -> None:
    with pytest.raises(ConflictError, match=f"{now} can't move to {to}"):
        item(now).advance(RemediationStatus(to))


def test_the_same_status_again_is_the_same_item() -> None:
    patched = item("patched")
    assert patched.advance(RemediationStatus("patched")) is patched
    assert not patched.is_done()


def test_where_an_item_stands_is_its_furthest_step() -> None:
    assert furthest(["candidate", "patched", "forked"]) == "patched"
    assert furthest(["merged", "candidate"]) == "merged"


@pytest.mark.parametrize(
    ("status", "resolution"),
    [
        ("candidate", None),
        ("forked", "fix_in_progress"),
        ("revalidated_fixed", "fix_in_progress"),
        ("checks_failed", "open"),
        ("abandoned", "open"),
        ("merged", "resolved"),
    ],
)
def test_each_step_says_where_fixing_stands(status: str, resolution: str | None) -> None:
    assert resolution_for(RemediationStatus(status)) == resolution
