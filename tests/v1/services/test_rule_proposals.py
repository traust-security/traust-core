"""The rule-proposal gate's checks, as table tests."""

from __future__ import annotations

from typing import Any

import pytest

from traust_core.v1.services import rule_proposals as gate

RID = "traust-proposed-py-shell"


def rule(**overrides: Any) -> dict[str, Any]:
    return {
        "id": RID,
        "message": "request data reaches a shell",
        "languages": ["python"],
        "severity": "ERROR",
        "metadata": {"cwe": ["CWE-78"]},
        "pattern": "os.system($CMD)",
    } | overrides


def test_a_well_formed_rule_passes_every_static_check() -> None:
    check, found = gate.structure({"rules": [rule()]})
    assert check.passed and found == rule()
    assert all(c(rule()).passed for c in (gate.catch_all, gate.paths, gate.regexes))


@pytest.mark.parametrize(
    ("doc", "problem"),
    [
        ({"rules": [rule(), rule(id="other-id")]}, "exactly one rule"),
        ({"rules": []}, "exactly one rule"),
        ("not a mapping", "exactly one rule"),
        ({"rules": [rule(id="Bad ID")]}, "id must be"),
        ({"rules": [rule(message="  ")]}, "message is required"),
        ({"rules": [rule(languages=[])]}, "languages"),
        ({"rules": [rule(severity="HIGH")]}, "severity"),
        ({"rules": [rule(metadata={"cwe": []})]}, "metadata.cwe"),
        ({"rules": [rule(metadata={"cwe": ["78"]})]}, "metadata.cwe"),
        ({"rules": [rule(metadata={"cwe": ["CWE-78"], "kind": "hardening"})]}, "metadata.kind"),
        ({"rules": [{k: v for k, v in rule().items() if k != "pattern"}]}, "needs patterns"),
    ],
)
def test_structure_refuses_a_malformed_rule(doc: Any, problem: str) -> None:
    check, _ = gate.structure(doc)
    assert not check.passed and problem in check.detail


def test_a_taint_rule_with_sources_and_sinks_is_well_formed() -> None:
    taint = {k: v for k, v in rule().items() if k != "pattern"} | {
        "mode": "taint",
        "pattern-sources": [{"pattern": "request.args.get(...)"}],
        "pattern-sinks": [{"pattern": "os.system(...)"}],
    }
    assert gate.structure({"rules": [taint]})[0].passed


@pytest.mark.parametrize(
    ("overrides", "caught"),
    [
        ({"pattern": "$X"}, True),
        ({"pattern": "$F(...)"}, True),
        ({"pattern": "..."}, True),
        ({"pattern": None, "patterns": [{"pattern-inside": "$X.$Y(...)"}]}, True),
        ({"pattern": None, "pattern-regex": ".*"}, True),
        (
            {"pattern": None, "pattern-either": [{"pattern": "os.system($X)"}, {"pattern": "$Y"}]},
            True,
        ),
        ({"pattern": "subprocess.run($CMD, shell=True)"}, False),
        ({"pattern": None, "pattern-regex": r"AKIA[0-9A-Z]{16}"}, False),
    ],
)
def test_catch_all_patterns_are_refused(overrides: dict[str, Any], caught: bool) -> None:
    r = {k: v for k, v in (rule() | overrides).items() if v is not None}
    assert gate.catch_all(r).passed is not caught


@pytest.mark.parametrize(
    ("spec", "passed"),
    [
        ({"include": ["src/**/*.py"], "exclude": ["tests/**"]}, True),
        ({"include": ["../secrets/*"]}, False),
        ({"include": ["/etc/*"]}, False),
        ({"exclude": ["~/x"]}, False),
        ({"include": ["**"]}, False),
        ({"include": ["*"]}, False),
        ({"exclude": ["**"]}, True),
    ],
)
def test_path_globs_stay_in_the_tree_and_never_select_everything(
    spec: dict[str, Any], passed: bool
) -> None:
    assert gate.paths(rule(paths=spec)).passed is passed


@pytest.mark.parametrize(
    ("regex", "problem"),
    [
        (r"(a)\1", "backreference"),
        (r"(?P<x>a)(?P=x)", "backreference"),
        (r"(?<=token=)\w+", "lookbehind"),
        (r"(?<!x)y", "lookbehind"),
        (r"(a+)+b", "nested quantifier"),
        (r"(\w+\s?)*$", "nested quantifier"),
        (r"(.*){2,}", "nested quantifier"),
        (r"([a-z", "doesn't compile"),
    ],
)
def test_unsafe_regexes_are_refused(regex: str, problem: str) -> None:
    r = rule(pattern=None) | {"patterns": [{"pattern-regex": regex}]}
    check = gate.regexes(r)
    assert not check.passed and problem in check.detail


def test_metavariable_regexes_are_checked_and_safe_ones_pass() -> None:
    unsafe = rule() | {"metavariable-regex": {"metavariable": "$CMD", "regex": r"(x+)+"}}
    assert not gate.regexes(unsafe).passed
    safe = rule() | {"metavariable-regex": {"metavariable": "$CMD", "regex": r"^rm\b.*"}}
    assert gate.regexes(safe).passed


EXAMPLE = f"""import os
# ruleid: {RID}
os.system(cmd)
# ok: {RID}
subprocess.run(["ls"])
# ok: other-rule
os.system(other)
"""


@pytest.mark.parametrize(
    ("hit_lines", "passed", "problem"),
    [
        ({3}, True, ""),
        ({3, 7}, True, ""),  # a marker for another rule doesn't bind this one
        (set(), False, "no match on ruleid line(s) [3]"),
        ({3, 5}, False, "matches ok line(s) [5]"),
    ],
)
def test_examples_must_fire_exactly(hit_lines: set[int], passed: bool, problem: str) -> None:
    check = gate.examples(RID, EXAMPLE, hit_lines)
    assert check.passed is passed and problem in check.detail


def test_examples_need_a_positive_and_a_negative_line() -> None:
    only_positive = f"# ruleid: {RID}\nos.system(x)\n"
    check = gate.examples(RID, only_positive, {2})
    assert not check.passed and "at least one" in check.detail


@pytest.mark.parametrize(
    ("hits", "hit_files", "files", "passed"),
    [
        (0, 0, 10, True),
        (25, 3, 10, True),
        (26, 3, 1000, False),
        (10, 4, 40, False),  # cap is max(3, 5% of 40) = 3
        (10, 10, 200, True),  # cap is 5% of 200 = 10
    ],
)
def test_explosion_caps_hits_and_the_share_of_files(
    hits: int, hit_files: int, files: int, passed: bool
) -> None:
    assert gate.explosion(hits, hit_files, files).passed is passed
