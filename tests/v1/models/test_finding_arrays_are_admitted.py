"""Every array of findings a contracts schema carries, and what becomes of it.

A new findings array fails here until it is admitted or listed with the reason it isn't.
"""

from __future__ import annotations

import ast
import importlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from traust_core.v1 import contracts
from traust_core.v1.models.artifacts import CloudConfigAuditArtifact, VerificationArtifact
from traust_core.v1.models.assessment import RECORDED_SCHEMAS, REPORTED_FINDINGS, AssessmentKind

TESTS = Path(__file__).parents[2]
FIXTURES = TESTS / "fixtures"


@dataclass(frozen=True)
class Door:
    """Where another door admits an array: the converter it passes the document through, a
    fixture that carries the array, and the service test that records it end to end."""

    converter: str
    document: Any
    fixture: str
    proven_by: str


# Arrays a kind recorded through `AssessmentService.record` admits (REPORTED_FINDINGS).
REPORTED = {("report", "findings"), ("vuln-findings", "findings"), ("fuzz-report", "crashers")}

# Arrays another door admits.
ADMITTED_ELSEWHERE = {
    ("cloud-config-audit", "findings"): Door(
        "traust_core.v1.models.cloud_config:audit_candidates",
        CloudConfigAuditArtifact,
        "cloud_config/myrepo-cloud-config-audit.json",
        "v1/services/test_cloud_config_audit.py::"
        "test_every_stated_finding_is_a_row_and_two_checks_on_one_bucket_stay_two",
    ),
    ("verification", "regressions"): Door(
        "traust_core.v1.models.remediation:regression_candidates",
        VerificationArtifact,
        "remediation/verification-report.json",
        "v1/services/test_verification.py::"
        "test_record_states_each_verdict_and_takes_the_regressions",
    ),
}

# Arrays that are not new findings, and why.
NOT_ADMITTED = {
    ("triage", "findings"): "verdicts on recorded findings (`traust triage record`)",
    ("validation", "validated_findings"): "verdicts on explicitly bound recorded findings",
    ("verification", "verified_findings"): "verification of recorded findings' fixes",
    ("remediation", "source_findings"): "references to the recorded findings it fixes",
    ("vuln-findings", "known_findings"): "the baseline's findings, carried for the diff",
    ("cloud-config-findings-current", "findings"): "a derived view over recorded findings",
    ("pqc-blockers", "findings"): "a derived projection of readiness remediations",
    ("compliance-assessment", "results"): "control results, not findings",
    ("adapter-result", "findings"): "tool hits `run_tools` hands to the auditing session",
    (
        "benchmark-target",
        "targets[].expected",
    ): "the benchmark's answer key, scored against by detection quality, never admitted",
}

# Arrays of new findings no door admits yet, with their reasons.
GAPS = {
    ("validation", "novel_findings"): "no door admits novel findings from validation",
    ("fuzz-campaign", "bugs"): "no kind records fuzz-campaign on development yet",
}

# Kinds recorded with a findings-bearing schema that admit none, and why.
UNREPORTED_KINDS = {
    AssessmentKind.BENCHMARK_AUDIT: "scored against the answer key, never admitted",
    AssessmentKind.CLOUD_CONFIG_CANONICAL: "recorded through record_audit (ADMITTED_ELSEWHERE)",
}


def _resolve(schema: dict[str, Any], node: Any, depth: int = 0) -> tuple[dict[str, Any], Any]:
    """`node` with local and cross-schema `$ref`s followed, and the schema it now sits in (its
    own local `$ref`s resolve there). A pointer to nothing fails: it would hide the array."""
    if not isinstance(node, dict) or depth > 8 or "$ref" not in node:
        return schema, node
    name, _, fragment = node["$ref"].partition("#")
    if name:
        schema = contracts.schema(name.split(".")[0])
    target: Any = schema
    for part in filter(None, fragment.split("/")):
        assert isinstance(target, dict) and part in target, f"unresolved $ref {node['$ref']}"
        target = target[part]
    return _resolve(schema, target, depth + 1)


def _item_fields(schema: dict[str, Any], node: Any, depth: int = 0) -> set[str]:
    """An array item's field names, following `$ref`s and composed schemas (`allOf` unions its
    branches; `anyOf`/`oneOf` conservatively union theirs)."""
    schema, node = _resolve(schema, node, depth)
    if not isinstance(node, dict) or depth > 8:
        return set()
    fields = set(node.get("properties", {}))
    for key in ("allOf", "anyOf", "oneOf"):
        for branch in node.get(key, ()) or ():
            fields |= _item_fields(schema, branch, depth + 2)
    return fields


def _finding_shaped(schema: dict[str, Any], node: dict[str, Any]) -> bool:
    """An array whose items are findings by their fields, whatever the array is called."""
    fields = _item_fields(schema, node.get("items", {}))
    return "title" in fields and bool(fields & {"severity", "cwe", "cwes", "locations"})


def _nested(schema: dict[str, Any], properties: Any, prefix: str, depth: int = 0) -> set[str]:
    """Finding-shaped arrays nested inside objects, as dotted paths (`box.items.findings`)."""
    found = set()
    if depth > 3 or not isinstance(properties, dict):
        return found
    for key, node in properties.items():
        if not isinstance(node, dict):
            continue
        at, node = _resolve(schema, node)
        if not isinstance(node, dict):
            continue
        if node.get("type") == "array" and _finding_shaped(at, node):
            found.add(f"{prefix}{key}")
        found |= _nested(at, node.get("properties"), f"{prefix}{key}.", depth + 1)
        if node.get("type") == "array":
            inner_at, inner = _resolve(at, node.get("items"))
            if isinstance(inner, dict):
                found |= _nested(inner_at, inner.get("properties"), f"{prefix}{key}[].", depth + 1)
    return found


def _arrays() -> set[tuple[str, str]]:
    """Every array named for findings, or holding finding-shaped items, nested or not."""
    found = set()
    for name in contracts.schema_names():
        schema = contracts.schema(name)
        found |= {
            (name, key)
            for key, node in schema.get("properties", {}).items()
            if isinstance(node, dict)
            and node.get("type") == "array"
            and key != "findings_summary"
            and (
                "finding" in key or key in ("crashers", "results") or _finding_shaped(schema, node)
            )
        }
        found |= {(name, path) for path in _nested(schema, schema.get("properties"), "")}
    return found


def test_every_findings_array_is_classified() -> None:
    classified = REPORTED | ADMITTED_ELSEWHERE.keys() | NOT_ADMITTED.keys() | GAPS.keys()
    assert _arrays() == classified


def test_classes_do_not_overlap() -> None:
    groups = [REPORTED, set(ADMITTED_ELSEWHERE), set(NOT_ADMITTED), set(GAPS)]
    assert sum(map(len, groups)) == len(set().union(*groups))


def test_a_recorded_kind_with_a_reported_array_admits_it() -> None:
    schemas = {schema for schema, _ in REPORTED}
    for kind, schema in RECORDED_SCHEMAS.items():
        if schema in schemas:
            assert kind in REPORTED_FINDINGS or kind in UNREPORTED_KINDS, kind
    assert {RECORDED_SCHEMAS[k] for k in REPORTED_FINDINGS} == schemas


def test_every_exempted_kind_is_recorded_and_admitted_elsewhere() -> None:
    """An exemption is only real while its kind is recorded and its schema's findings array is
    admitted by a named door; a stale exemption fails here."""
    for kind, why in UNREPORTED_KINDS.items():
        assert kind in RECORDED_SCHEMAS, (kind, why)
        assert kind not in REPORTED_FINDINGS, (kind, why)
        schema = RECORDED_SCHEMAS[kind]
        assert (schema, "findings") in REPORTED | ADMITTED_ELSEWHERE.keys(), (kind, why)


@pytest.mark.parametrize("array", sorted(ADMITTED_ELSEWHERE), ids="/".join)
def test_each_named_door_takes_every_entry_of_its_array(array: tuple[str, str]) -> None:
    door = ADMITTED_ELSEWHERE[array]
    module, name = door.converter.split(":")
    convert = getattr(importlib.import_module(module), name)
    raw = json.loads((FIXTURES / door.fixture).read_text())
    assert raw[array[1]], f"{door.fixture} carries no {array[1]}"
    candidates = convert(door.document.parse(json.dumps(raw).encode()), uuid4())
    assert len(candidates) == len(raw[array[1]])


@pytest.mark.parametrize("array", sorted(ADMITTED_ELSEWHERE), ids="/".join)
def test_each_named_door_has_a_running_service_test_that_records_it(array: tuple[str, str]) -> None:
    """The converter alone isn't the connection: a service test records a document through the
    door and asserts its findings are rows. It must exist and not be skipped or xfailed."""
    path, test = ADMITTED_ELSEWHERE[array].proven_by.split("::")
    tree = ast.parse((TESTS / path).read_text())
    (definition,) = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == test]
    for decorator in definition.decorator_list:
        tokens = set(re.split(r"[^\w]+", ast.unparse(decorator)))
        assert not {"skip", "skipif", "xfail"} & tokens, ast.unparse(decorator)
    calls = {
        n.func.attr
        for n in ast.walk(definition)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    assert not {"skip", "xfail"} & calls, f"{test} skips itself"
    body = [
        n
        for n in definition.body
        if not isinstance(n, ast.Pass)
        and not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))
    ]
    assert body, f"{test} has no body"
