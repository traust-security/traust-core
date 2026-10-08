import json

import pytest

from tests.v1.services.test_storage import TRIAGE
from traust_core.v1 import contracts
from traust_core.v1.errors import DocumentError
from traust_core.v1.models.artifacts import (
    ANALYSIS_ARTIFACTS,
    Artifact,
    Severity,
    TriageArtifact,
    Verdict,
)

FINDING = {
    "id": "f001",
    "title": "SQL injection in handler",
    "verdict": "true_positive",
    "severity": "high",
    "vote_breakdown": {"true_positive": 3, "hardening": 0, "false_positive": 0, "cannot_verify": 0},
}


def triage(*findings: dict) -> TriageArtifact:
    doc = json.loads(TRIAGE)
    doc["findings"] = list(findings)
    return TriageArtifact.from_document(doc)


def test_every_named_artifact_points_at_a_real_contract_schema() -> None:
    assert {a.schema for a in ANALYSIS_ARTIFACTS} <= set(contracts.schema_names())
    assert len({a.name for a in ANALYSIS_ARTIFACTS}) == len(ANALYSIS_ARTIFACTS)


def test_fields_come_from_the_schema() -> None:
    f = triage(FINDING).findings[0]
    assert (f.id, f.verdict, f.severity) == ("f001", Verdict.TRUE_POSITIVE, Severity.HIGH)
    assert f.vote_breakdown.true_positive == 3


def test_reading_a_field_the_schema_does_not_have_raises() -> None:
    f = triage(FINDING).findings[0]
    with pytest.raises(AttributeError, match=r"triage\.findings\[0\] has no field 'origin'"):
        _ = f.origin


def test_absent_optional_is_none_and_absent_array_is_empty() -> None:
    f = triage({"id": "f002", "title": "Missing check", "verdict": "hardening"}).findings[0]
    assert f.duplicate_of is None
    assert f.refute_reasons == ()


def test_parse_keeps_exact_bytes_and_rejects_off_contract_documents() -> None:
    assert TriageArtifact.parse(TRIAGE).payload == TRIAGE
    with pytest.raises(DocumentError):
        TriageArtifact.parse(b'{"findings": [{"id": "x"}]}')


def test_cross_file_refs_resolve_into_the_target_schema() -> None:
    ref = {"$ref": "report.schema.json#/$defs/finding"}
    (schema_name, node), *_ = contracts.resolve("validation", ref)
    assert schema_name == "report"
    assert "severity" in node["properties"]


def test_artifact_subclasses_must_declare_a_schema() -> None:
    with pytest.raises(TypeError):

        class Broken(Artifact): ...


def test_schema_path_points_at_the_installed_contract() -> None:
    assert TriageArtifact.schema_path().name == "triage.schema.json"
    assert TriageArtifact.schema_path().is_file()


def test_describe_lists_fields_with_types_and_requiredness() -> None:
    text = TriageArtifact.describe()
    assert text.splitlines()[0].startswith("TriageArtifact (triage)")
    assert "findings: array of object (required)" in text
    assert "  verdict: one of true_positive|hardening|undetermined|false_positive|duplicate" in text
