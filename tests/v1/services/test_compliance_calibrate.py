"""`ComplianceService.calibrate`: the run-twice idempotence gate (traust fabdb13
ops/calibrate_compliance.py) and the seeded efficacy target (ops/score_compliance_efficacy.py),
over `evaluate`.

Seeded truths (the answer key's own notes): one open confirmed critical CWE-1104 fails the si-2
family, no credential findings passes ia-5.7; bucket b1 unencrypted fails sc-28, every region
allowed passes gdpr-residency; KHS-W01 (privileged) fails ac-6, KHS-W13 (secrets in env) fails
C1.1, KHS-R01 / KHS-W02 absent pass 7.2.1 / cm-6; the crypto collector is deliberately absent, so
sc-13 / CC6.7 must stay not_assessed (a verdict there is guessing)."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

import pytest

from tests.v1.services import test_compliance as compliance
from tests.v1.services.test_compliance import FIXTURES, FakeFindings, World, critical_dependency
from traust_core.v1.models.artifacts import ComplianceAssessmentArtifact
from traust_core.v1.models.compliance import (
    EfficacyFailureClass,
    EfficacyKey,
    EvaluationRequest,
    EvaluationRun,
    InventorySnapshot,
    divergences,
)
from traust_core.v1.models.findings import FindingFilter, FindingView
from traust_core.v1.models.vocabulary import ComplianceFramework, ComplianceTargetKind

engine, uow, seed, world = compliance.engine, compliance.uow, compliance.seed, compliance.world

SEEDED = FIXTURES / "efficacy"
KEY = EfficacyKey.model_validate_json((SEEDED / "expected-verdicts.json").read_bytes())
FRAMEWORKS = tuple(
    ComplianceFramework(f) for f in ("nist-800-53-rev5", "pci-dss-v4", "soc2-tsc", "gdpr-technical")
)


def seeded(world: World, findings: Any = None) -> EvaluationRequest:
    world.publish_mapping()
    scope_id = world.declared(frameworks=list(FRAMEWORKS))
    world.findings = findings or FakeFindings()
    if findings is None:
        world.findings.views = {
            world.a.repository_id: [
                critical_dependency(world.a.repository_id).model_copy(
                    update={"cwes": ("CWE-1104",)}
                )
            ]
        }
    world.service = world.compliance(
        parameters={"allowed_data_regions": ["us-east-1", "eu-west-1"]}
    )
    inventory = json.loads((SEEDED / "cloud-inventory.json").read_text())
    return EvaluationRequest(
        scope_id=scope_id,
        harness_version="9.9.9",
        frameworks=FRAMEWORKS,
        target_kind=ComplianceTargetKind("both"),
        environment="seeded-efficacy-env",
        cde_boundary="seeded-cde (fixture declaration)",
        personal_data_stores=("seeded-pds",),
        trust_categories=("security", "confidentiality"),
        snapshots={"scan_k8s_hardening": json.loads((SEEDED / "khs.json").read_text())},
        inventory=InventorySnapshot.of(
            inventory["metadata"]["collector"], inventory["resources"], []
        ),
    )


def test_the_seeded_target_meets_its_answer_key_on_identical_runs(world: World) -> None:
    request = seeded(world)
    got = world.service.calibrate(request, KEY)
    assert (got.divergences, got.efficacy) == ((), ())
    assert got.passed and got.controls == sum(len(c) for c in KEY.expected.values())


def test_without_a_key_only_idempotence_is_reported(world: World) -> None:
    request = seeded(world)
    got = world.service.calibrate(request)
    assert (got.divergences, got.efficacy, got.passed) == ((), None, True)


class DriftingFindings(FakeFindings):
    """A findings source that answers differently on every read: nondeterminism to catch."""

    def __init__(self, repository_id: UUID) -> None:
        super().__init__()
        self.repository_id, self.reads = repository_id, 0

    def all(self, filter: FindingFilter) -> list[FindingView]:
        if filter.repository_id != self.repository_id:
            return []
        self.reads += 1
        return [critical_dependency(self.repository_id)] if self.reads > 1 else []


def test_a_run_that_drifts_between_evaluations_is_caught(world: World) -> None:
    request = seeded(world, DriftingFindings(world.a.repository_id))
    got = world.service.calibrate(request, KEY)
    assert "nist-800-53-rev5:si-2 differs: run1=satisfied run2=not_satisfied" in got.divergences
    assert "coverage blocks differ" in got.divergences
    assert not got.passed


def _run(doc: dict[str, Any], failures: tuple[str, ...] = ()) -> EvaluationRun:
    return EvaluationRun.model_construct(
        document=ComplianceAssessmentArtifact.from_document(doc), failures=failures
    )


@pytest.fixture
def body(world: World) -> dict[str, Any]:
    request = seeded(world)
    return json.loads(world.service.evaluate(request).document.payload)


def _edit(body: dict[str, Any], control: str, **changes: Any) -> dict[str, Any]:
    out = json.loads(json.dumps(body))
    for r in out["results"]:
        if r["control_id"] == control:
            r.update(changes)
    return out


@pytest.mark.parametrize(
    ("change", "want"),
    [
        (
            lambda b: {**b, "metadata": {**b["metadata"], "generated_at": "2030-01-01T00:00:00Z"}},
            (),
        ),
        (
            lambda b: _edit(b, "cm-6", reason="a different reason"),
            (
                "nist-800-53-rev5:cm-6 differs: run1=satisfied run2=satisfied (same verdict, "
                "differing evidence/fields)",
            ),
        ),
        (
            lambda b: {**b, "results": [r for r in b["results"] if r["control_id"] != "cm-6"]},
            ("nist-800-53-rev5:cm-6 present in only one run",),
        ),
        (
            lambda b: {**b, "metadata": {**b["metadata"], "harness_version": "0.0.1"}},
            ("(difference outside the result set)",),
        ),
    ],
    ids=["generated-at-only", "same-verdict", "missing-result", "outside-results"],
)
def test_divergences_name_what_differs(
    body: dict[str, Any], change: Any, want: tuple[str, ...]
) -> None:
    assert divergences(_run(body), _run(change(body))) == want


def test_a_differing_gate_is_a_divergence(body: dict[str, Any]) -> None:
    assert divergences(_run(body), _run(body, ("results[0]: uncited",))) == (
        "gate outcomes differ: [] vs ['results[0]: uncited']",
    )


@pytest.mark.parametrize(
    ("edits", "want"),
    [
        ({}, []),
        (
            {"sc-13": "satisfied"},
            [
                ("guessing", "nist-800-53-rev5:sc-13"),
                ("incoherence", "soc2-tsc:CC6.7 <> nist-800-53-rev5:sc-13"),
            ],
        ),
        ({"cm-6": "not_satisfied"}, [("wrong_verdict", "nist-800-53-rev5:cm-6")]),
        (
            {"si-2": "satisfied", "sc-13": "not_satisfied"},
            [
                ("guessing", "nist-800-53-rev5:sc-13"),
                ("wrong_verdict", "nist-800-53-rev5:si-2"),
                ("incoherence", "pci-dss-v4:6.3.3 <> nist-800-53-rev5:si-2"),
                ("incoherence", "soc2-tsc:CC7.1 <> nist-800-53-rev5:si-2"),
                ("incoherence", "soc2-tsc:CC6.7 <> nist-800-53-rev5:sc-13"),
            ],
        ),
    ],
    ids=["clean", "honesty-probe", "wrong", "worst-first"],
)
def test_the_key_scores_each_failure_class(
    body: dict[str, Any], edits: dict[str, str], want: list[tuple[str, str]]
) -> None:
    for control, verdict in edits.items():
        body = {
            **body,
            "results": [
                {**r, "verdict": verdict}
                if r["control_id"] == control and r["framework"] == "nist-800-53-rev5"
                else r
                for r in body["results"]
            ],
        }
    failures = KEY.score(_doc(body))
    assert [(f.kind, f.control) for f in failures] == want


def _doc(body: dict[str, Any]) -> ComplianceAssessmentArtifact:
    return ComplianceAssessmentArtifact(json.dumps(body).encode(), body)


def test_a_control_the_run_never_emitted_is_missing(body: dict[str, Any]) -> None:
    key = KEY.model_copy(update={"expected": {"nist-800-53-rev5": {"zz-99": "satisfied"}}})
    (failure,) = key.score(_doc(body))
    assert (failure.kind, failure.got) == (EfficacyFailureClass.MISSING, "(no result emitted)")
