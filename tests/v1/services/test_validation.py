from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
import sqlalchemy as sa
from pydantic import ValidationError as ModelValidationError
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed, saved_id
from traust_core.v1.errors import (
    IntegrityError,
    NotFoundError,
    RepositoryError,
    ServiceError,
    ValidationError,
)
from traust_core.v1.models.artifacts import TriageArtifact, ValidationArtifact
from traust_core.v1.models.assessment import Artifact, Assessment
from traust_core.v1.models.common import PageRequest, Provenance
from traust_core.v1.models.findings import Finding, ReviewFilter
from traust_core.v1.models.validation import (
    TargetAttestation,
    ValidationFindingBinding,
    ValidationRecordingEvidence,
    ValidationRecordingPolicy,
    ValidationRecordInput,
    ValidationRecordResult,
    ValidationSourceBinding,
)
from traust_core.v1.models.vocabulary import SourceType, ValidationVerdict
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore, ObjectKey, ObjectRef
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.findings.rating import RatingConfig, RatingPolicy
from traust_core.v1.services.findings.review import FindingReview, ReviewPolicy
from traust_core.v1.services.findings.views import FindingViewQuery
from traust_core.v1.services.ledger import LedgerConfig, LedgerService
from traust_core.v1.services.lint import Lint
from traust_core.v1.services.validation import ValidationService

NOW = datetime(2026, 10, 22, 12, tzinfo=UTC)
RUN_ID = UUID("00000000-0000-4000-8000-000000000001")
OTHER_RUN_ID = UUID("00000000-0000-4000-8000-000000000002")
UNKNOWN_ID = UUID("00000000-0000-4000-8000-000000000099")
PROVENANCE = Provenance(run_id=RUN_ID, source=SourceType.VALIDATION_REPORT, occurred_at=NOW)
SOURCE_REPORT = "findings/example/app-triage.json"
TRIAGE = Path(__file__).parents[2] / "fixtures" / "findings" / "triage" / "triage-report.json"
ATTESTATION = {
    "artifact": "target-attestation",
    "attested": True,
    "generated_at": "2026-10-22T11:59:00Z",
    "harness_version": "0.34.3",
    "fingerprint": [{"adapter": "k8s", "identity": "example-lab"}],
    "checks": [{"name": "target-ready", "ok": True, "required": True, "detail": "Ready"}],
}
TABLES = (
    "assessments",
    "artifacts",
    "findings",
    "occurrences",
    "locations",
    "decisions",
    "review_items",
    "finding_external_refs",
    "events",
    "layers",
)


@dataclass(frozen=True)
class ValidationHarness:
    engine: Engine
    objects: InMemoryObjectStore
    source: Assessment
    artifact: Artifact
    findings: tuple[Finding, ...]
    validation: ValidationService
    decisions: FindingDecisions
    review: FindingReview
    ledger: LedgerService

    def bindings(self, *indices: int, **changes: Any) -> ValidationRecordInput:
        source = ValidationSourceBinding(
            source_report=SOURCE_REPORT,
            assessment_id=saved_id(self.source),
            artifact_id=saved_id(self.artifact),
            findings=tuple(
                ValidationFindingBinding(
                    source_id=f"f{i + 1:03d}", finding_id=saved_id(self.findings[i])
                )
                for i in indices or (0,)
            ),
        )
        return ValidationRecordInput(sources=(source,), **changes)

    def evidence(self, result: ValidationRecordResult) -> ValidationRecordingEvidence:
        (artifact_id,) = result.evidence_artifact_ids
        return self.validation.evidence(artifact_id)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def harness(engine: Engine) -> ValidationHarness:
    objects = InMemoryObjectStore()
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = seed.repository()
        ref = seed.repository_ref(repository)
        source = seed.assessment(ref)
        findings = tuple(seed.finding(repository, fingerprint=str(i) * 64) for i in (1, 2))
        for finding in findings:
            occurrence = seed.occurrence(finding, source, severity="high")
            seed.location(occurrence)
        raw = json.loads(TRIAGE.read_bytes())
        raw["findings"] = [
            {
                "id": f"f{i:03d}",
                "title": finding.title,
                "verdict": "true_positive",
                "fingerprint": finding.fingerprint,
                "fingerprint_algo": finding.fingerprint_algo,
            }
            for i, finding in enumerate(findings, 1)
        ]
        doc = TriageArtifact.parse(json.dumps(raw).encode())
        stored = objects.put(ObjectKey.parse("sources/app-triage.json"), doc.payload)
        artifact = seed.artifact(source, kind="triage", digest=stored.sha256, uri=str(stored.key))
        uow.commit()
    shared = SqlTraustUnitOfWork(engine)
    ledger = LedgerService(shared, LedgerConfig())
    review_policy = ReviewPolicy()
    decisions = FindingDecisions(
        shared,
        ledger,
        Lint({}),
        FindingPrecedents(shared),
        clock=FixedClock(NOW),
        objects=objects,
        review=review_policy,
    )
    review = FindingReview(
        shared, review_policy, decisions, FindingViewQuery(RatingPolicy(RatingConfig()))
    )
    validation = ValidationService(shared, decisions, ())
    return ValidationHarness(
        engine, objects, source, artifact, findings, validation, decisions, review, ledger
    )


def report(
    harness: ValidationHarness,
    verdict: str = "confirmed",
    *,
    version: str = "0.34.3",
    attestation: dict[str, Any] | None = ATTESTATION,
    environment: str = "example-lab",
    finding: dict[str, Any] | None = None,
    additional: tuple[dict[str, Any], ...] = (),
    **changes: Any,
) -> ValidationArtifact:
    item = {
        "source_id": "f001",
        "source_report": SOURCE_REPORT,
        "verdict": verdict,
        "technique": "replay",
        "observed_impact": "The recorded action produced the documented observation.",
        **(finding or {}),
    }
    findings = [item, *additional]
    raw = {
        "title": "Live validation of example application",
        "metadata": {
            "date": "2026-10-22",
            "harness_version": version,
            "scope_binding_mode": "explicit",
            "target_fingerprint": [{"adapter": "k8s", "identity": environment}],
            "target_environment": environment,
            **({"target_attestation": attestation} if attestation is not None else {}),
        },
        "source_reports": [
            {"kind": "triage", "path": SOURCE_REPORT, "sha256": harness.artifact.digest}
        ],
        "summary": {
            "by_verdict": {
                v.value: sum(f["verdict"] == v.value for f in findings) for v in ValidationVerdict
            },
            "by_technique": {"replay": len(findings)},
        },
        "validated_findings": findings,
        "attack_chains": [],
        "novel_findings": [],
        "execution_log_ref": "validation-audit.jsonl",
        **changes,
    }
    return ValidationArtifact.parse(json.dumps(raw).encode())


def probe(
    *,
    observed: str = "no\nvf-rbac-tried: system:serviceaccount:app:worker",
    controls: list[dict[str, Any]] | None = None,
    differential: dict[str, Any] | None = None,
    **changes: Any,
) -> dict[str, Any]:
    return {
        "step_id": "S1",
        "adapter": "k8s",
        "verb": "rbac-can-i",
        "classification": "safe",
        "verdict": "refuted",
        "observed": observed,
        "controls": controls
        if controls is not None
        else [{"name": "same-client allowed action", "kind": "must_succeed", "ok": True}],
        "differential": differential
        if differential is not None
        else {
            "neighbor_action": "get pods",
            "discriminated": True,
        },
        **changes,
    }


def snapshot(engine: Engine) -> dict[str, tuple[tuple[object, ...], ...]]:
    with SqlTraustUnitOfWork(engine) as uow:
        return {
            name: tuple(
                tuple(row)
                for row in uow.connection.execute(
                    sa.select(getattr(uow, name).table).order_by(getattr(uow, name).table.c.id)
                )
            )
            for name in TABLES
        }


def test_record_confirms_e0_without_rerating_or_fabricating_occurrences(
    harness: ValidationHarness,
) -> None:
    before = snapshot(harness.engine)
    doc = report(harness, finding={"evidence_grade": "E0", "claimed_severity": "critical"})
    result = harness.validation.record(doc, PROVENANCE, harness.bindings())
    (outcome,) = result.findings
    assert (outcome.source_report, outcome.source_id, outcome.finding_id) == (
        SOURCE_REPORT,
        "f001",
        harness.findings[0].id,
    )
    assert outcome.verdict == "confirmed" and outcome.soundness_flag is None
    assert outcome.assessment_id in result.assessment_ids
    assert outcome.artifact_id in result.artifact_ids
    decision = harness.decisions.get(outcome.decision_id)
    assert (decision.validity, decision.evidence_grade, decision.severity) == (
        "confirmed",
        "E0",
        None,
    )
    assert (decision.actor, decision.auto_accept_tier, decision.occurred_at) == (None, False, NOW)
    assert decision.assessment_id == outcome.assessment_id
    assert decision.artifact_id == outcome.artifact_id
    assert outcome.review_item_ids == ()
    with SqlTraustUnitOfWork(harness.engine) as uow:
        assessment = uow.assessments.get(outcome.assessment_id)
        artifact = uow.artifacts.get(outcome.artifact_id)
        evidence = uow.artifacts.get(result.evidence_artifact_ids[0])
        assert uow.events.find_by_decision(decision.id) is not None
    assert (assessment.kind, assessment.status, assessment.baseline_assessment_id) == (
        "validation",
        "completed",
        harness.source.id,
    )
    assert assessment.repository_ref_id == harness.source.repository_ref_id
    assert (assessment.assessor_version, assessment.occurred_at) == ("0.34.3", NOW)
    assert artifact.kind == "validation" and artifact.assessment_id == assessment.id
    ref = ObjectRef(ObjectKey.parse(artifact.uri), artifact.digest, len(doc.payload))
    assert harness.objects.get(ref) == doc.payload
    assert evidence.kind == "validation-recording"
    retained = harness.evidence(result)
    assert retained.report_digest == artifact.digest
    assert retained.provenance == PROVENANCE and retained.bindings == harness.bindings()
    assert retained.findings[0].evidence_grade == "E0"
    after = snapshot(harness.engine)
    assert after["occurrences"] == before["occurrences"]
    assert after["locations"] == before["locations"]
    assert after["findings"] == before["findings"]


def test_record_preserves_a_sound_refutation_as_a_pending_human_proposal(
    harness: ValidationHarness,
) -> None:
    doc = report(harness, "refuted", finding={"steps": [probe()]})
    (outcome,) = harness.validation.record(doc, PROVENANCE, harness.bindings()).findings
    assert outcome.verdict == "refuted" and outcome.soundness_flag is None
    decision = harness.decisions.get(outcome.decision_id)
    assert (decision.validity, decision.auto_accept_tier, decision.severity) == (
        "false_positive",
        False,
        None,
    )
    (item_id,) = outcome.review_item_ids
    item = harness.review.get(item_id)
    assert (item.reason, item.status, item.decision_id) == (
        "analyst_review",
        "pending",
        decision.id,
    )
    assert harness.review.needs_review(saved_id(harness.findings[0]))
    (case,) = harness.review.queue(ReviewFilter(), PageRequest()).items
    assert case.finding.is_open()
    assert case.finding.disposition.awaiting_signoff


@pytest.mark.parametrize(
    ("verdict", "observed", "flag", "expected", "expected_flag"),
    [
        (
            "refuted",
            "no\nvf-rbac-tried:\nvf-rbac-probe: verb=delete",
            None,
            "inconclusive",
            "rbac-zero-subjects",
        ),
        ("refuted", "no\nvf-rbac-tried: system:serviceaccount:app:worker", None, "refuted", None),
        ("inconclusive", "no", "target-not-deployed", "inconclusive", "target-not-deployed"),
    ],
    ids=["legacy-ungated-unsound-refutation", "legacy-sound-refutation", "legacy-producer-flag"],
)
def test_legacy_report_soundness_scenarios_retain_their_meaning(
    harness: ValidationHarness,
    verdict: str,
    observed: str,
    flag: str | None,
    expected: str,
    expected_flag: str | None,
) -> None:
    finding = {"observed_impact": observed, **({"soundness_flag": flag} if flag else {})}
    doc = report(harness, verdict, version="0.175.0", attestation=None, finding=finding)
    bindings = harness.bindings(policy=ValidationRecordingPolicy.HISTORICAL)
    result = harness.validation.record(doc, PROVENANCE, bindings)
    (outcome,) = result.findings
    assert (outcome.verdict, outcome.soundness_flag) == (expected, expected_flag)
    assert harness.evidence(result).findings[0].soundness_flag == expected_flag
    assert (outcome.decision_id is not None) is (expected == "refuted")
    assert all(harness.review.get(i).status == "pending" for i in outcome.review_item_ids)


@pytest.mark.parametrize("verdict", [v.value for v in ValidationVerdict])
@pytest.mark.parametrize(
    "attestation,flag",
    [(None, "attestation_missing"), ({"attested": False}, "environment_invalid")],
)
def test_missing_or_failed_attestation_voids_every_verdict_but_retains_its_evidence(
    harness: ValidationHarness, verdict: str, attestation: dict[str, Any] | None, flag: str
) -> None:
    doc = report(harness, verdict, attestation=attestation, finding={"evidence_grade": "E0"})
    result = harness.validation.record(doc, PROVENANCE, harness.bindings())
    (outcome,) = result.findings
    assert outcome.decision_id is None and outcome.soundness_flag == flag
    assert outcome.verdict == "inconclusive"
    assert harness.decisions.list_for_finding(outcome.finding_id) == []
    assert outcome.review_item_ids
    assert all(
        harness.review.get(i).reason == "unsound_refutation" for i in outcome.review_item_ids
    )
    retained = harness.evidence(result)
    assert retained.findings[0].soundness_flag == flag
    assert retained.report_digest
    (case,) = harness.review.queue(ReviewFilter(), PageRequest()).items
    expected_ref = f"traust:artifact:{result.evidence_artifact_ids[0]}#finding={outcome.finding_id}"
    assert any(
        ref.system == "traust.validation" and ref.ref == expected_ref for ref in case.external_refs
    )
    assert case.history == ()
    assert case.finding.occurrence.assessment_id == harness.source.id
    assert case.finding.effective_severity == "high"


def test_separate_attestation_retains_the_full_actual_payload(harness: ValidationHarness) -> None:
    attestation = TargetAttestation.model_validate(ATTESTATION)
    bindings = harness.bindings(target_attestation=attestation)
    result = harness.validation.record(
        report(harness, attestation=None, finding={"evidence_grade": "E0"}), PROVENANCE, bindings
    )
    assert result.findings[0].decision_id is not None
    assert harness.evidence(result).bindings.target_attestation.model_dump() == ATTESTATION


@pytest.mark.parametrize("attested", ["false", "true", 0, 1, None])
def test_attestation_readiness_is_a_strict_boolean(attested: object) -> None:
    with pytest.raises(ModelValidationError):
        TargetAttestation.model_validate({"attested": attested})


@pytest.mark.parametrize(
    ("finding", "flag"),
    [
        ({"steps": [probe(controls=[])]}, "missing-positive-control"),
        ({"steps": [probe(differential={})]}, "missing-differential-probe"),
    ],
)
def test_current_policy_remains_strict_after_the_harness_version_reset(
    harness: ValidationHarness, finding: dict[str, Any], flag: str
) -> None:
    if flag == "missing-differential-probe":
        finding["steps"][0].pop("differential", None)
    result = harness.validation.record(
        report(harness, "refuted", finding=finding), PROVENANCE, harness.bindings()
    )
    (outcome,) = result.findings
    assert (outcome.verdict, outcome.soundness_flag, outcome.decision_id) == (
        "inconclusive",
        flag,
        None,
    )
    assert harness.evidence(result).bindings.policy is ValidationRecordingPolicy.CURRENT


@pytest.mark.parametrize(
    ("version", "verdict", "attest", "steps", "flag", "decision", "reason"),
    [
        ("0.175.999", "refuted", False, [], None, True, "analyst_review"),
        ("0.176.0", "refuted", False, [], "attestation_missing", False, "unsound_refutation"),
        (
            "0.176.0-rc.1",
            "refuted",
            False,
            [],
            "attestation_missing",
            False,
            "unsound_refutation",
        ),
        ("0.176.0", "refuted", True, [], None, True, "analyst_review"),
        ("0.177.0", "refuted", True, [], "missing-positive-control", False, "unsound_refutation"),
        ("0.177.999", "refuted", True, [probe(differential={})], None, True, "analyst_review"),
        (
            "0.178.0",
            "refuted",
            True,
            [probe(differential={})],
            "missing-differential-probe",
            False,
            "unsound_refutation",
        ),
        ("0.178.999", "confirmed", True, [], None, True, None),
        ("0.179.0-rc.1", "confirmed", True, [], None, False, "ungraded_confirmation"),
        ("0.179.0", "confirmed", True, [], None, False, "ungraded_confirmation"),
        ("0.179.0+build.7", "confirmed", True, [], None, False, "ungraded_confirmation"),
    ],
)
def test_historical_policy_validates_semver_but_compares_numeric_cutoff_components(
    harness: ValidationHarness,
    version: str,
    verdict: str,
    attest: bool,
    steps: list[dict[str, Any]],
    flag: str | None,
    decision: bool,
    reason: str | None,
) -> None:
    steps = [{k: v for k, v in step.items() if k != "differential" or v} for step in steps]
    result = harness.validation.record(
        report(
            harness,
            verdict,
            version=version,
            attestation=ATTESTATION if attest else None,
            finding={"steps": steps},
        ),
        PROVENANCE,
        harness.bindings(policy=ValidationRecordingPolicy.HISTORICAL),
    )
    (outcome,) = result.findings
    assert outcome.soundness_flag == flag
    assert (outcome.decision_id is not None) is decision
    reasons = {harness.review.get(i).reason for i in outcome.review_item_ids}
    assert reasons == ({reason} if reason else set())
    if decision:
        assert harness.decisions.get(outcome.decision_id).evidence_grade is None


@pytest.mark.parametrize(
    "version", ["latest", "0.179", "v0.179.0", "0.179.0junk", "0.179.01", "0.179.0-01"]
)
def test_malformed_historical_versions_refuse_without_metadata(
    harness: ValidationHarness, version: str
) -> None:
    before = snapshot(harness.engine)
    with pytest.raises(ValidationError):
        harness.validation.record(
            report(harness, version=version),
            PROVENANCE,
            harness.bindings(policy=ValidationRecordingPolicy.HISTORICAL),
        )
    assert snapshot(harness.engine) == before


@pytest.mark.parametrize(
    "grade,reason", [("E3", "weak_confirmation"), (None, "ungraded_confirmation")]
)
def test_weak_and_ungraded_confirmations_are_review_only(
    harness: ValidationHarness, grade: str | None, reason: str
) -> None:
    result = harness.validation.record(
        report(harness, finding={"evidence_grade": grade}), PROVENANCE, harness.bindings()
    )
    (outcome,) = result.findings
    assert outcome.decision_id is None
    assert {harness.review.get(i).reason for i in outcome.review_item_ids} == {reason}
    assert harness.decisions.list_for_finding(outcome.finding_id) == []
    assert harness.evidence(result).findings[0].evidence_grade == grade


def test_record_does_not_backfill_a_legacy_null_grade(harness: ValidationHarness) -> None:
    with SqlTraustUnitOfWork(harness.engine) as uow:
        legacy = Seed(uow).decision(
            harness.findings[0], validity="true_positive", evidence_grade=None
        )
        uow.commit()
    result = harness.validation.record(
        report(harness, version="0.175.0", attestation=None, finding={"evidence_grade": None}),
        PROVENANCE,
        harness.bindings(policy=ValidationRecordingPolicy.HISTORICAL),
    )
    assert harness.decisions.get(result.findings[0].decision_id).evidence_grade is None
    with SqlTraustUnitOfWork(harness.engine) as uow:
        assert uow.decisions.get(saved_id(legacy)) == legacy
        assert uow.decisions.get(saved_id(legacy)).evidence_grade is None


def test_severity_proposals_queue_review_without_changing_severity(
    harness: ValidationHarness,
) -> None:
    proposal = {
        "demonstrated": {"privileges_required": "high"},
        "proposal": {
            "severity": "low",
            "rationale": "The observed exploit required administrator credentials.",
        },
    }
    result = harness.validation.record(
        report(harness, finding={"evidence_grade": "E0", "severity_validation": proposal}),
        PROVENANCE,
        harness.bindings(),
    )
    (outcome,) = result.findings
    assert harness.decisions.get(outcome.decision_id).severity is None
    assert {harness.review.get(i).reason for i in outcome.review_item_ids} == {"severity_proposal"}
    (case,) = harness.review.queue(ReviewFilter(), PageRequest()).items
    assert case.finding.effective_severity == "high"
    assert harness.evidence(result).findings[0].evidence_grade == "E0"


@pytest.mark.parametrize(
    "defect",
    [
        "missing-source",
        "extra-source",
        "source-path",
        "unknown-assessment",
        "unknown-artifact",
        "unknown-finding",
        "source-label",
        "missing-finding",
        "extra-finding",
        "duplicate-binding",
        "duplicate-source",
        "duplicate-report-finding",
        "duplicate-report-source",
        "declared-digest",
        "stored-digest",
        "cross-repository",
        "not-reported",
        "fingerprint",
        "artifact-assessment",
    ],
)
def test_exact_source_bindings_refuse_invalid_identity_without_any_metadata(
    harness: ValidationHarness, defect: str
) -> None:
    bindings = harness.bindings()
    source = bindings.sources[0]
    finding = source.findings[0]
    doc = report(harness, finding={"evidence_grade": "E0"})
    raw = json.loads(doc.payload)
    if defect == "missing-source":
        bindings = bindings.model_copy(update={"sources": ()})
    elif defect == "extra-source":
        extra = source.model_copy(update={"source_report": "findings/extra.json"})
        bindings = bindings.model_copy(update={"sources": (source, extra)})
    elif defect == "source-path":
        source = source.model_copy(update={"source_report": "findings/wrong.json"})
    elif defect in {"unknown-assessment", "unknown-artifact"}:
        field = "assessment_id" if defect == "unknown-assessment" else "artifact_id"
        source = source.model_copy(update={field: UNKNOWN_ID})
    elif defect == "unknown-finding":
        unknown = finding.model_copy(update={"finding_id": UNKNOWN_ID})
        source = source.model_copy(update={"findings": (unknown,)})
    elif defect == "source-label":
        raw["validated_findings"][0]["source_id"] = "missing-label"
        missing = finding.model_copy(update={"source_id": "missing-label"})
        source = source.model_copy(update={"findings": (missing,)})
    elif defect == "missing-finding":
        source = source.model_copy(update={"findings": ()})
    elif defect == "extra-finding":
        extra = ValidationFindingBinding(source_id="f002", finding_id=saved_id(harness.findings[1]))
        source = source.model_copy(update={"findings": (*source.findings, extra)})
    elif defect == "duplicate-binding":
        source = source.model_copy(update={"findings": (finding, finding)})
    elif defect == "duplicate-source":
        bindings = bindings.model_copy(update={"sources": (source, source)})
    elif defect == "duplicate-report-finding":
        raw["validated_findings"].append(raw["validated_findings"][0])
    elif defect == "duplicate-report-source":
        raw["source_reports"].append(raw["source_reports"][0])
    elif defect == "declared-digest":
        raw["source_reports"][0]["sha256"] = "0" * 64
    elif defect == "stored-digest":
        harness.objects.put(ObjectKey.parse(harness.artifact.uri), b"corrupt source bytes")
    else:
        with SqlTraustUnitOfWork(harness.engine) as uow:
            seed = Seed(uow)
            ref = uow.repository_refs.get(harness.source.repository_ref_id)
            repository = uow.repositories.get(ref.repository_id)
            if defect in {"cross-repository", "not-reported", "fingerprint"}:
                target = (
                    seed.repository(url="https://github.com/org/foreign")
                    if defect == "cross-repository"
                    else repository
                )
                stranger = seed.finding(target)
                if defect in {"cross-repository", "fingerprint"}:
                    seed.occurrence(stranger, harness.source)
                rebound = finding.model_copy(update={"finding_id": saved_id(stranger)})
                source = source.model_copy(update={"findings": (rebound,)})
            else:
                source = source.model_copy(update={"assessment_id": saved_id(seed.assessment(ref))})
            uow.commit()
    if bindings.sources and source != bindings.sources[0]:
        bindings = bindings.model_copy(update={"sources": (source,)})
    doc = ValidationArtifact.parse(json.dumps(raw).encode())
    before = snapshot(harness.engine)
    objects_before = tuple(harness.objects.list())
    with pytest.raises((ValidationError, NotFoundError, IntegrityError)):
        harness.validation.record(doc, PROVENANCE, bindings)
    assert snapshot(harness.engine) == before
    assert tuple(harness.objects.list()) == objects_before


def test_replaying_a_report_returns_stable_ids_and_does_not_reopen_review(
    harness: ValidationHarness,
) -> None:
    doc = report(harness, "refuted", finding={"steps": [probe()]})
    bindings = harness.bindings()
    first = harness.validation.record(doc, PROVENANCE, bindings)
    for item_id in first.findings[0].review_item_ids:
        harness.review.close_unreviewed(item_id)
    before = snapshot(harness.engine)
    assert harness.validation.record(doc, PROVENANCE, bindings) == first
    assert snapshot(harness.engine) == before
    assert all(
        harness.review.get(i).status == "closed_unreviewed"
        for i in first.findings[0].review_item_ids
    )


@pytest.mark.parametrize("change", ["environment", "run"])
def test_distinct_environments_and_runs_are_not_replays(
    harness: ValidationHarness, change: str
) -> None:
    doc = report(harness, finding={"evidence_grade": "E0"})
    first = harness.validation.record(doc, PROVENANCE, harness.bindings())
    next_doc = (
        report(harness, environment="example-spoke", finding={"evidence_grade": "E0"})
        if change == "environment"
        else doc
    )
    provenance = (
        PROVENANCE.model_copy(update={"run_id": OTHER_RUN_ID}) if change == "run" else PROVENANCE
    )
    second = harness.validation.record(next_doc, provenance, harness.bindings())
    assert set(first.assessment_ids).isdisjoint(second.assessment_ids)
    assert set(first.artifact_ids).isdisjoint(second.artifact_ids)
    assert set(first.evidence_artifact_ids).isdisjoint(second.evidence_artifact_ids)
    assert first.findings[0].decision_id != second.findings[0].decision_id
    assert len(harness.decisions.list_for_finding(saved_id(harness.findings[0]))) == 2


@pytest.mark.parametrize("failure", ["first-object", "second-object", "second-ledger-append"])
def test_record_rolls_back_the_whole_aggregate_on_retention_or_ledger_failure(
    harness: ValidationHarness, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    doc = report(
        harness,
        "refuted",
        finding={"steps": [probe()]},
        additional=(
            {
                "source_id": "f002",
                "source_report": SOURCE_REPORT,
                "verdict": "confirmed",
                "technique": "replay",
                "evidence_grade": "E0",
            },
        ),
    )
    before = snapshot(harness.engine)
    calls = 0
    if failure.endswith("object"):
        put = harness.objects.put

        def fail_put(key: ObjectKey, data: bytes) -> ObjectRef:
            nonlocal calls
            calls += 1
            if calls == (1 if failure == "first-object" else 2):
                raise RepositoryError("injected object retention failure")
            return put(key, data)

        monkeypatch.setattr(harness.objects, "put", fail_put)
        error = RepositoryError
    else:
        append = harness.ledger.append_decision

        def fail_append(*args: Any, **kwargs: Any) -> Any:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ServiceError("injected ledger append failure")
            return append(*args, **kwargs)

        monkeypatch.setattr(harness.ledger, "append_decision", fail_append)
        error = ServiceError
    with pytest.raises(error, match="injected"):
        harness.validation.record(doc, PROVENANCE, harness.bindings(0, 1))
    assert calls == (2 if failure != "first-object" else 1)
    assert snapshot(harness.engine) == before
    assert harness.review.for_finding(saved_id(harness.findings[0])) == []
    assert harness.decisions.list_for_finding(saved_id(harness.findings[0])) == []


@pytest.mark.parametrize("replay", [True, False], ids=["exact-replay", "new-report"])
def test_corrupt_ledger_refuses_before_aggregate_or_review_mutation(
    harness: ValidationHarness, replay: bool
) -> None:
    doc = report(harness, "refuted", finding={"steps": [probe()]})
    first = harness.validation.record(doc, PROVENANCE, harness.bindings())
    harness.review.close_unreviewed(first.findings[0].review_item_ids[0])
    with SqlTraustUnitOfWork(harness.engine) as uow:
        layer = uow.layers.list_for_repository(harness.findings[0].repository_id)[0]
        uow.layers.update(layer.model_copy(update={"merkle_root": "00" * 32}))
        uow.commit()
    before = snapshot(harness.engine)
    objects_before = tuple(harness.objects.list())
    if not replay:
        doc = report(harness, finding={"evidence_grade": "E0"})
    with pytest.raises(IntegrityError):
        harness.validation.record(doc, PROVENANCE, harness.bindings())
    assert snapshot(harness.engine) == before
    assert tuple(harness.objects.list()) == objects_before


def test_a_triage_source_can_bind_occurrences_from_its_audit_baseline(
    harness: ValidationHarness,
) -> None:
    with SqlTraustUnitOfWork(harness.engine) as uow:
        seed = Seed(uow)
        ref = uow.repository_refs.get(harness.source.repository_ref_id)
        triaged = seed.assessment(
            ref, kind="triage", baseline_assessment_id=saved_id(harness.source)
        )
        artifact = seed.artifact(
            triaged, kind="triage", digest=harness.artifact.digest, uri=harness.artifact.uri
        )
        uow.commit()
    binding = (
        harness.bindings()
        .sources[0]
        .model_copy(update={"assessment_id": saved_id(triaged), "artifact_id": saved_id(artifact)})
    )
    result = harness.validation.record(
        report(harness, finding={"evidence_grade": "E0"}),
        PROVENANCE,
        ValidationRecordInput(sources=(binding,)),
    )
    assert result.findings[0].decision_id is not None
    with SqlTraustUnitOfWork(harness.engine) as uow:
        assessment = uow.assessments.get(result.assessment_ids[0])
        assert assessment.baseline_assessment_id == triaged.id
        assert uow.occurrences.list_for_assessment(saved_id(triaged)) == []
        assert uow.occurrences.list_for_assessment(assessment.id) == []


@pytest.mark.parametrize(
    ("finding", "changes", "flag"),
    [
        (
            {
                "steps": [
                    probe(
                        controls=[
                            {"name": "same-client control", "kind": "must_succeed", "ok": False}
                        ]
                    )
                ]
            },
            {},
            "failed-positive-control",
        ),
        (
            {
                "steps": [
                    probe(differential={"neighbor_action": "get pods", "discriminated": False})
                ]
            },
            {},
            "non-discriminating-oracle",
        ),
        (
            {"steps": [probe(observed="Error from server (Forbidden): User cannot get pods")]},
            {},
            "error-signature:forbidden",
        ),
        ({"steps": [probe()]}, {"install_failed": True}, "target-not-deployed"),
        (
            {"verdict": "confirmed", "evidence_grade": "E0", "soundness_flag": "producer-void"},
            {},
            "producer-void",
        ),
    ],
)
def test_soundness_failures_are_retained_without_creating_neutral_decisions(
    harness: ValidationHarness, finding: dict[str, Any], changes: dict[str, Any], flag: str
) -> None:
    result = harness.validation.record(
        report(harness, "refuted", finding=finding), PROVENANCE, harness.bindings(**changes)
    )
    (outcome,) = result.findings
    assert (outcome.verdict, outcome.soundness_flag, outcome.decision_id) == (
        "inconclusive",
        flag,
        None,
    )
    assert harness.evidence(result).findings[0].soundness_flag == flag
    assert harness.decisions.list_for_finding(outcome.finding_id) == []
    assert {harness.review.get(i).reason for i in outcome.review_item_ids} == {"unsound_refutation"}


@pytest.mark.parametrize("attested", ["false", "true", 0, 1, None])
def test_malformed_embedded_attestation_refuses_before_any_metadata(
    harness: ValidationHarness, attested: object
) -> None:
    before = snapshot(harness.engine)
    with pytest.raises((ModelValidationError, ValidationError)):
        harness.validation.record(
            report(harness, attestation={"attested": attested}, finding={"evidence_grade": "E0"}),
            PROVENANCE,
            harness.bindings(),
        )
    assert snapshot(harness.engine) == before


def test_failed_embedded_attestation_cannot_be_overridden_by_a_separate_pass(
    harness: ValidationHarness,
) -> None:
    result = harness.validation.record(
        report(harness, attestation={"attested": False}, finding={"evidence_grade": "E0"}),
        PROVENANCE,
        harness.bindings(target_attestation=TargetAttestation(attested=True)),
    )
    (outcome,) = result.findings
    assert outcome.decision_id is None and outcome.soundness_flag == "environment_invalid"


def test_different_source_reports_on_one_baseline_have_separate_recording_contexts(
    harness: ValidationHarness,
) -> None:
    second_path = "findings/example/second-triage.json"
    raw = json.loads(report(harness, finding={"evidence_grade": "E0"}).payload)
    raw["source_reports"].append(
        {"kind": "triage", "path": second_path, "sha256": harness.artifact.digest}
    )
    raw["validated_findings"].append({**raw["validated_findings"][0], "source_report": second_path})
    raw["summary"]["by_verdict"]["confirmed"] = 2
    raw["summary"]["by_technique"]["replay"] = 2
    source = harness.bindings().sources[0]
    bindings = ValidationRecordInput(
        sources=(source, source.model_copy(update={"source_report": second_path}))
    )
    doc = ValidationArtifact.parse(json.dumps(raw).encode())
    result = harness.validation.record(doc, PROVENANCE, bindings)
    assert len(set(result.assessment_ids)) == 2
    assert len(set(result.artifact_ids)) == 2
    assert len(set(result.evidence_artifact_ids)) == 2
    assert len({row.decision_id for row in result.findings}) == 2
    assert {
        harness.validation.evidence(artifact_id).source_report
        for artifact_id in result.evidence_artifact_ids
    } == {SOURCE_REPORT, second_path}
    before = snapshot(harness.engine)
    assert harness.validation.record(doc, PROVENANCE, bindings) == result
    assert snapshot(harness.engine) == before


def test_evidence_reads_verify_kind_digest_and_finding_membership(
    harness: ValidationHarness,
) -> None:
    result = harness.validation.record(
        report(harness, attestation=None), PROVENANCE, harness.bindings()
    )
    (artifact_id,) = result.evidence_artifact_ids
    assert harness.validation.evidence(
        artifact_id, finding_id=saved_id(harness.findings[0])
    ) == harness.evidence(result)
    with pytest.raises(ValidationError):
        harness.validation.evidence(artifact_id, finding_id=saved_id(harness.findings[1]))
    with pytest.raises(ValidationError):
        harness.validation.evidence(saved_id(harness.artifact))
    with SqlTraustUnitOfWork(harness.engine) as uow:
        artifact = uow.artifacts.get(artifact_id)
    harness.objects.put(ObjectKey.parse(artifact.uri), b'{"corrupt":true}')
    with pytest.raises(IntegrityError):
        harness.validation.evidence(artifact_id)


@pytest.mark.parametrize(
    "different_repository", [False, True], ids=["other-ref", "other-repository"]
)
def test_source_baselines_must_use_the_exact_assessed_repository_ref(
    harness: ValidationHarness, different_repository: bool
) -> None:
    with SqlTraustUnitOfWork(harness.engine) as uow:
        seed = Seed(uow)
        current = uow.repository_refs.get(harness.source.repository_ref_id)
        repository = (
            seed.repository(url="https://github.com/org/other-baseline")
            if different_repository
            else uow.repositories.get(current.repository_id)
        )
        other_ref = seed.repository_ref(repository, name="other", sha="b" * 40)
        source = seed.assessment(
            other_ref, kind="triage", baseline_assessment_id=saved_id(harness.source)
        )
        artifact = seed.artifact(
            source, kind="triage", digest=harness.artifact.digest, uri=harness.artifact.uri
        )
        uow.commit()
    source_binding = (
        harness.bindings()
        .sources[0]
        .model_copy(update={"assessment_id": saved_id(source), "artifact_id": saved_id(artifact)})
    )
    before = snapshot(harness.engine)
    with pytest.raises(ValidationError):
        harness.validation.record(
            report(harness, finding={"evidence_grade": "E0"}),
            PROVENANCE,
            ValidationRecordInput(sources=(source_binding,)),
        )
    assert snapshot(harness.engine) == before


def test_a_later_invalid_source_cannot_leave_the_first_source_partially_recorded(
    harness: ValidationHarness,
) -> None:
    second_path = "findings/example/unknown-triage.json"
    raw = json.loads(report(harness, finding={"evidence_grade": "E0"}).payload)
    raw["source_reports"].append({"kind": "triage", "path": second_path})
    raw["validated_findings"].append({**raw["validated_findings"][0], "source_report": second_path})
    raw["summary"]["by_verdict"]["confirmed"] = 2
    raw["summary"]["by_technique"]["replay"] = 2
    source = harness.bindings().sources[0]
    invalid = source.model_copy(update={"source_report": second_path, "artifact_id": UNKNOWN_ID})
    before = snapshot(harness.engine)
    before_objects = tuple(harness.objects.list())
    with pytest.raises(NotFoundError):
        harness.validation.record(
            ValidationArtifact.parse(json.dumps(raw).encode()),
            PROVENANCE,
            ValidationRecordInput(sources=(source, invalid)),
        )
    assert snapshot(harness.engine) == before
    assert tuple(harness.objects.list()) == before_objects


def test_recording_evidence_preserves_fractional_time_at_the_storage_boundary(
    harness: ValidationHarness,
) -> None:
    precise = PROVENANCE.model_copy(update={"occurred_at": NOW.replace(microsecond=123456)})
    result = harness.validation.record(
        report(harness, attestation=None, finding={"evidence_grade": "E0"}),
        precise,
        harness.bindings(),
    )
    retained = harness.validation.evidence(
        result.evidence_artifact_ids[0], finding_id=saved_id(harness.findings[0])
    )
    assert retained.provenance == precise
    assert retained.findings[0].soundness_flag == "attestation_missing"
    before = snapshot(harness.engine)
    assert (
        harness.validation.record(
            report(harness, attestation=None, finding={"evidence_grade": "E0"}),
            precise,
            harness.bindings(),
        )
        == result
    )
    assert snapshot(harness.engine) == before
