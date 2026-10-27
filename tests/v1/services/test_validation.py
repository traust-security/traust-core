from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
import sqlalchemy as sa
from pydantic import ValidationError as ModelValidationError
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed, saved_id
from traust_core.v1.context.config import Config, DatabaseConfig
from traust_core.v1.context.context import Context
from traust_core.v1.errors import (
    ForbiddenError,
    IntegrityError,
    NotFoundError,
    RepositoryError,
    ServiceError,
    ValidationError,
)
from traust_core.v1.models.artifacts import (
    TriageArtifact,
    ValidationArtifact,
    ValidationPlanArtifact,
)
from traust_core.v1.models.assessment import Artifact, Assessment
from traust_core.v1.models.common import ArtifactRef, PageRequest, Provenance, every_item
from traust_core.v1.models.findings import Finding, FindingExternalRef, ReviewFilter
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.validation import (
    ClusterScope,
    TargetAttestation,
    TargetObservation,
    ValidationDimension,
    ValidationFilter,
    ValidationFindingBinding,
    ValidationRecordingEvidence,
    ValidationRecordingPolicy,
    ValidationRecordInput,
    ValidationRecordResult,
    ValidationScope,
    ValidationSourceBinding,
)
from traust_core.v1.models.vocabulary import (
    ActorKind,
    SourceType,
    ValidationApprovalMode,
    ValidationVerdict,
)
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.rendering import MarkdownRenderer
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
    validation = ValidationService(shared, decisions)
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
    (case,) = harness.review.cases(ReviewFilter(), PageRequest()).items
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
    (case,) = harness.review.cases(ReviewFilter(), PageRequest()).items
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
    (case,) = harness.review.cases(ReviewFilter(), PageRequest()).items
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


def _attestation_plan(
    harness: ValidationHarness, tmp_path: Path
) -> tuple[ValidationService, ArtifactRef]:
    context = Context(
        Config(
            home=tmp_path / "attestation",
            database=DatabaseConfig(url=harness.engine.url.render_as_string(hide_password=False)),
        ),
        object_store=harness.objects,
    )
    validation = context.services().validation
    plan = validation.plan(
        ValidationPlanArtifact.from_document(
            {"target": "example", "scope_binding_mode": "explicit", "chains": [], "steps": []}
        )
    )
    return validation, plan


def test_attest_target_binds_measured_checks_to_the_published_plan(
    harness: ValidationHarness, tmp_path: Path
) -> None:
    validation, plan = _attestation_plan(harness, tmp_path)
    observation = TargetObservation.model_validate(
        {
            "target": "example",
            "observed_at": NOW,
            "harness_version": "0.34.3",
            "fingerprint": {"adapter": "k8s", "identity": "example-lab"},
            "checks": [
                {"name": "cluster-reachable", "ok": True, "required": True, "detail": "reachable"},
                {"name": "version-in-affected-range", "ok": False, "required": False},
            ],
        }
    )
    result = validation.attest_target(plan.id, observation)
    assert result.attested is True
    assert (result.plan_id, result.plan_digest) == (plan.id, plan.digest)
    assert result.model_dump()["checks"] == [check.model_dump() for check in observation.checks]
    assert result.model_dump()["fingerprint"] == observation.fingerprint.model_dump(
        exclude_none=True
    )
    assert result.model_dump()["generated_at"] == NOW.isoformat()
    assert result.model_dump()["harness_version"] == "0.34.3"
    with pytest.raises(NotFoundError):
        validation.attest_target(UNKNOWN_ID, observation)


@pytest.mark.parametrize("fault", ["wrong-target", "no-checks", "no-required", "duplicate-checks"])
def test_attest_target_refuses_unbound_or_ambiguous_observations(
    harness: ValidationHarness, tmp_path: Path, fault: str
) -> None:
    validation, plan = _attestation_plan(harness, tmp_path)
    check = {"name": "cluster-reachable", "ok": True, "required": fault != "no-required"}
    observation = TargetObservation.model_validate(
        {
            "target": "wrong" if fault == "wrong-target" else "example",
            "observed_at": NOW,
            "harness_version": "0.34.3",
            "fingerprint": {"adapter": "k8s", "identity": "example-lab"},
            "checks": []
            if fault == "no-checks"
            else [check, check]
            if fault == "duplicate-checks"
            else [check],
        }
    )
    with pytest.raises(ValidationError):
        validation.attest_target(plan.id, observation)


def test_attest_target_failed_required_check_cannot_be_overridden_by_optional_success(
    harness: ValidationHarness, tmp_path: Path
) -> None:
    validation, plan = _attestation_plan(harness, tmp_path)
    observation = TargetObservation.model_validate(
        {
            "target": "example",
            "observed_at": NOW,
            "harness_version": "0.34.3",
            "fingerprint": {"adapter": "k8s", "identity": "example-lab"},
            "checks": [
                {"name": "cluster-reachable", "ok": False, "required": True},
                {"name": "version-in-affected-range", "ok": True, "required": False},
            ],
        }
    )
    attestation = validation.attest_target(plan.id, observation)
    assert attestation.attested is False
    result = harness.validation.record(
        report(harness, attestation=None, finding={"evidence_grade": "E0"}),
        PROVENANCE,
        harness.bindings(target_attestation=attestation),
    )
    assert result.findings[0].soundness_flag == "environment_invalid"
    assert result.findings[0].decision_id is None


def _reviewer() -> Principal:
    return Principal(
        identity="reviewer@example.com",
        kind=ActorKind.HUMAN,
        display="Reviewer",
        verified_by=IdentitySource.LOCAL_USER,
    )


def _explicit_scope(environment: str = "lab", *, expires: date | None = None) -> ValidationScope:
    return ValidationScope.bind(
        explicit=ValidationScope(
            engagement="authorized-lab",
            authorized_by="Example Security Team",
            environment=environment,
            expires=expires,
            clusters=(ClusterScope(context="example-lab", namespaces=("example-*",)),),
        )
    )


def test_authorize_records_a_verified_review_of_the_exact_plan_and_scope(
    harness: ValidationHarness, tmp_path: Path
) -> None:
    validation, plan = _attestation_plan(harness, tmp_path)
    scope = _explicit_scope()
    authorized = validation.authorize(
        plan.id,
        scope,
        _reviewer(),
        confirmed=True,
        mode=ValidationApprovalMode.INTERACTIVE,
    )
    doc = validation.get_authorization(authorized.id)
    assert (doc.plan_id, doc.plan_digest) == (str(plan.id), plan.digest)
    assert doc.approved_by == "human:reviewer@example.com"
    assert doc.mode == "interactive"
    assert doc.scope.environment == "lab"
    assert doc.scope.clusters[0].explicit_namespaces == ("example-*",)
    assert doc.scope.modes == ("explicit",)
    assert doc.skip_step_ids == ()
    assert not doc.permit_destructive
    assert datetime.fromisoformat(doc.approved_at).tzinfo is not None
    with SqlTraustUnitOfWork(harness.engine) as uow:
        assert uow.artifacts.get(authorized.id).digest == authorized.digest
    with pytest.raises(IntegrityError):
        validation.get_authorization(plan.id)
    with SqlTraustUnitOfWork(harness.engine) as uow:
        stored = uow.artifacts.get(authorized.id)
    harness.objects.put(ObjectKey.parse(stored.uri), b'{"corrupted": true}')
    with pytest.raises(IntegrityError):
        validation.get_authorization(authorized.id)


@pytest.mark.parametrize(
    "fault",
    [
        "no-consent",
        "unverified",
        "missing-scope",
        "mismatched-scope",
        "expired",
        "unknown-skip",
        "dry-run",
        "auto-production",
        "auto-inline",
    ],
)
def test_authorize_refuses_unsafe_review_before_writing_artifacts(
    harness: ValidationHarness, tmp_path: Path, fault: str
) -> None:
    validation, plan = _attestation_plan(harness, tmp_path)
    scope = _explicit_scope(
        "production" if fault == "auto-production" else "lab",
        expires=date(2020, 1, 1) if fault == "expired" else None,
    )
    if fault == "missing-scope":
        scope = ValidationScope()
    elif fault in {"mismatched-scope", "auto-inline"}:
        scope = ValidationScope.bind(inline=ValidationScope(clusters=scope.clusters))
    principal = _reviewer()
    if fault == "unverified":
        principal = principal.model_copy(update={"verified_by": None})
    before = snapshot(harness.engine)
    objects_before = tuple(harness.objects.list())
    with pytest.raises((ForbiddenError, ValidationError)):
        validation.authorize(
            plan.id,
            scope,
            principal,
            confirmed=fault != "no-consent",
            mode=ValidationApprovalMode.AUTO
            if fault.startswith("auto-")
            else ValidationApprovalMode.DRY_RUN
            if fault == "dry-run"
            else ValidationApprovalMode.INTERACTIVE,
            skip_step_ids=("missing",) if fault == "unknown-skip" else (),
        )
    assert snapshot(harness.engine) == before
    assert tuple(harness.objects.list()) == objects_before


def test_authorize_records_approval_for_executable_steps_core_never_runs(
    harness: ValidationHarness, tmp_path: Path
) -> None:
    validation, _ = _attestation_plan(harness, tmp_path)
    plan = validation.plan(
        ValidationPlanArtifact.from_document(
            {
                "target": "example",
                "scope_binding_mode": "explicit",
                "chains": [],
                "steps": [
                    {
                        "id": "step-001",
                        "technique": "replay",
                        "adapter": "k8s",
                        "verb": "get",
                        "target": {"context": "example-lab", "namespace": "example-a"},
                        "classification": "safe",
                    }
                ],
            }
        )
    )
    authorized = validation.authorize(
        plan.id,
        _explicit_scope(),
        _reviewer(),
        confirmed=True,
        mode=ValidationApprovalMode.INTERACTIVE,
    )
    assert validation.get_authorization(authorized.id).skip_step_ids == ()
    skipped = validation.authorize(
        plan.id,
        _explicit_scope(),
        _reviewer(),
        confirmed=True,
        mode=ValidationApprovalMode.INTERACTIVE,
        skip_step_ids=("step-001",),
    )
    assert validation.get_authorization(skipped.id).skip_step_ids == ("step-001",)


def test_authorize_allows_a_verified_machine_only_in_an_explicit_lab(
    harness: ValidationHarness, tmp_path: Path
) -> None:
    validation, plan = _attestation_plan(harness, tmp_path)
    machine = Principal(
        identity="example-runner",
        kind=ActorKind.MACHINE,
        display="Runner",
        verified_by=IdentitySource.DATABASE,
    )
    authorized = validation.authorize(
        plan.id, _explicit_scope(), machine, confirmed=True, mode=ValidationApprovalMode.AUTO
    )
    assert validation.get_authorization(authorized.id).approved_by == "machine:example-runner"


def test_prepare_reads_selected_finding_and_its_source_artifacts(
    harness: ValidationHarness, tmp_path: Path
) -> None:
    context = Context(
        Config(
            home=tmp_path / "prepare",
            database=DatabaseConfig(url=harness.engine.url.render_as_string(hide_password=False)),
        ),
        object_store=harness.objects,
    )
    prepared = context.services().validation.prepare(saved_id(harness.findings[0]))
    assert prepared.subject.repository_id == harness.findings[0].repository_id
    assert prepared.subject.assessment_id == harness.source.id
    assert tuple(view.finding.id for view in prepared.selected) == (harness.findings[0].id,)
    assert harness.artifact.id in {artifact.id for artifact in prepared.source_artifacts}
    assert prepared.prepared_at.tzinfo is not None


def test_prepare_refuses_a_finding_without_a_source_assessment(
    harness: ValidationHarness, tmp_path: Path
) -> None:
    with SqlTraustUnitOfWork(harness.engine) as uow:
        orphan = Seed(uow).finding(
            uow.repositories.get(harness.findings[0].repository_id), fingerprint="f" * 64
        )
        uow.commit()
    context = Context(
        Config(
            home=tmp_path / "prepare",
            database=DatabaseConfig(url=harness.engine.url.render_as_string(hide_password=False)),
        ),
        object_store=harness.objects,
    )
    with pytest.raises(ValidationError, match="no source assessment"):
        context.services().validation.prepare(saved_id(orphan))
    with pytest.raises(NotFoundError):
        context.services().validation.prepare(UNKNOWN_ID)


def test_prepare_many_partitions_sources_without_selecting_a_default_repository(
    harness: ValidationHarness, tmp_path: Path
) -> None:
    with SqlTraustUnitOfWork(harness.engine) as uow:
        seed = Seed(uow)
        repository = seed.repository(url="https://github.com/org/other")
        source = seed.assessment(seed.repository_ref(repository))
        other = seed.finding(repository, fingerprint="a" * 64)
        seed.occurrence(other, source, severity="medium")
        uow.commit()
    context = Context(
        Config(
            home=tmp_path / "prepare",
            database=DatabaseConfig(url=harness.engine.url.render_as_string(hide_password=False)),
        ),
        object_store=harness.objects,
    )
    validation = context.services().validation
    ids = tuple(saved_id(finding) for finding in (*harness.findings, other))
    inputs = validation.prepare_many(ids)
    assert tuple(view.finding.id for view in inputs[0].selected) == ids[:2]
    assert inputs[0].subject.assessment_id == harness.source.id
    assert tuple(view.finding.id for view in inputs[1].selected) == ids[2:]
    assert inputs[1].subject.assessment_id == source.id
    assert inputs[0].subject.repository_id != inputs[1].subject.repository_id
    with pytest.raises(ValidationError, match="distinct finding IDs"):
        validation.prepare_many((ids[0], ids[0]))
    with pytest.raises(ValidationError, match="distinct finding IDs"):
        validation.prepare_many(())


def test_plan_publishes_exact_contract_document_without_authorizing_execution(
    harness: ValidationHarness, tmp_path: Path
) -> None:
    context = Context(
        Config(
            home=tmp_path / "plan",
            database=DatabaseConfig(url=harness.engine.url.render_as_string(hide_password=False)),
        ),
        object_store=harness.objects,
    )
    validation = context.services().validation
    doc = ValidationPlanArtifact.from_document(
        {"target": "example", "scope_binding_mode": "explicit", "chains": [], "steps": []}
    )
    published = validation.plan(doc)
    assert published.name == "validation-plan"
    assert validation.get_plan(published.id).payload == doc.payload
    with SqlTraustUnitOfWork(harness.engine) as uow:
        row = uow.artifacts.get(published.id)
    assert row.assessment_id is None
    assert row.digest == published.digest


@pytest.mark.parametrize("conflict", ["step", "chain-ref"])
def test_plan_rejects_ambiguous_step_and_chain_references_before_publishing(
    harness: ValidationHarness, tmp_path: Path, conflict: str
) -> None:
    context = Context(
        Config(
            home=tmp_path / "plan",
            database=DatabaseConfig(url=harness.engine.url.render_as_string(hide_password=False)),
        ),
        object_store=harness.objects,
    )
    step = {
        "id": "s1",
        "technique": "replay",
        "adapter": "k8s",
        "verb": "get",
        "target": {"namespace": "example", "resource": "pods"},
        "classification": "safe",
    }
    steps = [step, dict(step)] if conflict == "step" else [dict(step, chain_ref="missing")]
    doc = ValidationPlanArtifact.from_document(
        {"target": "example", "scope_binding_mode": "explicit", "chains": [], "steps": steps}
    )
    before = snapshot(harness.engine)
    with pytest.raises(ValidationError, match=r"duplicate step|unknown chains"):
        context.services().validation.plan(doc)
    assert snapshot(harness.engine) == before


@pytest.mark.parametrize(
    "dependencies",
    [
        (("s1", ("missing",)),),
        (("s1", ("s1",)),),
        (("s1", ("s2",)), ("s2", ())),
    ],
    ids=["unknown", "self-reference", "forward-reference"],
)
def test_plan_refuses_unresolvable_step_dependencies_without_publishing(
    harness: ValidationHarness,
    tmp_path: Path,
    dependencies: tuple[tuple[str, tuple[str, ...]], ...],
) -> None:
    context = Context(
        Config(
            home=tmp_path / "plan",
            database=DatabaseConfig(url=harness.engine.url.render_as_string(hide_password=False)),
        ),
        object_store=harness.objects,
    )
    step = {
        "id": "s1",
        "technique": "replay",
        "adapter": "k8s",
        "verb": "get",
        "target": {"namespace": "example", "resource": "pods"},
        "classification": "safe",
    }
    steps = [
        {**step, "id": step_id, "preconditions": list(preconditions)}
        for step_id, preconditions in dependencies
    ]
    doc = ValidationPlanArtifact.from_document(
        {"target": "example", "scope_binding_mode": "explicit", "chains": [], "steps": steps}
    )
    before = snapshot(harness.engine)
    objects_before = tuple(harness.objects.list())
    with pytest.raises(ValidationError, match="precondition"):
        context.services().validation.plan(doc)
    assert snapshot(harness.engine) == before
    assert tuple(harness.objects.list()) == objects_before


def test_plan_retains_ordered_step_dependencies(harness: ValidationHarness, tmp_path: Path) -> None:
    context = Context(
        Config(
            home=tmp_path / "plan",
            database=DatabaseConfig(url=harness.engine.url.render_as_string(hide_password=False)),
        ),
        object_store=harness.objects,
    )
    step = {
        "id": "s1",
        "technique": "replay",
        "adapter": "k8s",
        "verb": "get",
        "target": {"namespace": "example", "resource": "pods"},
        "classification": "safe",
    }
    doc = ValidationPlanArtifact.from_document(
        {
            "target": "example",
            "scope_binding_mode": "explicit",
            "chains": [],
            "steps": [step, {**step, "id": "s2", "preconditions": ["s1"]}],
        }
    )
    validation = context.services().validation
    ref = validation.plan(doc)
    assert validation.get_plan(ref.id).steps[1].preconditions == ("s1",)


@pytest.mark.parametrize("attested", [False, True], ids=["voided", "attested"])
def test_context_review_evidence_retains_primary_and_recording_companions(
    harness: ValidationHarness, tmp_path: Path, attested: bool
) -> None:
    doc = report(harness, "confirmed", attestation=ATTESTATION if attested else None)
    result = harness.validation.record(doc, PROVENANCE, harness.bindings())
    context = Context(
        Config(
            home=tmp_path / "review",
            database=DatabaseConfig(url=harness.engine.url.render_as_string(hide_password=False)),
        ),
        object_store=harness.objects,
    )
    services = context.services()
    finding_id = saved_id(harness.findings[0])
    harness.review.request_signoff(finding_id, "analyst_review")
    cases = services.findings.review.cases(ReviewFilter(finding_id=finding_id), PageRequest()).items
    expected = {saved_id(harness.artifact), *result.artifact_ids, *result.evidence_artifact_ids}
    assert cases
    assert all(set(case.evidence_artifact_ids) == expected for case in cases)
    assert all(case.evidence_artifact_ids == tuple(sorted(expected, key=str)) for case in cases)
    reader = services.findings.artifacts
    (primary_id,) = result.artifact_ids
    (companion_id,) = result.evidence_artifact_ids
    primary = reader.get(primary_id)
    assert isinstance(primary, ValidationArtifact)
    assert primary.payload == reader.payload(primary_id) == doc.payload
    assert ValidationRecordingEvidence.model_validate_json(reader.payload(companion_id)) == (
        harness.evidence(result)
    )
    metadata = reader.metadata(companion_id)
    assert metadata.kind == "validation-recording"
    assert metadata.assessment_id == result.assessment_ids[0]
    assert {artifact.id for artifact in reader.list_for_assessment(metadata.assessment_id)} == {
        primary_id,
        companion_id,
    }
    if not attested:
        assert all(case.history == () for case in cases)
        assert all(case.finding.occurrence.assessment_id == harness.source.id for case in cases)


@pytest.mark.parametrize("companion", [False, True], ids=["primary", "recording-companion"])
def test_context_review_artifact_reader_refuses_corrupted_recorded_bytes(
    harness: ValidationHarness, tmp_path: Path, companion: bool
) -> None:
    doc = report(harness, "confirmed", attestation=None)
    result = harness.validation.record(doc, PROVENANCE, harness.bindings())
    context = Context(
        Config(
            home=tmp_path / "review",
            database=DatabaseConfig(url=harness.engine.url.render_as_string(hide_password=False)),
        ),
        object_store=harness.objects,
    )
    services = context.services()
    reader = services.findings.artifacts
    artifact_id = (result.evidence_artifact_ids if companion else result.artifact_ids)[0]
    assert reader.payload(artifact_id)
    metadata = reader.metadata(artifact_id)
    harness.objects.put(ObjectKey.parse(metadata.uri), b'{"corrupted": true}\n')
    with pytest.raises(IntegrityError):
        reader.payload(artifact_id)
    if companion:
        with pytest.raises(IntegrityError):
            services.findings.review.cases(ReviewFilter(), PageRequest())
    else:
        with pytest.raises(IntegrityError):
            reader.get(artifact_id)


def test_review_evidence_refuses_a_validation_link_for_an_unbound_finding(
    harness: ValidationHarness,
) -> None:
    doc = report(harness, "confirmed", attestation=None)
    result = harness.validation.record(doc, PROVENANCE, harness.bindings(0))
    other = saved_id(harness.findings[1])
    with SqlTraustUnitOfWork(harness.engine) as uow:
        uow.finding_external_refs.add(
            FindingExternalRef(
                finding_id=other,
                system="traust.validation",
                ref=f"traust:artifact:{result.evidence_artifact_ids[0]}#finding={other}",
            )
        )
        uow.commit()
    harness.review.request_signoff(other, "analyst_review")
    with pytest.raises(ValidationError, match="different finding"):
        harness.review.cases(ReviewFilter(finding_id=other), PageRequest())


LATER = datetime(2026, 10, 22, 13, tzinfo=UTC)


def two_runs(harness: ValidationHarness) -> tuple[ValidationRecordResult, ValidationRecordResult]:
    """A confirmation of f001, then a later run: f001 inconclusive, f002 soundly refuted."""
    first = harness.validation.record(
        report(harness, finding={"evidence_grade": "E0"}), PROVENANCE, harness.bindings()
    )
    refuted = {
        "source_id": "f002",
        "source_report": SOURCE_REPORT,
        "verdict": "refuted",
        "technique": "replay",
        "steps": [probe()],
    }
    later = PROVENANCE.model_copy(update={"run_id": OTHER_RUN_ID, "occurred_at": LATER})
    second = harness.validation.record(
        report(harness, "inconclusive", additional=(refuted,)), later, harness.bindings(0, 1)
    )
    return first, second


def test_attempts_read_each_recorded_run_of_a_finding_newest_first(
    harness: ValidationHarness,
) -> None:
    f1, f2 = (saved_id(f) for f in harness.findings)
    assert harness.validation.attempts(f1) == []
    first, second = two_runs(harness)
    latest, earliest = harness.validation.attempts(f1)
    assert (latest.verdict, latest.occurred_at, latest.run_id, latest.decision_id) == (
        "inconclusive",
        LATER,
        OTHER_RUN_ID,
        None,
    )
    assert (latest.assessment_id, latest.artifact_id, latest.evidence_artifact_id) == (
        second.assessment_ids[0],
        second.artifact_ids[0],
        second.evidence_artifact_ids[0],
    )
    assert latest.review_reasons == ("needs_manual_test",)
    assert latest.repository_id == harness.findings[0].repository_id
    assert (earliest.verdict, earliest.evidence_grade) == ("confirmed", "E0")
    assert earliest.run_id == RUN_ID
    assert earliest.decision_id == first.findings[0].decision_id is not None
    assert (earliest.source_report, earliest.source_id) == (SOURCE_REPORT, "f001")
    (refuted,) = harness.validation.attempts(f2)
    assert (refuted.verdict, refuted.soundness_flag) == ("refuted", None)
    assert refuted.decision_id == second.findings[1].decision_id is not None
    assert refuted.attempt_id != latest.attempt_id


def test_attempts_are_not_duplicated_by_a_replay_and_refuse_an_unknown_finding(
    harness: ValidationHarness,
) -> None:
    doc = report(harness, finding={"evidence_grade": "E0"})
    harness.validation.record(doc, PROVENANCE, harness.bindings())
    harness.validation.record(doc, PROVENANCE, harness.bindings())
    assert len(harness.validation.attempts(saved_id(harness.findings[0]))) == 1
    with pytest.raises(NotFoundError):
        harness.validation.attempts(UNKNOWN_ID)


def test_attempts_refuse_a_malformed_validation_reference(harness: ValidationHarness) -> None:
    finding_id = saved_id(harness.findings[0])
    with SqlTraustUnitOfWork(harness.engine) as uow:
        uow.finding_external_refs.add(
            FindingExternalRef(
                finding_id=finding_id, system="traust.validation", ref="traust:artifact:nope"
            )
        )
        uow.commit()
    with pytest.raises(IntegrityError, match="malformed"):
        harness.validation.attempts(finding_id)


def test_list_pages_every_attempt_by_a_stable_cursor_and_filters(
    harness: ValidationHarness,
) -> None:
    two_runs(harness)
    every = list(harness.validation.list(ValidationFilter(), PageRequest()).items)
    assert [a.occurred_at for a in every] == [LATER, LATER, NOW]
    assert every[0].attempt_id > every[1].attempt_id
    assert {a.verdict for a in every[:2]} == {"inconclusive", "refuted"}
    paged = list(every_item(lambda p: harness.validation.list(ValidationFilter(), p), limit=1))
    assert paged == every
    refuted = next(a for a in every if a.verdict == "refuted")
    repository = harness.findings[0].repository_id
    for filter, expected in [
        (ValidationFilter(verdict="refuted"), [refuted]),
        (ValidationFilter(as_of=NOW), every[2:]),
        (ValidationFilter(repository_ids=frozenset()), []),
        (ValidationFilter(repository_ids=frozenset({repository})), every),
        (ValidationFilter(finding_id=saved_id(harness.findings[1])), [refuted]),
    ]:
        assert list(harness.validation.list(filter, PageRequest()).items) == expected
    with pytest.raises(ValidationError, match="positive"):
        harness.validation.list(ValidationFilter(), PageRequest(limit=0))


def test_summary_counts_each_finding_once_by_its_latest_verdict(
    harness: ValidationHarness,
) -> None:
    assert harness.validation.summary(ValidationFilter(), ValidationDimension.VERDICT) == []
    two_runs(harness)
    by_verdict = harness.validation.summary(ValidationFilter(), ValidationDimension.VERDICT)
    assert [(r.key, r.findings) for r in by_verdict] == [("inconclusive", 1), ("refuted", 1)]
    (repository,) = harness.validation.summary(ValidationFilter(), ValidationDimension.REPOSITORY)
    assert repository.key == str(harness.findings[0].repository_id)
    assert (repository.findings, dict(repository.by_verdict)) == (
        2,
        {"inconclusive": 1, "refuted": 1},
    )
    (then,) = harness.validation.summary(
        ValidationFilter(as_of=NOW), ValidationDimension.EVIDENCE_GRADE
    )
    assert (then.key, dict(then.by_verdict)) == ("E0", {"confirmed": 1})
    assert (
        harness.validation.summary(
            ValidationFilter(verdict="confirmed"), ValidationDimension.VERDICT
        )
        == []
    )
    (ungraded,) = harness.validation.summary(
        ValidationFilter(verdict="refuted"), ValidationDimension.EVIDENCE_GRADE
    )
    assert (ungraded.key, ungraded.findings) == (None, 1)


def test_the_validation_fuzz_view_ranks_repositories_by_latest_confirmed_verdicts(
    harness: ValidationHarness, tmp_path: Path
) -> None:
    context = Context(
        Config(
            home=tmp_path / "view",
            database=DatabaseConfig(url=harness.engine.url.render_as_string(hide_password=False)),
        ),
        object_store=harness.objects,
    )
    insight = context.services().insight
    empty = MarkdownRenderer().render(insight.report(ViewName.VALIDATION_FUZZ, ViewFilter()))
    assert b"0 findings validated live, by latest verdict: none." in empty
    assert b"_No validations recorded._" in empty
    two_runs(harness)
    with SqlTraustUnitOfWork(harness.engine) as uow:
        url = uow.repositories.get(harness.findings[0].repository_id).url
    (row,) = insight.build(ViewName.VALIDATION_FUZZ, ViewFilter()).validation
    assert (row.key, row.findings, dict(row.by_verdict)) == (
        url,
        2,
        {"inconclusive": 1, "refuted": 1},
    )
    (then,) = insight.build(ViewName.VALIDATION_FUZZ, ViewFilter(as_of=NOW)).validation
    assert dict(then.by_verdict) == {"confirmed": 1}
    md = MarkdownRenderer().render(insight.report(ViewName.VALIDATION_FUZZ, ViewFilter())).decode()
    assert "2 findings validated live, by latest verdict: 1 inconclusive, 1 refuted." in md
    assert f"| {url} | 2 | 0 | 1 | 1 | 0 | 0 |" in md
