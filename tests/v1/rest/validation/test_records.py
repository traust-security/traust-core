from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed, saved_id
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.services.test_validation import (
    ATTESTATION,
    PROVENANCE,
    SOURCE_REPORT,
    UNKNOWN_ID,
    ValidationHarness,
    probe,
    report,
    snapshot,
)
from traust_core.v1.context import Context
from traust_core.v1.models.artifacts import ValidationArtifact
from traust_core.v1.models.common import ArtifactRef, Provenance
from traust_core.v1.models.validation import (
    TargetAttestation,
    ValidationRecordingPolicy,
    ValidationRecordInput,
    ValidationRecordResult,
)
from traust_core.v1.repositories import ObjectKey
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.rest.validation.records import RecordValidation
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs, stored_bytes

URL = "/v1/validation-records"


def body(
    doc: ValidationArtifact,
    bindings: ValidationRecordInput,
    provenance: Provenance = PROVENANCE,
) -> dict[str, object]:
    return RecordValidation(
        payload=doc.payload.decode("utf-8"), provenance=provenance, bindings=bindings
    ).model_dump(mode="json")


def test_first_record_and_retries_preserve_native_ids_and_exact_utf8_evidence(
    context: Context, client: TestClient, harness: ValidationHarness
) -> None:
    raw = json.loads(report(harness, finding={"evidence_grade": "E0"}).payload)
    raw["title"] = "Validation café — exact evidence"
    doc = ValidationArtifact.parse(
        ("\n" + json.dumps(raw, indent=3, ensure_ascii=False) + "\n").encode()
    )
    bindings = harness.bindings()
    published = context.artifact_publisher(
        PublishSpecs(PublishSpec(ValidationArtifact))
    ).publish_ref(doc)
    provenance = PROVENANCE.model_copy(update={"artifact": published})
    before = snapshot(context.database)
    response = client.post(URL, json=body(doc, bindings, provenance), headers=bearer(context))
    assert response.status_code == 200, response.text
    result = ValidationRecordResult.model_validate(response.json())
    expected = context.services().validation.record(doc, provenance, bindings)
    same_as_in_process(response.json(), expected)
    (outcome,) = result.findings
    assert outcome.finding_id == harness.findings[0].id
    assert outcome.source_report == SOURCE_REPORT and outcome.source_id == "f001"
    assert outcome.verdict == "confirmed" and outcome.review_item_ids == ()
    assert outcome.assessment_id in result.assessment_ids
    assert outcome.artifact_id in result.artifact_ids
    assert outcome.decision_id is not None
    with SqlTraustUnitOfWork(context.database) as uow:
        assessment = uow.assessments.get(outcome.assessment_id)
        artifact = uow.artifacts.get(outcome.artifact_id)
        decision = uow.decisions.get(outcome.decision_id)
        assert stored_bytes(context.object_store, artifact) == doc.payload
        assert uow.events.find_by_decision(decision.id) is not None
    assert assessment.kind == "validation" and assessment.status == "completed"
    assert assessment.baseline_assessment_id == harness.source.id
    assert assessment.repository_ref_id == harness.source.repository_ref_id
    assert assessment.occurred_at == PROVENANCE.occurred_at
    assert artifact.assessment_id == assessment.id and artifact.kind == "validation"
    assert (decision.validity, decision.evidence_grade, decision.severity) == (
        "confirmed",
        "E0",
        None,
    )
    assert decision.actor is None and decision.auto_accept_tier is False
    evidence = context.services().validation.evidence(result.evidence_artifact_ids[0])
    assert evidence.provenance == provenance and evidence.bindings == bindings
    assert evidence.report_digest == artifact.digest
    assert evidence.findings[0].finding_id == outcome.finding_id
    after = snapshot(context.database)
    for table in ("findings", "occurrences", "locations"):
        assert after[table] == before[table]
    retry = client.post(URL, json=body(doc, bindings, provenance), headers=bearer(context))
    assert retry.status_code == 200 and retry.json() == response.json()
    assert snapshot(context.database) == after


@pytest.mark.parametrize(
    ("case", "verdict", "flag", "reason"),
    [
        ("weak-grade", "confirmed", None, "weak_confirmation"),
        ("ungraded", "confirmed", None, "ungraded_confirmation"),
        ("missing-target", "inconclusive", "attestation_missing", "unsound_refutation"),
        ("failed-target", "inconclusive", "environment_invalid", "unsound_refutation"),
        ("missing-control", "inconclusive", "missing-positive-control", "unsound_refutation"),
        ("failed-control", "inconclusive", "failed-positive-control", "unsound_refutation"),
        (
            "missing-differential",
            "inconclusive",
            "missing-differential-probe",
            "unsound_refutation",
        ),
        (
            "non-discriminating",
            "inconclusive",
            "non-discriminating-oracle",
            "unsound_refutation",
        ),
        ("error-output", "inconclusive", "error-signature:forbidden", "unsound_refutation"),
        ("install-failed", "inconclusive", "target-not-deployed", "unsound_refutation"),
        ("install-failure", "inconclusive", "target-not-deployed", "unsound_refutation"),
    ],
)
def test_review_only_outcomes_use_core_soundness_grade_and_target_rules(
    context: Context,
    client: TestClient,
    harness: ValidationHarness,
    case: str,
    verdict: str,
    flag: str | None,
    reason: str,
) -> None:
    finding = {"evidence_grade": "E3" if case == "weak-grade" else None}
    attestation = ATTESTATION
    bindings = harness.bindings()
    reported_verdict = "confirmed"
    if case == "missing-target":
        attestation = None
    elif case == "failed-target":
        attestation = {**ATTESTATION, "attested": False}
    elif case in {"missing-control", "failed-control", "error-output"}:
        reported_verdict = "refuted"
        finding["steps"] = [
            probe(controls=[])
            if case == "missing-control"
            else probe(controls=[{"name": "control", "kind": "must_succeed", "ok": False}])
            if case == "failed-control"
            else probe(observed="Error from server (Forbidden): User cannot get pods")
        ]
    elif case in {"missing-differential", "non-discriminating"}:
        reported_verdict = "refuted"
        step = probe()
        if case == "missing-differential":
            step.pop("differential")
        else:
            step["differential"]["discriminated"] = False
        finding["steps"] = [step]
    elif case in {"install-failed", "install-failure"}:
        reported_verdict = "refuted"
        finding["steps"] = [probe()]
        bindings = harness.bindings(
            **(
                {"install_failed": True}
                if case == "install-failed"
                else {"install_failure": "failed"}
            )
        )
    doc = report(harness, reported_verdict, attestation=attestation, finding=finding)
    response = client.post(URL, json=body(doc, bindings), headers=bearer(context))
    assert response.status_code == 200, response.text
    result = ValidationRecordResult.model_validate(response.json())
    same_as_in_process(
        response.json(), context.services().validation.record(doc, PROVENANCE, bindings)
    )
    (outcome,) = result.findings
    assert (outcome.verdict, outcome.soundness_flag, outcome.decision_id) == (verdict, flag, None)
    assert {harness.review.get(i).reason for i in outcome.review_item_ids} == {reason}
    assert all(harness.review.get(i).status == "pending" for i in outcome.review_item_ids)
    assert harness.decisions.list_for_finding(outcome.finding_id) == []
    evidence = context.services().validation.evidence(result.evidence_artifact_ids[0])
    assert evidence.bindings == bindings and evidence.findings[0].soundness_flag == flag


def test_sound_refutation_remains_an_unsigned_machine_proposal_awaiting_review(
    context: Context, client: TestClient, harness: ValidationHarness
) -> None:
    doc = report(harness, "refuted", finding={"steps": [probe()]})
    response = client.post(URL, json=body(doc, harness.bindings()), headers=bearer(context))
    assert response.status_code == 200, response.text
    result = ValidationRecordResult.model_validate(response.json())
    (outcome,) = result.findings
    assert outcome.verdict == "refuted" and outcome.soundness_flag is None
    assert outcome.decision_id is not None
    decision = harness.decisions.get(outcome.decision_id)
    assert decision.validity == "false_positive"
    assert decision.actor is None and decision.auto_accept_tier is False
    assert {harness.review.get(i).reason for i in outcome.review_item_ids} == {"analyst_review"}
    assert all(harness.review.get(i).status == "pending" for i in outcome.review_item_ids)
    assert context.services().findings.get(outcome.finding_id).is_open()


@pytest.mark.parametrize("historical", [False, True])
def test_existing_policy_and_separate_target_attestation_reach_the_owner_unchanged(
    context: Context, client: TestClient, harness: ValidationHarness, historical: bool
) -> None:
    bindings = harness.bindings(
        policy=(
            ValidationRecordingPolicy.HISTORICAL
            if historical
            else ValidationRecordingPolicy.CURRENT
        ),
        target_attestation=TargetAttestation.model_validate(ATTESTATION),
    )
    doc = report(harness, version="0.175.0", attestation=None)
    response = client.post(URL, json=body(doc, bindings), headers=bearer(context))
    assert response.status_code == 200, response.text
    result = ValidationRecordResult.model_validate(response.json())
    assert (result.findings[0].decision_id is not None) is historical
    retained = context.services().validation.evidence(result.evidence_artifact_ids[0])
    assert retained.bindings == bindings
    assert retained.bindings.target_attestation.model_dump() == ATTESTATION


@pytest.mark.parametrize(
    ("defect", "status"),
    [
        ("unbound", 422),
        ("unknown-assessment", 404),
        ("unknown-artifact", 404),
        ("unknown-finding", 404),
        ("wrong-assessment", 422),
        ("wrong-finding", 422),
        ("invented-label", 422),
        ("declared-digest", 409),
        ("stored-digest", 409),
        ("provenance-artifact", 409),
        ("refused-grade", 422),
        ("refused-verdict", 422),
    ],
)
def test_invalid_bindings_classifiers_and_evidence_leave_no_partial_records(
    context: Context, client: TestClient, harness: ValidationHarness, defect: str, status: int
) -> None:
    doc = report(harness, finding={"evidence_grade": "E0"})
    raw = json.loads(doc.payload)
    bindings = harness.bindings()
    source = bindings.sources[0]
    bound_finding = source.findings[0]
    provenance = PROVENANCE
    if defect == "unbound":
        bindings = ValidationRecordInput(sources=())
    elif defect in {"unknown-assessment", "unknown-artifact"}:
        field = "assessment_id" if defect == "unknown-assessment" else "artifact_id"
        source = source.model_copy(update={field: UNKNOWN_ID})
    elif defect == "unknown-finding":
        source = source.model_copy(
            update={"findings": (bound_finding.model_copy(update={"finding_id": UNKNOWN_ID}),)}
        )
    elif defect == "wrong-assessment":
        with SqlTraustUnitOfWork(context.database) as uow:
            ref = uow.repository_refs.get(harness.source.repository_ref_id)
            other = Seed(uow).assessment(ref)
            uow.commit()
        source = source.model_copy(update={"assessment_id": saved_id(other)})
    elif defect == "wrong-finding":
        source = source.model_copy(
            update={
                "findings": (
                    bound_finding.model_copy(update={"finding_id": saved_id(harness.findings[1])}),
                )
            }
        )
    elif defect == "invented-label":
        raw["validated_findings"][0]["source_id"] = "arbitrary-source-label"
        source = source.model_copy(
            update={
                "findings": (
                    bound_finding.model_copy(update={"source_id": "arbitrary-source-label"}),
                )
            }
        )
    elif defect == "declared-digest":
        raw["source_reports"][0]["sha256"] = "0" * 64
    elif defect == "stored-digest":
        harness.objects.put(ObjectKey.parse(harness.artifact.uri), b"corrupt source evidence")
    elif defect == "provenance-artifact":
        provenance = PROVENANCE.model_copy(
            update={
                "artifact": ArtifactRef(
                    id=saved_id(harness.artifact), name="triage", digest=harness.artifact.digest
                )
            }
        )
    elif defect == "refused-grade":
        raw["validated_findings"][0]["evidence_grade"] = "E99"
    elif defect == "refused-verdict":
        raw["validated_findings"][0]["verdict"] = "caller-approved"
    if bindings.sources:
        bindings = bindings.model_copy(update={"sources": (source,)})
    request = body(doc, bindings, provenance)
    request["payload"] = json.dumps(raw)
    before = snapshot(context.database)
    objects_before = tuple(harness.objects.list())
    response = client.post(URL, json=request, headers=bearer(context))
    assert response.status_code == status, response.text
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["request_id"] == response.headers["X-Request-ID"]
    assert snapshot(context.database) == before
    assert tuple(harness.objects.list()) == objects_before


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer not.a.token"}])
def test_recording_requires_a_verified_bearer_without_writing(
    context: Context, client: TestClient, harness: ValidationHarness, headers: dict[str, str]
) -> None:
    before = snapshot(context.database)
    response = client.post(URL, json=body(report(harness), harness.bindings()), headers=headers)
    assert response.status_code == 401
    assert response.headers["content-type"] == "application/problem+json"
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert snapshot(context.database) == before


@pytest.mark.parametrize(
    "defect",
    [
        "malformed-json",
        "invalid-utf8",
        "wrong-schema",
        "payload-object",
        "extra-actor",
        "missing-bindings",
        "bad-uuid",
    ],
)
def test_malformed_payload_and_transport_fields_are_422_without_writing(
    context: Context, client: TestClient, harness: ValidationHarness, defect: str
) -> None:
    request = body(report(harness), harness.bindings())
    if defect == "malformed-json":
        request["payload"] = "{not JSON"
    elif defect == "invalid-utf8":
        request["payload"] = chr(0xD800)
    elif defect == "wrong-schema":
        request["payload"] = "{}"
    elif defect == "payload-object":
        request["payload"] = json.loads(request["payload"])
    elif defect == "extra-actor":
        request["actor"] = {"identity": "admin@example.com", "verified_by": "caller"}
    elif defect == "missing-bindings":
        request.pop("bindings")
    elif defect == "bad-uuid":
        request["bindings"]["sources"][0]["findings"][0]["finding_id"] = "not-a-uuid"
    before = snapshot(context.database)
    response = client.post(
        URL,
        content=json.dumps(request),
        headers={**bearer(context), "Content-Type": "application/json"},
    )
    assert response.status_code == 422, response.text
    assert response.headers["content-type"] == "application/problem+json"
    assert snapshot(context.database) == before
