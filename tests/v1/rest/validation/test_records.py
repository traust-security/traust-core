from __future__ import annotations

import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed, saved_id
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.rest.ops.conftest import runner
from tests.v1.rest.validation.conftest import ValidationRun
from tests.v1.services.test_validation import (
    ATTESTATION,
    SOURCE_REPORT,
    UNKNOWN_ID,
    ValidationHarness,
    probe,
    report,
    snapshot,
)
from traust_core.v1.context import Context
from traust_core.v1.errors import ForbiddenError
from traust_core.v1.models.artifacts import ValidationArtifact
from traust_core.v1.models.common import ArtifactRef
from traust_core.v1.models.identity import Credential
from traust_core.v1.models.operations import RunOrder
from traust_core.v1.models.validation import (
    TargetAttestation,
    ValidationRecordingPolicy,
    ValidationRecordInput,
    ValidationRecordResult,
    ValidationSourceBinding,
)
from traust_core.v1.repositories import ObjectKey
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs, stored_bytes

URL = "/v1/validation-records"


def test_first_record_and_retries_preserve_native_ids_and_exact_utf8_evidence(
    context: Context, client: TestClient, harness: ValidationHarness, run: ValidationRun
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
    provenance = run.provenance.model_copy(update={"artifact": published})
    before = snapshot(context.database)
    response = client.post(URL, json=run.body(doc, bindings, provenance), headers=run.headers)
    assert response.status_code == 200, response.text
    result = ValidationRecordResult.model_validate(response.json())
    expected = context.services().validation.record_order(
        doc, provenance, bindings, saved_id(run.order), run.principal
    )
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
    assert assessment.run_order_id == run.order.id == provenance.run_id
    assert assessment.repository_ref_id == harness.source.repository_ref_id
    assert assessment.occurred_at == provenance.occurred_at
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
    retry = client.post(URL, json=run.body(doc, bindings, provenance), headers=run.headers)
    assert retry.status_code == 200 and retry.json() == response.json()
    assert snapshot(context.database) == after
    assert context.services().ops.get(saved_id(run.order)) == run.order


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
    run: ValidationRun,
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
    response = client.post(URL, json=run.body(doc, bindings), headers=run.headers)
    assert response.status_code == 200, response.text
    result = ValidationRecordResult.model_validate(response.json())
    same_as_in_process(
        response.json(),
        context.services().validation.record_order(
            doc, run.provenance, bindings, saved_id(run.order), run.principal
        ),
    )
    (outcome,) = result.findings
    assert (outcome.verdict, outcome.soundness_flag, outcome.decision_id) == (verdict, flag, None)
    assert {harness.review.get(i).reason for i in outcome.review_item_ids} == {reason}
    assert all(harness.review.get(i).status == "pending" for i in outcome.review_item_ids)
    assert harness.decisions.list_for_finding(outcome.finding_id) == []
    evidence = context.services().validation.evidence(result.evidence_artifact_ids[0])
    assert evidence.bindings == bindings and evidence.findings[0].soundness_flag == flag


def test_sound_refutation_remains_an_unsigned_machine_proposal_awaiting_review(
    context: Context, client: TestClient, harness: ValidationHarness, run: ValidationRun
) -> None:
    doc = report(harness, "refuted", finding={"steps": [probe()]})
    response = client.post(URL, json=run.body(doc, harness.bindings()), headers=run.headers)
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
    context: Context,
    client: TestClient,
    harness: ValidationHarness,
    run: ValidationRun,
    historical: bool,
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
    response = client.post(URL, json=run.body(doc, bindings), headers=run.headers)
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
    context: Context,
    client: TestClient,
    harness: ValidationHarness,
    run: ValidationRun,
    defect: str,
    status: int,
) -> None:
    doc = report(harness, finding={"evidence_grade": "E0"})
    raw = json.loads(doc.payload)
    bindings = harness.bindings()
    source = bindings.sources[0]
    bound_finding = source.findings[0]
    provenance = run.provenance
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
        provenance = run.provenance.model_copy(
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
    request = run.body(doc, bindings, provenance)
    request["payload"] = json.dumps(raw)
    before = snapshot(context.database)
    objects_before = tuple(harness.objects.list())
    response = client.post(URL, json=request, headers=run.headers)
    assert response.status_code == status, response.text
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["request_id"] == response.headers["X-Request-ID"]
    assert snapshot(context.database) == before
    assert tuple(harness.objects.list()) == objects_before


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer not.a.token"}])
def test_recording_requires_a_verified_bearer_without_writing(
    context: Context,
    client: TestClient,
    harness: ValidationHarness,
    run: ValidationRun,
    headers: dict[str, str],
) -> None:
    before = snapshot(context.database)
    objects_before = tuple(harness.objects.list())
    response = client.post(URL, json=run.body(report(harness), harness.bindings()), headers=headers)
    assert response.status_code == 401
    assert response.headers["content-type"] == "application/problem+json"
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert snapshot(context.database) == before
    assert tuple(harness.objects.list()) == objects_before


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
        "missing-order",
        "bad-order",
        "extra-caller",
        "extra-signer",
    ],
)
def test_malformed_payload_and_transport_fields_are_422_without_writing(
    context: Context,
    client: TestClient,
    harness: ValidationHarness,
    run: ValidationRun,
    defect: str,
) -> None:
    request = run.body(report(harness), harness.bindings())
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
    elif defect == "missing-order":
        request.pop("run_order_id")
    elif defect == "bad-order":
        request["run_order_id"] = "not-a-uuid"
    elif defect in {"extra-caller", "extra-signer"}:
        request[defect.removeprefix("extra-")] = run.principal.model_dump(mode="json")
    before = snapshot(context.database)
    objects_before = tuple(harness.objects.list())
    response = client.post(
        URL,
        content=json.dumps(request),
        headers={**run.headers, "Content-Type": "application/json"},
    )
    assert response.status_code == 422, response.text
    assert response.headers["content-type"] == "application/problem+json"
    assert snapshot(context.database) == before
    assert tuple(harness.objects.list()) == objects_before


@pytest.mark.parametrize("identity", ["unrelated-runner", "human-reader"])
def test_a_valid_report_requires_the_actual_verified_machine_lease_holder(
    context: Context,
    client: TestClient,
    harness: ValidationHarness,
    run: ValidationRun,
    identity: str,
) -> None:
    headers = runner(context, identity) if identity == "unrelated-runner" else bearer(context)
    doc = report(harness, finding={"evidence_grade": "E0"})
    request = run.body(doc, harness.bindings())
    readable = client.get(f"/v1/findings/{harness.findings[0].id}", headers=headers)
    assert readable.status_code == 200, readable.text
    before = snapshot(context.database)
    objects_before = tuple(harness.objects.list())
    denied = client.post(URL, json=request, headers=headers)
    assert denied.status_code == 403, denied.text
    assert denied.headers["content-type"] == "application/problem+json"
    assert snapshot(context.database) == before
    assert tuple(harness.objects.list()) == objects_before
    assert context.services().ops.get(saved_id(run.order)) == run.order
    accepted = client.post(URL, json=request, headers=run.headers)
    assert accepted.status_code == 200, accepted.text


def test_native_service_rejects_an_unrelated_runner_before_writing(
    context: Context, harness: ValidationHarness, run: ValidationRun
) -> None:
    assert context.identity is not None
    other = context.identity.authenticate(
        Credential(token=context.local_issuer.mint("unrelated-runner", machine=True).token)
    )
    before = snapshot(context.database)
    objects_before = tuple(harness.objects.list())
    with pytest.raises(ForbiddenError):
        context.services().validation.record_order(
            report(harness, finding={"evidence_grade": "E0"}),
            run.provenance,
            harness.bindings(),
            saved_id(run.order),
            other,
        )
    assert snapshot(context.database) == before
    assert tuple(harness.objects.list()) == objects_before


@pytest.mark.parametrize(
    ("defect", "status"),
    [
        ("wrong-repository", 403),
        ("fleet-order", 403),
        ("wrong-asset", 403),
        ("expired", 409),
        ("completed", 409),
        ("queued", 409),
        ("forged-run", 422),
        ("unknown-order", 404),
    ],
)
def test_order_scope_and_live_lease_are_checked_before_any_recording(
    context: Context,
    client: TestClient,
    harness: ValidationHarness,
    run: ValidationRun,
    defect: str,
    status: int,
) -> None:
    request = run.body(report(harness, finding={"evidence_grade": "E0"}), harness.bindings())
    if defect == "completed":
        completed = client.post(
            f"/v1/orders/{run.order.id}/complete",
            json={"result": {"outcome": "succeeded"}},
            headers=run.headers,
        )
        assert completed.status_code == 200, completed.text
    elif defect == "forged-run":
        request["provenance"]["run_id"] = str(UNKNOWN_ID)
    elif defect == "unknown-order":
        request["run_order_id"] = str(UNKNOWN_ID)
        request["provenance"]["run_id"] = str(UNKNOWN_ID)
    else:
        with SqlTraustUnitOfWork(context.database) as uow:
            order = uow.run_orders.get(saved_id(run.order))
            if defect == "wrong-repository":
                repository = Seed(uow).repository(url="https://github.com/org/unrelated")
                changes = {"repository_id": saved_id(repository)}
            elif defect == "fleet-order":
                changes = {"repository_id": None}
            elif defect == "wrong-asset":
                changes = {"asset": "audit"}
            elif defect == "expired":
                changes = {"lease_expires_at": context.clock.now() - timedelta(seconds=1)}
            else:
                changes = {"state": "queued", "lease_holder": None, "lease_expires_at": None}
            uow.run_orders.update(order.model_copy(update=changes))
            uow.commit()
    order_before = context.services().ops.get(saved_id(run.order))
    before = snapshot(context.database)
    objects_before = tuple(harness.objects.list())
    response = client.post(URL, json=request, headers=run.headers)
    assert response.status_code == status, response.text
    assert response.headers["content-type"] == "application/problem+json"
    assert snapshot(context.database) == before
    assert tuple(harness.objects.list()) == objects_before
    assert context.services().ops.get(saved_id(run.order)) == order_before


@pytest.mark.parametrize("explicit_artifact", [False, True])
def test_independent_run_keeps_new_identity_without_rebinding_another_orders_artifact(
    context: Context,
    client: TestClient,
    harness: ValidationHarness,
    run: ValidationRun,
    explicit_artifact: bool,
) -> None:
    doc = report(harness, finding={"evidence_grade": "E0"})
    request = run.body(doc, harness.bindings())
    recorded = client.post(URL, json=request, headers=run.headers)
    assert recorded.status_code == 200, recorded.text
    result = ValidationRecordResult.model_validate(recorded.json())
    with SqlTraustUnitOfWork(context.database) as uow:
        original_assessments = tuple(uow.assessments.get(i) for i in result.assessment_ids)
        original_artifacts = tuple(
            uow.artifacts.get(i) for i in (*result.artifact_ids, *result.evidence_artifact_ids)
        )
        other = Seed(uow).run_order(asset="validate", repository_id=run.order.repository_id)
        uow.commit()
    claimed = client.post(
        "/v1/orders/claim",
        json={"lease_seconds": 300, "assets": ["validate"]},
        headers=run.headers,
    )
    assert claimed.status_code == 200, claimed.text
    claimed_order = RunOrder.model_validate(claimed.json())
    assert claimed_order.id == other.id
    request["run_order_id"] = str(other.id)
    request["provenance"]["run_id"] = str(other.id)
    if explicit_artifact:
        with SqlTraustUnitOfWork(context.database) as uow:
            artifact = uow.artifacts.get(result.artifact_ids[0])
        request["provenance"]["artifact"] = ArtifactRef(
            id=saved_id(artifact), name="validation", digest=artifact.digest
        ).model_dump(mode="json")
    replay = client.post(URL, json=request, headers=run.headers)
    assert replay.status_code == 200, replay.text
    independent = ValidationRecordResult.model_validate(replay.json())
    assert set(independent.assessment_ids).isdisjoint(result.assessment_ids)
    assert set(independent.artifact_ids).isdisjoint(result.artifact_ids)
    assert set(independent.evidence_artifact_ids).isdisjoint(result.evidence_artifact_ids)
    with SqlTraustUnitOfWork(context.database) as uow:
        assert all(
            uow.assessments.get(i).run_order_id == other.id for i in independent.assessment_ids
        )
        for artifact_id in independent.artifact_ids:
            retained_report = uow.artifacts.get(artifact_id)
            assert retained_report.assessment_id in independent.assessment_ids
            assert stored_bytes(harness.objects, retained_report) == doc.payload
    for artifact_id in independent.evidence_artifact_ids:
        evidence = context.services().validation.evidence(artifact_id)
        assert evidence.provenance.model_dump(mode="json") == request["provenance"]
    independent_after = snapshot(context.database)
    objects_after = tuple(harness.objects.list())
    second_retry = client.post(URL, json=request, headers=run.headers)
    assert second_retry.status_code == 200 and second_retry.json() == replay.json()
    assert snapshot(context.database) == independent_after
    assert tuple(harness.objects.list()) == objects_after
    with SqlTraustUnitOfWork(context.database) as uow:
        assert tuple(uow.assessments.get(i) for i in result.assessment_ids) == original_assessments
        assert (
            tuple(
                uow.artifacts.get(i) for i in (*result.artifact_ids, *result.evidence_artifact_ids)
            )
            == original_artifacts
        )
    retained = context.services().validation.evidence(result.evidence_artifact_ids[0])
    assert retained.provenance == run.provenance
    after = snapshot(context.database)
    retry = client.post(URL, json=run.body(doc, harness.bindings()), headers=run.headers)
    assert retry.status_code == 200 and retry.json() == recorded.json()
    assert snapshot(context.database) == after


def test_order_recording_does_not_adopt_or_patch_an_existing_trusted_local_assessment(
    context: Context, client: TestClient, harness: ValidationHarness, run: ValidationRun
) -> None:
    doc = report(harness, finding={"evidence_grade": "E0"})
    bindings = harness.bindings()
    recorded = context.services().validation.record(doc, run.provenance, bindings)
    with SqlTraustUnitOfWork(context.database) as uow:
        assert all(
            uow.assessments.get(assessment_id).run_order_id is None
            for assessment_id in recorded.assessment_ids
        )
    before = snapshot(context.database)
    objects_before = tuple(harness.objects.list())
    response = client.post(URL, json=run.body(doc, bindings), headers=run.headers)
    assert response.status_code == 409, response.text
    assert response.headers["content-type"] == "application/problem+json"
    assert snapshot(context.database) == before
    assert tuple(harness.objects.list()) == objects_before


@pytest.mark.parametrize(
    ("foreign_repository", "foreign_first"),
    [(False, False), (True, False), (True, True)],
    ids=["all-sources-authorized", "foreign-source-last", "foreign-source-first"],
)
def test_every_report_source_must_belong_to_the_orders_repository(
    context: Context,
    client: TestClient,
    harness: ValidationHarness,
    run: ValidationRun,
    foreign_repository: bool,
    foreign_first: bool,
) -> None:
    second_path = "findings/example/second-triage.json"
    source_doc = json.loads(stored_bytes(harness.objects, harness.artifact))
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repository = (
            seed.repository(url="https://github.com/org/foreign-source")
            if foreign_repository
            else uow.repositories.get(run.order.repository_id)
        )
        second = seed.assessment(seed.repository_ref(repository, name="second"))
        finding = seed.finding(repository, fingerprint="3" * 64)
        seed.occurrence(finding, second, severity="high")
        source_doc["findings"] = [
            {
                "id": "f001",
                "title": finding.title,
                "verdict": "true_positive",
                "fingerprint": finding.fingerprint,
                "fingerprint_algo": finding.fingerprint_algo,
            }
        ]
        stored = harness.objects.put(
            ObjectKey.parse(f"sources/{second.id}.json"), json.dumps(source_doc).encode()
        )
        artifact = seed.artifact(second, kind="triage", digest=stored.sha256, uri=str(stored.key))
        uow.commit()
    first_binding = harness.bindings().sources[0]
    second_binding = ValidationSourceBinding(
        source_report=second_path,
        assessment_id=saved_id(second),
        artifact_id=saved_id(artifact),
        findings=(first_binding.findings[0].model_copy(update={"finding_id": saved_id(finding)}),),
    )
    raw = json.loads(report(harness, finding={"evidence_grade": "E0"}).payload)
    raw["source_reports"].append({"kind": "triage", "path": second_path, "sha256": artifact.digest})
    raw["validated_findings"].append({**raw["validated_findings"][0], "source_report": second_path})
    raw["summary"]["by_verdict"]["confirmed"] = 2
    raw["summary"]["by_technique"]["replay"] = 2
    sources = (first_binding, second_binding)
    if foreign_first:
        sources = sources[::-1]
        raw["source_reports"].reverse()
        raw["validated_findings"].reverse()
    bindings = ValidationRecordInput(sources=sources)
    doc = ValidationArtifact.parse(json.dumps(raw).encode())
    before = snapshot(context.database)
    objects_before = tuple(harness.objects.list())
    response = client.post(URL, json=run.body(doc, bindings), headers=run.headers)
    if foreign_repository:
        assert response.status_code == 403, response.text
        assert response.headers["content-type"] == "application/problem+json"
        assert snapshot(context.database) == before
        assert tuple(harness.objects.list()) == objects_before
        return
    assert response.status_code == 200, response.text
    result = ValidationRecordResult.model_validate(response.json())
    assert len(set(result.assessment_ids)) == len(set(result.artifact_ids)) == 2
    assert len(set(result.evidence_artifact_ids)) == 2
    assert {outcome.finding_id for outcome in result.findings} == {
        saved_id(harness.findings[0]),
        saved_id(finding),
    }
    with SqlTraustUnitOfWork(context.database) as uow:
        for assessment_id in result.assessment_ids:
            assert uow.assessments.get(assessment_id).run_order_id == run.order.id
        for artifact_id in result.artifact_ids:
            assert stored_bytes(harness.objects, uow.artifacts.get(artifact_id)) == doc.payload
    for artifact_id in result.evidence_artifact_ids:
        evidence = context.services().validation.evidence(artifact_id)
        assert evidence.provenance == run.provenance and evidence.bindings == bindings
    after = snapshot(context.database)
    retry = client.post(URL, json=run.body(doc, bindings), headers=run.headers)
    assert retry.status_code == 200 and retry.json() == response.json()
    assert snapshot(context.database) == after
