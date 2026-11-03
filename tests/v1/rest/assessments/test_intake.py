from __future__ import annotations

import json
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.assessments import test_records as recording
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.rest.ops.conftest import runner
from traust_core.v1.context import Context
from traust_core.v1.models.artifacts import SecurityAuditArtifact
from traust_core.v1.models.assessment import Assessment, AssessmentKind, AssessmentRecordResult
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import FindingCandidate
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey
from traust_core.v1.services.artifact_publishing import AssessmentLog, PublishSpec, PublishSpecs

engine, context, ref = recording.engine, recording.context, recording.ref


def recorded(context: Context, client: TestClient, ref: UUID) -> AssessmentRecordResult:
    response = client.post(
        recording.URL, json=recording.body(context, ref), headers=runner(context)
    )
    assert response.status_code == 200, response.text
    return AssessmentRecordResult.model_validate(response.json())


def path(assessment_id: UUID) -> str:
    return f"/v1/assessments/{assessment_id}/intake"


def test_intake_read_projects_only_original_labels_to_this_assessments_native_findings(
    context: Context, client: TestClient, ref: UUID
) -> None:
    result = recorded(context, client, ref)
    before = recording.rows(context)
    raw = context.services().artifacts.payload(result.artifact_id)
    response = client.get(path(result.assessment_id), headers=bearer(context))
    assert response.status_code == 200, response.text
    assert response.json() == {
        "findings": {
            str(label): str(identifier) for label, identifier in result.intake.findings.items()
        }
    }
    assert set(response.json()) == {"findings"}
    same_as_in_process(
        response.json(), context.services().assessment.intake_bindings(result.assessment_id)
    )
    assert recording.rows(context) == before
    assert context.services().artifacts.payload(result.artifact_id) == raw
    assert client.get(path(result.assessment_id)).status_code == 401


@pytest.mark.parametrize("kind", [AssessmentKind.CONTAINER, AssessmentKind.RPM])
def test_native_report_families_bind_their_own_findings_and_refuse_a_moved_identity(
    context: Context, client: TestClient, ref: UUID, kind: AssessmentKind
) -> None:
    services = context.services()
    assessment = services.assessment.record(
        recording.DOC,
        ref,
        kind,
        f"skill:{kind}",
        "1.2.3",
        Provenance(run_id=uuid4(), source=SourceType.VULN_SCAN_REPORT, occurred_at=recording.WHEN),
    )
    occurrences = services.findings.occurrences(assessment_id=assessment.id)
    assert len(occurrences) == len(recording.DOC.findings) == 2
    by_path = {
        location.path: occurrence.finding_id
        for occurrence in occurrences
        for location in services.findings.locations([occurrence.id])
    }
    assert set(by_path) == {"src/auth.py", "src/token.py"}
    expected = {
        "findings": {
            "AUDIT-1": str(by_path["src/auth.py"]),
            "AUDIT-2": str(by_path["src/token.py"]),
        }
    }
    before = recording.rows(context)
    original = services.assessment.report(assessment.id).payload
    response = client.get(path(assessment.id), headers=bearer(context))
    assert response.status_code == 200, response.text
    assert response.json() == expected
    same_as_in_process(response.json(), services.assessment.intake_bindings(assessment.id))
    assert recording.rows(context) == before
    assert services.assessment.report(assessment.id).payload == original
    with SqlTraustUnitOfWork(context.database) as uow:
        finding = uow.findings.get(occurrences[0].finding_id)
        uow.findings.update(finding.model_copy(update={"fingerprint": "f" * 64}))
        uow.commit()
    before = recording.rows(context)
    broken = client.get(path(assessment.id), headers=bearer(context))
    assert broken.status_code == 409, broken.text
    assert "does not identify an admitted finding" in broken.json()["detail"]
    assert recording.rows(context) == before
    assert services.assessment.report(assessment.id).payload == original


def test_intake_read_uses_digest_verified_original_report_bytes(
    context: Context, client: TestClient, ref: UUID
) -> None:
    result = recorded(context, client, ref)
    metadata = context.services().artifacts.metadata(result.artifact_id)
    context.object_store.put(ObjectKey.parse(metadata.uri), b"corrupt source report")
    before = recording.rows(context)
    response = client.get(path(result.assessment_id), headers=bearer(context))
    assert response.status_code == 409, response.text
    assert response.headers["content-type"] == "application/problem+json"
    assert "corrupt source report" not in response.text
    assert recording.rows(context) == before


def test_identical_repository_fingerprint_from_another_assessment_is_not_source_intake(
    context: Context, client: TestClient, ref: UUID
) -> None:
    services = context.services()
    provenance = Provenance(
        run_id=uuid4(), source=SourceType.VULN_SCAN_REPORT, occurred_at=recording.WHEN
    )
    source = services.assessment.record(
        recording.DOC,
        ref,
        AssessmentKind.SECURE_CODE_CANONICAL,
        "skill:secure-code-audit",
        "1.2.3",
        provenance,
    )
    services.assessment.record(
        recording.DOC, ref, AssessmentKind.CONTAINER, "skill:container", "1.2.3", provenance
    )
    before = recording.rows(context)
    response = client.get(path(source.id), headers=bearer(context))
    assert response.status_code == 409, response.text
    assert "does not identify an admitted finding" in response.json()["detail"]
    assert recording.rows(context) == before


def test_intake_read_does_not_match_a_moved_identity_by_unchanged_title(
    context: Context, client: TestClient, ref: UUID
) -> None:
    result = recorded(context, client, ref)
    with SqlTraustUnitOfWork(context.database) as uow:
        finding = uow.findings.get(next(iter(result.intake.findings.values())))
        uow.findings.update(finding.model_copy(update={"fingerprint": "f" * 64}))
        uow.commit()
    before = recording.rows(context)
    response = client.get(path(result.assessment_id), headers=bearer(context))
    assert response.status_code == 409, response.text
    assert recording.rows(context) == before


def test_historical_noncanonical_report_remains_readable_without_rewriting_its_bytes(
    context: Context, client: TestClient, ref: UUID
) -> None:
    document = json.loads(recording.DOC.payload)
    document["remediation_roadmap"][0]["priority"] = "P3"
    document["findings"][0]["remediation_effort"] = "moderate"
    raw = (" \n" + json.dumps(document, ensure_ascii=False, indent=3) + "\n\t").encode("utf-8")
    doc = SecurityAuditArtifact.parse(raw)
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(SecurityAuditArtifact)))
    published = publisher.publish_ref(doc)
    uow = SqlTraustUnitOfWork(context.database)
    assessment, artifact = AssessmentLog(uow).add(
        Assessment(
            repository_ref_id=ref,
            kind="secure-code",
            status="completed",
            assessor="skill:secure-code-audit",
            assessor_version="historical",
            occurred_at=recording.WHEN,
        ),
        published.id,
        published.digest,
    )
    services = context.services()
    repository_id = services.portfolio.inventory.get_ref(ref).repository_id
    intake = services.findings.intake.accept(
        assessment.id, FindingCandidate.of_report(doc.findings, repository_id)
    )
    before = recording.rows(context)
    response = client.get(path(assessment.id), headers=bearer(context))
    assert response.status_code == 200, response.text
    assert response.json() == {
        "findings": {str(label): str(identifier) for label, identifier in intake.findings.items()}
    }
    assert services.artifacts.payload(artifact.id) == raw
    assert recording.rows(context) == before


@pytest.mark.parametrize("kind", ["scanner", AssessmentKind.BENCHMARK_AUDIT])
def test_assessments_without_native_report_intake_are_outside_this_binding_projection(
    context: Context, client: TestClient, ref: UUID, kind: str
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        assessment = Seed(uow).assessment(uow.repository_refs.get(ref), kind=kind)
        uow.commit()
    response = client.get(path(assessment.id), headers=bearer(context))
    assert response.status_code == 422, response.text


@pytest.mark.parametrize(
    "kind",
    [
        AssessmentKind.SECURE_CODE_CANONICAL,
        AssessmentKind.CONTAINER,
        AssessmentKind.RPM,
    ],
)
def test_missing_assessment_or_original_report_is_not_a_manufactured_empty_mapping(
    context: Context, client: TestClient, ref: UUID, kind: AssessmentKind
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        assessment = Seed(uow).assessment(uow.repository_refs.get(ref), kind=kind)
        uow.commit()
    assert client.get(path(uuid4()), headers=bearer(context)).status_code == 404
    response = client.get(path(assessment.id), headers=bearer(context))
    assert response.status_code == 404 and "has no report artifact" in response.json()["detail"]


def test_empty_authored_report_has_an_authentic_empty_label_mapping(
    context: Context, client: TestClient, ref: UUID
) -> None:
    request = recording.body(context, ref, recording.report())
    response = client.post(recording.URL, json=request, headers=runner(context))
    assert response.status_code == 200, response.text
    source = AssessmentRecordResult.model_validate(response.json())
    read = client.get(path(source.assessment_id), headers=bearer(context))
    assert read.status_code == 200 and read.json() == {"findings": {}}


def test_intake_operation_exposes_mapping_only_native_result(client: TestClient) -> None:
    operation = client.get("/openapi.json").json()["paths"][
        "/v1/assessments/{assessment_id}/intake"
    ]["get"]
    assert operation["operationId"] == "get_assessment_intake"
    assert operation["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/AssessmentIntakeBindings"
    }
