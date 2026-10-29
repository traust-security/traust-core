from __future__ import annotations

import json
from uuid import UUID

import pytest

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.assessments.test_records import rows
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.rest.findings import test_triage_records as triage
from tests.v1.rest.ops.conftest import runner
from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.findings import TriageRecordResult
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey

world = triage.world


def record(world: triage.TriageWorld) -> TriageRecordResult:
    response = world.client.post(world.path, json=world.body, headers=runner(world.context))
    assert response.status_code == 200, response.text
    return TriageRecordResult.model_validate(response.json())


def path(assessment_id: UUID) -> str:
    return f"/v1/assessments/{assessment_id}/intake"


def expected(world: triage.TriageWorld) -> dict[str, dict[str, str]]:
    return {"findings": {f"f{i + 1:03d}": str(f.id) for i, f in enumerate(world.findings)}}


def test_triage_intake_read_includes_weakness_and_undetermined_rows_without_decisions(
    world: triage.TriageWorld,
) -> None:
    result = record(world)
    assert len(result.decisions) == 2
    before = rows(world.context)
    raw = world.context.services().artifacts.payload(result.artifact_id)
    response = world.client.get(path(result.assessment_id), headers=bearer(world.context))
    assert response.status_code == 200, response.text
    assert response.json() == expected(world)
    same_as_in_process(
        response.json(),
        world.context.services().findings.decisions.intake_bindings(result.assessment_id),
    )
    same_as_in_process(
        response.json(), world.context.services().assessment.intake_bindings(result.assessment_id)
    )
    assert rows(world.context) == before
    assert world.context.services().artifacts.payload(result.artifact_id) == raw
    assert world.client.get(path(result.assessment_id)).status_code == 401


def test_all_undetermined_rows_have_native_bindings_even_when_no_decision_was_recorded(
    world: triage.TriageWorld,
) -> None:
    document = json.loads(world.body["payload"])
    for finding in document["findings"]:
        finding.update(verdict="undetermined", kind="weakness", confidence=0, severity=None)
        finding.pop("exclusion_rule", None)
    document["summary"].update(true_positives=0, hardening=0, undetermined=3)
    document["summary"]["by_severity"]["high"] = 0
    world.body = {**world.body, "payload": json.dumps(document)}
    result = record(world)
    assert result.decisions == []
    before = rows(world.context)
    response = world.client.get(path(result.assessment_id), headers=bearer(world.context))
    assert response.status_code == 200 and response.json() == expected(world)
    assert rows(world.context) == before


def test_triage_intake_read_requires_digest_verified_artifact_content(
    world: triage.TriageWorld,
) -> None:
    result = record(world)
    metadata = world.context.services().artifacts.metadata(result.artifact_id)
    world.context.object_store.put(ObjectKey.parse(metadata.uri), b"not the recorded triage")
    before = rows(world.context)
    response = world.client.get(path(result.assessment_id), headers=bearer(world.context))
    assert response.status_code == 409, response.text
    assert rows(world.context) == before


def test_triage_row_binding_fails_closed_when_baseline_finding_identity_moved(
    world: triage.TriageWorld,
) -> None:
    result = record(world)
    with SqlTraustUnitOfWork(world.context.database) as uow:
        uow.findings.update(world.findings[0].model_copy(update={"fingerprint": "f" * 64}))
        uow.commit()
    before = rows(world.context)
    response = world.client.get(path(result.assessment_id), headers=bearer(world.context))
    assert response.status_code == 422, response.text
    assert "didn't report: f001" in response.json()["detail"]
    assert rows(world.context) == before


@pytest.mark.parametrize(
    "fault", ["empty-baseline", "wrong-ref", "missing-baseline", "missing-artifact"]
)
def test_triage_read_requires_original_baseline_scope_and_original_artifact(
    world: triage.TriageWorld, fault: str
) -> None:
    result = record(world)
    with SqlTraustUnitOfWork(world.context.database) as uow:
        seed = Seed(uow)
        source = uow.assessments.get(world.assessment_id)
        original = uow.assessments.get(result.assessment_id)
        baseline = seed.assessment(
            uow.repository_refs.get(source.repository_ref_id) if fault != "wrong-ref" else None
        )
        assessment = seed.assessment(
            uow.repository_refs.get(original.repository_ref_id),
            kind="triage",
            baseline_assessment_id=None if fault == "missing-baseline" else baseline.id,
        )
        if fault != "missing-artifact":
            artifact = uow.artifacts.get(result.artifact_id)
            seed.artifact(assessment, digest=artifact.digest, kind="triage", uri=artifact.uri)
        uow.commit()
    before = rows(world.context)
    response = world.client.get(path(assessment.id), headers=bearer(world.context))
    status = 422 if fault == "empty-baseline" else 404 if fault == "missing-artifact" else 409
    assert response.status_code == status, response.text
    assert rows(world.context) == before


def test_historical_triage_labels_are_read_without_rewriting_legacy_verdict_bytes(
    world: triage.TriageWorld,
) -> None:
    document = json.loads(world.body["payload"])
    document["findings"][0]["verdict"] = "hardening"
    document["findings"][0].pop("kind", None)
    raw = (" \n" + json.dumps(document, ensure_ascii=False, indent=3) + "\n\t").encode("utf-8")
    TriageArtifact.parse(raw)
    stored = world.context.object_store.put(ObjectKey.parse("triage/historical-read.json"), raw)
    with SqlTraustUnitOfWork(world.context.database) as uow:
        seed = Seed(uow)
        source = uow.assessments.get(world.assessment_id)
        assessment = seed.assessment(
            uow.repository_refs.get(source.repository_ref_id),
            kind="triage",
            baseline_assessment_id=source.id,
        )
        artifact = seed.artifact(
            assessment, digest=stored.sha256, kind="triage", uri=str(stored.key)
        )
        uow.commit()
    before = rows(world.context)
    response = world.client.get(path(assessment.id), headers=bearer(world.context))
    assert response.status_code == 200 and response.json() == expected(world)
    assert world.context.services().artifacts.payload(artifact.id) == raw
    assert rows(world.context) == before
