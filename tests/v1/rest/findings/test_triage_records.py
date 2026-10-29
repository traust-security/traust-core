from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.providers.test_forge_file import GITHUB, SHA
from tests.v1.providers.test_forge_inventory import (
    forge,
    http,
)
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.rest.conftest import bearer
from tests.v1.rest.ops.conftest import runner
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import RecordingConfig
from traust_core.v1.errors import ForbiddenError
from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import Finding
from traust_core.v1.models.identity import Credential, Principal
from traust_core.v1.models.operations import JobResult, OrderRequest, WorkerId
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey
from traust_core.v1.rest.app import create_app
from traust_core.v1.services.identity import IdentityConfig


@dataclass
class TriageWorld:
    context: Context
    client: TestClient
    assessment_id: UUID
    findings: list[Finding]
    body: dict
    order_id: UUID
    principal: Principal

    @property
    def path(self) -> str:
        return f"/v1/assessments/{self.assessment_id}/triage-records"


@pytest.fixture(params=SQL_BACKENDS)
def world(
    request: pytest.FixtureRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[TriageWorld]:
    text = "void parse(void) { /* observed guard */ }\n"
    provider, _, _ = forge(
        {},
        github={
            "git/trees/": http(
                json.dumps({"truncated": False, "tree": [{"type": "blob", "path": "entry.c"}]})
            ),
            f"contents/entry.c?ref={SHA}": http(
                json.dumps(
                    {
                        "type": "file",
                        "encoding": "base64",
                        "content": base64.b64encode(text.encode()).decode(),
                    }
                )
            ),
        },
    )
    monkeypatch.setattr(
        "traust_core.v1.context.context.command_source", lambda *args, **kwargs: provider
    )
    with contract_db(request.param, tmp_path) as engine:
        context = Context(
            Config(
                home=tmp_path / "store",
                identity=IdentityConfig(trust_local=True),
                recording=RecordingConfig(triage=("triage", "triage_again")),
            ),
        )
        context.__dict__["database"] = engine
        with SqlTraustUnitOfWork(engine) as uow:
            seed = Seed(uow)
            repository = seed.repository(url=str(GITHUB))
            ref = seed.repository_ref(repository, sha=str(SHA))
            assessment = seed.assessment(ref)
            findings = [
                seed.finding(repository, fingerprint=hashlib.sha256(str(i).encode()).hexdigest())
                for i in range(3)
            ]
            for finding in findings:
                seed.occurrence(finding, assessment)
            uow.commit()
        token = context.local_issuer.mint("runner-7", machine=True).token
        principal = context.identity.authenticate(Credential(token=token))
        order = context.services().ops.start(
            OrderRequest(asset="triage", priority=1, repository_id=repository.id),
            principal,
            WorkerId(principal.ref),
            timedelta(minutes=10),
        )
        rows = [
            {
                "id": f"f{i + 1:03d}",
                "title": f"Observed security claim {i}",
                "fingerprint": finding.fingerprint,
                "fingerprint_algo": finding.fingerprint_algo,
                "file": "entry.c",
                "line": 1,
                "rationale": "Observed guard at entry.c:1 — café",
                "first_links": ["entry.c:1"],
                "verdict": "true_positive",
                "severity": None,
            }
            for i, finding in enumerate(findings)
        ]
        rows[0].update(kind="weakness", exclusion_rule=13)
        rows[1].update(kind="vulnerability", severity="high")
        rows[2].update(kind="weakness", verdict="undetermined", confidence=0)
        document = {
            "triage_completed": "2026-10-05",
            "triage_context": {
                "mode": "auto",
                "environment": "Isolated native source assessment",
                "votes_per_finding": 3,
                "repo": "/not/a/server/checkout",
                "harness_version": "0.39.2",
            },
            "summary": {
                "input_count": 3,
                "true_positives": 1,
                "hardening": 1,
                "false_positives": 0,
                "undetermined": 1,
                "duplicates": 0,
                "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            },
            "findings": rows,
        }
        provenance = Provenance(run_id=order.id, source=SourceType.TRIAGE_REPORT, occurred_at=T0)
        body = {
            "run_order_id": str(order.id),
            "payload": json.dumps(document, indent=3, ensure_ascii=False) + "\n\n",
            "provenance": provenance.model_dump(mode="json"),
        }
        with TestClient(create_app(context), raise_server_exceptions=False) as client:
            yield TriageWorld(context, client, assessment.id, findings, body, order.id, principal)


def test_native_triage_records_kind_and_review_without_changing_evidence_bytes(
    world: TriageWorld,
) -> None:
    response = world.client.post(world.path, json=world.body, headers=runner(world.context))
    assert response.status_code == 200, response.text
    receipt = response.json()
    decisions = receipt["decisions"]
    assert {(d["finding_id"], d["validity"], d["severity"], d["actor"]) for d in decisions} == {
        (str(world.findings[0].id), "confirmed", None, None),
        (str(world.findings[1].id), "confirmed", "high", None),
    }
    with SqlTraustUnitOfWork(world.context.database) as uow:
        assert [uow.findings.get(f.id).kind for f in world.findings] == [
            "weakness",
            "vulnerability",
            "weakness",
        ]
        assert uow.decisions.list_for_finding(world.findings[2].id) == []
        [pending] = uow.review_items.list_for_finding(world.findings[2].id)
        assert pending.reason == "undetermined_finding" and pending.decision_id is None
        artifact = uow.artifacts.get(UUID(decisions[0]["artifact_id"]))
        assessment = uow.assessments.get(UUID(decisions[0]["assessment_id"]))
    assert receipt["assessment_id"] == str(assessment.id)
    assert receipt["artifact_id"] == str(artifact.id)
    assert assessment.baseline_assessment_id == world.assessment_id
    assert assessment.occurred_at == T0
    assert assessment.run_order_id == world.order_id
    assert (
        world.context.object_store.get(
            world.context.object_store.stat(ObjectKey.parse(artifact.uri))
        )
        == world.body["payload"].encode()
    )
    assert (
        world.client.post(world.path, json=world.body, headers=runner(world.context)).json()
        == receipt
    )
    with SqlTraustUnitOfWork(world.context.database) as uow:
        assert all(len(uow.decisions.list_for_finding(f.id)) == 1 for f in world.findings[:2])
        assert len(uow.review_items.list_for_finding(world.findings[2].id)) == 1


@pytest.mark.parametrize("valid_citation", [False, True])
def test_native_source_citations_control_autoaccept_not_a_client_filesystem_path(
    world: TriageWorld, valid_citation: bool
) -> None:
    document = json.loads(world.body["payload"])
    document["findings"] = [
        {
            **document["findings"][0],
            "kind": "vulnerability",
            "verdict": "false_positive",
            "exclusion_rule": 2,
            "claimed_severity": "low",
            "confidence": 9,
            "refute_reasons": ["guard before use"],
            "rationale": "Observed guard at entry.c:1" if valid_citation else "guard at ghost.c:1",
            "first_links": ["entry.c:1" if valid_citation else "ghost.c:1"],
            "vote_breakdown": {
                "true_positive": 0,
                "hardening": 0,
                "false_positive": 3,
                "cannot_verify": 0,
            },
        }
    ]
    document["summary"].update(
        input_count=1, true_positives=0, hardening=0, false_positives=1, undetermined=0
    )
    document["summary"]["by_severity"]["high"] = 0
    body = {**world.body, "payload": json.dumps(document)}
    response = world.client.post(world.path, json=body, headers=runner(world.context))
    assert response.status_code == 200, response.text
    [decision] = response.json()["decisions"]
    assert decision["validity"] == "false_positive"
    assert decision["actor"] is None
    assert decision["auto_accept_tier"] is valid_citation


@pytest.mark.parametrize("fault", ["legacy", "unknown-kind", "wrong-fingerprint", "malformed"])
def test_refused_triage_does_not_publish_partial_records(world: TriageWorld, fault: str) -> None:
    document = json.loads(world.body["payload"])
    if fault == "legacy":
        document["findings"][1]["verdict"] = "hardening"
    elif fault == "unknown-kind":
        document["findings"][1]["kind"] = "miscellaneous"
    elif fault == "wrong-fingerprint":
        document["findings"][1]["fingerprint"] = "f" * 64
    body = {**world.body, "payload": "{" if fault == "malformed" else json.dumps(document)}
    response = world.client.post(world.path, json=body, headers=runner(world.context))
    assert response.status_code == 422, response.text
    with SqlTraustUnitOfWork(world.context.database) as uow:
        source = uow.assessments.get(world.assessment_id)
        assert uow.assessments.list_for_refs([source.repository_ref_id], "triage") == []
        for finding in world.findings:
            assert uow.findings.get(finding.id).kind is None
            assert uow.decisions.list_for_finding(finding.id) == []
            assert uow.review_items.list_for_finding(finding.id) == []
    assert list(world.context.object_store.list()) == []


@pytest.mark.parametrize("field", ["checkout", "assessment_id", "actor", "signer"])
def test_triage_rejects_client_paths_and_forged_authority(world: TriageWorld, field: str) -> None:
    response = world.client.post(
        world.path,
        json={**world.body, field: "/private/server/data"},
        headers=runner(world.context),
    )
    assert response.status_code == 422, response.text


def test_unknown_assessment_cannot_be_replaced_by_a_report_label(world: TriageWorld) -> None:
    missing = world.client.post(
        f"/v1/assessments/{uuid4()}/triage-records", json=world.body, headers=runner(world.context)
    )
    assert missing.status_code == 404
    label = world.client.post(
        "/v1/assessments/EXAMPLE-abcdef0-001/triage-records",
        json=world.body,
        headers=runner(world.context),
    )
    assert label.status_code == 422


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer invalid"}])
def test_triage_prepare_and_record_require_a_verified_caller(
    world: TriageWorld, headers: dict
) -> None:
    assert world.client.post(world.path, json=world.body, headers=headers).status_code == 401
    assert (
        world.client.get(
            f"/v1/assessments/{world.assessment_id}/triage-input", headers=headers
        ).status_code
        == 401
    )


def test_prepare_returns_native_finding_and_occurrence_bindings(world: TriageWorld) -> None:
    response = world.client.get(
        f"/v1/assessments/{world.assessment_id}/triage-input", headers=runner(world.context)
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["subject"]["assessment_id"] == str(world.assessment_id)
    assert {item["finding"]["id"] for item in body["items"]} == {str(f.id) for f in world.findings}
    assert all(
        item["occurrence"]["assessment_id"] == str(world.assessment_id) for item in body["items"]
    )


def test_review_only_triage_still_returns_native_recording_ids(world: TriageWorld) -> None:
    document = json.loads(world.body["payload"])
    for finding in document["findings"]:
        finding.update(verdict="undetermined", severity=None, confidence=0)
    document["summary"].update(true_positives=0, hardening=0, undetermined=3)
    document["summary"]["by_severity"]["high"] = 0
    body = {**world.body, "payload": json.dumps(document)}
    response = world.client.post(world.path, json=body, headers=runner(world.context))
    assert response.status_code == 200, response.text
    receipt = response.json()
    assert receipt["decisions"] == []
    with SqlTraustUnitOfWork(world.context.database) as uow:
        assessment = uow.assessments.get(UUID(receipt["assessment_id"]))
        artifact = uow.artifacts.get(UUID(receipt["artifact_id"]))
        assert assessment.baseline_assessment_id == world.assessment_id
        assert artifact.assessment_id == assessment.id
        assert all(not uow.decisions.list_for_finding(f.id) for f in world.findings)
        reviews = [uow.review_items.list_for_finding(f.id) for f in world.findings]
    assert all(len(items) == 1 and items[0].reason == "undetermined_finding" for items in reviews)
    retry = world.client.post(world.path, json=body, headers=runner(world.context))
    assert retry.status_code == 200 and retry.json() == receipt
    with SqlTraustUnitOfWork(world.context.database) as uow:
        assert [uow.review_items.list_for_finding(f.id) for f in world.findings] == reviews


def test_forge_failure_is_not_treated_as_missing_citation_evidence(
    world: TriageWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider, _, _ = forge({}, github={"git/trees/": (503, "HTTP 503 Service Unavailable")})
    monkeypatch.setattr(
        "traust_core.v1.context.context.command_source", lambda *args, **kwargs: provider
    )
    response = world.client.post(world.path, json=world.body, headers=runner(world.context))
    assert response.status_code == 500
    with SqlTraustUnitOfWork(world.context.database) as uow:
        source = uow.assessments.get(world.assessment_id)
        assert uow.assessments.list_for_refs([source.repository_ref_id], "triage") == []
        assert all(not uow.decisions.list_for_finding(f.id) for f in world.findings)
        assert all(uow.findings.get(f.id).kind is None for f in world.findings)


def recording_snapshot(world: TriageWorld) -> dict:
    with SqlTraustUnitOfWork(world.context.database) as uow:
        return {
            name: tuple(uow.connection.execute(sa.select(getattr(uow, name).table)))
            for name in (
                "assessments",
                "artifacts",
                "findings",
                "decisions",
                "review_items",
                "run_orders",
                "events",
                "layers",
                "finding_external_refs",
            )
        }


@pytest.mark.parametrize("human", [False, True])
def test_unrelated_runner_or_read_only_human_cannot_record_triage(
    world: TriageWorld, human: bool
) -> None:
    before = recording_snapshot(world)
    headers = bearer(world.context) if human else runner(world.context, "unrelated")
    response = world.client.post(world.path, json=world.body, headers=headers)
    assert response.status_code == 403, response.text
    assert recording_snapshot(world) == before


def test_in_process_protected_triage_also_denies_an_unrelated_runner(world: TriageWorld) -> None:
    token = world.context.local_issuer.mint("unrelated", machine=True).token
    unrelated = world.context.identity.authenticate(Credential(token=token))
    before = recording_snapshot(world)
    with pytest.raises(ForbiddenError):
        world.context.services().findings.decisions.record_triage(
            world.assessment_id,
            TriageArtifact.parse(world.body["payload"].encode()),
            Provenance.model_validate(world.body["provenance"]),
            run_order_id=world.order_id,
            principal=unrelated,
        )
    assert recording_snapshot(world) == before


@pytest.mark.parametrize(
    ("fault", "status"),
    [
        ("repository", 403),
        ("asset", 403),
        ("expired", 409),
        ("finished", 409),
        ("run-id", 422),
        ("source", 422),
        ("default-deny", 403),
    ],
)
def test_triage_authority_and_provenance_refusals_precede_all_report_mutations(
    world: TriageWorld, fault: str, status: int
) -> None:
    body = json.loads(json.dumps(world.body))
    ops = world.context.services().ops
    if fault in {"repository", "asset"}:
        with SqlTraustUnitOfWork(world.context.database) as uow:
            source = uow.assessments.get(world.assessment_id)
            repository_id = uow.repository_refs.get(source.repository_ref_id).repository_id
            if fault == "repository":
                repository_id = Seed(uow).repository().id
                uow.commit()
        order = ops.start(
            OrderRequest(
                asset="unrelated" if fault == "asset" else "triage",
                priority=1,
                repository_id=repository_id,
            ),
            world.principal,
            WorkerId(world.principal.ref),
            timedelta(minutes=10),
        )
        body["run_order_id"] = str(order.id)
        body["provenance"]["run_id"] = str(order.id)
    elif fault == "expired":
        with SqlTraustUnitOfWork(world.context.database) as uow:
            order = uow.run_orders.get(world.order_id)
            uow.run_orders.update(
                order.model_copy(
                    update={"lease_expires_at": datetime.now(UTC) - timedelta(seconds=1)}
                )
            )
            uow.commit()
    elif fault == "finished":
        ops.complete(world.order_id, WorkerId(world.principal.ref), JobResult.succeeded())
    elif fault == "run-id":
        body["provenance"]["run_id"] = str(uuid4())
    elif fault == "source":
        body["provenance"]["source"] = SourceType.VALIDATION_REPORT.value
    elif fault == "default-deny":
        world.context.config = world.context.config.model_copy(
            update={"recording": RecordingConfig()}
        )
    before = recording_snapshot(world)
    response = world.client.post(world.path, json=body, headers=runner(world.context))
    assert response.status_code == status, response.text
    assert recording_snapshot(world) == before


def test_triage_replay_cannot_adopt_another_orders_assessment(world: TriageWorld) -> None:
    response = world.client.post(world.path, json=world.body, headers=runner(world.context))
    assert response.status_code == 200, response.text
    with SqlTraustUnitOfWork(world.context.database) as uow:
        source = uow.assessments.get(world.assessment_id)
        repository_id = uow.repository_refs.get(source.repository_ref_id).repository_id
    order = world.context.services().ops.start(
        OrderRequest(asset="triage_again", priority=1, repository_id=repository_id),
        world.principal,
        WorkerId(world.principal.ref),
        timedelta(minutes=10),
    )
    body = json.loads(json.dumps(world.body))
    body["run_order_id"] = str(order.id)
    body["provenance"]["run_id"] = str(order.id)
    before = recording_snapshot(world)
    denied = world.client.post(world.path, json=body, headers=runner(world.context))
    assert denied.status_code == 409, denied.text
    assert recording_snapshot(world) == before
