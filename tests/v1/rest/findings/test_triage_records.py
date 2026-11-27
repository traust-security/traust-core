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
    Api,
    forge,
    http,
)
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer
from tests.v1.rest.ops.conftest import runner
from tests.v1.services.test_ledger import keys as keys
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import RecordingConfig
from traust_core.v1.errors import ConflictError, ForbiddenError, PreflightError, ServiceError
from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import Finding
from traust_core.v1.models.identity import Credential, Principal
from traust_core.v1.models.operations import JobResult, OrderRequest, WorkerId
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey, ObjectRef
from traust_core.v1.rest.app import create_app
from traust_core.v1.services.findings.review import ReviewConfig
from traust_core.v1.services.identity import IdentityConfig
from traust_core.v1.services.ledger import LedgerConfig


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
    request: pytest.FixtureRequest,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    keys: tuple[str, str],
) -> Iterator[TriageWorld]:
    text = "void parse(void) { /* observed guard */ }\n"
    monkeypatch.setenv("TRIAGE_TEST_SALT", "synthetic-test-salt")
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
                ledger=LedgerConfig(
                    required=True, key_path=Path(keys[0]), public_key_path=Path(keys[1])
                ),
                recording=RecordingConfig(triage=("triage", "triage_again")),
                review=ReviewConfig(valve_salt_env="TRIAGE_TEST_SALT"),
            ),
        )
        context.__dict__["database"] = engine
        with SqlTraustUnitOfWork(engine) as uow:
            seed = Seed(uow)
            repository = seed.repository(url=str(GITHUB))
            ref = seed.repository_ref(repository, sha=str(SHA), is_default=True)
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
        provenance = Provenance(
            run_id=order.id,
            source=SourceType.TRIAGE_REPORT,
            occurred_at=datetime(2026, 10, 5, tzinfo=UTC),
        )
        body = {
            "run_order_id": str(order.id),
            "lease_generation": order.lease_generation,
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
    assert assessment.occurred_at == Provenance.model_validate(world.body["provenance"]).occurred_at
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
        [layer] = uow.layers.list_for_repository(world.findings[0].repository_id)
        assert layer.merkle_size == 2 and layer.merkle_root_signature
        assert {event.decision_id for event in uow.events.list_for_layer(layer.id)} == {
            UUID(d["id"]) for d in decisions
        }
    assert world.context.services().ledger.verify(layer.id).passed


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


@pytest.mark.parametrize("generation", [None, 0, -1, True, "1", 1.5])
def test_triage_needs_an_explicit_positive_integer_generation(
    world: TriageWorld, generation: object
) -> None:
    body = dict(world.body)
    if generation is None:
        del body["lease_generation"]
    else:
        body["lease_generation"] = generation
    before = recording_snapshot(world)
    response = world.client.post(world.path, json=body, headers=runner(world.context))
    assert response.status_code == 422, response.text
    assert recording_snapshot(world) == before
    assert list(world.context.object_store.list()) == []


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
    assert response.status_code == 502  # the forge is an upstream core relays, not a bug
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


def test_reclaim_during_forge_read_fences_triage_before_any_writes(
    world: TriageWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = Api._answer
    fetches = 0
    generation: int | None = None

    def answer(api: Api, endpoint: str) -> str:
        nonlocal fetches, generation
        fetches += 1
        if generation is None:
            with SqlTraustUnitOfWork(world.context.database) as other:
                if other.connection.dialect.name == "postgresql":
                    other.connection.exec_driver_sql("SET LOCAL lock_timeout = '1s'")
                order = other.run_orders.get(world.order_id)
                other.run_orders.update(
                    order.model_copy(update={"lease_expires_at": order.started_at})
                )
                other.commit()
            reclaimed = world.context.services().ops.claim(
                WorkerId(world.principal.ref), timedelta(minutes=10), order_id=world.order_id
            )
            assert reclaimed is not None and reclaimed.id == world.order_id
            generation = reclaimed.lease_generation
        return original(api, endpoint)

    monkeypatch.setattr(Api, "_answer", answer)
    headers = runner(world.context)
    before = recording_snapshot(world)
    objects = tuple(world.context.object_store.list())
    stale = world.client.post(world.path, json=world.body, headers=headers)
    assert stale.status_code == 409, stale.text
    assert generation == world.body["lease_generation"] + 1
    after = recording_snapshot(world)
    assert after.pop("run_orders") != before.pop("run_orders")
    assert after == before
    assert tuple(world.context.object_store.list()) == objects
    fetched = fetches
    assert world.client.post(world.path, json=world.body, headers=headers).status_code == 409
    assert fetches == fetched
    body = {**world.body, "lease_generation": generation}
    current = world.client.post(world.path, json=body, headers=headers)
    assert current.status_code == 200, current.text
    assert fetches > fetched
    fetched = fetches
    replay = world.client.post(world.path, json=body, headers=headers)
    assert replay.status_code == 200 and replay.json() == current.json()
    assert fetches == fetched


@pytest.mark.parametrize("policy", ["no-ledger", "optional-signing"])
def test_a_ready_planner_cannot_admit_an_unready_triage_writer(
    world: TriageWorld, policy: str
) -> None:
    config = world.context.config
    assert config.ledger is not None
    planner = world.client.post(
        "/v1/preflight",
        json={"asset": "triage", "repository_id": str(world.findings[0].repository_id)},
        headers=bearer(world.context),
    )
    assert planner.status_code == 200, planner.text
    ledger = None if policy == "no-ledger" else config.ledger.model_copy(update={"required": False})
    writer = Context(config.model_copy(update={"ledger": ledger}))
    writer.__dict__["database"] = world.context.database
    before = recording_snapshot(world)
    message = "requires a ledger" if ledger is None else "ledger.required: true"
    with pytest.raises(PreflightError, match=message):
        create_app(writer)
    decisions = writer.services().findings.decisions
    assert decisions.prepare(world.assessment_id).items
    with pytest.raises(ServiceError, match=message):
        decisions.record_triage(
            world.assessment_id,
            TriageArtifact.parse(world.body["payload"].encode()),
            Provenance.model_validate(world.body["provenance"]),
            run_order_id=world.order_id,
            principal=world.principal,
            lease_generation=world.body["lease_generation"],
        )
    assert recording_snapshot(world) == before
    assert list(writer.object_store.list()) == []


@pytest.mark.parametrize(
    ("fault", "message"),
    [
        ("identity", "no verified identity configured"),
        ("issuer", "no verified issuer"),
        ("missing-keys", "no usable local JWKS"),
        ("salt-name", "salt is missing"),
        ("missing-salt", "names unset variable WRITER_ONLY_SALT"),
        ("blank-salt", "salt is missing or blank"),
    ],
)
def test_triage_startup_uses_the_writers_own_verifier_and_salt(
    world: TriageWorld, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fault: str, message: str
) -> None:
    # A healthy, independently composed app cannot supply this writer's missing capability.
    create_app(Context(world.context.config))
    cfg = world.context.config
    if fault == "identity":
        cfg = cfg.model_copy(update={"identity": None})
    elif fault == "issuer":
        cfg = cfg.model_copy(update={"identity": IdentityConfig()})
    elif fault == "missing-keys":
        cfg = cfg.model_copy(update={"home": tmp_path / "fresh-writer"})
    elif fault == "salt-name":
        cfg = cfg.model_copy(update={"review": ReviewConfig()})
    else:
        cfg = cfg.model_copy(update={"review": ReviewConfig(valve_salt_env="WRITER_ONLY_SALT")})
        if fault == "blank-salt":
            monkeypatch.setenv("WRITER_ONLY_SALT", "  ")
        else:
            monkeypatch.delenv("WRITER_ONLY_SALT", raising=False)
    writer = Context(cfg)
    with pytest.raises(PreflightError, match=message):
        create_app(writer)
    assert "database" not in writer.__dict__


def test_loss_of_signer_after_admission_rolls_back_the_whole_order(
    world: TriageWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = world.context.object_store
    put = store.put
    staged = []

    def lose_signer(key: ObjectKey, payload: bytes) -> ObjectRef:
        staged.append(key)
        monkeypatch.setenv("COSIGN_PASSWORD", "incorrect-after-admission")
        return put(key, payload)

    monkeypatch.setattr(store, "put", lose_signer)
    before = recording_snapshot(world)
    response = world.client.post(world.path, json=world.body, headers=runner(world.context))
    assert staged and response.status_code == 500, response.text
    assert recording_snapshot(world) == before


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
            lease_generation=world.body["lease_generation"],
        )
    assert recording_snapshot(world) == before


@pytest.mark.parametrize(
    ("fault", "status"),
    [
        ("repository", 403),
        ("asset", 403),
        ("remediation lease", 403),
        ("expired", 409),
        ("finished", 409),
        ("wrong-generation", 409),
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
    if fault == "remediation lease":
        # The remediation door shares the triage allowlist (NEED: contracts has no
        # recording.remediation section yet), so the operator's triage list carries
        # the remediation asset — a remediation order's lease must still be refused
        # here: only a triage order records triage.
        world.context.config = world.context.config.model_copy(
            update={
                "recording": world.context.config.recording.model_copy(
                    update={"triage": ("triage", "triage_again", "remediate_finding")}
                )
            }
        )
        with SqlTraustUnitOfWork(world.context.database) as uow:
            source = uow.assessments.get(world.assessment_id)
            repository_id = uow.repository_refs.get(source.repository_ref_id).repository_id
            # only the scheduling door queues remediate_finding; the runner's start takes
            # the door's order over rather than storing a new one
            Seed(uow).run_order(asset="remediate_finding", priority=1, repository_id=repository_id)
            uow.commit()
        order = ops.start(
            OrderRequest(asset="remediate_finding", priority=1, repository_id=repository_id),
            world.principal,
            WorkerId(world.principal.ref),
            timedelta(minutes=10),
        )
        body["run_order_id"] = str(order.id)
        body["provenance"]["run_id"] = str(order.id)
        body["lease_generation"] = order.lease_generation
    elif fault in {"repository", "asset"}:
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
        body["lease_generation"] = order.lease_generation
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
        ops.complete(
            world.order_id,
            WorkerId(world.principal.ref),
            JobResult.succeeded(),
            lease_generation=body["lease_generation"],
        )
    elif fault == "wrong-generation":
        body["lease_generation"] += 1
    elif fault == "run-id":
        body["provenance"]["run_id"] = str(uuid4())
    elif fault == "source":
        body["provenance"]["source"] = SourceType.VALIDATION_REPORT.value
    elif fault == "default-deny":
        world.context.config = world.context.config.model_copy(
            update={"recording": RecordingConfig()}
        )
    before = recording_snapshot(world)
    objects = tuple(world.context.object_store.list())
    response = world.client.post(world.path, json=body, headers=runner(world.context))
    assert response.status_code == status, response.text
    assert recording_snapshot(world) == before
    assert tuple(world.context.object_store.list()) == objects


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
    body["lease_generation"] = order.lease_generation
    before = recording_snapshot(world)
    denied = world.client.post(world.path, json=body, headers=runner(world.context))
    assert denied.status_code == 409, denied.text
    assert recording_snapshot(world) == before


def test_reclaimed_triage_returns_original_and_refuses_stale_attempt_bytes_and_baseline(
    world: TriageWorld,
) -> None:
    headers = runner(world.context)
    first = world.client.post(world.path, json=world.body, headers=headers)
    assert first.status_code == 200, first.text
    with SqlTraustUnitOfWork(world.context.database) as uow:
        order = uow.run_orders.get(world.order_id)
        uow.run_orders.update(order.model_copy(update={"lease_expires_at": order.started_at}))
        source = uow.assessments.get(world.assessment_id)
        seed = Seed(uow)
        other = seed.assessment(uow.repository_refs.get(source.repository_ref_id))
        for finding in world.findings:
            seed.occurrence(finding, other)
        uow.commit()
    claimed = world.client.post(
        "/v1/orders/claim",
        json={"order_id": str(world.order_id), "lease_seconds": 60},
        headers=headers,
    )
    assert claimed.status_code == 200, claimed.text
    latest = claimed.json()
    assert latest["id"] == str(world.order_id)
    assert latest["lease_holder"] == world.principal.ref
    assert latest["lease_generation"] == world.body["lease_generation"] + 1
    current = {**world.body, "lease_generation": latest["lease_generation"]}
    before = recording_snapshot(world)
    objects = tuple(world.context.object_store.list())
    replay = world.client.post(world.path, json=current, headers=headers)
    assert replay.status_code == 200 and replay.json() == first.json()
    for path, request in (
        (world.path, world.body),
        (world.path, {**current, "payload": current["payload"] + " "}),
        (f"/v1/assessments/{other.id}/triage-records", current),
    ):
        refused = world.client.post(path, json=request, headers=headers)
        assert refused.status_code == 409, refused.text
    with pytest.raises(ConflictError, match="run order binding"):
        world.context.services().findings.decisions.record(
            world.assessment_id,
            TriageArtifact.parse(world.body["payload"].encode()),
            Provenance.model_validate(world.body["provenance"]),
        )
    assert recording_snapshot(world) == before
    assert tuple(world.context.object_store.list()) == objects
