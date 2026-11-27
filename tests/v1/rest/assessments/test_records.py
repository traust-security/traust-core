from __future__ import annotations

import json
import os
import socket
import subprocess
from collections.abc import Iterator, Sequence
from datetime import timedelta
from pathlib import Path
from threading import Thread
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
import uvicorn
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer
from tests.v1.rest.ops.conftest import runner
from tests.v1.services.test_assessment_record import WHEN
from tests.v1.services.test_assessment_record_findings import finding, report
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import RecordingConfig
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.artifacts import SecurityAuditArtifact
from traust_core.v1.models.assessment import AssessmentKind, AssessmentRecordResult
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import FindingCandidate, IntakeResult
from traust_core.v1.models.identity import Credential, Principal
from traust_core.v1.models.operations import (
    JobResult,
    OrderReason,
    OrderRequest,
    OrderState,
    RecordingStartScope,
    RunOrder,
    WorkerId,
)
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import CONTRACT_TABLES, SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey, ObjectRef
from traust_core.v1.rest.app import create_app
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.findings.intake import FindingIntake
from traust_core.v1.services.identity import IdentityConfig

URL = "/v1/assessment-records"
DOC = report(
    finding("AUDIT-1", "src/auth.py", "14-19", kind="weakness", validation_status="confirmed"),
    finding("AUDIT-2", "src/token.py", "40", kind="weakness", cwes=["CWE-287"]),
)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as database:
        yield database


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    context = Context(
        Config(
            home=tmp_path,
            identity=IdentityConfig(trust_local=True),
            recording=RecordingConfig(assessment=("audit",)),
        )
    )
    context.local_issuer.mint("runner-7", machine=True)
    context.__dict__["database"] = engine
    return context


@pytest.fixture
def ref(context: Context) -> UUID:
    with SqlTraustUnitOfWork(context.database) as uow:
        saved = Seed(uow).repository_ref(is_default=True)
        uow.commit()
    assert saved.id is not None
    return saved.id


def principal(context: Context) -> Principal:
    assert context.identity is not None
    token = context.local_issuer.mint("runner-7", machine=True).token
    return context.identity.authenticate(Credential(token=token))


def leased(context: Context, ref: UUID, asset: str = "audit") -> RunOrder:
    services = context.services()
    repository_id = services.portfolio.inventory.get_ref(ref).repository_id
    return services.ops.start(
        OrderRequest(asset=asset, priority=1, repository_id=repository_id),
        principal(context),
        WorkerId(principal(context).ref),
        timedelta(minutes=5),
    )


def body(context: Context, ref: UUID, doc: SecurityAuditArtifact = DOC) -> dict[str, object]:
    order = leased(context, ref)
    return {
        "run_order_id": str(order.id),
        "lease_generation": order.lease_generation,
        "repository_ref_id": str(ref),
        "payload": doc.payload.decode("utf-8"),
        "provenance": Provenance(
            run_id=order.id, source=SourceType.VULN_SCAN_REPORT, occurred_at=WHEN
        ).model_dump(mode="json"),
        "assessor_version": "1.2.3",
    }


def rows(context: Context) -> dict[str, tuple[tuple[object, ...], ...]]:
    with SqlTraustUnitOfWork(context.database) as uow:
        return {
            spec.name: tuple(
                tuple(row)
                for row in uow.connection.execute(
                    sa.select(uow.tables.table(spec)).order_by(*uow.tables.table(spec).primary_key)
                )
            )
            for spec in CONTRACT_TABLES
        }


def test_authored_claims_record_exact_bytes_and_unjudged_native_findings(
    context: Context, client: TestClient, ref: UUID
) -> None:
    document = json.loads(DOC.payload)
    document["title"] += " — contrôle"
    payload = " \n" + json.dumps(document, ensure_ascii=False, indent=3) + "\n\t"
    request = body(context, ref, SecurityAuditArtifact.parse(payload.encode("utf-8")))
    response = client.post(URL, json=request, headers=runner(context))
    assert response.status_code == 200, response.text
    result = AssessmentRecordResult.model_validate(response.json())
    assert set(result.intake.findings) == {"AUDIT-1", "AUDIT-2"}
    assert set(result.intake.created) == set(result.intake.findings.values())
    services = context.services()
    assessment = services.assessment.get(result.assessment_id)
    assert (assessment.kind, assessment.assessor, assessment.assessor_version) == (
        "secure_code",
        "skill:secure-code-audit",
        "1.2.3",
    )
    assert str(assessment.run_order_id) == request["run_order_id"]
    assert assessment.occurred_at == WHEN
    assert services.artifacts.payload(result.artifact_id) == payload.encode("utf-8")
    assert services.artifacts.metadata(result.artifact_id).assessment_id == assessment.id
    with SqlTraustUnitOfWork(context.database) as uow:
        assert len(uow.occurrences.list_for_assessment(result.assessment_id)) == 2
        for finding_id in result.intake.findings.values():
            assert uow.findings.get(finding_id).kind == "weakness"
            assert uow.decisions.list_for_finding(finding_id) == []
    before = rows(context)
    replay = client.post(URL, json=request, headers=runner(context))
    assert replay.status_code == 200, replay.text
    repeated = AssessmentRecordResult.model_validate(replay.json())
    assert repeated.assessment_id == result.assessment_id
    assert repeated.artifact_id == result.artifact_id
    assert repeated.intake.findings == result.intake.findings
    assert repeated.intake.created == ()
    assert rows(context) == before
    same = services.assessment.record_secure_code(
        SecurityAuditArtifact.parse(payload.encode("utf-8")),
        ref,
        "1.2.3",
        Provenance.model_validate(request["provenance"]),
        run_order_id=UUID(request["run_order_id"]),
        lease_generation=request["lease_generation"],
        principal=principal(context),
    )
    assert same == repeated


@pytest.mark.parametrize(
    ("fault", "status"),
    [
        ("human", 403),
        ("runner", 403),
        ("asset", 403),
        ("capability", 403),
        ("repository", 403),
        ("provenance", 422),
        ("source", 422),
        ("unknown-order", 404),
        ("missing-generation", 422),
        ("null-generation", 422),
        ("zero-generation", 422),
        ("bool-generation", 422),
        ("string-generation", 422),
        ("wrong-generation", 409),
        ("expired", 409),
    ],
)
def test_authored_recording_rejects_unowned_or_mismatched_recording_context(
    context: Context, client: TestClient, ref: UUID, fault: str, status: int
) -> None:
    request = body(context, ref)
    headers = runner(context)
    if fault == "human":
        headers = bearer(context)
    elif fault == "runner":
        headers = runner(context, "other-runner")
    elif fault == "capability":
        context.config = context.config.model_copy(
            update={"recording": context.config.recording.model_copy(update={"assessment": ()})}
        )
    elif fault == "repository":
        with SqlTraustUnitOfWork(context.database) as uow:
            seed = Seed(uow)
            other = seed.repository_ref(
                seed.repository(url="https://github.com/example-org/unrelated-source")
            )
            uow.commit()
        request["repository_ref_id"] = str(other.id)
    elif fault == "provenance":
        request["provenance"]["run_id"] = str(uuid4())
    elif fault == "source":
        request["provenance"]["source"] = SourceType.TRIAGE_REPORT.value
    elif fault == "unknown-order":
        request["run_order_id"] = str(uuid4())
    elif fault == "missing-generation":
        del request["lease_generation"]
    elif fault == "null-generation":
        request["lease_generation"] = None
    elif fault == "zero-generation":
        request["lease_generation"] = 0
    elif fault == "bool-generation":
        request["lease_generation"] = True
    elif fault == "string-generation":
        request["lease_generation"] = str(request["lease_generation"])
    elif fault == "wrong-generation":
        request["lease_generation"] += 1
    elif fault in {"asset", "expired"}:
        with SqlTraustUnitOfWork(context.database) as uow:
            held = uow.run_orders.get(UUID(request["run_order_id"]))
            update = {"asset": "unsupported"} if fault == "asset" else {"lease_expires_at": WHEN}
            uow.run_orders.update(held.model_copy(update=update))
            uow.commit()
    before = rows(context)
    objects = tuple(context.object_store.list())
    response = client.post(URL, json=request, headers=headers)
    assert response.status_code == status, response.text
    assert response.headers["content-type"] == "application/problem+json"
    assert rows(context) == before
    assert tuple(context.object_store.list()) == objects


@pytest.mark.parametrize("fault", ["effort", "validity", "location"])
def test_new_authored_recording_requires_canonical_report_and_existing_intake_checks(
    context: Context, client: TestClient, ref: UUID, fault: str
) -> None:
    request = body(context, ref)
    document = json.loads(DOC.payload)
    if fault == "effort":
        document["findings"][0]["remediation_effort"] = "moderate"
    elif fault == "validity":
        document["findings"][0]["validation_status"] = "hardening"
    else:
        document["findings"][0]["locations"] = [{"path": "."}]
    request["payload"] = json.dumps(document)
    before = rows(context)
    response = client.post(URL, json=request, headers=runner(context))
    assert response.status_code == 422, response.text
    assert rows(context) == before


def test_schema_permitted_priority_keeps_original_bytes_in_explicit_authored_recording(
    context: Context, client: TestClient, ref: UUID
) -> None:
    document = json.loads(DOC.payload)
    document["remediation_roadmap"][0]["priority"] = "P3"
    payload = " \n" + json.dumps(document, ensure_ascii=False, indent=3) + "\n\t"
    request = body(context, ref, SecurityAuditArtifact.parse(payload.encode("utf-8")))
    response = client.post(URL, json=request, headers=runner(context))
    assert response.status_code == 200, response.text
    result = AssessmentRecordResult.model_validate(response.json())
    assert context.services().artifacts.payload(result.artifact_id) == payload.encode("utf-8")
    before = rows(context)
    replay = client.post(URL, json=request, headers=runner(context))
    assert replay.status_code == 200, replay.text
    repeated = AssessmentRecordResult.model_validate(replay.json())
    assert (repeated.assessment_id, repeated.artifact_id, repeated.intake.findings) == (
        result.assessment_id,
        result.artifact_id,
        result.intake.findings,
    )
    assert rows(context) == before


@pytest.mark.parametrize("initial", ["unbound", "other-order"])
def test_authored_replay_never_adopts_an_unbound_or_differently_bound_assessment(
    context: Context, client: TestClient, ref: UUID, initial: str
) -> None:
    services = context.services()
    if initial == "unbound":
        first = services.assessment.record(
            DOC,
            ref,
            AssessmentKind.SECURE_CODE_CANONICAL,
            "skill:secure-code-audit",
            "1.2.3",
            Provenance(run_id=uuid4(), source=SourceType.VULN_SCAN_REPORT, occurred_at=WHEN),
        )
        original_order = None
    else:
        request = body(context, ref)
        response = client.post(URL, json=request, headers=runner(context))
        assert response.status_code == 200, response.text
        result = AssessmentRecordResult.model_validate(response.json())
        first = services.assessment.get(result.assessment_id)
        original_order = first.run_order_id
        services.ops.complete(
            original_order,
            WorkerId(principal(context).ref),
            JobResult.succeeded(),
            lease_generation=request["lease_generation"],
        )
    request = body(context, ref)
    before = rows(context)
    response = client.post(URL, json=request, headers=runner(context))
    assert response.status_code == 409, response.text
    assert "belongs to order" in response.json()["detail"]
    assert rows(context) == before
    assert services.assessment.get(first.id).run_order_id == original_order


def test_matching_published_provenance_retains_exact_artifact_bytes(
    context: Context, client: TestClient, ref: UUID
) -> None:
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(SecurityAuditArtifact)))
    published = publisher.publish_ref(DOC)
    request = body(context, ref)
    request["provenance"]["artifact"] = published.model_dump(mode="json")
    response = client.post(URL, json=request, headers=runner(context))
    assert response.status_code == 200, response.text
    result = AssessmentRecordResult.model_validate(response.json())
    assert context.services().artifacts.payload(result.artifact_id) == DOC.payload


@pytest.mark.parametrize("fault", ["missing-artifact", "wrong-digest"])
def test_authored_recording_rejects_invalid_evidence_without_partial_intake(
    context: Context, client: TestClient, ref: UUID, fault: str
) -> None:
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(SecurityAuditArtifact)))
    evidence = publisher.publish_ref(report())
    request = body(context, ref)
    request["provenance"]["artifact"] = evidence.model_dump(mode="json")
    if fault == "missing-artifact":
        request["provenance"]["artifact"]["id"] = str(uuid4())
    before = rows(context)
    response = client.post(URL, json=request, headers=runner(context))
    assert response.status_code == (404 if fault == "missing-artifact" else 409), response.text
    assert rows(context) == before


@pytest.fixture
def interrupted_orders(monkeypatch: pytest.MonkeyPatch) -> list[RunOrder]:
    interrupted: list[RunOrder] = []
    accept = FindingIntake.accept

    def fail(
        self: FindingIntake, assessment_id: UUID, candidates: Sequence[FindingCandidate]
    ) -> IntakeResult:
        taken = accept(self, assessment_id, candidates)
        with self._uow as uow:
            assessment = uow.assessments.get(assessment_id)
            assert assessment.run_order_id is not None
            order = uow.run_orders.get(assessment.run_order_id)
            assert order.state == OrderState.LEASED
            assert len(taken.created) == 2
            occurrences = uow.occurrences.list_for_assessment(assessment_id)
            assert {row.finding_id for row in occurrences} == set(taken.created)
            (attached,) = uow.artifacts.list_for_assessment(assessment_id)
            assert uow.artifacts.find(None, attached.digest) is not None
            interrupted.append(order)
        raise ValidationError("intake failed after writing")

    monkeypatch.setattr(FindingIntake, "accept", fail)
    return interrupted


def test_nested_intake_failure_rolls_back_assessment_artifact_and_findings(
    context: Context, client: TestClient, ref: UUID, interrupted_orders: list[RunOrder]
) -> None:
    request = body(context, ref)
    before = rows(context)
    response = client.post(URL, json=request, headers=runner(context))
    assert response.status_code == 422, response.text
    assert [str(order.id) for order in interrupted_orders] == [request["run_order_id"]]
    assert rows(context) == before


@pytest.fixture
def dispatch_repository(context: Context, ref: UUID) -> UUID:
    repository_id = context.services().portfolio.inventory.get_ref(ref).repository_id
    scope = RecordingStartScope(
        principal=principal(context).ref, assets=("audit",), repository_ids=(repository_id,)
    )
    context.config = context.config.model_copy(
        update={"recording": context.config.recording.model_copy(update={"start": (scope,)})}
    )
    return repository_id


def run_sdk(
    context: Context,
    tmp_path: Path,
    ref: UUID,
    repository_id: UUID,
    tag: str,
    test: str,
) -> None:
    token = tmp_path / "runner.token"
    token.touch(mode=0o600)
    token.write_text(context.local_issuer.mint("runner-7", machine=True).token.get_secret_value())
    report_file = tmp_path / "report.json"
    report_file.write_bytes(DOC.payload)

    server = uvicorn.Server(
        uvicorn.Config(create_app(context), log_config=None, timeout_graceful_shutdown=2)
    )
    with socket.create_server(("127.0.0.1", 0)) as listener:
        thread = Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            subprocess.run(
                [
                    "go",
                    "test",
                    f"-tags={tag}",
                    "-v",
                    "-count=1",
                    "-timeout=60s",
                    f"-run=^{test}$",
                    "./v1/ops",
                ],
                env={
                    **os.environ,
                    "TRAUST_E2E_URL": f"http://127.0.0.1:{listener.getsockname()[1]}",
                    "TRAUST_E2E_RUNNER_TOKEN_FILE": str(token),
                    "TRAUST_E2E_REPOSITORY_ID": str(repository_id),
                    "TRAUST_E2E_REF_ID": str(ref),
                    "TRAUST_E2E_REPORT_FILE": str(report_file),
                },
                cwd=os.environ["TRAUST_TEST_SDK_GO"],
                timeout=180,
                check=True,
            )
        finally:
            server.should_exit = True
            thread.join(timeout=5)
            assert not thread.is_alive(), "SDK test server did not shut down"


@pytest.mark.skipif("TRAUST_TEST_SDK_GO" not in os.environ, reason="requires the Go SDK checkout")
def test_recording_runner_fails_the_order_after_intake_rollback(
    context: Context,
    ref: UUID,
    dispatch_repository: UUID,
    tmp_path: Path,
    interrupted_orders: list[RunOrder],
) -> None:
    before = rows(context)
    run_sdk(context, tmp_path, ref, dispatch_repository, "core_rollback", "TestCoreIntakeRollback")

    (held,) = interrupted_orders
    assert held.id is not None and held.started_at is not None
    assert held.lease_holder == principal(context).ref
    with SqlTraustUnitOfWork(context.database) as uow:
        failed = uow.run_orders.get(held.id)
        assert failed.state == OrderState.FAILED
        assert failed.reason == OrderReason.SESSION_OUTPUT_INVALID
        assert failed.started_at == held.started_at and failed.finished_at is not None
        assert failed.lease_holder is None and failed.lease_expires_at is None
        assert failed.artifact_id is None

    # Ledger layers/events and all SQL pointers participate; staged object bytes do not.
    after = rows(context)
    assert before.pop("run_order") == ()
    assert len(after.pop("run_order")) == 1
    assert after == before


@pytest.mark.skipif("TRAUST_TEST_SDK_GO" not in os.environ, reason="requires the Go SDK checkout")
def test_sdk_claim_reclaim_recording(context: Context, ref: UUID, tmp_path: Path) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        repository_id = uow.repository_refs.get(ref).repository_id
        order = Seed(uow).run_order(asset="audit", repository_id=repository_id)
        uow.commit()
    run_sdk(context, tmp_path, ref, repository_id, "core_reclaim", "TestCoreClaimReclaim")
    with SqlTraustUnitOfWork(context.database) as uow:
        (audit,) = uow.assessments.list_for_run_order(order.id)
        (report,) = uow.artifacts.list_for_assessment(audit.id)
        reclaimed = uow.run_orders.get(order.id)
        assert reclaimed.state == OrderState.SUCCEEDED
        assert reclaimed.lease_generation == 2
        assert audit.repository_ref_id == ref
        assert len(uow.occurrences.list_for_assessment(audit.id)) == 2
        assert len(uow.findings.list_for_repository(repository_id)) == 2
    assert context.services().artifacts.payload(report.id) == DOC.payload


def test_explicit_dispatched_worker_start_returns_real_source_ids(
    context: Context, client: TestClient, ref: UUID, dispatch_repository: UUID
) -> None:
    started = client.post(
        "/v1/orders/start",
        json={
            "order": {"asset": "audit", "priority": 1, "repository_id": str(dispatch_repository)},
            "lease_seconds": 300,
        },
        headers=runner(context),
    )
    assert started.status_code == 200, started.text
    request = {
        "run_order_id": started.json()["id"],
        "lease_generation": started.json()["lease_generation"],
        "repository_ref_id": str(ref),
        "payload": DOC.payload.decode("utf-8"),
        "provenance": Provenance(
            run_id=UUID(started.json()["id"]),
            source=SourceType.VULN_SCAN_REPORT,
            occurred_at=WHEN,
        ).model_dump(mode="json"),
        "assessor_version": "1.2.3",
    }
    response = client.post(URL, json=request, headers=runner(context))
    assert response.status_code == 200, response.text
    result = AssessmentRecordResult.model_validate(response.json())
    assert len(result.intake.findings) == 2
    content = client.get(f"/v1/artifacts/{result.artifact_id}/content", headers=bearer(context))
    assert content.status_code == 200 and content.content == DOC.payload


def test_recording_requires_authentication_and_rejects_extra_identity_fields(
    context: Context, client: TestClient, ref: UUID
) -> None:
    request = body(context, ref)
    before = rows(context)
    assert client.post(URL, json=request).status_code == 401
    request["principal"] = "machine:someone-else"
    assert client.post(URL, json=request, headers=runner(context)).status_code == 422
    assert rows(context) == before


def test_recording_service_needs_the_shared_operations_guard(context: Context, ref: UUID) -> None:
    service = AssessmentService(SqlTraustUnitOfWork(context.database))
    with pytest.raises(ConfigError, match="operations authorization"):
        service.record_secure_code(
            DOC,
            ref,
            "1.2.3",
            Provenance(run_id=uuid4(), source=SourceType.VULN_SCAN_REPORT, occurred_at=WHEN),
            run_order_id=uuid4(),
            lease_generation=1,
            principal=principal(context),
        )


@pytest.mark.parametrize("commit", ["b" * 40, "a" * 7, ""])
def test_authored_subject_mismatch_refuses_before_intake(
    context: Context, client: TestClient, ref: UUID, commit: str
) -> None:
    document = json.loads(DOC.payload)
    document["metadata"]["commit"] = commit
    request = body(context, ref, SecurityAuditArtifact.from_document(document))
    before = rows(context)
    refused = client.post(URL, json=request, headers=runner(context))
    assert refused.status_code == 422 and "metadata.commit" in refused.json()["detail"]
    assert rows(context) == before
    assert not list(context.object_store.list())


def test_an_order_cannot_replay_its_bytes_on_a_different_ref(
    context: Context, client: TestClient, ref: UUID
) -> None:
    request = body(context, ref)
    headers = runner(context)
    assert client.post(URL, json=request, headers=headers).status_code == 200
    with SqlTraustUnitOfWork(context.database) as uow:
        repo = uow.repositories.get(uow.repository_refs.get(ref).repository_id)
        other = Seed(uow).repository_ref(repo, sha="b" * 40)
        uow.commit()
    before = rows(context)
    request["repository_ref_id"] = str(other.id)
    refused = client.post(URL, json=request, headers=headers)
    assert refused.status_code == 409 and "different subject" in refused.json()["detail"]
    assert rows(context) == before


@pytest.mark.parametrize(
    "stamp", ["matching", "legacy-matching", "wrong-value", "wrong-algo", "algo-only"]
)
def test_authored_fingerprint_stamp_must_agree_with_native_intake(
    context: Context, client: TestClient, ref: UUID, stamp: str
) -> None:
    services = context.services()
    subject = services.portfolio.inventory.get_ref(ref)
    candidate = FindingCandidate.of_report(DOC.findings, subject.repository_id)[0]
    native = services.findings.intake.fingerprint(candidate)
    document = json.loads(DOC.payload)
    document["metadata"]["commit"] = subject.sha
    entry = document["findings"][0]
    if stamp != "algo-only":
        entry["fingerprint"] = "f" * 64 if stamp == "wrong-value" else native.value
    if stamp != "legacy-matching":
        entry["fingerprint_algo"] = "v999" if stamp == "wrong-algo" else native.algo
    request = body(context, ref, SecurityAuditArtifact.from_document(document))
    before = rows(context)
    result = client.post(URL, json=request, headers=runner(context))
    if stamp not in {"matching", "legacy-matching"}:
        assert result.status_code == 422 and "stamp mismatch" in result.json()["detail"]
        assert rows(context) == before
    else:
        assert result.status_code == 200, result.text
        receipt = AssessmentRecordResult.model_validate(result.json())
        saved = services.findings.intake.get(receipt.intake.findings[candidate.label])
        assert (saved.fingerprint_algo, saved.fingerprint) == (native.algo, native.value)
        assert services.artifacts.payload(receipt.artifact_id) == request["payload"].encode()


def test_same_principal_reclaim_during_staging_fences_the_old_first_write(
    context: Context, client: TestClient, ref: UUID, monkeypatch: pytest.MonkeyPatch
) -> None:
    context.__dict__["clock"] = FixedClock(context.clock.now())
    request = body(context, ref)
    order_id = UUID(request["run_order_id"])
    ops = context.services().ops
    old = ops.get(order_id)
    put = context.object_store.put
    reclaimed: list[RunOrder] = []

    def reclaim_after_upload(key: ObjectKey, payload: bytes) -> ObjectRef:
        stored = put(key, payload)
        if not reclaimed:
            with SqlTraustUnitOfWork(context.database) as uow:
                uow.run_orders.update(old.model_copy(update={"lease_expires_at": old.started_at}))
                uow.commit()
            new = ops.claim(WorkerId(old.lease_holder), timedelta(minutes=5), order_id=order_id)
            assert new is not None and new.lease_generation == old.lease_generation + 1
            assert new.started_at == old.started_at
            reclaimed.append(new)
        return stored

    before = rows(context)
    with monkeypatch.context() as patch:
        patch.setattr(context.object_store, "put", reclaim_after_upload)
        stale = client.post(URL, json=request, headers=runner(context))
    assert stale.status_code == 409, stale.text
    (new,) = reclaimed
    after = rows(context)
    assert after.pop("run_order") != before.pop("run_order")
    assert after == before
    current = {**request, "lease_generation": new.lease_generation}
    recorded = client.post(URL, json=current, headers=runner(context))
    assert recorded.status_code == 200, recorded.text


def test_exact_receipt_replay_after_same_worker_reclaim_uses_current_generation(
    context: Context, client: TestClient, ref: UUID
) -> None:
    request = body(context, ref)
    headers = runner(context)
    first = client.post(URL, json=request, headers=headers)
    assert first.status_code == 200, first.text
    order_id = UUID(request["run_order_id"])
    with SqlTraustUnitOfWork(context.database) as uow:
        held = uow.run_orders.get(order_id)
        uow.run_orders.update(held.model_copy(update={"lease_expires_at": held.started_at}))
        uow.commit()
    current = context.services().ops.claim(
        WorkerId(principal(context).ref), timedelta(minutes=5), order_id=order_id
    )
    assert current is not None and current.lease_generation == held.lease_generation + 1
    before = rows(context)
    assert client.post(URL, json=request, headers=headers).status_code == 409
    replay = client.post(
        URL, json={**request, "lease_generation": current.lease_generation}, headers=headers
    )
    assert replay.status_code == 200, replay.text
    saved, repeated = first.json(), replay.json()
    assert repeated["assessment_id"] == saved["assessment_id"]
    assert repeated["artifact_id"] == saved["artifact_id"]
    assert repeated["intake"]["findings"] == saved["intake"]["findings"]
    assert not repeated["intake"]["created"]
    assert rows(context) == before


@pytest.mark.parametrize("same_bytes", [True, False])
def test_overlapping_authored_requests_decide_replay_at_the_serialized_write(
    context: Context,
    client: TestClient,
    ref: UUID,
    monkeypatch: pytest.MonkeyPatch,
    same_bytes: bool,
) -> None:
    outer = body(context, ref)
    winner = DOC if same_bytes else SecurityAuditArtifact.parse(b"\n" + DOC.payload)
    put = context.object_store.put
    receipts: list[AssessmentRecordResult] = []

    def record_before_resume(key: ObjectKey, payload: bytes) -> ObjectRef:
        stored = put(key, payload)
        if not receipts:
            monkeypatch.setattr(context.object_store, "put", put)
            receipts.append(
                context.services().assessment.record_secure_code(
                    winner,
                    ref,
                    "1.2.3",
                    Provenance.model_validate(outer["provenance"]),
                    run_order_id=UUID(outer["run_order_id"]),
                    lease_generation=outer["lease_generation"],
                    principal=principal(context),
                )
            )
        return stored

    monkeypatch.setattr(context.object_store, "put", record_before_resume)
    response = client.post(URL, json=outer, headers=runner(context))
    (saved,) = receipts
    if same_bytes:
        assert response.status_code == 200, response.text
        replay = AssessmentRecordResult.model_validate(response.json())
        assert replay.assessment_id == saved.assessment_id
        assert replay.artifact_id == saved.artifact_id
        assert replay.intake.findings == saved.intake.findings and not replay.intake.created
    else:
        assert response.status_code == 409 and "different bytes" in response.json()["detail"]
    with SqlTraustUnitOfWork(context.database) as uow:
        (audit,) = uow.assessments.list_for_run_order(UUID(outer["run_order_id"]))
        (report,) = uow.artifacts.list_for_assessment(audit.id)
        assert (audit.id, report.id) == (saved.assessment_id, saved.artifact_id)
        assert len(uow.occurrences.list_for_assessment(audit.id)) == 2
