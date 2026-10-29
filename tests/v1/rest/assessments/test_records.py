from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from datetime import timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
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
    OrderRequest,
    RecordingStartScope,
    RunOrder,
    WorkerId,
)
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.repositories.contract import CONTRACT_TABLES, SqlTraustUnitOfWork
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
    context.__dict__["database"] = engine
    return context


@pytest.fixture
def ref(context: Context) -> UUID:
    with SqlTraustUnitOfWork(context.database) as uow:
        saved = Seed(uow).repository_ref()
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
        "repository_ref_id": str(ref),
        "payload": doc.payload.decode("utf-8"),
        "provenance": Provenance(
            run_id=order.id, source=SourceType.VULN_SCAN_REPORT, occurred_at=WHEN
        ).model_dump(mode="json"),
        "assessor_version": "1.2.3",
    }


def rows(context: Context) -> dict[str, object]:
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
            original_order, WorkerId(principal(context).ref), JobResult.succeeded()
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


def test_nested_intake_failure_rolls_back_assessment_artifact_and_findings(
    context: Context, client: TestClient, ref: UUID, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = body(context, ref)
    accept = FindingIntake.accept

    def fail(
        self: FindingIntake, assessment_id: UUID, candidates: Sequence[FindingCandidate]
    ) -> IntakeResult:
        accept(self, assessment_id, candidates)
        raise ValidationError("intake failed after writing")

    monkeypatch.setattr(FindingIntake, "accept", fail)
    before = rows(context)
    response = client.post(URL, json=request, headers=runner(context))
    assert response.status_code == 422, response.text
    assert rows(context) == before


def test_explicit_dispatched_worker_start_returns_real_source_ids(
    context: Context, client: TestClient, ref: UUID
) -> None:
    repository_id = context.services().portfolio.inventory.get_ref(ref).repository_id
    scope = RecordingStartScope(
        principal=principal(context).ref, assets=("audit",), repository_ids=(repository_id,)
    )
    context.config = context.config.model_copy(
        update={"recording": context.config.recording.model_copy(update={"start": (scope,)})}
    )
    started = client.post(
        "/v1/orders/start",
        json={
            "order": {"asset": "audit", "priority": 1, "repository_id": str(repository_id)},
            "lease_seconds": 300,
        },
        headers=runner(context),
    )
    assert started.status_code == 200, started.text
    request = {
        "run_order_id": started.json()["id"],
        "repository_ref_id": str(ref),
        "payload": DOC.payload.decode("utf-8"),
        "provenance": Provenance(
            run_id=UUID(started.json()["id"]), source=SourceType.VULN_SCAN_REPORT, occurred_at=WHEN
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
            principal=principal(context),
        )
