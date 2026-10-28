"""ComplianceService doors, ported from traust (fabdb13) tests/test_compliance_scope_intake.py,
test_run_compliance_check.py, test_compliance_phase1.py (gate), test_compliance_phase4.py (n-pass)
and traust-engine (435225b) tests/test_resolve_compliance_scope.py."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    ValidationError,
)
from traust_core.v1.models.artifacts import (
    AdrRegistryArtifact,
    ComplianceAssessmentArtifact,
    ComplianceMappingArtifact,
    ComplianceScopeArtifact,
    DocVarianceArtifact,
    OrgParametersArtifact,
)
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.code_facts import CryptoFact, CryptoProbeId
from traust_core.v1.models.common import ArtifactRef, Provenance
from traust_core.v1.models.compliance import (
    ComplianceTarget,
    EvaluationRequest,
    InventorySnapshot,
    evidence_id,
)
from traust_core.v1.models.findings import Finding, FindingFilter, FindingView
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.inventory import DEFAULT_FORGE_HOSTS, Product, RepositoryRef
from traust_core.v1.models.vocabulary import (
    ActorKind,
    ComplianceEvidenceKind,
    ComplianceFramework,
    Severity,
    SourceType,
)
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpec, PublishSpecs
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.compliance import ComplianceService, evidence_key
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed

FIXTURES = Path(__file__).parents[2] / "fixtures" / "compliance"
NOW = datetime(2026, 10, 23, 9, tzinfo=UTC)
NIST, SOC2, PCI = (ComplianceFramework(f) for f in ("nist-800-53-rev5", "soc2-tsc", "pci-dss-v4"))
ALICE = Principal(
    identity="alice@example.com",
    kind=ActorKind("human"),
    display="Alice",
    verified_by=IdentitySource.OIDC,
)
UNVERIFIED = Principal(identity="alice@example.com", kind=ActorKind("human"), display="Alice")


def khs(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / "checks" / name / "good" / "snapshot.json").read_text())


class FakeFindings:
    def __init__(self, views: dict[UUID, list[FindingView]] | None = None) -> None:
        self.views = views or {}

    def all(self, filter: FindingFilter) -> list[FindingView]:
        return list(self.views.get(filter.repository_id, ()))


class FakeInventory:
    name = "aws"

    def __init__(self, ready: bool = True) -> None:
        self.ready = ready
        self.targets: list[ComplianceTarget] = []

    def check(self) -> Readiness:
        return Readiness(ready=self.ready, detail="" if self.ready else "aws CLI not on PATH")

    def collect(self, targets: list[ComplianceTarget]) -> Result[InventorySnapshot]:
        self.targets = targets
        snapshot = InventorySnapshot.of(
            "aws", [{"id": "b1", "region": "us-east-1", "encryption_at_rest": True}], []
        )
        return Result(snapshot, Acquisition(provider=self.name, acquired_at=NOW))


class World:
    def __init__(self, uow: SqlTraustUnitOfWork, seed: Seed) -> None:
        self.uow, self.seed = uow, seed
        self.store = InMemoryObjectStore()
        self.findings = FakeFindings()
        self.inventory = FakeInventory()
        self.product = seed.product(slug="acme")
        self.a = self.shipped("org/a")
        self.b = self.shipped("org/b")
        self.c = seed.repository_ref(
            seed.repository(url="https://github.com/org/c"), is_default=True
        )
        seed.assessment(self.c, kind=AssessmentKind.REPO_STATE, occurred_at=NOW)
        self.publisher = ArtifactPublisher(
            PublishSpecs(
                PublishSpec(ComplianceScopeArtifact),
                PublishSpec(ComplianceMappingArtifact),
                PublishSpec(ComplianceAssessmentArtifact),
                PublishSpec(AdrRegistryArtifact),
                PublishSpec(DocVarianceArtifact),
                PublishSpec(OrgParametersArtifact),
            ),
            self.store,
            uow,
        )
        self.service = self.compliance()

    def shipped(self, repo: str) -> RepositoryRef:
        ref = self.seed.repository_ref(self.seed.repository(url=f"https://github.com/{repo}"))
        self.seed.component(self.seed.release(self.product), ref)
        return ref

    def compliance(self, **kw: Any) -> ComplianceService:
        return ComplianceService(
            self.uow,
            portfolio=PortfolioService(
                self.uow,
                PortfolioPolicy(),
                assessment=AssessmentService(self.uow, clock=FixedClock(NOW)),
            ),
            findings=self.findings,  # type: ignore[arg-type]
            publisher=self.publisher,
            objects=self.store,
            clock=FixedClock(NOW),
            hosts=DEFAULT_FORGE_HOSTS,
            **{
                "inventory": self.inventory,
                "parameters": {"allowed_data_regions": ["us-east-1"]},
                **kw,
            },
        )

    def publish_mapping(self) -> None:
        self.publisher.publish_artifact(
            ComplianceMappingArtifact.parse((FIXTURES / "compliance-mapping.json").read_bytes())
        )

    def declared(self, principal: Principal = ALICE, **entry: Any) -> UUID:
        scope = self.service.set_scope(scope_doc(**entry), principal)
        assert scope.scope_id is not None
        return scope.scope_id

    def run(self, scope_id: UUID, **kw: Any) -> Any:
        return self.service.evaluate(
            EvaluationRequest(
                scope_id=scope_id,
                harness_version="9.9.9",
                snapshots={"scan_k8s_hardening": khs("chk-no-privileged-workloads")},
                **kw,
            )
        )


def scope_doc(name: str = "acme-cde", **entry: Any) -> ComplianceScopeArtifact:
    base = {
        "frameworks": ["nist-800-53-rev5", "soc2-tsc"],
        "resolves_via": "repo-graph",
        "product": "acme",
        "declared_by": "alice",
        "declared_at": "2026-01-01",
    }
    return ComplianceScopeArtifact.from_document(
        {
            "version": 1,
            "updated": "2026-01-01",
            "boundaries": {name: {k: v for k, v in {**base, **entry}.items() if v is not None}},
        }
    )


@pytest.fixture
def world(uow: SqlTraustUnitOfWork, seed: Seed) -> World:
    return World(uow, seed)


def provenance(artifact: ArtifactRef | None = None) -> Provenance:
    return Provenance(
        run_id=uuid4(), artifact=artifact, source=SourceType("interactive"), occurred_at=NOW
    )


# set_scope (the intake writer) and resolution


def test_identical_scope_replacement_does_not_log_another_declaration(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    logger = logging.getLogger("traust_core.v1.services.compliance")
    with caplog.at_level(logging.INFO, logger=logger.name):
        logger.addHandler(caplog.handler)
        try:
            first = world.service.set_scope(scope_doc(), ALICE)
            assert (
                world.service.set_scope(scope_doc(), ALICE, replace=True).scope_id == first.scope_id
            )
            world.uow.commit()
        finally:
            logger.removeHandler(caplog.handler)
    events = [
        record
        for record in caplog.records
        if record.name == logger.name
        and record.getMessage().startswith("declared compliance boundary (")
    ]
    assert len({id(record) for record in events}) == 1


def test_a_verified_declarant_signs_the_boundary_and_anyone_else_records_a_draft(
    world: World,
) -> None:
    signed = world.service.set_scope(scope_doc(), ALICE)
    assert (signed.declared_by, signed.declared_at, signed.draft) == ("alice", "2026-10-23", False)
    bob = ALICE.model_copy(update={"identity": "bob@example.com"})
    for principal, name in ((UNVERIFIED, "b2"), (bob, "b3")):
        draft = world.service.set_scope(scope_doc(name), principal)
        assert (draft.declared_by, draft.draft) == ("draft:alice", True)
    redeclared = world.service.set_scope(scope_doc("b4", declared_by="draft:alice"), ALICE)
    assert redeclared.declared_by == "alice"


def test_a_declared_boundary_changes_only_with_replace_and_the_old_version_is_superseded(
    world: World,
) -> None:
    first = world.declared()
    with pytest.raises(ConflictError, match="already declared"):
        world.declared()
    second = world.service.set_scope(
        scope_doc(frameworks=["soc2-tsc"]), ALICE, replace=True
    ).scope_id
    assert second is not None and second != first
    assert world.service.resolve(second).scope.frameworks == (SOC2,)
    with pytest.raises(ConflictError, match="superseded"):
        world.service.resolve(first)
    assert world.service.get_scope(first).frameworks == (NIST, SOC2)


def test_repo_graph_resolution_unions_includes_and_drops_excludes(world: World) -> None:
    scope_id = world.declared(
        include=[{"repo": "org/c", "reason": "deploys the CDE"}],
        exclude=[{"repo": "org/b", "reason": "docs only"}],
    )
    resolved = world.service.resolve(scope_id)
    assert resolved.repos == ("org/a", "org/c")
    assert [m.repository_ref_id for m in resolved.members] == [world.a.id, world.c.id]


def test_explicit_resolution_uses_only_the_include_list(world: World) -> None:
    scope_id = world.declared(
        resolves_via="explicit", product=None, include=[{"repo": "org/c", "reason": "the app"}]
    )
    assert world.service.resolve(scope_id).repos == ("org/c",)


@pytest.mark.parametrize(
    ("entry", "error", "match"),
    [
        ({"product": "nope"}, NotFoundError, "product 'nope' is not in the inventory"),
        ({"product": None}, ValidationError, "requires 'product'"),
        (
            {"exclude": [{"repo": "org/z", "reason": "x"}]},
            ValidationError,
            "stale boundary claim",
        ),
        (
            {"exclude": [{"repo": "org/a", "reason": "x"}, {"repo": "org/b", "reason": "y"}]},
            ValidationError,
            "empty repo set",
        ),
        ({"resolves_via": "explicit", "product": None}, ValidationError, "non-empty include"),
        (
            {"include": [{"repo": "org/unknown", "reason": "x"}]},
            NotFoundError,
            "org/unknown is not in the inventory",
        ),
        ({"resolves_via": "deployment-iac"}, ValidationError, "deployment-iac is not supported"),
    ],
)
def test_an_unresolvable_declaration_is_refused_not_recorded(
    world: World, entry: dict[str, Any], error: type[Exception], match: str
) -> None:
    with pytest.raises(error, match=match):
        world.declared(**entry)
    assert world.uow.artifacts.list_imported("compliance-scope", limit=5) == []


def test_an_included_repository_needs_an_observed_default_branch_head(world: World) -> None:
    world.seed.repository(url="https://github.com/org/bare")
    with pytest.raises(NotFoundError, match="no observed default-branch head"):
        world.declared(include=[{"repo": "org/bare", "reason": "x"}])


def test_one_boundary_per_declaration(world: World) -> None:
    doc = json.loads(scope_doc().payload)
    doc["boundaries"]["other"] = doc["boundaries"]["acme-cde"]
    with pytest.raises(ValidationError, match="one boundary at a time, not 2"):
        world.service.set_scope(ComplianceScopeArtifact.from_document(doc), ALICE)


def test_get_scope_refuses_another_documents_id(world: World) -> None:
    world.publish_mapping()
    mapping = world.uow.artifacts.latest_imported("compliance-mapping")
    assert mapping is not None and mapping.id is not None
    with pytest.raises(NotFoundError, match="is a compliance-mapping"):
        world.service.get_scope(mapping.id)


# evaluate (the deterministic runner)


def critical_dependency(repository_id: UUID) -> FindingView:
    finding = Finding(
        id=uuid4(), repository_id=repository_id, fingerprint_algo="v3", fingerprint="f", title="t"
    )
    return FindingView(finding=finding, effective_severity=Severity("critical"), cwes=("CWE-1395",))


def test_evaluate_computes_check_verdicts_skips_with_reasons_and_passes_the_gate(
    world: World,
) -> None:
    world.publish_mapping()
    world.findings.views = {world.a.repository_id: [critical_dependency(world.a.repository_id)]}
    scope_id = world.declared()
    killswitch = CryptoFact(
        probe_id=CryptoProbeId("CRYPTO_GODEBUG_TLS_KILLSWITCH"), provider="go", detail="x"
    )
    run = world.run(
        scope_id,
        frameworks=(NIST, SOC2, PCI),
        trust_categories=("security",),
        crypto=(killswitch,),
        inventory=world.service.collect_inventory(scope_id),
    )
    doc = json.loads(run.document.payload)
    meta = doc["metadata"]
    assert run.failures == ()
    assert meta["skipped_frameworks"] == {
        "pci-dss-v4": "skipped: no declared CDE boundary (--cde-boundary)"
    }
    assert [f["id"] for f in meta["frameworks"]] == ["nist-800-53-rev5", "soc2-tsc"]
    assert "point-in-time" in meta["frameworks"][1]["caveat"]
    assert meta["scope_id"] == str(scope_id)
    assert meta["target"]["repos"] == ["org/a", "org/b"]
    assert meta["target"]["scope"]["draft"] is False
    assert meta["target"]["snapshot_id"] == world.service.collect_inventory(scope_id).snapshot_id
    assert meta["registry_hash"] == evidence_id(
        json.loads((FIXTURES / "compliance-mapping.json").read_text())
    )
    assert meta["generated_at"] == "2026-10-23T09:00:00Z"
    verdicts = {(r["framework"], r["control_id"]): r for r in doc["results"]}
    assert verdicts[("nist-800-53-rev5", "si-2")]["verdict"] == "not_satisfied"
    assert verdicts[("nist-800-53-rev5", "sc-28")]["verdict"] == "satisfied"
    killswitch_controls = [
        r for r in doc["results"] if r.get("check_id") == "chk-no-pqc-tls-killswitch"
    ]
    assert killswitch_controls and all(r["verdict"] == "not_satisfied" for r in killswitch_controls)
    assert all(world.store.exists(evidence_key(sha)) for sha in run.evidence)
    assert sum(c["total_in_scope"] for c in doc["coverage"].values()) == len(doc["results"])
    assert world.inventory.targets[0].ref == "org/a"


def test_a_missing_collector_leaves_its_controls_not_assessed(world: World) -> None:
    world.publish_mapping()
    run = world.service.evaluate(
        EvaluationRequest(scope_id=world.declared(), harness_version="t", frameworks=(NIST,))
    )
    sc28 = next(
        r for r in json.loads(run.document.payload)["results"] if r["control_id"] == "sc-28"
    )
    assert (sc28["verdict"], sc28["reason"]) == (
        "not_assessed",
        "collector unavailable: cloud_inventory",
    )
    assert run.failures == ()


def test_evaluate_needs_a_published_mapping(world: World) -> None:
    with pytest.raises(ConfigError, match="no compliance-mapping"):
        world.run(world.declared())


def mapping_doc(**changes: Any) -> ComplianceMappingArtifact:
    return ComplianceMappingArtifact.from_document(
        {**json.loads((FIXTURES / "compliance-mapping.json").read_text()), **changes}
    )


def test_record_publishes_the_next_mapping_version_and_evaluate_reads_the_newest(
    world: World,
) -> None:
    first = world.service.record(mapping_doc(), provenance())
    assert world.service.record(mapping_doc(), provenance()).artifact_id == first.artifact_id
    second = world.service.record(mapping_doc(note="revised"), provenance())
    assert second.artifact_id != first.artifact_id
    meta = json.loads(world.run(world.declared()).document.payload)["metadata"]
    assert meta["registry_hash"] == evidence_id(json.loads(mapping_doc(note="revised").payload))


def test_policy_replay_has_no_second_recorded_outcome(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    logger = logging.getLogger("traust_core.v1.services.compliance")
    with caplog.at_level(logging.INFO, logger=logger.name):
        logger.addHandler(caplog.handler)
        try:
            first = world.service.record(mapping_doc(), provenance())
            assert (
                world.service.record(mapping_doc(), provenance()).artifact_id == first.artifact_id
            )
            world.uow.commit()
        finally:
            logger.removeHandler(caplog.handler)
    events = {
        id(record): record.getMessage()
        for record in caplog.records
        if record.name == logger.name
        and record.getMessage().startswith("recorded ComplianceMappingArtifact ")
    }
    assert len(events) == 1 and str(first.artifact_id) in next(iter(events.values()))


def test_record_refuses_reverting_to_an_older_mapping_version(world: World) -> None:
    world.service.record(mapping_doc(), provenance())
    world.service.record(mapping_doc(note="revised"), provenance())
    with pytest.raises(IntegrityError, match="not the newest version"):
        world.service.record(mapping_doc(), provenance())


def test_record_refuses_a_mapping_citing_unknown_checks(world: World) -> None:
    raw = json.loads((FIXTURES / "compliance-mapping.json").read_text())
    raw["controls"][0]["checks"] = ["chk-nowhere"]
    with pytest.raises(ValidationError, match="unknown checks"):
        world.service.record(ComplianceMappingArtifact.from_document(raw), provenance())
    assert world.publisher.latest(ComplianceMappingArtifact) is None


def test_record_publishes_the_adr_registers(world: World) -> None:
    doc = AdrRegistryArtifact.from_document(
        {
            "version": 1,
            "registers": [
                {
                    "name": "arch",
                    "repo": "https://github.com/org/architecture",
                    "paths": ["decisions"],
                    "pin": "a" * 40,
                    "governs": ["product:acme"],
                }
            ],
        }
    )
    published = world.service.record(doc, provenance())
    latest = world.publisher.latest_imported(AdrRegistryArtifact)
    assert latest is not None and latest.artifact_id == published.artifact_id


def org_parameters(*regions: str) -> OrgParametersArtifact:
    return OrgParametersArtifact.from_document(
        {
            "version": 1,
            "declared_by": "platform-security",
            "parameters": {
                "allowed_data_regions": {"value": list(regions), "controls": ["gdpr:art-44"]}
            },
        }
    )


def residency(service: ComplianceService, scope_id: UUID) -> dict[str, Any]:
    """The gdpr-residency result (its check reads `param:allowed_data_regions`) and metadata."""
    doc = service.evaluate(
        EvaluationRequest(
            scope_id=scope_id,
            harness_version="t",
            target_kind="environment",
            personal_data_stores=("db",),
            inventory=service.collect_inventory(scope_id),
        )
    ).document
    body = json.loads(doc.payload)
    (result,) = (r for r in body["results"] if r["control_id"] == "gdpr-residency")
    return {"result": result, "metadata": body["metadata"]}


def test_record_publishes_org_parameters_and_evaluate_reads_the_newest(world: World) -> None:
    world.publish_mapping()
    service = world.compliance(parameters=None)
    scope_id = world.declared(frameworks=["gdpr-technical"])
    first = service.record(org_parameters("eu-west-1"), provenance())
    again = service.record(org_parameters("eu-west-1"), provenance())
    assert again.artifact_id == first.artifact_id
    assert residency(service, scope_id)["result"]["verdict"] == "not_satisfied"
    second = service.record(org_parameters("us-east-1"), provenance())
    assert second.artifact_id != first.artifact_id
    run = residency(service, scope_id)
    assert run["result"]["verdict"] == "satisfied"
    assert run["metadata"]["org_parameters_hash"] == evidence_id(
        {"allowed_data_regions": ["us-east-1"]}
    )


def test_without_recorded_org_parameters_a_param_check_stays_undeclared(world: World) -> None:
    world.publish_mapping()
    scope_id = world.declared(frameworks=["gdpr-technical"])
    run = residency(world.compliance(parameters=None), scope_id)
    assert (run["result"]["verdict"], run["result"]["reason"]) == (
        "not_assessed",
        "parameter undeclared: allowed_data_regions",
    )
    assert "org_parameters_hash" not in run["metadata"]


def test_explicit_parameters_win_over_recorded_org_parameters(world: World) -> None:
    world.publish_mapping()
    world.service.record(org_parameters("eu-west-1"), provenance())
    scope_id = world.declared(frameworks=["gdpr-technical"])
    assert residency(world.service, scope_id)["result"]["verdict"] == "satisfied"


def test_readding_evidence_does_not_claim_another_addition(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    kind = ComplianceEvidenceKind("human_artifact")
    payload = {"topic": "tls", "statement": "synthetic test evidence"}
    first = world.service.add_evidence(kind, "attestation:tls", payload)
    logger = logging.getLogger("traust_core.v1.services.compliance")
    with caplog.at_level(logging.INFO, logger=logger.name):
        logger.addHandler(caplog.handler)
        try:
            assert world.service.add_evidence(kind, "attestation:tls", payload) == first
        finally:
            logger.removeHandler(caplog.handler)
    assert not [
        record
        for record in caplog.records
        if record.name == logger.name
        and record.levelno >= logging.INFO
        and "evidence" in record.getMessage()
    ]


def test_added_evidence_is_in_the_bundle_and_a_verdict_citing_it_passes_the_gate(
    world: World,
) -> None:
    world.publish_mapping()
    run = world.run(world.declared(), frameworks=(NIST,))
    attestation = {"topic": "tls", "statement": "TLS 1.3 at the edge", "by": "alice"}
    evidence = world.service.add_evidence(
        ComplianceEvidenceKind("human_artifact"), "attestation:tls", attestation
    )
    assert evidence.sha256 == evidence_id(attestation)
    assert (
        world.service.add_evidence(
            ComplianceEvidenceKind("human_artifact"), "attestation:tls", attestation
        )
        == evidence
    )

    def judged(doc: dict[str, Any]) -> None:
        sc8 = result(doc, "sc-8")
        sc8.update(
            verdict="satisfied",
            verdict_source="agent",
            evidence=[evidence.model_dump(mode="json", exclude_none=True)],
            n_pass_agreement={"passes": 2, "agreed": True},
        )
        sc8.pop("reason")
        doc["coverage"] = recount(doc)

    assert world.service.check(edited(run, judged)).passed


def test_prepare_lists_the_evidence_review_controls_awaiting_artifacts(world: World) -> None:
    world.publish_mapping()
    run = world.run(world.declared(), frameworks=(NIST,))
    prepared = world.service.prepare(run)
    awaiting = {(a.framework, a.control_id): a.evidence_request for a in prepared.awaiting}
    assert awaiting[(NIST, "sc-8")].startswith("TLS posture for in-scope service endpoints")
    assert prepared.scope == run.scope and prepared.prepared_at == NOW


def test_collect_inventory_needs_a_ready_provider(world: World) -> None:
    scope_id = world.declared()
    with pytest.raises(ConfigError, match="needs a cloud inventory provider"):
        world.compliance(inventory=None).collect_inventory(scope_id)
    with pytest.raises(ConfigError, match="aws CLI not on PATH"):
        world.compliance(inventory=FakeInventory(ready=False)).collect_inventory(scope_id)


# the citation gate


def edited(run: Any, edit: Callable[[dict[str, Any]], None]) -> ComplianceAssessmentArtifact:
    doc = json.loads(run.document.payload)
    edit(doc)
    return ComplianceAssessmentArtifact.from_document(doc)


def result(doc: dict[str, Any], control_id: str) -> dict[str, Any]:
    return next(r for r in doc["results"] if r["control_id"] == control_id)


def agent_on_deterministic(doc: dict[str, Any]) -> None:
    result(doc, "si-2")["verdict_source"] = "agent"
    result(doc, "si-2")["n_pass_agreement"] = {"passes": 2, "agreed": True}


def agent_without_agreement(doc: dict[str, Any]) -> None:
    sc8 = result(doc, "sc-8")
    sc8.update(
        verdict="satisfied",
        verdict_source="agent",
        evidence=[{"sha256": "0" * 64, "kind": "human_artifact", "locator": "a"}],
    )
    sc8.pop("reason")
    doc["coverage"] = recount(doc)


def agent_disagreeing(doc: dict[str, Any]) -> None:
    agent_without_agreement(doc)
    result(doc, "sc-8")["n_pass_agreement"] = {"passes": 2, "agreed": False}


def organizational_satisfied(doc: dict[str, Any]) -> None:
    ctl = next(r for r in doc["results"] if r["classification"] == "organizational")
    ctl.update(verdict="satisfied", evidence=result(doc, "si-2")["evidence"])
    ctl.pop("reason")
    doc["coverage"] = recount(doc)


def recount(doc: dict[str, Any]) -> dict[str, Any]:
    from traust_core.v1.models.compliance import coverage

    return coverage(doc["results"])


def tampered_coverage(doc: dict[str, Any]) -> None:
    doc["coverage"]["nist-800-53-rev5"]["satisfied"] += 1


def blended(doc: dict[str, Any]) -> None:
    doc["metadata"]["compliance_score"] = 0.9


def soc2_without_caveat(doc: dict[str, Any]) -> None:
    doc["metadata"]["frameworks"][1].pop("caveat")
    doc["metadata"]["target"].pop("trust_service_categories")


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (agent_on_deterministic, "deterministic control with agent-sourced verdict"),
        (agent_without_agreement, "without n_pass_agreement"),
        (agent_disagreeing, "disagreement or <2 passes"),
        (organizational_satisfied, "organizational control carries"),
        (tampered_coverage, "declared"),
        (blended, "blended compliance percentage"),
        (soc2_without_caveat, "point-in-time"),
        (soc2_without_caveat, "trust_service_categories"),
    ],
)
def test_the_gate_refuses_a_narrative_verdict(
    world: World, edit: Callable[[dict[str, Any]], None], message: str
) -> None:
    world.publish_mapping()
    run = world.run(world.declared(), frameworks=(NIST, SOC2), trust_categories=("security",))
    report = world.service.check(edited(run, edit))
    assert any(message in v.message for v in report.violations), report.violations
    with pytest.raises(ValidationError, match="fails its gate"):
        world.service.record(edited(run, edit), provenance())


def test_agreed_two_pass_agent_verdicts_on_evidence_review_pass_the_gate(world: World) -> None:
    world.publish_mapping()
    run = world.run(world.declared(), frameworks=(NIST,))
    cited = result(json.loads(run.document.payload), "si-2")["evidence"]

    def agreed(doc: dict[str, Any]) -> None:
        sc8 = result(doc, "sc-8")
        sc8.update(
            verdict="satisfied",
            verdict_source="agent",
            evidence=cited,
            n_pass_agreement={"passes": 2, "agreed": True},
        )
        sc8.pop("reason")
        doc["coverage"] = recount(doc)

    assert world.service.check(edited(run, agreed)).passed


def test_the_gate_verifies_each_cited_evidence_item_in_the_bundle(world: World) -> None:
    world.publish_mapping()
    run = world.run(world.declared(), frameworks=(NIST,))
    sha = run.evidence[0]
    world.store.put(evidence_key(sha), b'{"tampered": true}')
    missing = "f" * 64

    def cite_missing(doc: dict[str, Any]) -> None:
        result(doc, "sc-28")  # keep shape
        for r in doc["results"]:
            for ev in r.get("evidence") or []:
                if ev["sha256"] != sha:
                    ev["sha256"] = missing

    messages = [v.message for v in world.service.check(edited(run, cite_missing)).violations]
    assert any("does not hash to its id" in m for m in messages)
    assert any("bundle has no such item" in m for m in messages)
    world.store.put(evidence_key(sha), b"not json")
    assert any("not JSON" in v.message for v in world.service.check(run.document).violations)


# record and latest


def test_record_attaches_the_assessment_to_each_in_scope_commit_once(world: World) -> None:
    world.publish_mapping()
    scope_id = world.declared()
    run = world.run(scope_id, frameworks=(NIST,))
    recorded = world.service.record(run.document, provenance())
    assessments = [world.uow.assessments.get(i) for i in recorded.assessment_ids]
    assert {a.repository_ref_id for a in assessments} == {world.a.id, world.b.id}
    assert {(a.kind, a.assessor, a.assessor_version) for a in assessments} == {
        ("compliance", "skill:compliance-check", "9.9.9")
    }
    assert recorded.frameworks == (NIST,) and recorded.scope_id == scope_id
    again = world.service.record(run.document, provenance())
    assert set(again.assessment_ids) == set(recorded.assessment_ids)
    assert again.artifact == recorded.artifact
    latest = world.service.latest(scope_id, NIST)
    assert latest is not None and latest.artifact.digest == recorded.artifact.digest
    assert latest.results == recorded.results
    assert world.service.latest(scope_id, SOC2) is None


def test_record_refuses_a_provenance_artifact_of_other_bytes(world: World) -> None:
    world.publish_mapping()
    run = world.run(world.declared(), frameworks=(NIST,))
    other = ArtifactRef(id=uuid4(), name="compliance-assessment", digest="0" * 64)
    with pytest.raises(IntegrityError, match="doc digest"):
        world.service.record(run.document, provenance(other))


def test_record_refuses_an_assessment_of_a_superseded_declaration(world: World) -> None:
    world.publish_mapping()
    run = world.run(world.declared(), frameworks=(NIST,))
    world.service.set_scope(
        scope_doc(exclude=[{"repo": "org/b", "reason": "moved out"}]), ALICE, replace=True
    )
    with pytest.raises(ConflictError, match="superseded"):
        world.service.record(run.document, provenance())


def test_record_attaches_only_to_the_commits_it_evaluated(world: World) -> None:
    world.publish_mapping()
    run = world.run(world.declared(), frameworks=(NIST,))
    world.shipped("org/d")
    recorded = world.service.record(run.document, provenance())
    refs = {world.uow.assessments.get(i).repository_ref_id for i in recorded.assessment_ids}
    assert refs == {world.a.id, world.b.id}


def test_record_refuses_when_an_evaluated_repo_left_the_boundary(world: World) -> None:
    world.publish_mapping()
    run = world.run(world.declared(), frameworks=(NIST,))
    moved = edited(run, lambda doc: doc["metadata"]["target"]["repos"].append("org/gone"))
    with pytest.raises(ConflictError, match="membership changed since evaluation \\(org/gone\\)"):
        world.service.record(moved, provenance())


def test_latest_is_none_before_any_record(world: World) -> None:
    assert world.service.latest(world.declared(), NIST) is None


def test_context_wires_the_compliance_service(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    with SqlTraustUnitOfWork(ctx.database) as u:
        product: Product = Seed(u).product(slug="acme")
        ref = Seed(u).repository_ref(Seed(u).repository(url="https://github.com/org/a"))
        Seed(u).component(Seed(u).release(product), ref)
        u.commit()
    scope = ctx.services().compliance.set_scope(scope_doc(), UNVERIFIED)
    assert scope.draft and ctx.services().compliance.resolve(scope.scope_id).repos == ("org/a",)  # type: ignore[arg-type]
