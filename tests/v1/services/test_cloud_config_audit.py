"""The cloud-config-audit doors: run_tools over the Checkov provider, the report gate
(ported from traust tests/test_cloud_config_audit.py) and record_audit."""

from __future__ import annotations

import copy
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.findings.test_reads import ALICE
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import (
    ConfigError,
    DocumentError,
    IntegrityError,
    ServiceError,
    ValidationError,
)
from traust_core.v1.models.artifacts import CloudConfigAuditArtifact, TriageArtifact
from traust_core.v1.models.assessment import Assessment, ToolName
from traust_core.v1.models.cloud_config import CHECKOV, CheckovScan, CloudConfigFacts
from traust_core.v1.models.common import ArtifactRef, CodeSpan, Provenance, RepoPath
from traust_core.v1.models.findings import (
    AssessedJudgment,
    CandidateFormat,
    Decision,
    ExposureKey,
    FindingCandidate,
    Label,
    RecordDecision,
)
from traust_core.v1.models.integrity import FingerprintInput, FingerprintLocation, sha256_hex
from traust_core.v1.models.vocabulary import ScannerSeverity, SourceType, Validity
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Readiness, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.tools import ToolProvider, ToolRequest
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpec, PublishSpecs
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.cloud_config import CloudConfigCitations
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.identity import IdentityPolicy
from traust_core.v1.services.findings.intake import FindingIntake
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.findings.review import ReviewPolicy
from traust_core.v1.services.findings.taxonomy import TaxonomyPolicy
from traust_core.v1.services.ledger import LedgerConfig, LedgerService
from traust_core.v1.services.lint import Lint, LintContext

FIXTURES = Path(__file__).parents[2] / "fixtures"
REPORT = json.loads((FIXTURES / "cloud_config" / "myrepo-cloud-config-audit.json").read_text())
WHEN = datetime(2026, 10, 23, 9, tzinfo=UTC)


class FakeCheckov:
    name = "checkov"

    def __init__(self, ready: bool = True) -> None:
        self.ready = ready
        self.seen: list[Path] = []

    def check(self) -> Readiness:
        return Readiness(ready=self.ready, detail="" if self.ready else "checkov not on PATH")

    def acquire(self, request: ToolRequest) -> Result[CloudConfigFacts]:
        self.seen.append(request.workspace)
        raw = (FIXTURES / "cloud_config" / "checkov-3.3.6.json").read_bytes()
        scan = CheckovScan(target="myrepo", version="3.3.6", outputs=(raw,))
        return Result(
            CloudConfigFacts.of(scan),
            Acquisition(provider=self.name, acquired_at=WHEN, version="3.3.6"),
        )


def registry(*providers: Any) -> ProviderRegistry[ToolProvider[Any]]:
    tools: ProviderRegistry[ToolProvider[Any]] = ProviderRegistry("tool")
    for p in providers:
        tools.register(p.name, lambda p=p: p)
    return tools


def doc(**changes: Any) -> CloudConfigAuditArtifact:
    raw = copy.deepcopy(REPORT)
    for key, value in changes.items():
        raw[key] = value
    return CloudConfigAuditArtifact.parse(json.dumps(raw).encode())


def with_finding(index: int, **fields: Any) -> CloudConfigAuditArtifact:
    findings = copy.deepcopy(REPORT["findings"])
    findings[index].update(fields)
    for key in [k for k, v in fields.items() if v is None]:
        findings[index].pop(key)
    return doc(findings=findings)


# run_tools


def test_run_tools_returns_each_tools_result_over_the_checkout(tmp_path: Path) -> None:
    checkov = FakeCheckov()
    run = AssessmentService(None, tools=registry(checkov)).run_tools(tmp_path, [CHECKOV, CHECKOV])  # type: ignore[arg-type]
    facts = run.data(CHECKOV, CloudConfigFacts)
    assert (len(facts.facts), run.results[CHECKOV].acquisition.version) == (33, "3.3.6")
    assert checkov.seen == [tmp_path]


def test_a_tool_not_ready_stops_the_run_before_any_tool_starts(tmp_path: Path) -> None:
    ready, unready = FakeCheckov(), FakeCheckov(ready=False)
    unready.name = "bicep"
    service = AssessmentService(None, tools=registry(ready, unready))  # type: ignore[arg-type]
    with pytest.raises(ConfigError, match="bicep: checkov not on PATH"):
        service.run_tools(tmp_path, [CHECKOV, ToolName("bicep")])
    assert ready.seen == []


def test_run_tools_refuses_unknown_tools_no_tools_and_a_missing_registry(tmp_path: Path) -> None:
    service = AssessmentService(None, tools=registry(FakeCheckov()))  # type: ignore[arg-type]
    with pytest.raises(ConfigError, match="unknown tool provider 'grype'"):
        service.run_tools(tmp_path, [ToolName("grype")])
    with pytest.raises(ValidationError, match="at least one tool"):
        service.run_tools(tmp_path, [])
    with pytest.raises(ConfigError, match="needs the tool providers"):
        AssessmentService(None).run_tools(tmp_path, [CHECKOV])  # type: ignore[arg-type]


def test_reading_a_result_as_the_wrong_type_is_an_integrity_error(tmp_path: Path) -> None:
    run = AssessmentService(None, tools=registry(FakeCheckov())).run_tools(tmp_path, [CHECKOV])  # type: ignore[arg-type]
    with pytest.raises(IntegrityError, match="returned CloudConfigFacts, not str"):
        run.data(CHECKOV, str)


def test_context_tools_reach_run_tools(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    ctx.tools.register("checkov", FakeCheckov)
    run = ctx.services().assessment.run_tools(tmp_path, [CHECKOV])
    assert run.data(CHECKOV, CloudConfigFacts).snapshot_id


# the report gate


def violations(subject: CloudConfigAuditArtifact) -> list[tuple[str, str]]:
    return [(v.item, v.message) for v in CloudConfigCitations().check(subject, LintContext())]


def test_a_conformant_report_passes_the_gate() -> None:
    assert violations(doc()) == []


def test_severity_over_an_unrated_fact_needs_the_rubric_row() -> None:
    assert violations(with_finding(0, rationale=None)) == [
        (
            "CCA-myrepo-001",
            "severity assigned over an unrated fact without rationale "
            "(cite the SKILL.md rubric row)",
        )
    ]


@pytest.mark.parametrize("status", ["suppressed", "needs_review"])
def test_a_suppression_or_review_needs_a_rationale(status: str) -> None:
    messages = [m for _, m in violations(with_finding(4, status=status, rationale="  "))]
    assert f"status '{status}' without rationale" in messages


def test_changing_a_rated_facts_severity_needs_a_rationale() -> None:
    assert violations(with_finding(5, scanner_severity="low", rationale=None)) == [
        ("CCA-myrepo-006", "severity changed from scanner's without rationale")
    ]
    assert violations(with_finding(5, scanner_severity="medium", rationale=None)) == []


def test_a_finding_without_a_file_location_fails_the_gate() -> None:
    assert violations(with_finding(2, locations=[{"resource": "aws_security_group.admin"}])) == [
        ("CCA-myrepo-003", "no location with a file_path, so the finding can't be tracked")
    ]
    assert violations(with_finding(4, locations=[])) == [
        ("CCA-myrepo-005", "no location with a file_path, so the finding can't be tracked")
    ]


def test_the_schema_rejects_an_observed_claim_and_an_uncited_finding() -> None:
    metadata = {**REPORT["metadata"], "assessment_mode": "observed"}
    with pytest.raises(DocumentError):
        doc(metadata=metadata)
    with pytest.raises(DocumentError):
        with_finding(0, fact_ids=[])


def test_the_gate_checks_only_cloud_config_audits() -> None:
    triage = TriageArtifact.parse(
        (FIXTURES / "findings" / "triage" / "triage-report.json").read_bytes()
    )
    with pytest.raises(ValidationError, match="checks cloud-config audits"):
        CloudConfigCitations().check(triage, LintContext())


# record_audit


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path))
    ctx.__dict__["database"] = engine
    return ctx


def a_ref(engine: Engine) -> UUID:
    with SqlTraustUnitOfWork(engine) as uow:
        ref = Seed(uow).repository_ref()
        uow.commit()
    assert ref.id is not None
    return ref.id


def published(context: Context, audit: CloudConfigAuditArtifact) -> Provenance:
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(CloudConfigAuditArtifact)))
    result = publisher.publish_artifact(audit)
    ref = ArtifactRef(id=result.artifact_id, name=audit.name, digest="sha256:x")
    return Provenance(
        run_id=uuid4(), artifact=ref, source=SourceType.VULN_SCAN_REPORT, occurred_at=WHEN
    )


IDS = [f["id"] for f in REPORT["findings"]]


def recorded(
    context: Context, engine: Engine, audit: CloudConfigAuditArtifact | None = None
) -> tuple[UUID, Assessment, dict[str, Decision]]:
    ref, audit = a_ref(engine), audit or doc()
    assessment, decisions = context.services().assessment.record_audit(
        audit, ref, published(context, audit)
    )
    return ref, assessment, dict(zip(IDS, decisions, strict=True))


def test_an_audit_with_gaps_is_a_degraded_cloud_config_assessment_with_its_report(
    context: Context, engine: Engine
) -> None:
    _, assessment, decided = recorded(context, engine)
    assert (assessment.kind, assessment.status, assessment.occurred_at) == (
        "cloud_config",
        "degraded",
        WHEN,
    )
    assert (assessment.assessor, assessment.assessor_version) == (
        "skill:cloud-config-audit",
        "0.150.0",
    )
    with SqlTraustUnitOfWork(engine) as uow:
        [artifact] = uow.artifacts.list_for_assessment(assessment.id)
    assert artifact.kind == "cloud-config-audit"
    assert {d.artifact_id for d in decided.values()} == {artifact.id}
    assert {d.assessment_id for d in decided.values()} == {assessment.id}


def test_every_stated_finding_is_a_row_and_two_checks_on_one_bucket_stay_two(
    context: Context, engine: Engine
) -> None:
    _, assessment, decided = recorded(context, engine)
    assert len({d.finding_id for d in decided.values()}) == 6
    with SqlTraustUnitOfWork(engine) as uow:
        occurrence = uow.occurrences.find(decided["CCA-myrepo-004"].finding_id, assessment.id)
        assert occurrence is not None
        [location] = uow.locations.list_for_occurrence(occurrence.id)
    assert (occurrence.severity, occurrence.rule) == ("unrated", "CKV_K8S_16")
    assert (location.path, location.line_start, location.symbol) == (
        "k8s/deploy.yaml",
        1,
        "Deployment.default.web",
    )


def test_each_disposition_is_the_assessors_decision(context: Context, engine: Engine) -> None:
    _, _, decided = recorded(context, engine)
    assert {i: d.validity for i, d in decided.items()} == {
        "CCA-myrepo-001": "confirmed",
        "CCA-myrepo-002": "confirmed",
        "CCA-myrepo-003": "confirmed",
        "CCA-myrepo-004": None,
        "CCA-myrepo-005": "false_positive",
        "CCA-myrepo-006": "confirmed",
    }
    assert decided["CCA-myrepo-005"].rationale == (
        "(facts: cca-d4266ab73726) R5 hygiene: the namespace is set at deploy time by the "
        "overlay; the manifest declares none by design."
    )
    assert {i: d.severity for i, d in decided.items()} == {  # the audit's rubric re-rating
        "CCA-myrepo-001": "critical",
        "CCA-myrepo-002": "critical",
        "CCA-myrepo-003": "critical",
        "CCA-myrepo-004": None,
        "CCA-myrepo-005": None,
        "CCA-myrepo-006": "medium",
    }
    assert not any(d.auto_accept_tier for d in decided.values())


def test_a_needs_review_finding_waits_for_a_person(context: Context, engine: Engine) -> None:
    _, _, decided = recorded(context, engine)
    review = decided["CCA-myrepo-004"]
    with SqlTraustUnitOfWork(engine) as uow:
        item = uow.review_items.find_pending(review.finding_id, "undetermined_finding")
        others = [
            uow.review_items.find_pending(d.finding_id, "undetermined_finding")
            for i, d in decided.items()
            if i != "CCA-myrepo-004"
        ]
    assert item is not None and item.decision_id == review.id
    assert others == [None] * 5


def test_a_changed_rated_severity_is_the_decisions_severity(
    context: Context, engine: Engine
) -> None:
    audit = with_finding(5, scanner_severity="low", rationale="R4 audit: raised, logs hold PII.")
    _, _, decided = recorded(context, engine, audit)
    assert decided["CCA-myrepo-006"].severity == "medium"


def test_a_rubric_severity_equal_to_checkovs_is_no_re_rating(
    context: Context, engine: Engine
) -> None:
    audit = with_finding(5, scanner_severity="medium")
    _, assessment, decided = recorded(context, engine, audit)
    confirmed = decided["CCA-myrepo-006"]
    with SqlTraustUnitOfWork(engine) as uow:
        occurrence = uow.occurrences.find(confirmed.finding_id, assessment.id)
    assert occurrence is not None
    assert (confirmed.severity, occurrence.severity) == (None, "medium")
    assert decided["CCA-myrepo-001"].severity == "critical"


def test_a_resolved_review_stays_resolved_when_the_report_is_recorded_again(
    context: Context, engine: Engine
) -> None:
    ref, audit = a_ref(engine), doc()
    service = context.services().assessment
    _, decisions = service.record_audit(audit, ref, published(context, audit))
    review = dict(zip(IDS, decisions, strict=True))["CCA-myrepo-004"]
    with SqlTraustUnitOfWork(engine) as uow:
        item = uow.review_items.find_pending(review.finding_id, "undetermined_finding")
    assert item is not None and item.id is not None and review.id is not None
    resolved = context.services().findings.review.resolve(
        item.id,
        RecordDecision(
            finding_id=review.finding_id,
            validity="confirmed",
            rationale="Reviewed the deployment and reproduced the reported configuration.",
        ),
        ALICE,
    )
    assert resolved.status == "accepted"
    assert resolved.decision_id == review.id
    assert resolved.resolved_by_decision_id is not None
    with SqlTraustUnitOfWork(engine) as uow:
        answer = uow.decisions.get(resolved.resolved_by_decision_id)
        before = uow.decisions.list_for_finding(review.finding_id)
    assert (answer.actor, answer.validity) == (ALICE.ref, "confirmed")
    assert answer.id != review.id
    service.record_audit(audit, ref, published(context, audit))
    with SqlTraustUnitOfWork(engine) as uow:
        items = uow.review_items.list_for_finding(review.finding_id)
        after = uow.decisions.list_for_finding(review.finding_id)
    assert items == [resolved]
    assert after == before


def resource_fingerprint(
    engine: Engine, ref: UUID, finding_id: UUID, check: str, cwe: str, **anchors: tuple[str, ...]
) -> tuple[str, str]:
    with SqlTraustUnitOfWork(engine) as uow:
        url = uow.repositories.get(uow.repository_refs.get(ref).repository_id).url
        finding = uow.findings.get(finding_id)
    [(kind, values)] = anchors.items()
    expected = IdentityPolicy().match_key(
        FingerprintInput(
            repo=url,
            cwes=(cwe,),
            check_id=check,
            locations=tuple(FingerprintLocation(**{kind: v}) for v in values),
        )
    )
    assert (finding.fingerprint_algo, finding.fingerprint) == (expected.algo, expected.value)
    return finding.fingerprint_algo, finding.fingerprint


def test_identity_takes_every_resource_even_one_with_no_file(
    context: Context, engine: Engine
) -> None:
    locations = [
        {**REPORT["findings"][0]["locations"][0]},
        {"resource": "aws_s3_bucket.logs"},
    ]
    ref, _, decided = recorded(context, engine, with_finding(0, locations=locations))
    finding_id = decided["CCA-myrepo-001"].finding_id
    resource_fingerprint(
        engine,
        ref,
        finding_id,
        "CKV_AWS_20",
        "CWE-732",
        resource=("aws_s3_bucket.data", "aws_s3_bucket.logs"),
    )
    with SqlTraustUnitOfWork(engine) as uow:
        [occurrence] = uow.occurrences.list_for_finding(finding_id)
        [location] = uow.locations.list_for_occurrence(occurrence.id)
    assert (location.path, location.symbol) == ("iac/main.tf", "aws_s3_bucket.data")


def test_identity_falls_back_to_paths_when_no_location_names_a_resource(
    context: Context, engine: Engine
) -> None:
    locations = [{"file_path": "/iac/main.tf", "file_line_range": [1, 4]}]
    ref, _, decided = recorded(context, engine, with_finding(0, locations=locations))
    resource_fingerprint(
        engine,
        ref,
        decided["CCA-myrepo-001"].finding_id,
        "CKV_AWS_20",
        "CWE-732",
        path=("iac/main.tf",),
    )


def test_a_policy_finding_keeps_the_legacy_identity_recipe(
    context: Context, engine: Engine
) -> None:
    ref, _, decided = recorded(context, engine)
    with SqlTraustUnitOfWork(engine) as uow:
        url = uow.repositories.get(uow.repository_refs.get(ref).repository_id).url
        finding = uow.findings.get(decided["CCA-myrepo-002"].finding_id)
    reported = {**REPORT["findings"][1], "locations": [{"resource": "aws_s3_bucket.data"}]}
    legacy = IdentityPolicy().match_key(FingerprintInput.from_report(reported, url))
    assert (finding.fingerprint_algo, finding.fingerprint) == (legacy.algo, legacy.value)


def test_an_audit_without_gaps_is_completed(context: Context, engine: Engine) -> None:
    _, assessment, _ = recorded(context, engine, doc(gaps=[]))
    assert assessment.status == "completed"


def test_the_same_report_again_is_the_same_assessment_and_adds_nothing(
    context: Context, engine: Engine
) -> None:
    ref, audit = a_ref(engine), doc()
    service = context.services().assessment
    first, decided = service.record_audit(audit, ref, published(context, audit))
    again, redecided = service.record_audit(audit, ref, published(context, audit))
    assert again.id == first.id
    assert [d.id for d in redecided] == [d.id for d in decided]
    with SqlTraustUnitOfWork(engine) as uow:
        assert len(uow.assessments.list_for_ref(ref)) == 1
        assert all(len(uow.decisions.list_for_finding(d.finding_id)) == 1 for d in decided)


def test_assessed_decisions_are_appended_to_the_ledger_and_sealed(engine: Engine) -> None:
    uow = SqlTraustUnitOfWork(engine)
    decisions = FindingDecisions(
        uow,
        LedgerService(uow, LedgerConfig()),
        Lint({}),
        FindingPrecedents(uow),
        clock=FixedClock(WHEN),
        objects=InMemoryObjectStore(),
        review=ReviewPolicy(),
    )
    intake = FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy())
    service = AssessmentService(uow, intake, decisions=decisions)
    ref, audit = a_ref(engine), doc()
    publisher = ArtifactPublisher(
        PublishSpecs(PublishSpec(CloudConfigAuditArtifact)), InMemoryObjectStore(), uow
    )
    result = publisher.publish_artifact(audit)
    prov = Provenance(
        run_id=uuid4(),
        artifact=ArtifactRef(id=result.artifact_id, name=audit.name, digest="sha256:x"),
        source=SourceType.VULN_SCAN_REPORT,
        occurred_at=WHEN,
    )
    _, decided = service.record_audit(audit, ref, prov)
    with SqlTraustUnitOfWork(engine) as check:
        assert all(check.events.find_by_decision(d.id) is not None for d in decided)
        repository_id = check.repository_refs.get(ref).repository_id
        [layer] = check.layers.list_for_repository(repository_id)
    assert layer.merkle_size == 6


def test_a_report_failing_its_gate_records_nothing(context: Context, engine: Engine) -> None:
    ref, audit = a_ref(engine), with_finding(0, rationale=None)
    prov = published(context, audit)
    with pytest.raises(ValidationError, match="CCA-myrepo-001: severity assigned"):
        context.services().assessment.record_audit(audit, ref, prov)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.assessments.list_for_ref(ref) == []


def a_service_with_an_unsignable_ledger(engine: Engine) -> AssessmentService:
    uow = SqlTraustUnitOfWork(engine)
    decisions = FindingDecisions(
        uow,
        LedgerService(uow, LedgerConfig(required=True)),
        Lint({}),
        FindingPrecedents(uow),
        clock=FixedClock(WHEN),
        objects=InMemoryObjectStore(),
        review=ReviewPolicy(),
    )
    return AssessmentService(
        uow, FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()), decisions=decisions
    )


def test_a_ledger_that_cannot_sign_records_no_assessment(context: Context, engine: Engine) -> None:
    ref, audit = a_ref(engine), doc()
    prov = published(context, audit)
    with pytest.raises(ServiceError, match="signing is required"):
        a_service_with_an_unsignable_ledger(engine).record_audit(audit, ref, prov)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.assessments.list_for_ref(ref) == []


def test_a_report_intake_would_refuse_records_no_assessment(
    context: Context, engine: Engine
) -> None:
    findings = copy.deepcopy(REPORT["findings"])
    here = {"file_path": "/iac/main.tf", "file_line_range": [1, 4]}
    findings[0]["locations"] = [
        {**here, "resource": "aws_s3_bucket.data"},
        {"resource": "aws_s3_bucket.other"},
    ]
    findings[1].update(
        check_id="CKV_AWS_20",
        locations=[{**here, "resource": "aws_s3_bucket.other"}, {"resource": "aws_s3_bucket.data"}],
    )
    ref, audit = a_ref(engine), doc(findings=findings)
    prov = published(context, audit)
    with pytest.raises(ValidationError, match=r"conflicting symbols at iac/main\.tf:1"):
        context.services().assessment.record_audit(audit, ref, prov)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.assessments.list_for_ref(ref) == []


def test_assessed_decisions_need_the_assessments_occurrence(
    context: Context, engine: Engine
) -> None:
    ref, audit = a_ref(engine), doc()
    service = context.services().assessment
    assessment, decided = service.record_audit(audit, ref, published(context, audit))
    raw = (FIXTURES / "findings" / "scanners" / "codeql.sarif").read_bytes()
    prov = Provenance(run_id=uuid4(), source=SourceType.VULN_SCAN_REPORT, occurred_at=WHEN)
    _, scanned = service.record_scan(ref, raw, CandidateFormat.SARIF, prov)
    stranger = next(iter(scanned.findings.values()))
    uow = SqlTraustUnitOfWork(engine)
    decisions = FindingDecisions(
        uow,
        None,
        Lint({}),
        FindingPrecedents(uow),
        clock=FixedClock(WHEN),
        objects=InMemoryObjectStore(),
        review=ReviewPolicy(),
    )
    artifact_id = decided[0].artifact_id
    assert assessment.id is not None and artifact_id is not None
    with pytest.raises(ValidationError, match=f"didn't report finding {stranger}"):
        decisions.record_assessed(
            assessment.id, artifact_id, [(stranger, AssessedJudgment(validity=Validity.CONFIRMED))]
        )
    with SqlTraustUnitOfWork(engine) as check:
        assert check.decisions.list_for_finding(stranger) == []


def test_a_candidate_cannot_be_both_an_exposure_and_a_policy_check(engine: Engine) -> None:
    ref = a_ref(engine)
    with SqlTraustUnitOfWork(engine) as uow:
        repository_id = uow.repository_refs.get(ref).repository_id
    exposure = ExposureKey(
        advisory_id=uuid4(), advisory="GHSA-xxxx-xxxx-xxxx", ecosystem="go", package="x"
    )
    both = FindingCandidate(
        label=Label("BOTH-001"),
        repository_id=repository_id,
        title="both",
        rule="CKV_AWS_20",
        policy=True,
        exposure=exposure,
        locations=(CodeSpan(path=RepoPath("iac/main.tf")),),
        reported_severity=ScannerSeverity("unrated"),
    )
    intake = FindingIntake(SqlTraustUnitOfWork(engine), IdentityPolicy(), TaxonomyPolicy())
    with pytest.raises(ValidationError, match="BOTH-001: both an exposure and a policy check"):
        intake.check(repository_id, [both])
    with pytest.raises(ValidationError, match="both an exposure and a policy check"):
        intake.check(repository_id, [both.model_copy(update={"resources": ("r",)})])


def test_record_audit_refuses_a_reference_to_other_bytes(context: Context, engine: Engine) -> None:
    ref = a_ref(engine)
    prov = published(context, doc(gaps=[]))
    with pytest.raises(IntegrityError, match="doc digest"):
        context.services().assessment.record_audit(doc(), ref, prov)


def unpublished() -> Provenance:
    return Provenance(run_id=uuid4(), source=SourceType.VULN_SCAN_REPORT, occurred_at=WHEN)


def test_record_audit_publishes_a_report_the_caller_has_not(
    context: Context, engine: Engine
) -> None:
    ref, audit = a_ref(engine), doc()
    service = context.services().assessment
    first, decided = service.record_audit(audit, ref, unpublished())
    again, _ = service.record_audit(audit, ref, published(context, audit))
    assert (first.status, len(decided), again.id) == ("degraded", len(IDS), first.id)
    with SqlTraustUnitOfWork(engine) as uow:
        [report] = uow.artifacts.list_for_assessment(first.id, kind="cloud-config-audit")
    assert report.digest == sha256_hex(audit.payload)
    stored = context.object_store.get(context.object_store.stat(ObjectKey.parse(report.uri)))
    assert stored == audit.payload


def test_record_audit_without_a_publisher_or_a_published_report_records_nothing(
    context: Context, engine: Engine
) -> None:
    ref, uow = a_ref(engine), SqlTraustUnitOfWork(engine)
    decisions = FindingDecisions(
        uow,
        None,
        Lint({}),
        FindingPrecedents(uow),
        clock=FixedClock(WHEN),
        objects=InMemoryObjectStore(),
        review=ReviewPolicy(),
    )
    service = AssessmentService(
        uow, FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()), decisions=decisions
    )
    with pytest.raises(ConfigError, match="needs a publisher"):
        service.record_audit(doc(), ref, unpublished())
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.assessments.list_for_ref(ref) == []


def test_record_audit_needs_intake_and_decisions(engine: Engine) -> None:
    with pytest.raises(ConfigError, match="needs finding intake and decisions"):
        AssessmentService(SqlTraustUnitOfWork(engine)).record_audit(doc(), uuid4(), None)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("fixture", "format"),
    [
        ("codeql.sarif", CandidateFormat.SARIF),
        ("dependabot-alerts.json", CandidateFormat.DEPENDABOT),
        ("govulncheck.jsonl", CandidateFormat.GOVULNCHECK),
    ],
)
def test_scanner_findings_keep_their_path_and_cwe_identity(
    context: Context, engine: Engine, fixture: str, format: CandidateFormat
) -> None:
    ref = a_ref(engine)
    raw = (FIXTURES / "findings" / "scanners" / fixture).read_bytes()
    prov = Provenance(run_id=uuid4(), source=SourceType.VULN_SCAN_REPORT, occurred_at=WHEN)
    assessment, intake = context.services().assessment.record_scan(ref, raw, format, prov)
    with SqlTraustUnitOfWork(engine) as uow:
        url = uow.repositories.get(uow.repository_refs.get(ref).repository_id).url
        for finding_id in intake.findings.values():
            finding = uow.findings.get(finding_id)
            occurrence = uow.occurrences.find(finding_id, assessment.id)
            assert occurrence is not None
            paths = [loc.path for loc in uow.locations.list_for_occurrence(occurrence.id)]
            cwes = [
                uow.cwes.get(fc.cwe_id).identifier
                for fc in uow.finding_cwes.list_for_finding(finding_id)
            ]
            before = IdentityPolicy().match_key(
                FingerprintInput(
                    repo=url,
                    cwes=tuple(cwes),
                    locations=tuple(FingerprintLocation(path=p) for p in paths),
                )
            )
            assert finding.fingerprint == before.value
