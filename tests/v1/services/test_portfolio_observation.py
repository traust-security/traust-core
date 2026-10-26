import json
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.v1.observation_support import NOW, REFERENCE, observer, repository_id_for
from tests.v1.services.test_assessment_population import report
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.artifacts import ReportArtifact
from traust_core.v1.models.assessment import ASSESSMENT_COMPLETED, Assessment, AssessmentKind
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.values import ProductSlug
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.services.artifact_publishing import AssessmentLog
from traust_core.v1.services.portfolio import BanBreaker

RID = repository_id_for(None, "test")
# Not answered, deferred or not asked: the run order's outcome, never a stored state.
NOT_KEPT = {
    ComparisonStatus.QUOTA_DEFERRED,
    ComparisonStatus.NO_CREDENTIALS,
    ComparisonStatus.UNREACHABLE,
    ComparisonStatus.ERROR,
    ComparisonStatus.BAN_SUSPECTED,
    ComparisonStatus.NETWORK_SKIPPED,
}


@pytest.mark.parametrize("case", REFERENCE["cases"], ids=lambda c: c["name"])
def test_recorded_legacy_observation_parity(case):
    service, _, _, _, source = observer(case)
    facts = service.record_forge_facts(repo_url=case["repo"]["repo_url"])
    if case["status"] in NOT_KEPT:
        # The forge didn't answer: the order's outcome, never a stored state (repo-state schema).
        assert facts.status == case["status"]
        with pytest.raises(NotFoundError, match="observe it first"):
            service.repo_state(repo_url=case["repo"]["repo_url"])
        return
    state = service.repo_state(repo_url=case["repo"]["repo_url"])
    assert state.status == case["status"]
    for new, old in {
        "changed_lines": "C",
        "sensitive_changed": "S",
        "sensitive_lines": "S_lines",
        "deps_only": "deps_only",
        "ahead_by": "ahead_by",
        "compare_truncated": "truncated",
    }.items():
        assert getattr(state, new) == case["observed"][old]
    # Legacy exposure assumed public repos ship; Core now reads component membership.
    for field, old in {
        "risk_tier": "tier",
        "audit_age_days": "audit_age_days",
    }.items():
        assert getattr(state, field) == case["ctx"][old]
    assert bool(state.push_changed) == case["ctx"]["changed"]
    assert state.churn_ratio == (case["ctx"]["R"] if state.changed_lines is not None else None)
    assert source.calls.count("compare") == int(case["info"]["ok"] and case["ctx"]["changed"])


def test_state_recomputes_findings_and_age_without_contacting_forge():
    service, portfolio, _assessment, findings, source = observer(live_crit_high=5)
    service.record_forge_facts(repository_id=RID)
    before = service.repo_state(repository_id=RID)
    stored = portfolio.forge_facts(RID)
    calls = list(source.calls)
    findings.counts.clear()
    service._clock = service.query._clock = FixedClock(NOW + timedelta(days=3))
    after = service.repo_state(repository_id=RID)
    assert before.risk_tier == "P0" and after.risk_tier == "P2"
    assert after.audit_age_days == before.audit_age_days + 3
    assert portfolio.forge_facts(RID) == stored
    assert source.calls == calls


def test_exposure_tracks_product_membership_without_refetching_forge():
    service, portfolio, _, _, source = observer()
    repo_id = service.repository_id
    service.record_forge_facts(repository_id=repo_id)
    assert service.repo_state(repository_id=repo_id).exposure == "public-internal"
    calls = list(source.calls)

    product = portfolio.register_product(ProductSlug("example"), "Example")
    release = portfolio.record_release(product.id, "1")
    ref = portfolio.inventory.default_ref(repo_id)
    assert ref is not None and ref.id is not None
    portfolio.add_component(release.id, ref.id)

    assert service.repo_state(repository_id=repo_id).exposure == "public-external"
    assert source.calls == calls


def test_changed_baseline_cannot_reuse_comparison():
    service, _, assessment, _, _ = observer()
    service.record_forge_facts(repository_id=RID)
    new_audit = {"audit_assessment_id": uuid4(), "pinned_sha": "b" * 40, "audit_date": "2026-10-02"}
    assessment.target = assessment.target.model_copy(update=new_audit)
    with pytest.raises(NotFoundError, match="baseline changed"):
        service.repo_state(repository_id=RID)


def test_a_repository_without_an_audit_needs_no_observation():
    service, _, assessment, _, source = observer()
    service.record_forge_facts(repository_id=RID)
    assessment.target = assessment.target.model_copy(update={"has_audit": False})
    assert service.repo_state(repository_id=RID).status == ComparisonStatus.NEVER_AUDITED
    assert source.calls.count("info") == 1


def test_new_lines_reviewed_recomputes_churn_without_refetch():
    service, _, assessment, _, source = observer(lines_reviewed=100)
    service.record_forge_facts(repository_id=RID)
    before = service.repo_state(repository_id=RID)
    assessment.target = assessment.target.model_copy(update={"lines_reviewed": 200})
    assert service.repo_state(repository_id=RID).churn_ratio == before.churn_ratio / 2
    assert source.calls.count("compare") == 1


@pytest.mark.parametrize("status", list(ComparisonStatus))
def test_status_is_stored_and_reassembled(status):
    changes, kwargs = {}, {}
    if status == ComparisonStatus.NO_REPO_URL:
        changes["repo_url"] = None
    elif status == ComparisonStatus.UNSUPPORTED_HOST:
        changes["repo_url"] = "https://unsupported.example/o/r"
    elif status == ComparisonStatus.NEVER_AUDITED:
        changes["has_audit"] = False
    elif status == ComparisonStatus.NO_PINNED_SHA:
        changes["pinned_sha"] = None
    elif status == ComparisonStatus.NETWORK_SKIPPED:
        kwargs["network"] = False
    elif status == ComparisonStatus.QUOTA_DEFERRED:
        kwargs["quota_deferred"] = True
    elif status == ComparisonStatus.BAN_SUSPECTED:
        breaker = BanBreaker(1)
        breaker.record(False)
        kwargs["breaker"] = breaker
    service, _, _, _, source = observer(**changes)
    if status in (
        ComparisonStatus.NO_CREDENTIALS,
        ComparisonStatus.UNREACHABLE,
        ComparisonStatus.ERROR,
    ):
        source.info_data = {"ok": False, "kind": status}
    facts = service.record_forge_facts(repository_id=RID, **kwargs)
    assert facts.status == status
    if status in NOT_KEPT:
        with pytest.raises(NotFoundError, match="observe it first"):
            service.repo_state(repository_id=RID)
    else:
        assert service.repo_state(repository_id=RID).status == status


def test_no_network_never_contacts_source():
    service, _, _, _, source = observer()
    service.record_forge_facts(repository_id=RID, network=False)
    assert source.calls == []


def test_batch_quota_decision_does_not_query_live_quota():
    service, _, _, _, source = observer()
    service.record_forge_facts(repository_id=RID, quota_deferred=False)
    assert source.calls == ["info", "head", "compare"]


def test_metric_programming_errors_are_not_degraded(monkeypatch):
    service, _, _, _, _ = observer()

    def broken(files):
        raise TypeError("metric bug")

    monkeypatch.setattr("traust_core.v1.services.observation.change_metrics", broken)
    with pytest.raises(TypeError, match="metric bug"):
        service.record_forge_facts(repository_id=RID)


ROUTER_FILES = [
    {"filename": "infra/main.tf", "changes": 10},
    {"filename": "cmd/server/main.go", "changes": 5},
    {"filename": "pkg/auth.go", "changes": 3},
    {"filename": "vendor/lib/x.go", "changes": 100},
    {"filename": "docs/README.md", "changes": 1},
]
TREE = ["infra/main.tf", "cmd/server/main.go", "pkg/auth.go", "pkg/util.go", "vendor/v.go", "a.md"]


def compared(files=ROUTER_FILES, truncated=False):
    return {"ok": True, "ahead_by": 4, "truncated": truncated, "files": files}


def test_the_router_file_counts_are_stored_and_read_back():
    service, portfolio, _, _, source = observer()
    source.comparison_data = compared()
    source.tree_data = {"ok": True, "paths": TREE, "truncated": False}
    service.record_forge_facts(repository_id=RID)
    state = service.repo_state(repository_id=RID)
    assert (state.first_party_files, state.iac_files, state.threat_model_files) == (3, 1, 1)
    assert state.tree_first_party_files == 4
    assert portfolio.forge_facts(RID).tree_first_party_files == 4
    assert source.calls.count("tree") == 1


@pytest.mark.parametrize(
    ("changes", "comparison", "tree", "counted", "calls"),
    [
        ({}, compared(ROUTER_FILES[:2]), None, None, 0),
        ({}, compared(truncated=True), None, None, 0),
        ({"repo_url": "https://gitlab.com/o/repo"}, compared(), None, None, 0),
        ({}, compared(), {"ok": True, "paths": TREE, "truncated": True}, None, 1),
        ({}, compared(), {"ok": False, "kind": "unreachable"}, None, 1),
    ],
    ids=[
        "too few first-party files",
        "compare truncated",
        "gitlab has no cheap listing",
        "tree truncated",
        "tree listing failed",
    ],
)
def test_the_tree_is_counted_only_when_the_ratio_can_matter(
    changes, comparison, tree, counted, calls
):
    service, _, _, _, source = observer(**changes)
    source.comparison_data = comparison
    if tree is not None:
        source.tree_data = tree
    service.record_forge_facts(repository_id=RID)
    state = service.repo_state(repository_id=RID)
    assert state.status == ComparisonStatus.OK
    assert state.tree_first_party_files == counted
    assert source.calls.count("tree") == calls


def _assess(portfolio, kind, occurred_at, ref=None):
    with portfolio._uow as uow:
        ref = ref or uow.repository_refs.default(portfolio._assessment.target.repository_id)
        added = uow.assessments.add(
            Assessment(
                repository_ref_id=ref.id,
                kind=kind,
                status=ASSESSMENT_COMPLETED,
                assessor="skill:test",
                assessor_version="1",
                occurred_at=occurred_at,
            )
        )
        uow.commit()
    return added


def test_the_default_line_models_and_baselines_reach_the_state():
    service, portfolio, _, _, _ = observer()
    service.record_forge_facts(repository_id=RID)
    state = service.repo_state(repository_id=RID)
    assert (state.has_cloud_config_baseline, state.threat_model_age_days) == (False, None)
    _assess(portfolio, AssessmentKind.CLOUD_CONFIG_CANONICAL, NOW - timedelta(days=5))
    _assess(portfolio, AssessmentKind.THREAT_MODEL_CANONICAL, NOW - timedelta(days=100))
    state = service.repo_state(repository_id=RID)
    assert (state.has_cloud_config_baseline, state.threat_model_age_days) == (True, 100)


def _audited(portfolio, assessment, loc, lanes=()):
    """A completed code audit holding a report that states `loc` and `lanes`."""
    doc = json.loads(report({"companion_lanes": list(lanes)}))
    doc["metadata"]["loc_reviewed"] = loc
    with portfolio._uow as uow:
        repository_id = assessment.target.repository_id
        ref = uow.repository_refs.add(RepositoryRef(repository_id=repository_id, sha="a" * 40))
        uow.commit()
    audit = _assess(portfolio, AssessmentKind.SECURE_CODE_CANONICAL, NOW - timedelta(days=30), ref)
    payload = json.dumps(doc).encode()
    published = assessment._publisher.publish_artifact(ReportArtifact.parse(payload))
    with portfolio._uow as uow:
        AssessmentLog(uow).attach(audit.id, published.artifact_id, sha256_hex(payload))
        uow.commit()
    assessment.target = assessment.target.model_copy(
        update={"audit_assessment_id": audit.id, "lines_reviewed": None}
    )


def test_churn_and_companions_come_from_the_audit_report():
    service, portfolio, assessment, _, _ = observer()
    _audited(portfolio, assessment, 2400, ["cloud-config-audit"])
    service.record_forge_facts(repository_id=RID)
    state = service.repo_state(repository_id=RID)
    assert state.churn_ratio == pytest.approx(240 / 2400)
    assert state.companion_lanes == ("cloud-config-audit",)


def test_an_unchanged_repository_with_a_cloud_config_baseline_skips_the_report_read(monkeypatch):
    service, portfolio, assessment, _, source = observer()
    _audited(portfolio, assessment, 2400, ["cloud-config-audit"])
    source.info_data = {**source.info_data, "pushed_at": "2026-08-01T00:00:00Z"}
    service.record_forge_facts(repository_id=RID)
    _assess(portfolio, AssessmentKind.CLOUD_CONFIG_CANONICAL, NOW - timedelta(days=5))
    monkeypatch.setattr(assessment, "audit_scope", lambda _: pytest.fail("report read"))
    state = service.repo_state(repository_id=RID)
    assert (state.changed_lines, state.companion_lanes, state.churn_ratio) == (None, (), None)
