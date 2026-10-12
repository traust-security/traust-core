from datetime import timedelta

import pytest

from tests.v1.observation_support import NOW, REFERENCE, observer
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.portfolio import ComparisonStatus
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.services.portfolio import BanBreaker


@pytest.mark.parametrize("case", REFERENCE["cases"], ids=lambda c: c["name"])
def test_recorded_legacy_observation_parity(case):
    service, _, _, _, source = observer(case)
    service.record_forge_facts(repo_key=case["repo"]["repo_key"])
    state = service.repo_state(repo_key=case["repo"]["repo_key"])
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
    for field, old in {
        "risk_tier": "tier",
        "exposure": "exposure",
        "audit_age_days": "audit_age_days",
    }.items():
        assert getattr(state, field) == case["ctx"][old]
    assert bool(state.push_changed) == case["ctx"]["changed"]
    assert state.churn_ratio == (case["ctx"]["R"] if state.changed_lines is not None else None)
    assert source.calls.count("compare") == int(case["info"]["ok"] and case["ctx"]["changed"])


def test_state_recomputes_findings_and_age_without_contacting_forge():
    service, uow, _assessment, findings, source = observer(live_crit_high=5)
    service.record_forge_facts(repo_key="test")
    before = service.repo_state(repo_key="test")
    stored = dict(uow.portfolio.rows)
    calls = list(source.calls)
    findings.findings.rows.clear()
    service._clock = FixedClock(NOW + timedelta(days=3))
    after = service.repo_state(repo_key="test")
    assert before.risk_tier == "P0" and after.risk_tier == "P2"
    assert after.audit_age_days == before.audit_age_days + 3
    assert uow.portfolio.rows == stored
    assert source.calls == calls


@pytest.mark.parametrize(
    "field,value", [("pinned_sha", "b" * 40), ("audit_date", "2026-10-02"), ("has_audit", False)]
)
def test_changed_baseline_cannot_reuse_comparison(field, value):
    service, _, assessment, _, _ = observer()
    service.record_forge_facts(repo_key="test")
    assessment.target = assessment.target.model_copy(update={field: value})
    with pytest.raises(NotFoundError, match="baseline changed"):
        service.repo_state(repo_key="test")


def test_new_lines_reviewed_recomputes_churn_without_refetch():
    service, _, assessment, _, source = observer(lines_reviewed=100)
    service.record_forge_facts(repo_key="test")
    before = service.repo_state(repo_key="test")
    assessment.target = assessment.target.model_copy(update={"lines_reviewed": 200})
    assert service.repo_state(repo_key="test").churn_ratio == before.churn_ratio / 2
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
    facts = service.record_forge_facts(repo_key="test", **kwargs)
    assert facts.status == service.repo_state(repo_key="test").status == status


def test_no_network_never_contacts_source():
    service, _, _, _, source = observer()
    service.record_forge_facts(repo_key="test", network=False)
    assert source.calls == []


def test_batch_quota_decision_does_not_query_live_quota():
    service, _, _, _, source = observer()
    service.record_forge_facts(repo_key="test", quota_deferred=False)
    assert source.calls == ["info", "compare"]


def test_metric_programming_errors_are_not_degraded(monkeypatch):
    service, _, _, _, _ = observer()

    def broken(files):
        raise TypeError("metric bug")

    monkeypatch.setattr("traust_core.v1.services.portfolio.change_metrics", broken)
    with pytest.raises(TypeError, match="metric bug"):
        service.record_forge_facts(repo_key="test")
