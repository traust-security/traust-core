"""observation_target and open counts over the contract tables (SQLite + Postgres)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest

from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.observation import ObservationTarget
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.assessment import AssessmentService


def service(uow: SqlTraustUnitOfWork) -> AssessmentService:
    """A service sharing the open unit of work, as the observation door wires it."""
    return AssessmentService(uow)


def test_resolves_latest_audit_and_pinned_commit(uow, seed: Seed):
    repo = seed.repository(url="https://github.com/org/audited")
    old_ref = seed.repository_ref(repository=repo, sha="a" * 40)
    new_ref = seed.repository_ref(repository=repo, sha="b" * 40)
    seed.assessment(
        ref=old_ref,
        kind=AssessmentKind.SECURE_CODE,
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    seed.assessment(
        ref=new_ref,
        kind=AssessmentKind.SECURE_CODE,
        occurred_at=datetime(2026, 9, 1, tzinfo=UTC),
    )
    # a non-audit assessment on a newer ref must not win
    seed.assessment(
        ref=new_ref,
        kind=AssessmentKind.THREAT_MODEL,
        occurred_at=datetime(2026, 10, 1, tzinfo=UTC),
    )
    target = service(uow).observation_target(repo_url="https://github.com/org/audited")
    assert target == ObservationTarget(
        repository_id=repo.id,
        repo_url="https://github.com/org/audited",
        has_audit=True,
        audit_date="2026-09-01",
        pinned_sha="b" * 40,
        repository_ref_id=new_ref.id,
    )
    by_id = service(uow).observation_target(repository_id=repo.id)
    assert by_id == target


@pytest.mark.parametrize(
    "offset,expected_date",
    [(5, "2026-08-31"), (-5, "2026-09-01")],
)
def test_audit_date_uses_utc_instead_of_the_database_timezone(
    uow, seed: Seed, offset, expected_date
):
    ref = seed.repository_ref()
    seed.assessment(
        ref=ref,
        kind=AssessmentKind.SECURE_CODE,
        occurred_at=datetime(2026, 9, 1, 1, tzinfo=timezone(timedelta(hours=offset))),
    )

    target = service(uow).observation_target(repository_id=ref.repository_id)
    assert target.audit_date == expected_date


def test_a_failed_audit_is_never_the_baseline(uow, seed: Seed):
    repo = seed.repository(url="https://github.com/org/flaky")
    ref = seed.repository_ref(repository=repo, sha="a" * 40)
    seed.assessment(
        ref=ref,
        kind=AssessmentKind.SECURE_CODE,
        occurred_at=datetime(2026, 9, 1, tzinfo=UTC),
    )
    # a newer run that failed must not displace the completed baseline
    seed.assessment(
        ref=ref,
        kind=AssessmentKind.SECURE_CODE,
        status="failed",
        occurred_at=datetime(2026, 10, 1, tzinfo=UTC),
    )

    target = service(uow).observation_target(repo_url="https://github.com/org/flaky")
    assert target.audit_date == "2026-09-01"


def test_only_failed_audits_count_as_never_audited(uow, seed: Seed):
    repo = seed.repository(url="https://github.com/org/all-failed")
    ref = seed.repository_ref(repository=repo, sha="a" * 40)
    seed.assessment(
        ref=ref,
        kind=AssessmentKind.SECURE_CODE,
        status="failed",
        occurred_at=datetime(2026, 10, 1, tzinfo=UTC),
    )

    target = service(uow).observation_target(repo_url="https://github.com/org/all-failed")
    assert target.has_audit is False


def test_observation_target_without_an_audit_is_never_audited(uow, seed: Seed):
    repo = seed.repository(url="https://github.com/org/never-audited")
    target = service(uow).observation_target(repo_url="https://github.com/org/never-audited")
    assert target.has_audit is False
    assert target.repository_id == repo.id


def test_observation_target_requires_inventory_membership(uow, seed: Seed):
    with pytest.raises(NotFoundError):
        service(uow).observation_target(repo_url="https://github.com/org/unknown")


def test_observation_target_takes_exactly_one_selector(uow):
    with pytest.raises(ValidationError):
        service(uow).observation_target()
    with pytest.raises(ValidationError):
        service(uow).observation_target(
            repository_id=UUID(int=1), repo_url="https://github.com/org/x"
        )


def test_open_counts_read_the_finding_status_view(uow, seed: Seed):
    from traust_core.v1.models.vocabulary import Severity

    repo = seed.repository()
    counts = uow.open_counts
    assert counts.open_count(repo.id, (Severity.CRITICAL, Severity.HIGH)) == 0
    critical, high, medium = (
        seed.finding(repository=repo),
        seed.finding(repository=repo),
        seed.finding(repository=repo),
    )
    # severity rides on the occurrence (the finding row is identity only)
    seed.occurrence(finding=critical, severity="critical")
    seed.occurrence(finding=high, severity="high")
    seed.occurrence(finding=medium, severity="medium")
    # decisions close two of the three: one false_positive, one resolved
    seed.decision(finding=critical, validity="false_positive")
    seed.decision(finding=medium, resolution="resolved")
    assert counts.open_count(repo.id, (Severity.CRITICAL, Severity.HIGH)) == 1
    assert counts.open_count(repo.id, ()) == 0
