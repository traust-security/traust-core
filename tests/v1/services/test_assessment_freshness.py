"""AssessmentService.freshness by commit: measured against its repository's latest code audit."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.assessment import ASSESSMENT_DEGRADED, AssessmentKind
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.assessment import AssessmentService

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed

SECURE_CODE = AssessmentKind.SECURE_CODE.value


@pytest.fixture
def service(uow: SqlTraustUnitOfWork) -> AssessmentService:
    return AssessmentService(uow, clock=FixedClock(T0 + timedelta(days=30)))


def test_a_commit_is_as_fresh_as_its_repositorys_latest_completed_audit(
    service: AssessmentService, seed: Seed
) -> None:
    repo = seed.repository()
    audited = seed.repository_ref(repo, is_default=True)
    head = seed.repository_ref(repo, name=None, kind=None, sha="c" * 40)
    seed.assessment(audited, kind=SECURE_CODE, occurred_at=T0 + timedelta(days=2))
    seed.assessment(
        audited, kind=SECURE_CODE, occurred_at=T0 + timedelta(days=9), status=ASSESSMENT_DEGRADED
    )

    found = service.freshness(head.id)

    assert found.repository_ref_id == head.id
    assert found.last_assessed_at == datetime(2026, 10, 7)
    assert found.churn_ratio is None


def test_a_never_audited_repository_has_no_last_assessment(
    service: AssessmentService, seed: Seed
) -> None:
    ref = seed.repository_ref(seed.repository(), is_default=True)
    seed.assessment(ref, kind=AssessmentKind.THREAT_MODEL.value)
    assert service.freshness(ref.id).last_assessed_at is None


def test_freshness_needs_a_known_ref_or_a_baseline(service: AssessmentService) -> None:
    with pytest.raises(NotFoundError):
        service.freshness(uuid4())
    with pytest.raises(ValidationError, match="repository ref or an observation baseline"):
        service.freshness()
