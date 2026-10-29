"""AssessmentService reads the security pack's router needs through RepoState: the latest
completed assessment of a kind on the default line, and what a code audit's report covered."""

from __future__ import annotations

import json
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.test_assessment_population import SECURE_CODE, Fleet, report
from traust_core.v1.errors import ConfigError, NotFoundError
from traust_core.v1.models.assessment import ASSESSMENT_DEGRADED, AssessmentKind, AuditScope
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.assessment import AssessmentService

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed

CLOUD_CONFIG = AssessmentKind.CLOUD_CONFIG_CANONICAL.value


@pytest.fixture
def fleet(uow: SqlTraustUnitOfWork, seed: Seed) -> Fleet:
    return Fleet(uow, seed)


def test_the_latest_completed_default_line_assessment_of_a_kind(fleet: Fleet) -> None:
    repo, main, branch = fleet.repo()
    assert repo.id is not None
    assert fleet.service.latest_on_default_line(repo.id, AssessmentKind.CLOUD_CONFIG) is None
    older = fleet.seed.assessment(main, kind=CLOUD_CONFIG, occurred_at=T0)
    later = T0 + timedelta(days=2)
    fleet.seed.assessment(main, kind=CLOUD_CONFIG, occurred_at=later, status=ASSESSMENT_DEGRADED)
    fleet.seed.assessment(branch, kind=CLOUD_CONFIG, occurred_at=T0 + timedelta(days=3))
    fleet.seed.assessment(main, kind=SECURE_CODE, occurred_at=T0 + timedelta(days=4))
    found = fleet.service.latest_on_default_line(repo.id, AssessmentKind.CLOUD_CONFIG)
    assert found is not None and found.id == older.id


def test_a_repository_with_no_refs_has_no_latest(fleet: Fleet) -> None:
    repo = fleet.seed.repository()
    assert repo.id is not None
    assert fleet.service.latest_on_default_line(repo.id, AssessmentKind.THREAT_MODEL) is None


def test_latest_on_default_lines_is_each_repositorys_latest_at_once(fleet: Fleet) -> None:
    first, first_main, first_branch = fleet.repo()
    second, second_main, _ = fleet.repo()
    moved = fleet.seed.repository_ref(second, is_default=True, sha="c" * 40)
    never = fleet.seed.repository()
    fleet.seed.assessment(first_main, kind=CLOUD_CONFIG, occurred_at=T0)
    fleet.seed.assessment(first_branch, kind=CLOUD_CONFIG, occurred_at=T0 + timedelta(days=5))
    fleet.seed.assessment(second_main, kind=CLOUD_CONFIG, occurred_at=T0 + timedelta(days=1))
    fleet.seed.assessment(moved, kind=CLOUD_CONFIG, occurred_at=T0 + timedelta(days=2))
    ids = [r.id for r in (first, second, never) if r.id]
    found = fleet.service.latest_on_default_lines(ids, AssessmentKind.CLOUD_CONFIG)
    assert found == {
        r: a
        for r in ids
        if (a := fleet.service.latest_on_default_line(r, AssessmentKind.CLOUD_CONFIG))
    }
    assert {r: a.repository_ref_id for r, a in found.items()} == {
        first.id: first_main.id,
        second.id: moved.id,
    }
    assert fleet.service.latest_on_default_lines([], AssessmentKind.CLOUD_CONFIG) == {}


def test_audit_scope_reads_the_audit_report(fleet: Fleet) -> None:
    _, main, _ = fleet.repo()
    doc = json.loads(report({"companion_lanes": ["cloud-config-audit"]}))
    doc["metadata"]["loc_reviewed"] = 2400
    audit = fleet.audit(main, 1, json.dumps(doc).encode())
    assert fleet.service.audit_scope(audit) == AuditScope(
        lines_reviewed=2400, companion_lanes=("cloud-config-audit",)
    )


def test_an_audit_without_a_report_has_an_unknown_scope(fleet: Fleet) -> None:
    _, main, _ = fleet.repo()
    assert fleet.service.audit_scope(fleet.audit(main, 1)) == AuditScope()


def test_audit_scope_of_an_unknown_assessment_is_not_found(fleet: Fleet) -> None:
    with pytest.raises(NotFoundError):
        fleet.service.audit_scope(uuid4())


def test_audit_scope_needs_the_publisher(uow: SqlTraustUnitOfWork, fleet: Fleet) -> None:
    _, main, _ = fleet.repo()
    with pytest.raises(ConfigError, match="publisher"):
        AssessmentService(uow).audit_scope(fleet.audit(main, 1))
