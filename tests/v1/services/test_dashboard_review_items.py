"""The review_items subject: the countersign queue's counts as one dashboard query. The
oracle is the seeded table below, every review item's status and reason stated, never
derived from the code under test."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.test_dashboards import T0, _service
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.dashboard import DashboardQuery
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

# (repository, status, reason, the finding's band)
ITEMS = (
    ("svc", "pending", "needs_manual_test", "critical"),
    ("svc", "pending", "needs_manual_test", "high"),
    ("svc", "pending", "undetermined_finding", "medium"),
    ("svc", "accepted", "needs_manual_test", "low"),
    ("svc", "pending", "fp_audit_valve", "high"),
    ("lib", "pending", "needs_manual_test", "critical"),
    ("lib", "accepted", "fp_audit_valve", "medium"),
    ("outside", "pending", "needs_manual_test", "critical"),
)
GRANT = ("svc", "lib")


def _seed(engine: Engine) -> dict[str, UUID]:
    with SqlTraustUnitOfWork(engine) as uow:
        s = Seed(uow)
        repos = {
            name: s.repository(url=f"https://github.com/example-org/{name}")
            for name in ("svc", "lib", "outside")
        }
        audits = {n: s.assessment(s.repository_ref(r), occurred_at=T0) for n, r in repos.items()}
        for index, (repo, status, reason, band) in enumerate(ITEMS):
            finding = s.finding(repos[repo], title=f"item {index}")
            s.occurrence(finding, audits[repo], severity=band)
            s.review_item(finding, status=status, reason=reason)
        uow.commit()
        return {name: r.id for name, r in repos.items()}


@pytest.fixture(params=SQL_BACKENDS)
def seeded(
    request: pytest.FixtureRequest, tmp_path: Path
) -> Iterator[tuple[Engine, dict[str, UUID]]]:
    with contract_db(request.param, tmp_path) as engine:
        yield engine, _seed(engine)


def _query(engine: Engine, repos: dict[str, UUID], **shape: object) -> dict[tuple, float]:
    results = _service(engine).query(
        DashboardQuery(
            subject="review_items",
            repository_ids=tuple(repos[name] for name in GRANT),
            measures=("review_items",),
            **shape,  # type: ignore[arg-type]
        )
    )
    return {tuple(row.groups.values()): row.measures["review_items"] for row in results.rows}


def test_the_pending_countersigns_are_one_count(seeded) -> None:
    engine, repos = seeded
    got = _query(engine, repos, where={"status": ("pending",)})
    expected = sum(1 for repo, status, _, _ in ITEMS if repo in GRANT and status == "pending")
    assert got == {(): float(expected)}


def test_the_queue_groups_by_status_and_reason(seeded) -> None:
    engine, repos = seeded
    got = _query(engine, repos, group_by=("status", "reason"))
    expected = Counter((status, reason) for repo, status, reason, _ in ITEMS if repo in GRANT)
    assert got == {key: float(n) for key, n in expected.items()}


def test_pending_items_carry_their_findings_severity(seeded) -> None:
    engine, repos = seeded
    got = _query(engine, repos, group_by=("severity",), where={"status": ("pending",)})
    expected = Counter(
        (band,) for repo, status, _, band in ITEMS if repo in GRANT and status == "pending"
    )
    assert got == {key: float(n) for key, n in expected.items()}


def test_nothing_outside_the_grant_contributes(seeded) -> None:
    engine, repos = seeded
    got = _query(engine, repos, group_by=("repository",))
    assert {key[0] for key in got} == {str(repos[name]) for name in GRANT}


def test_the_subjects_do_not_borrow_each_others_vocabulary(seeded) -> None:
    engine, repos = seeded
    with pytest.raises(ValidationError):
        _query(engine, repos, group_by=("category",))  # a finding fact, not a review item's
    with pytest.raises(ValidationError):
        _service(engine).query(
            DashboardQuery(subject="findings", measures=("findings",), group_by=("status",))
        )
