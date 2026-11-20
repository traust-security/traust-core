"""The dashboard service: one metrics query over the facts, trimmed to the
caller's repositories. Correctness against a seeded estate, the access trim,
and the refusal of everything the catalog does not serve."""

from __future__ import annotations

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.dashboard import DashboardQuery
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.dashboards import DashboardService
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

HUMAN = "human:analyst@example.com"


def _seed(engine: Engine) -> dict[str, object]:
    with SqlTraustUnitOfWork(engine) as uow:
        s = Seed(uow)
        repo = s.repository(url="https://github.com/example-org/svc")
        other = s.repository(url="https://github.com/example-org/lib")
        audit = s.assessment(s.repository_ref(repo), occurred_at=T0)
        other_audit = s.assessment(s.repository_ref(other), occurred_at=T0)
        for severity in ("critical", "high", "medium"):
            s.occurrence(s.finding(repo, title=f"Open {severity}"), audit, severity=severity)
        resolved = s.finding(repo, title="Resolved")
        s.occurrence(resolved, audit, severity="high")
        s.decision(resolved, validity="confirmed", resolution="resolved", actor=HUMAN)
        labelled = s.finding(repo, title="Labelled")
        s.occurrence(labelled, audit, severity="low")
        s.finding_label(labelled, taxonomy="category", label="xss")
        s.occurrence(s.finding(other, title="Elsewhere"), other_audit, severity="critical")
        uow.commit()
        return {"repo": repo.id, "other": other.id}


def _service(engine: Engine) -> DashboardService:
    uow = SqlTraustUnitOfWork(engine)
    return DashboardService(uow, PortfolioService(uow, PortfolioPolicy()))


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_counts_by_severity_within_the_grant(backend: str, tmp_path) -> None:
    with contract_db(backend, tmp_path) as engine:
        seeded = _seed(engine)
        service = _service(engine)

        results = service.query(
            DashboardQuery(
                subject="findings",
                repository_ids=(seeded["repo"],),
                measures=("findings",),
                group_by=("severity",),
                where={"state": ("open",)},
            )
        )

        assert {(row.groups["severity"], row.measures["findings"]) for row in results.rows} == {
            ("critical", 1.0),
            ("high", 1.0),
            ("medium", 1.0),
            ("low", 1.0),
        }  # the resolved high and the other repository's critical are not open, not granted


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_the_whole_estate_needs_no_filter(backend: str, tmp_path) -> None:
    with contract_db(backend, tmp_path) as engine:
        _seed(engine)
        service = _service(engine)

        results = service.query(
            DashboardQuery(subject="findings", measures=("findings",), group_by=("state",))
        )

        assert {row.groups["state"]: row.measures["findings"] for row in results.rows} == {
            "open": 5.0,
            "resolved": 1.0,
        }


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_the_catalog_refuses_what_it_does_not_serve(backend: str, tmp_path) -> None:
    with contract_db(backend, tmp_path) as engine:
        _seed(engine)
        service = _service(engine)

        with pytest.raises(ValidationError, match="not yet served"):
            service.query(DashboardQuery(subject="repositories", measures=("repositories",)))
        with pytest.raises(ValidationError, match="does not group by"):
            service.query(
                DashboardQuery(subject="findings", measures=("findings",), group_by=("sla_status",))
            )
        with pytest.raises(ValidationError, match="does not measure"):
            service.query(DashboardQuery(subject="findings", measures=("median_open_days",)))


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_a_where_value_is_a_bound_literal_never_sql(backend: str, tmp_path) -> None:
    with contract_db(backend, tmp_path) as engine:
        _seed(engine)
        service = _service(engine)

        results = service.query(
            DashboardQuery(
                subject="findings",
                measures=("findings",),
                where={"category": ("xss' OR '1'='1", "xss")},
            )
        )

        assert sum(row.measures["findings"] for row in results.rows) == 1.0  # only the real label


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_order_and_limit_cap_the_answer(backend: str, tmp_path) -> None:
    with contract_db(backend, tmp_path) as engine:
        _seed(engine)
        service = _service(engine)

        results = service.query(
            DashboardQuery(
                subject="findings",
                measures=("findings",),
                group_by=("severity",),
                order=({"by": "findings", "desc": True},),
                limit=2,
            )
        )

        assert len(results.rows) == 2
        counts = [row.measures["findings"] for row in results.rows]
        assert counts == sorted(counts, reverse=True)


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_an_order_key_the_query_does_not_serve_is_refused(backend: str, tmp_path) -> None:
    with contract_db(backend, tmp_path) as engine:
        _seed(engine)
        service = _service(engine)
        for order in ({"by": "median_open_days"}, {"by": "category"}):  # unserved; not grouped
            with pytest.raises(ValidationError, match="cannot order by"):
                service.query(
                    DashboardQuery(
                        subject="findings",
                        measures=("findings",),
                        group_by=("severity",),
                        order=(order,),
                    )
                )


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_the_oldest_open_age_ignores_closed_findings(backend: str, tmp_path) -> None:
    with contract_db(backend, tmp_path) as engine:
        _seed(engine)  # every seeded finding was recorded now; one is resolved
        with engine.begin() as conn:  # the resolved one becomes the oldest by far
            table = "finding" if engine.dialect.name == "sqlite" else "traust.finding"
            conn.exec_driver_sql(
                f"UPDATE {table} SET created_at = '2000-01-01T00:00:00Z' WHERE title = 'Resolved'"
            )
        results = _service(engine).query(
            DashboardQuery(subject="findings", measures=("oldest_open_age",))
        )
        age = results.rows[0].measures["oldest_open_age"]
        assert age is not None and age < 1  # days: the open ones are new; the resolved one is not
