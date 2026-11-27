"""The dashboard service: one metrics query over the facts, trimmed to the
caller's repositories. Correctness against a seeded estate, the access trim,
and the refusal of everything the catalog does not serve."""

from __future__ import annotations

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.dashboard import DashboardQuery, Subject
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.traust.findings.dashboard_facts import _facts_sql
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


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_a_team_scoped_query_counts_the_teams_repositories(backend: str, tmp_path) -> None:
    with contract_db(backend, tmp_path) as engine:
        seeded = _seed(engine)
        with SqlTraustUnitOfWork(engine) as uow:
            team = Seed(uow).team()
            Seed(uow).ownership(repository_id=seeded["repo"], team=team)
            uow.commit()
        assert team.id is not None
        results = _service(engine).query(
            DashboardQuery(subject="findings", team_ids=(team.id,), measures=("findings",))
        )
        assert results.rows[0].measures["findings"] == 5  # the team's repository, not the estate


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_decided_keys_and_filters_are_the_same_text_on_every_engine(backend: str, tmp_path) -> None:
    with contract_db(backend, tmp_path) as engine:
        _seed(engine)  # one resolved (decided) finding, the rest undecided
        service = _service(engine)
        grouped = service.query(
            DashboardQuery(subject="findings", measures=("findings",), group_by=("decided",))
        )
        keys = {row.groups["decided"] for row in grouped.rows}
        assert keys <= {"true", "false"}  # never True/False, never 1/0
        undecided = service.query(
            DashboardQuery(
                subject="findings", measures=("findings",), where={"decided": ("false",)}
            )
        )
        # every seeded finding but the resolved one
        assert undecided.rows[0].measures["findings"] == 5


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_the_uncategorized_bucket_groups_and_filters_as_none(backend: str, tmp_path) -> None:
    with contract_db(backend, tmp_path) as engine:
        _seed(engine)  # one labelled finding, the rest uncategorized
        service = _service(engine)
        grouped = service.query(
            DashboardQuery(subject="findings", measures=("findings",), group_by=("category",))
        )
        buckets = {row.groups["category"]: row.measures["findings"] for row in grouped.rows}
        assert buckets["<none>"] == 5  # null is a state the queries carry, never an absence
        assert buckets["xss"] == 1
        only = service.query(
            DashboardQuery(
                subject="findings", measures=("findings",), where={"category": ("<none>",)}
            )
        )
        assert only.rows[0].measures["findings"] == 5


def _seed_products(engine: Engine) -> dict[str, object]:
    """Three repositories: one ships in two products, one in one, one in none."""
    with SqlTraustUnitOfWork(engine) as uow:
        s = Seed(uow)
        shared = s.repository(url="https://github.com/example-org/shared")
        alone = s.repository(url="https://github.com/example-org/alone")
        unshipped = s.repository(url="https://github.com/example-org/unshipped")
        shared_ref = s.repository_ref(shared)
        alone_ref = s.repository_ref(alone)
        unshipped_ref = s.repository_ref(unshipped)
        alpha = s.product(slug="alpha", name="Alpha")
        beta = s.product(slug="beta", name="Beta")
        alpha_release = s.release(product=alpha)
        beta_release = s.release(product=beta)
        s.component(release=alpha_release, ref=shared_ref)
        s.component(release=alpha_release, ref=alone_ref)
        s.component(release=beta_release, ref=shared_ref)
        for repository, ref, title in (
            (shared, shared_ref, "In both products"),
            (shared, shared_ref, "Also in both products"),
            (shared, shared_ref, "Third in both products"),
            (alone, alone_ref, "Only in alpha"),
            (unshipped, unshipped_ref, "In no product"),
        ):
            audit = s.assessment(ref, occurred_at=T0)
            s.occurrence(s.finding(repository, title=title), audit, severity="high")
        uow.commit()
        return {"shared": shared.id, "alone": alone.id, "unshipped": unshipped.id}


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_grouping_by_product_counts_each_products_estate(backend: str, tmp_path) -> None:
    with contract_db(backend, tmp_path) as engine:
        _seed_products(engine)
        service = _service(engine)

        results = service.query(
            DashboardQuery(subject="findings", measures=("findings",), group_by=("product",))
        )

        assert {row.groups["product"]: row.measures["findings"] for row in results.rows} == {
            "alpha": 4.0,  # the shared repository's three and alpha's own
            "beta": 3.0,  # the shared repository's three again: its estate too
            None: 1.0,  # the unshipped repository's finding groups under no product
        }


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_a_product_filter_counts_a_shared_repository_once(backend: str, tmp_path) -> None:
    with contract_db(backend, tmp_path) as engine:
        _seed_products(engine)
        service = _service(engine)

        results = service.query(
            DashboardQuery(
                subject="findings", measures=("findings",), where={"product": ("alpha", "beta")}
            )
        )

        assert results.rows[0].measures["findings"] == 4.0  # not 7: no double count


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_product_grouping_and_filtering_read_slugs(backend: str, tmp_path) -> None:
    with contract_db(backend, tmp_path) as engine:
        _seed_products(engine)
        service = _service(engine)

        both = service.query(
            DashboardQuery(
                subject="findings",
                measures=("findings",),
                group_by=("product", "severity"),
                where={"product": ("beta",)},
            )
        )

        assert [(row.groups["product"], row.groups["severity"]) for row in both.rows] == [
            ("beta", "high")
        ]
        with pytest.raises(ValidationError, match="does not group by"):
            service.query(
                DashboardQuery(
                    subject="review_items", measures=("review_items",), group_by=("product",)
                )
            )


@pytest.mark.parametrize("backend", SQL_BACKENDS)
def test_the_grant_constrains_the_estate_walk_before_the_dedup(backend: str, tmp_path) -> None:
    """SQLite cannot flatten a distinct subquery on the right of a left join, so
    the grant must reach inside the estate subquery: the scoped plan walks the
    granted repositories' components by index, not the estate's."""
    with contract_db(backend, tmp_path) as engine:
        _seed_products(engine)
        explain = "EXPLAIN QUERY PLAN" if backend == "sqlite" else "EXPLAIN"
        with engine.connect() as conn:

            def plan(scoped: bool) -> str:
                statement = sa.text(
                    f"{explain} {_facts_sql(Subject.FINDINGS, True, scoped)}"
                    "SELECT count(distinct id) FROM facts"
                )
                binds: dict[str, object] = {}
                if scoped:
                    statement = statement.bindparams(
                        sa.bindparam("estate_repository_ids", expanding=True)
                    )
                    binds["estate_repository_ids"] = ["00000000-0000-4000-8000-000000000001"]
                return "\n".join(
                    str(row[-1] if backend == "sqlite" else row[0])
                    for row in conn.execute(statement, binds).all()
                )

            whole, granted = plan(False), plan(True)
        if backend == "sqlite":
            assert "SCAN c " in whole and "SEARCH rr" in granted  # the estate's walk vs the grant's
            assert "idx_repository_ref_repository" in granted  # the grant drives the lookup
            assert "SCAN c " not in granted
        else:
            # the planner may rightly seq-scan a small component table; what must
            # hold is the grant reaching the walk as a repository_id constraint
            assert "repository_id = '" in granted  # a literal constant, not a join
            assert "repository_id = '" not in whole
