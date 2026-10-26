"""The operator least-privilege view, ported from traust#199's dashboard_privileges.py (the
operator-priv-profile fleet rollup): ranking, the md/html assessment table and the CSV export."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0
from tests.v1.services.test_insight import FakePortfolio
from traust_core.v1.context import Config, Context
from traust_core.v1.models.assessment import Permission, PrivilegeProfile
from traust_core.v1.models.insight import PrivilegesRollup, ViewFilter, ViewName
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.rendering import MarkdownRenderer, Table, csv_table
from traust_core.v1.services.insight import InsightService, PrivilegesView


def profile(repository_id: UUID, **kw: Any) -> PrivilegeProfile:
    return PrivilegeProfile(
        assessment_id=uuid4(), repository_id=repository_id, workloads=1, rbac_rules=1, **kw
    )


class FakeAssessment:
    def __init__(self, *profiles: PrivilegeProfile) -> None:
        self.profiles = profiles
        self.asked: list[Any] = []

    def privileges(self, filter: Any, repository_ids: Any, as_of: Any) -> list[PrivilegeProfile]:
        self.asked.append((sorted(repository_ids, key=str), as_of))
        return [p for p in self.profiles if p.repository_id in repository_ids]


def fleet() -> tuple[FakePortfolio, FakeAssessment, dict[str, UUID]]:
    ids = {name: uuid4() for name in ("a", "b", "c", "d", "e")}
    portfolio = FakePortfolio(
        repositories={i: f"https://github.com/example-org/{n}" for n, i in ids.items()}
    )
    assessment = FakeAssessment(
        profile(ids["a"], surplus=None, wildcard_rules=9),
        profile(ids["b"], surplus=3, wildcard_rules=0),
        profile(ids["c"], surplus=3, wildcard_rules=2, privileged_workloads=0),
        profile(ids["d"], surplus=3, wildcard_rules=2, privileged_workloads=4),
        profile(
            ids["e"],
            scc_requests=("privileged", "anyuid", "privileged"),
            containers=4,
            privileged_containers=1,
            run_as_non_root_containers=3,
            namespaces=("ns-1", "ns-2", "ns-3", "ns-4"),
            install_modes=("OwnNamespace",),
            flags={"secrets_read": 2, "escalate": 5},
            kubebuilder_markers=7,
            permissions=(
                Permission(resource="secrets", verb="get", cluster_scoped=True),
                Permission(resource="pods", verb="list"),
            ),
        ),
    )
    return portfolio, assessment, ids


def test_rows_rank_by_surplus_then_wildcards_then_privileged_workloads_then_url() -> None:
    portfolio, assessment, _ = fleet()
    model = PrivilegesView(assessment, portfolio).build(ViewFilter(as_of=T0))  # type: ignore[arg-type]
    assert [r.repository.rsplit("/", 1)[1] for r in model.rows] == ["d", "c", "b", "a", "e"]
    assert (model.as_of, assessment.asked[0][1]) == (T0, T0)
    e = model.rows[-1]
    assert (e.distinct_rule_triples, e.distinct_cluster_triples) == (2, 1)


def test_the_view_scopes_to_the_filters_repositories() -> None:
    portfolio, assessment, ids = fleet()
    team = uuid4()
    portfolio.teams[team] = {ids["b"]}
    model = PrivilegesView(assessment, portfolio).build(ViewFilter(team_ids=(team,)))  # type: ignore[arg-type]
    assert [r.repository for r in model.rows] == ["https://github.com/example-org/b"]
    assert assessment.asked == [([ids["b"]], None)]


def test_the_report_and_export_carry_the_rollups_columns() -> None:
    portfolio, assessment, _ = fleet()
    view = PrivilegesView(assessment, portfolio)  # type: ignore[arg-type]
    model = view.build(ViewFilter())
    md = MarkdownRenderer().render(view.report(model, T0)).decode()
    assert "5 operators profiled: 1 request explicit SCCs, 4 expect the restricted-v2" in md
    assert (
        "| Repo | SCCs requested | Security context | Namespaces / install modes "
        "| Required roles (RBAC) |"
    ) in md
    assert (
        "| https://github.com/example-org/e | anyuid, privileged | 1 privileged, runAsNonRoot 3/4 "
        "| ns-1, ns-2, ns-3… · OwnNamespace | 1 cluster / 2 total grants; escalate\u00d75, "
        "secrets_read\u00d72 |"
    ) in md
    assert (
        "| https://github.com/example-org/d | (none — restricted-v2 default) | 4 host-touching wl, "
        "no workloads listed | — | 0 cluster / 0 total grants; surplus 3 |"
    ) in md
    assert "RED HAT" not in md
    csv = csv_table(view.export(model)).splitlines()
    assert csv[0] == (
        "repo,sccs_requested,privileged_containers,host_touching_workloads,"
        "runasnonroot_containers,containers_total,namespaces,install_modes,cluster_grants,"
        "total_grants,wildcard_rules,rbac_risk_flags,tier2_surplus,kubebuilder_markers"
    )
    assert csv[-1] == (
        "https://github.com/example-org/e,anyuid;privileged,1,,3,4,ns-1;ns-2;ns-3;ns-4,"
        "OwnNamespace,1,2,,escalate=5;secrets_read=2,n/a,7"
    )


def test_publish_adds_the_csv_only_for_a_view_with_an_export() -> None:
    portfolio, assessment, _ = fleet()
    insight = InsightService([PrivilegesView(assessment, portfolio)], FixedClock(T0))  # type: ignore[arg-type]
    rendered = insight.publish(ViewName.PRIVILEGES, ViewFilter())
    assert rendered.stem == "operator-least-privilege-rollup"
    assert rendered.csv is not None and rendered.csv.startswith("repo,sccs_requested,")
    assert isinstance(rendered.model, PrivilegesRollup) and len(rendered.model.rows) == 5


@pytest.mark.parametrize(
    ("cell", "written"),
    [
        ("=HYPERLINK(1)", "'=HYPERLINK(1)"),
        ("@sum", "'@sum"),
        ("+1", "'+1"),
        ("-x", "'-x"),
        ("-3", "-3"),
        ("a,b", '"a,b"'),
        ("two\nlines", "two lines"),
    ],
)
def test_csv_cells_are_one_line_and_never_formulas(cell: str, written: str) -> None:
    assert csv_table(Table(columns=("c",), rows=((cell,),))).splitlines()[1] == written


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def test_an_empty_fleet_renders_through_context(engine: Engine, tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0))
    ctx.__dict__["database"] = engine
    rendered = ctx.services().insight.publish(ViewName.PRIVILEGES, ViewFilter())
    assert "_No priv-profiles recorded._" in rendered.markdown
    assert rendered.csv is not None and len(rendered.csv.splitlines()) == 1
    other = ctx.services().insight.publish(ViewName.FINDINGS_ROLLUP, ViewFilter())
    assert other.csv is None
