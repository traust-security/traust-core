from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.test_compliance import ALICE, FIXTURES, NIST, NOW, World, scope_doc
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import CloudConfigAuditArtifact
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import Provenance, TimeWindow
from traust_core.v1.models.compliance import EvaluationRequest
from traust_core.v1.models.insight import ComplianceDashboard, ViewFilter, ViewName
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed
DAY = timedelta(days=1)
CLOUD = Path(__file__).parents[2] / "fixtures/cloud_config/myrepo-cloud-config-audit.json"


def provenance(at: datetime) -> Provenance:
    return Provenance(run_id=uuid4(), source=SourceType.INTERACTIVE, occurred_at=at)


@dataclass
class Posture:
    context: Context
    world: World
    red: UUID
    blue: UUID
    alpha: UUID
    beta: UUID
    a_scope: UUID
    b_scope: UUID

    def build(self, **filter: object) -> ComplianceDashboard:
        result = self.context.services().insight.build(ViewName.COMPLIANCE, ViewFilter(**filter))
        assert isinstance(result, ComplianceDashboard)
        return result

    def assess(self, scope_id: UUID, at: datetime, *, bad: bool = False) -> None:
        snapshot = json.loads(
            (
                FIXTURES
                / "checks/chk-no-privileged-workloads"
                / ("bad" if bad else "good")
                / "snapshot.json"
            ).read_text()
        )
        run = self.world.service.evaluate(
            EvaluationRequest(
                scope_id=scope_id,
                frameworks=(NIST,),
                harness_version="9.9.9",
                snapshots={"scan_k8s_hardening": snapshot},
            )
        )
        self.world.service.record(run.document, provenance(at))
        self.world.uow.commit()


@pytest.fixture
def posture(engine: Engine, uow: SqlTraustUnitOfWork, seed: Seed, tmp_path: Path) -> Posture:
    world = World(uow, seed)
    for ref in (world.a, world.b):
        observed = uow.repository_refs.update(ref.model_copy(update={"is_default": True}))
        seed.assessment(observed, kind=AssessmentKind.REPO_STATE, occurred_at=NOW - DAY)
    red, blue = seed.team(name="red"), seed.team(name="blue")
    a, b = uow.repositories.get(world.a.repository_id), uow.repositories.get(world.b.repository_id)
    seed.ownership(a, red)
    seed.ownership(b, blue)
    alpha, beta = seed.product(slug="alpha"), seed.product(slug="beta")
    seed.component(seed.release(alpha), world.a)
    seed.component(seed.release(beta), world.b)
    world.publish_mapping()
    scopes = [
        world.service.set_scope(
            scope_doc(
                name=f"boundary-{name}",
                frameworks=[str(NIST)],
                resolves_via="explicit",
                product=None,
                include=[{"repo": f"org/{name}", "reason": "declared test boundary"}],
            ),
            ALICE,
        ).scope_id
        for name in ("a", "b")
    ]
    uow.commit()
    context = Context(Config(home=tmp_path), clock=FixedClock(NOW + 2 * DAY))
    context.__dict__["database"] = engine
    context.__dict__["object_store"] = world.store
    assert all(value is not None for value in (red.id, blue.id, alpha.id, beta.id, *scopes))
    scenario = Posture(context, world, red.id, blue.id, alpha.id, beta.id, *scopes)
    for name, ref, control in (
        ("a", world.a, "NIST-800-53:AC-2"),
        ("b", world.b, "SOC2:CC6.1"),
    ):
        body = json.loads(CLOUD.read_text())
        body["metadata"].update(repository=f"https://github.com/org/{name}", target=name)
        for index, finding in enumerate(body["findings"]):
            finding["control_refs"] = [control, control] if index < 2 else []
        body["findings"][4]["control_refs"] = ["suppressed-only"]
        context.services().assessment.record_audit(
            CloudConfigAuditArtifact.from_document(body), ref.id, provenance(NOW)
        )
    scenario.assess(scenario.a_scope, NOW)
    scenario.assess(scenario.b_scope, NOW, bad=True)
    return scenario


def test_compliance_population_team_refs_and_real_scoped_boundaries(posture: Posture) -> None:
    fleet = posture.build()
    assert (fleet.repositories, fleet.reported, fleet.dispositioned) == (3, 2, 2)
    teams = {row.team: row for row in fleet.by_team}
    assert set(teams) == {"red", "blue", "Unowned"}
    assert (teams["red"].repositories, teams["red"].findings) == (1, 5)
    assert teams["red"].without_control_refs == 3
    assert teams["red"].control_refs == {"NIST-800-53:AC-2": 2}
    assert teams["blue"].control_refs == {"SOC2:CC6.1": 2}
    assert (teams["Unowned"].findings, teams["Unowned"].repositories) == (0, 1)
    assert [(row.pairs, row.assessed) for row in fleet.by_framework] == [(2, 2)]
    red = posture.build(team_ids=(posture.red,))
    alpha = posture.build(product_ids=(posture.alpha,))
    assert red == alpha
    assert (red.repositories, red.reported, red.dispositioned) == (1, 1, 1)
    assert [row.key for row in red.by_scope] == ["boundary-a"]
    assert [row.team for row in red.by_team] == ["red"]
    assert red.by_team[0].control_refs == teams["red"].control_refs
    blue = posture.build(product_ids=(posture.beta,))
    assert [row.key for row in blue.by_scope] == ["boundary-b"]
    assert [row.team for row in blue.by_team] == ["blue"]
    assert blue.by_framework[0].coverage != red.by_framework[0].coverage
    union = posture.build(product_ids=(posture.alpha,), team_ids=(posture.blue,))
    assert (union.repositories, union.by_framework) == (2, fleet.by_framework)


def test_compliance_history_uses_distinct_recorded_times_and_as_of_posture(
    posture: Posture,
) -> None:
    assert posture.build().history == ()
    earlier = posture.build(as_of=NOW)
    posture.assess(posture.a_scope, NOW + DAY, bad=True)
    current = posture.build()
    assert [point.assessed_at for point in current.history] == [NOW, NOW + DAY]
    assert current.history[0].by_framework == earlier.by_framework
    assert current.history[-1].by_framework == current.by_framework
    assert current.history[0].by_framework != current.history[-1].by_framework
    assert posture.build(as_of=NOW) == earlier
    assert posture.build(team_ids=(posture.blue,)).history == ()
    red = posture.build(team_ids=(posture.red,))
    assert [point.assessed_at for point in red.history] == [NOW, NOW + DAY]
    assert all(point.by_framework[0].pairs == 1 for point in red.history)
    assert posture.build(window=TimeWindow(start=NOW + DAY, end=NOW + 2 * DAY)).history == ()
    before = posture.build(as_of=NOW - DAY)
    assert (before.reported, before.dispositioned, before.history) == (0, 0, ())
    assert before.by_framework[0].assessed == 0
    assert before.by_framework[0].pairs == 2


def test_compliance_render_includes_population_and_only_real_history(posture: Posture) -> None:
    insight = posture.context.services().insight
    report = insight.report(ViewName.COMPLIANCE, ViewFilter())
    assert [
        section.table.rows for section in report.sections if section.heading == "Population"
    ] == [(("In scope", "3"), ("With findings reported", "2"), ("With a decision recorded", "2"))]
    assert not any(section.heading == "Recorded assessment history" for section in report.sections)
    posture.assess(posture.a_scope, NOW + DAY, bad=True)
    rendered = insight.publish(ViewName.COMPLIANCE, ViewFilter(team_ids=(posture.red,)))
    assert isinstance(rendered.model, ComplianceDashboard)
    (team,) = rendered.model.by_team
    assert (team.team, team.repositories, team.findings, team.without_control_refs) == (
        "red",
        1,
        5,
        3,
    )
    assert team.control_refs == {"NIST-800-53:AC-2": 2}
    report = insight.report(ViewName.COMPLIANCE, ViewFilter(team_ids=(posture.red,)))
    history = next(
        section.table
        for section in report.sections
        if section.heading == "Recorded assessment history"
    )
    assert history is not None
    assert [datetime.fromisoformat(row[0]) for row in history.rows] == [NOW, NOW + DAY]


def test_compliance_refuses_category_cuts_it_cannot_apply_to_boundary_posture(
    posture: Posture,
) -> None:
    with pytest.raises(ValidationError):
        posture.build(categories=("credentials",))


def test_latest_control_refs_replace_older_claims_without_fabricating_posture_history(
    posture: Posture,
) -> None:
    body = json.loads(CLOUD.read_text())
    body["metadata"].update(repository="https://github.com/org/a", target="a")
    for finding in body["findings"]:
        finding["control_refs"] = []
    posture.context.services().assessment.record_audit(
        CloudConfigAuditArtifact.from_document(body), posture.world.a.id, provenance(NOW + DAY)
    )
    current = posture.build(team_ids=(posture.red,))
    assert current.by_team[0].control_refs == {}
    assert current.by_team[0].without_control_refs == 5
    assert current.history == ()
    previous = posture.build(team_ids=(posture.red,), as_of=NOW)
    assert previous.by_team[0].control_refs["NIST-800-53:AC-2"] == 2
