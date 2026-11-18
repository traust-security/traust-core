from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services import test_remediation as remediation
from traust_core.v1.context import Context
from traust_core.v1.models.insight import Scoreboard, ViewFilter, ViewName
from traust_core.v1.models.vocabulary import RemediationStatus
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

engine = remediation.engine
context = remediation.context


@pytest.mark.parametrize(
    "status", ["checks_passed", "checks_failed", "pr_opened", "merged", "abandoned"]
)
def test_the_scoreboard_matches_current_resolution_without_treating_progress_as_a_fix(
    context: Context, engine: Engine, status: str
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url="https://github.com/example-org/service")
        main = seed.repository_ref(repo, is_default=True)
        release = seed.repository_ref(repo, name="release", sha="b" * 40)
        scan = seed.assessment(main)
        finding = seed.finding(repo)
        seed.occurrence(finding, scan, severity="high")
        seed.occurrence(finding, seed.assessment(release), severity="high")
        seed.decision(finding, validity="confirmed", severity="high", actor="human:a@example.com")
        seed.decision(
            finding,
            resolution="resolved",
            repository_ref_id=release.id,
            actor="human:a@example.com",
        )
        closed = seed.finding(repo, fingerprint="already-fixed")
        seed.occurrence(closed, scan, severity="high")
        seed.decision(
            closed,
            validity="confirmed",
            resolution="resolved",
            repository_ref_id=main.id,
            actor="human:a@example.com",
        )
        uow.commit()
    assert finding.id is not None and main.id is not None and release.id is not None
    services = context.services()
    item = services.remediation.open([finding.id], main.id)
    doc = remediation.report([finding.id], summary__status=status)
    services.remediation.record(doc, remediation.provenance())
    assert services.remediation.get(item.work_item_id).status == status
    on_main = services.findings.on_ref(main.id)
    on_release = services.findings.on_ref(release.id)
    assert next(v for v in on_main if v.finding.id == finding.id).is_open()
    assert not next(v for v in on_release if v.finding.id == finding.id).is_open()
    scoreboard = services.insight.build(ViewName.SCOREBOARD, ViewFilter())
    assert isinstance(scoreboard, Scoreboard)
    assert scoreboard.open.total == sum(v.is_open() for v in on_main) == 1
    assert (
        scoreboard.resolved
        == sum(
            v.disposition is not None and v.disposition.resolution == "resolved" for v in on_main
        )
        == 1
    )


def test_the_scoreboard_counts_a_later_resolution_not_the_merged_work_item(
    context: Context, engine: Engine
) -> None:
    ref, found = remediation.seeded(engine)
    finding = found[0]
    assert ref.id is not None and finding.id is not None
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        seed.occurrence(finding, seed.assessment(ref), severity="high")
        uow.commit()
    services = context.services()
    item = services.remediation.open([finding.id], ref.id)
    services.remediation.record_progress(item.work_item_id, RemediationStatus.MERGED)
    with SqlTraustUnitOfWork(engine) as uow:
        Seed(uow).decision(
            finding,
            resolution="resolved",
            repository_ref_id=ref.id,
            fixed_repository_ref_id=ref.id,
            actor="human:a@example.com",
            occurred_at=context.clock.now() + timedelta(seconds=1),
        )
        uow.commit()
    as_of = context.clock.now() + timedelta(seconds=2)
    scoreboard = services.insight.build(ViewName.SCOREBOARD, ViewFilter(as_of=as_of))
    assert isinstance(scoreboard, Scoreboard)
    assert scoreboard.open.total == 0 and scoreboard.resolved == 1
    assert services.remediation.get(item.work_item_id).status == "merged"
