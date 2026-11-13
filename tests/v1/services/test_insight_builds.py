"""The stored census builds: recorded through the Context on SQLite and Postgres, served by the
route's read until a person's judgement postdates them; scoped and refreshed reads always fold."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.artifacts import InsightBuildsArtifact
from traust_core.v1.models.insight import FindingsRollup, FindingTally, ViewFilter, ViewName
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects.store import ObjectKey
from traust_core.v1.services.insight import CENSUS_VIEWS, InsightService, ParsedBuilds

HUMAN = "human:analyst@example.com"


class CountingParsedBuilds(ParsedBuilds):
    """A parse cache that counts its underlying reads, to prove one parse serves many wirings."""

    def __init__(self, reads: list[object]) -> None:
        super().__init__()
        self._reads = reads

    def parse(self, row_id, read):
        def counted():
            self._reads.append(row_id)
            return read()

        return super().parse(row_id, counted)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0))
    ctx.__dict__["database"] = engine
    return ctx


def seeded(context: Context) -> None:
    """One repository with two findings: an open critical and a person-refuted high."""
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repo = seed.repository(url="https://github.com/example-org/svc")
        audit = seed.assessment(seed.repository_ref(repo))
        seed.occurrence(
            seed.finding(repo, title="RCE"), audit, severity="critical", cvss_score=Decimal("9.8")
        )
        refuted = seed.finding(repo, title="Refuted")
        seed.occurrence(refuted, audit, severity="high")
        seed.decision(
            refuted, validity="false_positive", actor=HUMAN, occurred_at=T0 - timedelta(hours=1)
        )
        uow.commit()


def test_record_builds_publishes_one_artifact_the_route_serves(context: Context) -> None:
    seeded(context)
    insight_service = context.services().insight
    result = insight_service.record_builds()
    assert result.artifact == "insight-builds"

    served = insight_service.serve(ViewName.FINDINGS_ROLLUP, ViewFilter())
    assert served.built_at is not None
    assert isinstance(served.model, FindingsRollup)
    # the counts' identity: the stored model is the fold's model on the same data
    assert (
        served.model
        == insight_service.serve(ViewName.FINDINGS_ROLLUP, ViewFilter(), refresh=True).model
    )
    assert served.model.total.open.critical == 1
    assert served.model.total.false_positive == 1


def test_every_census_view_is_stored_and_served(context: Context) -> None:
    seeded(context)
    insight_service = context.services().insight
    insight_service.record_builds()
    for name in CENSUS_VIEWS:
        served = insight_service.serve(name, ViewFilter())
        assert served.built_at is not None, name
        assert served.model == insight_service.build(name, ViewFilter()), name


def test_the_first_request_before_any_build_folds(context: Context) -> None:
    seeded(context)
    served = context.services().insight.serve(ViewName.COVERAGE, ViewFilter())
    assert served.built_at is None
    assert served.model == context.services().insight.build(ViewName.COVERAGE, ViewFilter())


def test_a_scoped_filter_folds_even_with_a_stored_build(context: Context) -> None:
    seeded(context)
    with SqlTraustUnitOfWork(context.database) as uow:
        product = Seed(uow).product()
        uow.commit()
    insight_service = context.services().insight
    insight_service.record_builds()
    scoped = insight_service.serve(
        ViewName.FINDINGS_ROLLUP,
        ViewFilter(product_ids=(product.id,)),  # type: ignore[arg-type]
    )
    assert scoped.built_at is None
    assert scoped.model == insight_service.build(
        ViewName.FINDINGS_ROLLUP,
        ViewFilter(product_ids=(product.id,)),  # type: ignore[arg-type]
    )


def test_a_view_the_census_does_not_carry_always_folds(context: Context) -> None:
    seeded(context)
    insight_service = context.services().insight
    insight_service.record_builds()
    served = insight_service.serve(ViewName.LOC, ViewFilter())
    assert served.built_at is None
    assert served.model == insight_service.build(ViewName.LOC, ViewFilter())


def test_a_persons_judgement_recorded_after_the_build_supersedes_it(context: Context) -> None:
    seeded(context)
    context.services().insight.record_builds()
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        finding = seed.finding()
        seed.occurrence(finding, seed.assessment(seed.repository_ref()))
        seed.decision(finding, validity="false_positive", actor=HUMAN)
        uow.commit()

    served = context.services().insight.serve(ViewName.FINDINGS_ROLLUP, ViewFilter())
    assert served.built_at is None  # the counts must move with the countersign
    assert served.model.total.false_positive == 2

    context.services().insight.record_builds()
    rebuilt = context.services().insight.serve(ViewName.FINDINGS_ROLLUP, ViewFilter())
    assert rebuilt.built_at is not None
    assert rebuilt.model.total.false_positive == 2


@pytest.mark.parametrize("actor", ["user:analyst", "analyst@example.test"])
def test_a_legacy_actor_invalidates_the_build_without_gaining_human_authority(
    context: Context, actor: str
) -> None:
    seeded(context)
    context.services().insight.record_builds()
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        finding = seed.finding()
        seed.occurrence(finding, seed.assessment(seed.repository_ref()))
        seed.decision(finding, validity="false_positive", actor=actor)
        uow.commit()
    served = context.services().insight.serve(ViewName.FINDINGS_ROLLUP, ViewFilter())
    assert served.built_at is None
    assert served.model.total.false_positive == 1
    assert served.model.total.open.high == 1
    context.services().insight.record_builds()
    rebuilt = context.services().insight.serve(ViewName.FINDINGS_ROLLUP, ViewFilter())
    assert rebuilt.built_at is not None
    assert rebuilt.model == served.model


def test_a_backdated_judgement_recorded_after_the_build_still_supersedes_it(
    context: Context,
) -> None:
    # a forge comment imported today, claiming last month's moment (the qodo review of #434)
    seeded(context)
    context.services().insight.record_builds()
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        finding = seed.finding()
        seed.occurrence(finding, seed.assessment(seed.repository_ref()))
        seed.decision(
            finding, validity="false_positive", actor=HUMAN, occurred_at=T0 - timedelta(days=30)
        )
        uow.commit()
    served = context.services().insight.serve(ViewName.FINDINGS_ROLLUP, ViewFilter())
    assert served.built_at is None
    assert served.model.total.false_positive == 2


def test_a_decide_during_the_fold_supersedes_the_build(context: Context) -> None:
    # the P2 reproduction: a decision committed after the fold's watermark read but before
    # the artifact is published — absent from or unverifiable in the stored build, older than
    # the publication row — must still fold (stored open-critical would say 1, fresh says 0)
    seeded(context)
    wired = context.services().insight
    rollup = wired._views[ViewName.FINDINGS_ROLLUP]

    class DecidingMidFold:
        name = ViewName.FINDINGS_ROLLUP

        def build(self, filter: ViewFilter) -> object:
            with SqlTraustUnitOfWork(context.database) as uow:  # the decide lands mid-fold
                seed = Seed(uow)
                finding = seed.finding()
                seed.occurrence(finding, seed.assessment(seed.repository_ref()))
                seed.decision(finding, validity="false_positive", actor=HUMAN)
                uow.commit()
            return rollup.build(filter)

        def report(self, model: object, generated_at: object) -> object:
            return rollup.report(model, generated_at)  # type: ignore[arg-type]

    folding = InsightService(
        (DecidingMidFold() if v is rollup else v for v in wired._views.values()),
        FixedClock(datetime.now(UTC)),
        builds=wired._builds,
        decisions=wired._decisions,
        parsed=wired._parsed,
    )
    folding.record_builds()
    served = context.services().insight.serve(ViewName.FINDINGS_ROLLUP, ViewFilter())
    assert served.built_at is None
    assert served.model.total.false_positive == 2


def test_a_machine_judgement_does_not_supersede_the_build(context: Context) -> None:
    seeded(context)
    context.services().insight.record_builds()
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        finding = seed.finding()
        seed.occurrence(finding, seed.assessment(seed.repository_ref()))
        seed.decision(finding, actor="machine:scanner")
        uow.commit()
    served = context.services().insight.serve(ViewName.FINDINGS_ROLLUP, ViewFilter())
    assert served.built_at is not None


def test_an_unreadable_build_folds_instead_of_failing_the_read(context: Context) -> None:
    seeded(context)
    context.services().insight.record_builds()
    insight_service = context.services().insight
    rows = insight_service._builds.history(InsightBuildsArtifact, 1)  # type: ignore[union-attr]
    # corrupt the stored bytes: the digest recorded at publication no longer matches, so the
    # read raises where a 500 would come from
    context.object_store.put(ObjectKey.parse(rows[0].uri), b"not the census")
    served = insight_service.serve(ViewName.FINDINGS_ROLLUP, ViewFilter())
    assert served.built_at is None
    assert served.model.total.open.critical == 1


def test_the_parse_is_once_per_publication_across_wirings(context: Context) -> None:
    seeded(context)
    context.services().insight.record_builds()
    reads: list[object] = []
    shared = CountingParsedBuilds(reads)
    wired = context.services().insight
    second = InsightService(
        tuple(wired._views.values()),
        FixedClock(T0),
        builds=wired._builds,
        decisions=wired._decisions,
        parsed=shared,
    )
    wired._parsed = shared
    assert wired.serve(ViewName.COVERAGE, ViewFilter()).built_at is not None
    assert second.serve(ViewName.COVERAGE, ViewFilter()).built_at is not None
    assert len(reads) == 1  # one parse served two wirings


def test_serving_reads_the_newest_build(context: Context) -> None:
    seeded(context)
    context.services().insight.record_builds()
    first = context.services().insight.serve(ViewName.FINDINGS_TREND, ViewFilter()).built_at
    context.__dict__["clock"] = FixedClock(T0 + timedelta(minutes=10))
    context.services().insight.record_builds()
    second = context.services().insight.serve(ViewName.FINDINGS_TREND, ViewFilter()).built_at
    assert first is not None and second is not None and second > first


def test_an_unchanged_cadence_observation_is_a_new_publication(
    context: Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    seeded(context)
    service = context.services().insight
    models = {name: service.build(name, ViewFilter()) for name in CENSUS_VIEWS}
    monkeypatch.setattr(InsightService, "build", lambda _, name, _filter: models[name])
    first = service.record_builds()
    context.__dict__["clock"] = FixedClock(T0 + timedelta(minutes=10))
    service = context.services().insight
    second = service.record_builds()
    assert second.artifact_id != first.artifact_id
    served = service.serve(ViewName.FINDINGS_ROLLUP, ViewFilter())
    assert served.built_at is not None
    assert served.model.total.open.critical == 1


def test_returning_to_an_earlier_census_publishes_it_as_the_latest_build(
    context: Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    seeded(context)
    service = context.services().insight
    original = {name: service.build(name, ViewFilter()) for name in CENSUS_VIEWS}
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        seed.occurrence(seed.finding(), seed.assessment(seed.repository_ref()), severity="critical")
        uow.commit()
    changed = {name: service.build(name, ViewFilter()) for name in CENSUS_VIEWS}
    current = dict(original)
    monkeypatch.setattr(InsightService, "build", lambda _, name, _filter: current[name])
    first = service.record_builds()
    current.update(changed)
    context.__dict__["clock"] = FixedClock(T0 + timedelta(minutes=10))
    second = context.services().insight.record_builds()
    current.update(original)
    context.__dict__["clock"] = FixedClock(T0 + timedelta(minutes=20))
    service = context.services().insight
    third = service.record_builds()
    assert third.artifact_id not in {first.artifact_id, second.artifact_id}
    served = service.serve(ViewName.FINDINGS_ROLLUP, ViewFilter())
    assert served.built_at is not None
    assert served.model.total.open.critical == 1


def test_record_builds_without_a_store_refuses(context: Context) -> None:
    seeded(context)

    class StubRollup:
        name = ViewName.FINDINGS_ROLLUP

        def build(self, filter: ViewFilter) -> FindingsRollup:
            return FindingsRollup(total=FindingTally())

        def report(self, model: object, generated_at: object) -> object:
            raise NotImplementedError

    bare = InsightService((StubRollup(),), FixedClock(T0))
    with pytest.raises(ConfigError):
        bare.record_builds()
    served = bare.serve(ViewName.FINDINGS_ROLLUP, ViewFilter())
    assert served.built_at is None
    assert served.model.total.tracked == 0


def test_a_build_older_than_the_serving_bound_folds(context: Context) -> None:
    seeded(context)
    context.services().insight.record_builds()
    # the serving bound reads the publication row's moment against the clock, so the test's
    # fixed clock must stand in the row's future, not at the seed's epoch
    soon = datetime.now(UTC) + timedelta(minutes=29)
    context.__dict__["clock"] = FixedClock(soon)
    within = context.services().insight.serve(ViewName.FINDINGS_ROLLUP, ViewFilter())
    assert within.built_at is not None
    context.__dict__["clock"] = FixedClock(soon + timedelta(minutes=2))
    stale = context.services().insight.serve(ViewName.FINDINGS_ROLLUP, ViewFilter())
    assert stale.built_at is None
    assert stale.model == context.services().insight.build(ViewName.FINDINGS_ROLLUP, ViewFilter())
