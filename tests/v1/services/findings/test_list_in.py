"""FindingService.list_in on SQLite and Postgres: `all_in` (Shaun's service-layer batch,
core#410) paged with `list`'s cursor discipline — the union of several repositories'
findings in one walk, so a consumer whose scope spans repositories (SCI's findings
worklist) reads one listing per page instead of one per repository (the estate-scale
fan-out behind the integration cluster's 504s)."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from datetime import datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.findings.test_reads import service
from tests.v1.services.findings.test_rollups import Repo, new_repo
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.findings import Finding, FindingSetFilter, FindingView
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def set_of(*repos: Repo) -> FindingSetFilter:
    ids = []
    for repo in repos:
        assert repo.repository.id is not None
        ids.append(repo.repository.id)
    return FindingSetFilter(repository_ids=tuple(ids))


def walk(findings, filter: FindingSetFilter, limit: int = 2) -> list[UUID]:
    """Every finding id the listing serves across its pages, in served order."""
    ids: list[UUID] = []
    page = PageRequest(limit=limit)
    while True:
        found = findings.list_in(filter, page)
        ids.extend(v.finding.id for v in found.items if v.finding.id is not None)
        if found.next is None:
            return ids
        page = PageRequest(limit=limit, cursor=found.next)


def created_at_of(engine: Engine, ids: list[UUID]) -> dict[UUID, datetime]:
    with SqlTraustUnitOfWork(engine) as uow:
        rows = uow.findings.list_by_ids(ids)
    return {row.id: row.created_at for row in rows if row.id is not None}


def test_the_batch_returns_the_union_of_the_set_repositories_findings(
    engine: Engine,
) -> None:
    left, right, untouched = new_repo(engine), new_repo(engine), new_repo(engine)
    expected = {left.reported(day=0).id, right.reported(day=1).id}
    # A repository outside the set never serves, and the empty set serves nothing.
    assert set(walk(service(engine), set_of(left, right))) == expected
    assert walk(service(engine), set_of(untouched)) == []
    assert walk(service(engine), FindingSetFilter(repository_ids=())) == []


def test_the_batch_matches_all_in_per_repository(engine: Engine) -> None:
    left, right = new_repo(engine), new_repo(engine)
    for day in range(3):
        (left if day % 2 == 0 else right).reported(day=day)
    findings = service(engine)
    both = set_of(left, right)
    served = walk(findings, both)
    grouped = findings.all_in(both.repository_ids)
    assert {i for i in served} == {
        view.finding.id for rows in grouped.values() for view in rows if view.finding.id
    }


def test_the_census_fold_serves_all_in_s_views_without_locations_or_cwes(
    engine: Engine,
) -> None:
    """The rollup's fold: a tally reads states, severities and labels, so the census skips the
    locations and cwes it never counts — and delivers each batch for counting instead of
    holding the whole scope's views."""
    left, right = new_repo(engine), new_repo(engine)
    located = left.reported(day=0, cwes=("CWE-79",), labels=(("category", "xss"),))
    latest = left.reported(day=2, severity="critical")
    other = right.reported(day=1)
    with SqlTraustUnitOfWork(engine) as uow:
        occurrence = uow.occurrences.list_for_findings([located.id])[0]  # type: ignore[list-item]
        Seed(uow).location(occurrence, path="pkg/api/handler.go")
        uow.commit()
    findings = service(engine)
    both = set_of(left, right)
    counted: dict[UUID, list[FindingView]] = {}
    batches: list[int] = []
    findings.census_fold(
        both.repository_ids,
        lambda batch: (batches.append(len(batch)), counted.update(batch)),
    )
    assert batches == [2]  # one bounded batch of whole repositories
    served = {
        repository_id: [v.finding.id for v in views] for repository_id, views in counted.items()
    }
    assert served == {
        repository_id: [v.finding.id for v in views]
        for repository_id, views in findings.all_in(both.repository_ids).items()
    }
    lean = {v.finding.id: v for rows in counted.values() for v in rows}
    assert lean[located.id].locations == () and lean[located.id].cwes == ()
    assert lean[located.id].labels  # the labels a tally counts stay loaded
    full = {v.finding.id: v for rows in findings.all_in(both.repository_ids).values() for v in rows}
    assert full[located.id].locations and full[located.id].cwes
    assert [v.finding.id for v in counted[left.repository.id]] == [  # type: ignore[index]
        latest.id,
        located.id,
    ]
    assert lean[other.id].effective_severity is not None  # the fold still serves full tallies


def test_a_census_inside_shared_rides_the_builds_one_fleet_load(engine: Engine) -> None:
    """The composition of the shared loads and the census fold: inside `shared()` the fold
    counts over the build's memoized loads — no findings or facts re-read, the counting
    views carrying the cwes the build's full facts already hold — while a standalone fold
    still reads its own counting facts and leaves the cwes a tally never reads unread."""
    left = new_repo(engine)
    tagged = left.reported(day=0, cwes=("CWE-79",), labels=(("category", "xss"),))
    findings = service(engine)
    repository_ids = set_of(left).repository_ids

    def statements(call: Callable[[], object]) -> int:
        issued: list[str] = []

        def record(*args: object) -> None:
            issued.append(str(args[2]))

        sa.event.listen(engine, "before_cursor_execute", record)
        try:
            call()
        finally:
            sa.event.remove(engine, "before_cursor_execute", record)
        return len(issued)

    def collect(into: dict[UUID, FindingView]) -> Callable[[Mapping[UUID, object]], None]:
        def keep(batch: Mapping[UUID, object]) -> None:
            into.update({v.finding.id: v for views in batch.values() for v in views})  # type: ignore[union-attr]

        return keep

    def composed() -> None:
        with findings.shared():
            findings.all_in(repository_ids)
            findings.census_fold(repository_ids, collect({}))

    served = statements(lambda: findings.all_in(repository_ids))
    rode = statements(composed)
    assert rode == served  # the census inside the block added no read of its own

    shared: dict[UUID, FindingView] = {}
    with findings.shared():
        findings.all_in(repository_ids)
        findings.census_fold(repository_ids, collect(shared))
    assert shared[tagged.id].cwes  # it counted over the build's full facts

    standalone: dict[UUID, FindingView] = {}
    again = statements(lambda: findings.census_fold(repository_ids, collect(standalone)))
    assert again  # outside the block the fold reads its own counting facts
    assert again < served  # the census's lean loads, never the full view read
    assert standalone[tagged.id].cwes == ()
    assert standalone[tagged.id].labels  # what a tally counts stays loaded


def test_paging_walks_the_whole_set_newest_first_exactly_once(engine: Engine) -> None:
    left, right = new_repo(engine), new_repo(engine)
    for day in range(6):
        (left if day % 2 == 0 else right).reported(day=day)
    # limit 1: every page boundary falls between repositories' interleaved findings.
    ids = walk(service(engine), set_of(left, right), limit=1)
    assert len(ids) == len(set(ids)) == 6
    at = created_at_of(engine, ids)
    keys = [(at[i], str(i)) for i in ids]
    assert keys == sorted(keys, reverse=True)


# The worklist's pushed-down cut and its sorted windows (the S1 slice): the exposure
# classes, the severity set, the count, and the column orders a worklist pages by —
# the rules SCI's worklist applied per row before the push-down, mirrored so its
# counts and orders are identical by construction.
from traust_core.v1.services.findings.service import FindingWindow  # noqa: E402


def seeded_estate(engine: Engine) -> tuple[Repo, Repo, dict[str, Finding]]:
    """Two repositories whose findings cover the census classes and the severity ladder;
    the map names each seeded finding by its story. A hardening validity normalizes in
    the fold to confirmed plus a weakness kind (the contracts' alias pairs), so the
    worklist's cut — which reads the folded disposition, never the kind — keeps such a
    finding open: the classification SCI's core path derived per row, pinned here."""
    left, right = new_repo(engine), new_repo(engine)
    made: dict[str, Finding] = {}
    made["open_critical"] = left.reported(day=0, severity="critical")
    made["open_low"] = left.reported(day=1, severity="low")
    made["false_positive"] = left.reported(day=2, severity="high")
    left.judged(made["false_positive"], 3, validity="false_positive")
    made["hardening"] = left.reported(day=3, severity="medium")
    left.judged(made["hardening"], 4, validity="hardening")  # folds to confirmed + weakness
    made["closed"] = left.reported(day=4, severity="high")
    left.judged(made["closed"], 5, validity="confirmed", resolution="resolved")
    made["other_open_critical"] = right.reported(day=1, severity="critical")
    return left, right, made


def test_the_exposure_cut_keeps_the_census_classes(engine: Engine) -> None:
    left, right, made = seeded_estate(engine)
    findings = service(engine)
    both = set_of(left, right)

    def ids(**update: object) -> set[UUID]:
        return set(walk(findings, both.model_copy(update=update)))

    assert ids() == {f.id for f in made.values()}  # absent exposure: every class serves
    assert ids(exposure="open") == {
        made["open_critical"].id,
        made["open_low"].id,
        made["other_open_critical"].id,
        made["hardening"].id,  # the folded disposition says confirmed: open, not hardening
    }
    assert ids(exposure="false_positive") == {made["false_positive"].id}
    assert ids(exposure="hardening") == set()  # the fold's validity never spells hardening
    assert ids(exposure="closed") == {made["closed"].id}


def test_the_severity_set_matches_the_effective_severity(engine: Engine) -> None:
    left, right, made = seeded_estate(engine)
    findings = service(engine)
    both = set_of(left, right)
    with SqlTraustUnitOfWork(engine) as uow:  # a finding no occurrence backs: no effective severity
        undecided = Seed(uow).finding(left.repository, fingerprint=str(uuid4()))
        uow.commit()

    def ids(**update: object) -> set[UUID]:
        return set(walk(findings, both.model_copy(update=update)))

    assert ids(severity=("critical",)) == {
        made["open_critical"].id,
        made["other_open_critical"].id,
    }
    assert ids(severity=("critical", "low")) == {
        made["open_critical"].id,
        made["other_open_critical"].id,
        made["open_low"].id,
    }
    # A finding without an effective severity matches no severity cut, exactly as a
    # consumer's mapped row (no effective severity) never matched one.
    assert undecided.id not in ids(severity=("critical", "high", "medium", "low"))
    assert undecided.id in ids()  # but an unfiltered listing still serves it


def test_the_count_counts_what_the_filtered_listing_serves(engine: Engine) -> None:
    left, right, _made = seeded_estate(engine)
    findings = service(engine)
    both = set_of(left, right)
    for update in (
        {},
        {"exposure": "open"},
        {"exposure": "false_positive"},
        {"exposure": "hardening"},
        {"exposure": "closed"},
        {"severity": ("critical",)},
        {"severity": ("critical", "low")},
        {"exposure": "open", "severity": ("critical",)},
    ):
        filter = both.model_copy(update=update)
        served = walk(findings, filter)
        assert findings.count_in(filter).total == len(served), update
    assert findings.count_in(set_of(left)).total == 5  # one repository's own cut


def test_a_sorted_window_serves_the_worklists_severity_order(engine: Engine) -> None:
    left, right, _made = seeded_estate(engine)
    findings = service(engine)
    both = set_of(left, right)

    opened = both.model_copy(update={"exposure": "open"})

    def window(column: str, direction: str, limit: int = 100) -> list[UUID]:
        page = findings.list_in(
            opened, PageRequest(limit=limit), FindingWindow(column=column, direction=direction)
        )
        assert page.next is None  # a window pages by a wider limit, never a cursor
        return [v.finding.id for v in page.items if v.finding.id is not None]

    # Every open finding, severity rank first with the CVSS tiebreak, id last.
    served = {
        v.finding.id: v
        for views in findings.all_in(both.repository_ids).values()
        for v in views
        if v.exposure() == "open"
    }
    ranked = sorted(
        served.values(),
        key=lambda v: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(
                v.effective_severity.value if v.effective_severity else "", 5
            ),
            -(float(v.occurrence.cvss_score) if v.occurrence and v.occurrence.cvss_score else 0.0),
            str(v.finding.id),
        ),
    )
    expected = [v.finding.id for v in ranked]
    assert [
        v.finding.id
        for v in findings.list_in(
            opened, PageRequest(limit=100), FindingWindow(column="severity")
        ).items
    ] == expected
    assert window("severity", "asc") == expected
    # Descending flips the column (and the CVSS within a rank) but never the id
    # tiebreak — the direction-independent order of last resort.
    inverse = sorted(
        served.values(),
        key=lambda v: (
            -{"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(
                v.effective_severity.value if v.effective_severity else "", 5
            ),
            float(v.occurrence.cvss_score) if v.occurrence and v.occurrence.cvss_score else 0.0,
            str(v.finding.id),
        ),
    )
    assert window("severity", "desc") == [v.finding.id for v in inverse]


def test_a_sorted_window_bounds_itself_to_the_limit(engine: Engine) -> None:
    left, right, _made = seeded_estate(engine)
    findings = service(engine)
    both = set_of(left, right)
    whole = findings.list_in(both, PageRequest(limit=100), FindingWindow(column="severity")).items
    top2 = findings.list_in(both, PageRequest(limit=2), FindingWindow(column="severity")).items
    assert [v.finding.id for v in top2] == [v.finding.id for v in whole[:2]]


def test_a_sorted_window_serves_title_and_id_orders(engine: Engine) -> None:
    left, right, _made = seeded_estate(engine)
    findings = service(engine)
    both = set_of(left, right)
    served = [v for views in findings.all_in(both.repository_ids).values() for v in views]
    by_title = sorted(served, key=lambda v: (v.finding.title.lower(), str(v.finding.id)))
    assert [
        v.finding.id
        for v in findings.list_in(both, PageRequest(limit=100), FindingWindow(column="title")).items
    ] == [v.finding.id for v in by_title]
    by_id = sorted(served, key=lambda v: str(v.finding.id))
    assert [
        v.finding.id
        for v in findings.list_in(
            both, PageRequest(limit=100), FindingWindow(column="finding_id")
        ).items
    ] == [v.finding.id for v in by_id]
