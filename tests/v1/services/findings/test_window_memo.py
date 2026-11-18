"""The worklist windows' process memo: one scope folds once however many readers ask.

The stampede the memo answers: twenty readers arriving together for one scope folded it
twenty times (the GIL serializing every fold), and nothing was shared between requests.
The memo is keyed by repository, so the readers of one scope fold once and the readers of
overlapping scopes pay only for the repositories nobody folded. These tests pin the fold
counts, the freshness bound, the bound on the memory, and the composition rule — a build
inside `shared()` reads its own fleet, never a mix of memo and fresh.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.services.findings.test_list_in import seeded_estate, set_of
from tests.v1.services.findings.test_reads import service
from tests.v1.services.findings.test_rollups import Repo, new_repo
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.findings import FindingSetFilter, FindingSort, FindingView
from traust_core.v1.services.findings.service import FindingService, FindingWindow
from traust_core.v1.services.findings.windows import WindowMemo


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def window(findings, filter: FindingSetFilter, limit: int = 100) -> list[FindingView]:
    page = findings.list_in(
        filter, PageRequest(limit=limit), FindingWindow(column=FindingSort.SEVERITY)
    )
    assert page.next is None
    return list(page.items)


def test_one_scope_folds_once_however_many_readers_ask(engine: Engine) -> None:
    left, right, _made = seeded_estate(engine)
    memo = WindowMemo()
    scope = set_of(left, right)
    first = window(service(engine, windows=memo), scope)
    second = window(service(engine, windows=memo), scope)
    assert first == second
    assert memo.folds == 1  # the second reader read the deposit
    assert memo.folded_repositories == 2


def test_concurrent_readers_of_one_scope_fold_it_once(engine: Engine) -> None:
    left, right, _made = seeded_estate(engine)
    memo = WindowMemo()
    scope = set_of(left, right)
    expected = [v.finding.id for v in window(service(engine), scope)]
    served: list[list[object]] = []
    failures: list[BaseException] = []
    barrier = threading.Barrier(8)

    def read() -> None:
        try:
            barrier.wait(timeout=30)
            served.append([v.finding.id for v in window(service(engine, windows=memo), scope)])
        except BaseException as e:
            failures.append(e)

    threads = [threading.Thread(target=read) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not failures
    assert served == [expected] * 8
    assert memo.folds == 1  # one reader folded; the seven queued on the scope's flight
    assert memo.folded_repositories == 2


def test_a_burst_that_arrives_before_the_first_fold_finishes_shares_it(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stampede's real shape: every reader is in flight before the first deposit, so a
    reader must queue on the fill that is already folding a repository it wants — the
    registration is atomic with the fill lock, never a window the burst slips through."""
    left, right, _made = seeded_estate(engine)
    memo = WindowMemo()
    scope = set_of(left, right)
    real = FindingService._facts_of

    def slow_facts(self, batch, as_of, *, census):  # type: ignore[no-untyped-def]
        time.sleep(0.15)
        return real(self, batch, as_of, census=census)

    monkeypatch.setattr(FindingService, "_facts_of", slow_facts)
    barrier = threading.Barrier(8)
    served: list[list[object]] = []

    def read() -> None:
        barrier.wait(timeout=30)
        served.append([v.finding.id for v in window(service(engine, windows=memo), scope)])

    threads = [threading.Thread(target=read) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert len(served) == 8
    assert memo.folds == 1


def test_an_overlapping_scope_folds_only_its_new_repositories(engine: Engine) -> None:
    first, shared, third = new_repo(engine), new_repo(engine), new_repo(engine)
    for repo in (first, shared, third):
        repo.reported(day=0, severity="high")
    memo = WindowMemo()
    window(service(engine, windows=memo), set_of(first, shared))
    assert (memo.folds, memo.folded_repositories) == (1, 2)
    served = window(service(engine, windows=memo), set_of(shared, third))
    assert memo.folds == 2  # the second scope is a fold of its own...
    assert memo.folded_repositories == 3  # ...of one repository, not two
    assert {v.finding.repository_id for v in served} == {
        shared.repository.id,
        third.repository.id,
    }


def test_a_stale_entry_is_not_served(engine: Engine) -> None:
    left, right, _made = seeded_estate(engine)
    now = [0.0]
    memo = WindowMemo(ttl=15.0, clock=lambda: now[0])
    scope = set_of(left, right)
    window(service(engine, windows=memo), scope)
    now[0] = 14.9
    window(service(engine, windows=memo), scope)
    assert memo.folds == 1
    now[0] = 15.0
    window(service(engine, windows=memo), scope)
    assert memo.folds == 2  # the entry's freshness is the promised bound, never longer


def test_the_memo_holds_a_bounded_number_of_repositories(engine: Engine) -> None:
    left, right, _made = seeded_estate(engine)
    memo = WindowMemo(repositories=1)
    window(service(engine, windows=memo), set_of(left, right))
    assert memo.held() == 1  # least recently served evicted, never unbounded growth


def test_a_window_inside_a_shared_build_reads_its_own_fleet(engine: Engine) -> None:
    left, right, _made = seeded_estate(engine)
    memo = WindowMemo()
    findings = service(engine, windows=memo)
    with findings.shared():
        window(findings, set_of(left, right))
    assert memo.folds == 0  # the build's composition owns the load; the memo stays out


def test_a_count_folds_once_and_agrees_with_the_window(engine: Engine) -> None:
    left, right, _made = seeded_estate(engine)
    memo = WindowMemo()
    scope = set_of(left, right)
    counted = service(engine, windows=memo).count_in(scope)
    again = service(engine, windows=memo).count_in(scope)
    listed = window(service(engine, windows=memo), scope)
    assert counted.total == again.total == len(listed)  # the pager's number and the page agree
    # Two flavours, two folds: a count never pays the window's weight (locations and
    # cwes), and a window never serves the censused rows a tally folded.
    assert memo.folds == 2
    assert memo.take([left.repository.id], None, census=True)[1] == []  # type: ignore[list-item]
    assert memo.take([left.repository.id], None, census=False)[1] == []  # type: ignore[list-item]


def test_a_newest_page_never_reads_the_memo(engine: Engine) -> None:
    left, right, _made = seeded_estate(engine)
    memo = WindowMemo()
    findings = service(engine, windows=memo)
    findings.list_in(set_of(left, right), PageRequest(limit=2))
    assert memo.folds == 0  # the cursor walk is not a window; the memo is not a page store


def test_a_memo_served_window_matches_the_memo_less_one(engine: Engine) -> None:
    left, right, _made = seeded_estate(engine)
    scope = set_of(left, right)
    served = window(service(engine, windows=WindowMemo()), scope)
    plain = window(service(engine), scope)
    assert served == plain


def test_a_repository_without_findings_is_remembered_as_empty(engine: Engine) -> None:
    left, right, _made = seeded_estate(engine)
    quiet: Repo = new_repo(engine)
    memo = WindowMemo()
    scope = FindingSetFilter(
        repository_ids=(left.repository.id, right.repository.id, quiet.repository.id)  # type: ignore[arg-type]
    )
    window(service(engine, windows=memo), scope)
    window(service(engine, windows=memo), scope)
    assert memo.folds == 1
    assert memo.folded_repositories == 3


def test_a_fill_of_an_unrelated_scope_is_not_waited_on() -> None:
    memo = WindowMemo(fill_wait=30.0)
    unrelated = [uuid4() for _ in range(4)]
    filled, release = threading.Event(), threading.Event()

    def fill_unrelated() -> None:
        with memo.fill(unrelated) as held:
            assert held
            filled.set()
            release.wait(timeout=30)

    thread = threading.Thread(target=fill_unrelated)
    thread.start()
    try:
        assert filled.wait(timeout=30)
        started = time.monotonic()
        with memo.fill([uuid4()]) as held:
            # the held fill cannot save this reader a fold: it folds its own rather than
            # queueing behind work it will never read
            assert held is False
        assert time.monotonic() - started < 5.0
    finally:
        release.set()
        thread.join(timeout=30)


def test_a_fill_that_holds_a_wanted_repository_is_waited_on() -> None:
    memo = WindowMemo(fill_wait=30.0)
    shared, ours = uuid4(), uuid4()
    filled, release = threading.Event(), threading.Event()
    outcome: list[bool] = []

    def fill_shared() -> None:
        with memo.fill([shared]) as held:
            assert held
            filled.set()
            release.wait(timeout=30)

    def wait_for_shared() -> None:
        with memo.fill([shared, ours]) as held:
            outcome.append(held)

    thread = threading.Thread(target=fill_shared)
    thread.start()
    try:
        assert filled.wait(timeout=30)
        waiter = threading.Thread(target=wait_for_shared)
        waiter.start()
        time.sleep(0.2)
        assert waiter.is_alive()  # queued behind the fill that holds a repository it wants
        release.set()
        waiter.join(timeout=30)
        assert outcome == [True]
    finally:
        release.set()
        thread.join(timeout=30)
