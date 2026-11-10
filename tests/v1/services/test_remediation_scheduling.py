"""RemediationSchedulingService over SQLite and Postgres: the door that starts the pipeline,
and the status sync that keeps the remediation row beside the decisions that move it."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pydantic
import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed, apart, repository_for
from tests.v1.services.test_remediation import provenance, report
from tests.v1.services.test_verification import World, audited
from tests.v1.services.test_verification import provenance as verification_provenance
from tests.v1.services.test_verification import report as verification_report
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import ProcessConfig
from traust_core.v1.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.operations import (
    OrderRequest,
    OrderState,
    RecordingStartScope,
    RunOrder,
    WorkerId,
)
from traust_core.v1.models.remediation_scheduling import (
    RemediationFindingRequest,
    RemediationState,
    ScheduledEffort,
)
from traust_core.v1.models.vocabulary import ActorKind, RemediationStatus
from traust_core.v1.repositories import create_database_engine
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.remediation import RemediationConfig
from traust_core.v1.services.remediation_scheduling import (
    REMEDIATE_FINDING,
    RemediationSchedulingService,
)

FORK = "https://github.com/example-mirrors/example-service"
VERIFIED_AT = datetime(2026, 10, 24, 9, tzinfo=UTC)
BRANCH = "fix/1f0e8dad-e8d3-4c1e-9a1a-8b2f6b0d1b7c/title"
GIT = ProcessConfig(allowed_binaries=("git",))
PRIVATE = RemediationConfig(fork_org="mirror-org")
PERSON = Principal(
    identity="analyst@example.com",
    kind=ActorKind.HUMAN,
    display="Analyst",
    verified_by=IdentitySource.OIDC,
)
MACHINE = Principal(
    identity="sci-trigger", kind=ActorKind.MACHINE, display="SCI", verified_by=IdentitySource.OIDC
)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path, remediation=PRIVATE, process=GIT))
    ctx.__dict__["database"] = engine
    return ctx


@pytest.fixture
def service(context: Context) -> RemediationSchedulingService:
    return context.services().remediation_scheduling


def seeded(
    engine: Engine, *, findings: int = 1, **finding: Any
) -> tuple[UUID, list[UUID], list[UUID]]:
    """A repository on its default branch and confirmed, open findings on it."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/example-org/svc-{uuid4().hex[:8]}")
        seed.repository_ref(repo, is_default=True)
        made = [seed.finding(repo, **finding) for _ in range(findings)]
        for f in made:
            seed.decision(
                f, validity="confirmed", severity="high", actor="human:analyst@example.com"
            )
        uow.commit()
        return repo.id, [f.id for f in made], [f.repository_id for f in made]  # type: ignore[misc]


def pairs(finding_ids: list[UUID], repository_ids: list[UUID]) -> list[RemediationFindingRequest]:
    return [
        RemediationFindingRequest(finding_id=f, repository_id=r)
        for f, r in zip(finding_ids, repository_ids, strict=True)
    ]


def fork_of(engine: Engine, request: list[RemediationFindingRequest]) -> str:
    """The repository's remediation fork under PRIVATE (ForkPolicy: the convention's plain
    patch-<name> in the fork org)."""
    if not request:  # refused before any fork is resolved
        return "https://github.com/mirror-org/patch-none"
    with SqlTraustUnitOfWork(engine) as uow:
        url = uow.repositories.get(request[0].repository_id).url
    return f"https://github.com/mirror-org/patch-{url.rsplit('/', 1)[-1]}"


def folded(service: RemediationSchedulingService, effort: ScheduledEffort) -> RemediationStatus:
    """The effort's effective status, folded from its decisions and the verification verdicts
    on its fix (what the removed scheduled row's status sync kept)."""
    return service.get(effort.work_item.work_item_id).status


def tied_id_for(engine: Engine, order_id: UUID, before: UUID, stamp: datetime) -> RunOrder:
    """Re-stamp the order to `stamp` with an id sorting before `before`: the door never
    opens two efforts one statement apart, so only a direct row write reaches the tie —
    and the re-read shows the store kept both."""
    with SqlTraustUnitOfWork(engine) as uow:
        table = repository_for(uow, "run_order").table
        id_ = uuid4()
        while not id_.hex < before.hex:
            id_ = uuid4()
        uow.connection.execute(
            sa.update(table).where(table.c.id == order_id).values(id=id_, created_at=stamp)
        )
        uow.commit()
        return uow.run_orders.get(id_)


def pushed(scheduled: ScheduledEffort, finding_ids: list[UUID], **changes: Any) -> Any:
    """A remediation report of the fix pushed where it was scheduled."""
    where = {
        "fork__url": str(scheduled.fork_url),
        "fork__fix_branch": scheduled.fork_branch,
    }
    return report(finding_ids, **{**where, **changes})


def queued_orders(engine: Engine, repository_id: UUID) -> list[Any]:
    with SqlTraustUnitOfWork(engine) as uow:
        return uow.run_orders.list_for_repository(repository_id, OrderState.QUEUED)


def default_ref(engine: Engine, repository_id: UUID) -> UUID:
    with SqlTraustUnitOfWork(engine) as uow:
        return next(r.id for r in uow.repository_refs.list_for(repository_id) if r.is_default)  # type: ignore[arg-type]


# create


def test_create_schedules_the_row_the_findings_the_work_item_and_the_order(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    repository_id, finding_ids, repository_ids = seeded(engine, findings=2)
    scheduled = service.create(
        fork_of(engine, pairs(finding_ids, repository_ids)),
        BRANCH,
        pairs(finding_ids, repository_ids),
        PERSON,
    )
    assert (scheduled.fork_url, scheduled.fork_branch, scheduled.status) == (
        fork_of(engine, pairs(finding_ids, repository_ids)),
        BRANCH,
        "candidate",
    )
    detail = service.get(scheduled.work_item.work_item_id)
    assert detail == scheduled
    assert detail.work_item.status == "candidate"
    assert detail.work_item.finding_ids == tuple(sorted(finding_ids, key=str))
    assert context.services().remediation.get(detail.work_item.work_item_id) == detail.work_item
    (order,) = queued_orders(engine, repository_id)
    assert (order.asset, order.repository_id, order.state, order.requested_by) == (
        REMEDIATE_FINDING,
        repository_id,
        "queued",
        "human:analyst@example.com",
    )
    assert order.work_item_id == detail.work_item.work_item_id  # the runner prepares this one


def test_create_schedules_the_same_findings_once(
    service: RemediationSchedulingService, engine: Engine
) -> None:
    repository_id, finding_ids, repository_ids = seeded(engine, findings=2)
    request = pairs(finding_ids, repository_ids)
    first = service.create(
        fork_of(engine, request + request), BRANCH, request + request, PERSON
    )  # a retried pair is a no-op
    assert (
        service.create(fork_of(engine, request), BRANCH, list(reversed(request)), PERSON) == first
    )
    assert len(queued_orders(engine, repository_id)) == 1
    assert list(service.list(PageRequest()).items) == [first]


def test_create_refuses_what_it_cannot_schedule(
    service: RemediationSchedulingService, engine: Engine
) -> None:
    repository_id, finding_ids, _ = seeded(engine, findings=2)
    _, elsewhere, elsewhere_repos = seeded(engine)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = uow.repositories.get(repository_id)
        closed = seed.finding(repo, fingerprint="fp-closed")
        seed.decision(closed, validity="confirmed", severity="high", actor="human:a@example.com")
        seed.decision(closed, resolution="resolved", validity=None, actor="human:a@example.com")
        uow.commit()
    cases = [
        ([], "at least one finding"),
        ([(finding_ids[0], elsewhere_repos[0])], "is not in repository"),
        ([(closed.id, repository_id)], "is closed"),
        ([(finding_ids[0], repository_id), (elsewhere[0], elsewhere_repos[0])], "one repository"),
    ]
    for finding_pairs, message in cases:
        request = [
            RemediationFindingRequest(finding_id=f, repository_id=r) for f, r in finding_pairs
        ]
        with pytest.raises(ValidationError, match=message):
            service.create(fork_of(engine, request), BRANCH, request, PERSON)
    with pytest.raises(NotFoundError, match="finding"):
        service.create(
            FORK,
            BRANCH,
            [RemediationFindingRequest(finding_id=uuid4(), repository_id=repository_id)],
            PERSON,
        )
    assert list(service.list(PageRequest()).items) == []


def test_create_refuses_a_fork_that_is_not_https_or_a_branch_git_would_reject(
    service: RemediationSchedulingService, engine: Engine
) -> None:
    _, finding_ids, repository_ids = seeded(engine)
    request = pairs(finding_ids, repository_ids)
    for fork in ("http://github.com/example-mirrors/example-service", "github.com/x/y", "https://"):
        with pytest.raises(ValidationError, match="remediation fork"):
            service.create(fork, BRANCH, request, PERSON)
    for branch in (
        "",
        "-leading-dash",
        "a..b",
        "a//b",
        "/leading",
        "trailing/",
        "ends.lock",
        "a~b",
        "a^b",
        "a:b",
        "a?b",
        "a*b",
        "a[b",
        "a\\b",
        "@",
        "a@{b",
        "a b",
        # per-component rules of check-ref-format
        ".x",
        "a/.b",
        "a.lock/b",
        "a.",
        "fix.",
        "fix/x.lock/next",
    ):
        with pytest.raises(ValidationError, match="fork_branch"):
            service.create(fork_of(engine, request), branch, request, PERSON)
    assert list(service.list(PageRequest()).items) == []


def test_create_needs_the_repositorys_default_line_to_patch(
    service: RemediationSchedulingService, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/example-org/bare-{uuid4().hex[:8]}")
        finding = seed.finding(repo)
        seed.decision(
            finding, validity="confirmed", severity="high", actor="human:analyst@example.com"
        )
        uow.commit()
        repository_id, finding_id = repo.id, finding.id
    lone = [RemediationFindingRequest(finding_id=finding_id, repository_id=repository_id)]
    with pytest.raises(ValidationError, match="no single default ref"):
        service.create(
            fork_of(engine, lone),
            BRANCH,
            lone,
            PERSON,
        )


def test_create_patches_the_latest_default_line_once_the_branch_has_moved(
    service: RemediationSchedulingService, engine: Engine
) -> None:
    """An import's default line and a later observation's both stay flagged; the fix patches
    the latest (Qodo 392: a moved default branch blocked remediation)."""
    repository_id, finding_ids, repository_ids = seeded(engine)
    imported = default_ref(engine, repository_id)
    with SqlTraustUnitOfWork(engine) as uow:
        first = uow.repository_refs.get(imported)
        moved = Seed(uow).repository_ref(
            uow.repositories.get(repository_id),
            sha="d" * 40,
            is_default=True,
            created_at=first.created_at + timedelta(minutes=1),
        )
        uow.commit()
    request = pairs(finding_ids, repository_ids)
    scheduled = service.create(fork_of(engine, request), BRANCH, request, PERSON)
    detail = service.get(scheduled.work_item.work_item_id)
    with SqlTraustUnitOfWork(engine) as uow:
        patched = uow.assessments.get(detail.work_item.work_item_id).repository_ref_id
    assert patched == moved.id != imported


def test_create_patches_a_reimported_head_even_though_its_row_predates_the_observation(
    service: RemediationSchedulingService, engine: Engine
) -> None:
    """B's row is recorded first, A is observed after (A→B→A's tail), then B is imported
    again: the work item patches B, the newest naming, even though B's row was created
    before the observation (Qodo 401: a line is immutable once recorded, so the row's
    creation time can't order the namings)."""
    repository_id, finding_ids, repository_ids = seeded(engine)
    with SqlTraustUnitOfWork(engine) as uow:
        repo = uow.repositories.get(repository_id)
        seed = Seed(uow)
        b = seed.repository_ref(repo, name="main", sha="b" * 40, is_default=True)
        apart()
        a = seed.repository_ref(repo, name="main", sha="e" * 40, is_default=True)
        apart()
        observed_at = a.created_at + timedelta(minutes=1)  # the last observation: A
        seed.assessment(a, kind="repo-state", occurred_at=observed_at)
        uow.commit()
        imported = uow.repository_refs.update(
            b.model_copy(update={"default_named_at": observed_at + timedelta(minutes=1)})
        )
        uow.commit()
        reimported = b.id
    request = pairs(finding_ids, repository_ids)
    scheduled = service.create(fork_of(engine, request), BRANCH, request, PERSON)
    detail = service.get(scheduled.work_item.work_item_id)
    with SqlTraustUnitOfWork(engine) as uow:
        patched = uow.assessments.get(detail.work_item.work_item_id).repository_ref_id
    assert patched == reimported != a.id
    assert imported.default_named_at is not None


# get, list


def test_get_and_list_filter_the_scheduled_efforts(
    service: RemediationSchedulingService, engine: Engine
) -> None:
    repository_id, finding_ids, repository_ids = seeded(engine, findings=2)
    other_repository, other_findings, other_repos = seeded(engine)
    first = service.create(
        fork_of(engine, pairs(finding_ids[:1], repository_ids[:1])),
        BRANCH,
        pairs(finding_ids[:1], repository_ids[:1]),
        PERSON,
    )
    apart()  # listed by when each was scheduled: the store stamps milliseconds
    second = service.create(
        fork_of(engine, pairs(finding_ids[1:], repository_ids[1:])),
        BRANCH,
        pairs(finding_ids[1:], repository_ids[1:]),
        PERSON,
    )
    apart()
    third = service.create(
        fork_of(engine, pairs(other_findings, other_repos)),
        BRANCH,
        pairs(other_findings, other_repos),
        PERSON,
    )
    assert list(service.list(PageRequest()).items) == [first, second, third]
    assert list(service.list(PageRequest(), repository_id=repository_id).items) == [first, second]
    assert list(service.list(PageRequest(), finding_id=finding_ids[0]).items) == [first]
    assert list(service.list(PageRequest(), repository_id=other_repository).items) == [third]
    assert list(service.list(PageRequest(), status=RemediationStatus("candidate")).items) == [
        first,
        second,
        third,
    ]
    assert service.list(PageRequest(), status=RemediationStatus("merged")).items == ()
    detail = service.get(second.work_item.work_item_id)
    assert detail == second
    assert detail.work_item.finding_ids == (finding_ids[1],)
    with pytest.raises(NotFoundError):
        service.get(uuid4())


# status sync


def test_record_progress_moves_the_scheduled_row_with_the_work_item(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    _, finding_ids, repository_ids = seeded(engine)
    scheduled = service.create(
        fork_of(engine, pairs(finding_ids, repository_ids)),
        BRANCH,
        pairs(finding_ids, repository_ids),
        PERSON,
    )
    remediation = context.services().remediation
    remediation.record_progress(scheduled.work_item.work_item_id, RemediationStatus("forked"))
    assert folded(service, scheduled) == "forked"
    remediation.record_progress(scheduled.work_item.work_item_id, RemediationStatus("patched"))
    assert folded(service, scheduled) == "patched"
    with pytest.raises(ConflictError, match="can't move"):
        remediation.record_progress(
            scheduled.work_item.work_item_id, RemediationStatus("candidate")
        )


def test_record_moves_the_scheduled_row_with_the_report(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    _, finding_ids, repository_ids = seeded(engine)
    scheduled = service.create(
        fork_of(engine, pairs(finding_ids, repository_ids)),
        BRANCH,
        pairs(finding_ids, repository_ids),
        PERSON,
    )
    done = context.services().remediation.record(pushed(scheduled, finding_ids), provenance())
    assert done.status == "checks_passed"
    assert folded(service, scheduled) == "checks_passed"


def test_work_items_without_a_scheduled_effort_record_as_before(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    repository_id, finding_ids, _ = seeded(engine)
    remediation = context.services().remediation
    item = remediation.open(finding_ids, default_ref(engine, repository_id))
    remediation.record_progress(item.work_item_id, RemediationStatus("forked"))
    done = remediation.record(report(finding_ids), provenance())
    assert (done.status, list(service.list(PageRequest()).items)) == ("checks_passed", [])


def test_a_verification_revalidates_the_scheduled_row(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    scheduled = service.create(
        fork_of(engine, pairs(world.ids, [world.repo.id] * len(world.ids))),
        world.patched.name,
        pairs(world.ids, [world.repo.id] * len(world.ids)),
        PERSON,
    )
    context.services().remediation.record(
        pushed(scheduled, world.ids, fork__fix_commit=world.patched.sha), provenance()
    )
    fixed = context.services().verification.record(
        verification_report(world), verification_provenance()
    )
    assert fixed.verdicts
    assert folded(service, scheduled) == "revalidated_fixed"


def test_a_verification_that_leaves_a_finding_open_marks_the_effort_still_vulnerable(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    world = World(engine, findings=2, patched_name="main")
    audited(engine, world, world.base)
    scheduled = service.create(
        fork_of(engine, pairs(world.ids, [world.repo.id] * len(world.ids))),
        world.patched.name,
        pairs(world.ids, [world.repo.id] * len(world.ids)),
        PERSON,
    )
    context.services().remediation.record(
        pushed(scheduled, world.ids, fork__fix_commit=world.patched.sha), provenance()
    )
    got = context.services().verification.record(
        verification_report(world, {world.ids[0]: "resolved", world.ids[1]: "unresolved"}),
        verification_provenance(),
    )
    assert len(got.verdicts) == 2
    assert folded(service, scheduled) == "revalidated_still_vulnerable"


# the state reports (what the engine's trigger plans off)


def test_state_of_reports_the_effort_the_work_item_is(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    """The keyed read maps the effort onto its state: the handle is the work item (the
    assessment, so the feed's events name it directly), the repository comes off the
    effort — no ref resolution — and the status is the fold the effort reads."""
    repository_id, finding_ids, repository_ids = seeded(engine)
    request = pairs(finding_ids, repository_ids)
    scheduled = service.create(fork_of(engine, request), BRANCH, request, PERSON)
    context.services().remediation.record_progress(
        scheduled.work_item.work_item_id, RemediationStatus("patched")
    )
    assert service.state_of(scheduled.work_item.work_item_id) == RemediationState(
        work_item_id=scheduled.work_item.work_item_id,
        repository_id=repository_id,
        status=RemediationStatus("patched"),
    )


def test_state_of_of_what_was_never_scheduled_is_none(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    """The keyed read misses softly: no work item at all, or a work item whose order carries
    no fork facts (opened beside the scheduling door), reads None — the feed-driven consumer
    that replays events naming them suppresses no 404 of its own."""
    repository_id, finding_ids, _ = seeded(engine)
    beside = context.services().remediation.open(finding_ids, default_ref(engine, repository_id))
    assert service.state_of(beside.work_item_id) is None
    assert service.state_of(uuid4()) is None


def test_states_of_fold_a_lineage_to_its_head_with_its_priors(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    """The repository's lineages, one report each: the newest effort over a finding set —
    the head — reports for it with the lineage's over attempts as its `reattempts` (an
    over attempt is retried as a new work item over the same findings, so those are its
    priors); an over attempt a newer one over the same findings supersedes is not reported;
    an effort over overlapping-but-different findings is another lineage's, never counting
    against this one; and a live effort is reported whatever was opened beside it — the
    door opens no second live effort over findings a live one covers, so nothing live is
    ever displaced."""
    repository_id, finding_ids, repository_ids = seeded(engine, findings=3)
    remediation = context.services().remediation

    def over(request: list[RemediationFindingRequest]) -> ScheduledEffort:
        effort = service.create(fork_of(engine, request), BRANCH, request, PERSON)
        remediation.record_progress(effort.work_item.work_item_id, RemediationStatus("abandoned"))
        return effort

    apart()  # the store stamps milliseconds: keeps each lineage's scheduling order apart
    first = over(pairs(finding_ids[:2], repository_ids[:2]))  # {f1, f2}: the lineage's prior
    apart()
    overlap = over(pairs(finding_ids[1:2], repository_ids[1:2]))  # {f2}: another lineage
    apart()
    separate = over(pairs(finding_ids[2:], repository_ids[2:]))  # {f3}: another lineage
    apart()
    head = over(pairs(finding_ids[:2], repository_ids[:2]))  # {f1, f2} again: the retry
    apart()
    live = service.create(  # {f1}: live beside the over lineages that cover it
        fork_of(engine, pairs(finding_ids[:1], repository_ids[:1])),
        BRANCH,
        pairs(finding_ids[:1], repository_ids[:1]),
        PERSON,
    )

    states = {s.work_item_id: s for s in service.states_of(repository_id)}

    assert set(states) == {
        head.work_item.work_item_id,
        overlap.work_item.work_item_id,
        separate.work_item.work_item_id,
        live.work_item.work_item_id,
    }  # the lineage's over prior is not reported; every head and the live effort are
    assert states[head.work_item.work_item_id].reattempts == 1  # the abandoned prior
    assert states[overlap.work_item.work_item_id].reattempts == 0  # another lineage's
    assert states[separate.work_item.work_item_id].reattempts == 0
    assert states[live.work_item.work_item_id].reattempts == 0
    assert states[live.work_item.work_item_id].status == RemediationStatus("candidate")
    # The keyed read resolves the effort's own lineage, so it agrees with the listing for
    # the head at any status — and a superseded prior at a status no limit gates on still
    # reports as itself (abandoned: no order a trigger would plan).
    assert service.state_of(head.work_item.work_item_id) == states[head.work_item.work_item_id]
    assert service.state_of(first.work_item.work_item_id) == RemediationState(
        work_item_id=first.work_item.work_item_id,
        repository_id=repository_id,
        status=RemediationStatus("abandoned"),
    )


def test_a_superseded_still_vulnerable_effort_reads_as_no_effort(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    """A still-vulnerable effort a newer one over the same findings superseded reads as no
    effort: a replayed event naming it dispatches nothing and cannot bypass the lineage's
    reattempt limit. The retry — the lineage's head, itself still vulnerable on the same
    fix — reports with the lineage's priors, the count the limit gates on, because a
    still-vulnerable effort resolves through its repository's lineages."""
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    request = pairs(world.ids, [world.repo.id] * len(world.ids))
    first = service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    context.services().remediation.record(
        pushed(first, world.ids, fork__fix_commit=world.patched.sha), provenance()
    )
    verification = context.services().verification
    verification.record(
        verification_report(world, dict.fromkeys(world.ids, "unresolved")),
        verification_provenance(),
    )
    assert folded(service, first) == "revalidated_still_vulnerable"
    retry = service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    assert retry.work_item.work_item_id != first.work_item.work_item_id
    context.services().remediation.record(
        pushed(retry, world.ids, fork__fix_commit=world.patched.sha),
        provenance(),
        work_item_id=retry.work_item.work_item_id,
    )
    apart()
    # a check recorded before the retry was scheduled never counts for it (#396): re-check it
    verification.record(
        verification_report(
            world, dict.fromkeys(world.ids, "unresolved"), metadata__date="2026-11-08"
        ),
        verification_provenance(),
    )
    assert folded(service, retry) == "revalidated_still_vulnerable"

    assert service.state_of(first.work_item.work_item_id) is None
    assert service.state_of(retry.work_item.work_item_id) == RemediationState(
        work_item_id=retry.work_item.work_item_id,
        repository_id=world.repo.id,
        status=RemediationStatus("revalidated_still_vulnerable"),
        reattempts=1,
    )
    assert service.states_of(world.repo.id) == [
        RemediationState(
            work_item_id=retry.work_item.work_item_id,
            repository_id=world.repo.id,
            status=RemediationStatus("revalidated_still_vulnerable"),
            reattempts=1,
        )
    ]


def test_a_retry_reported_under_a_tied_scheduling_stamp_still_folds_as_the_head(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    """A lineage's head under a tie: orders stamp one value per statement (milliseconds on
    SQLite), so a retry the door opened a write later can share its prior's stamp — and, ids
    being random, land before it. Head selection never reads the stamps as chronology: the
    door opens no attempt over findings a live effort covers, so the lineage's live attempt
    is its head and its over priors fold before it, whatever the stamps and ids say. The
    door never produces the tie itself (a retry needs a write between the two creates), so
    the test re-stamps the retry's order directly."""
    repository_id, finding_ids, repository_ids = seeded(engine, findings=2)
    remediation = context.services().remediation
    request = pairs(finding_ids, repository_ids)

    prior = service.create(fork_of(engine, request), BRANCH, request, PERSON)
    remediation.record_progress(prior.work_item.work_item_id, RemediationStatus("abandoned"))
    apart()  # the stamps stay tied only by the row write below, never the door
    retry = service.create(fork_of(engine, request), BRANCH, request, PERSON)

    assert retry.work_item.work_item_id != prior.work_item.work_item_id
    prior_stamp = service.get(prior.work_item.work_item_id).scheduled_at
    assert prior_stamp is not None
    assert retry.order_id is not None and prior.order_id is not None
    tied = tied_id_for(engine, retry.order_id, prior.order_id, prior_stamp)
    assert tied.created_at == prior_stamp and tied.id < prior.order_id

    states = {s.work_item_id: s for s in service.states_of(repository_id)}
    assert set(states) == {retry.work_item.work_item_id}
    assert states[retry.work_item.work_item_id] == RemediationState(
        work_item_id=retry.work_item.work_item_id,
        repository_id=repository_id,
        status=RemediationStatus("candidate"),
        reattempts=1,  # the tied, abandoned prior: folded by liveness, not by stamps
    )
    # the keyed read folds the same lineage chronology, so it agrees under the tie too
    assert service.state_of(retry.work_item.work_item_id) == states[retry.work_item.work_item_id]
    assert service.state_of(prior.work_item.work_item_id) == RemediationState(
        work_item_id=prior.work_item.work_item_id,
        repository_id=repository_id,
        status=RemediationStatus("abandoned"),
    )


def test_states_of_name_only_the_repository_asked_for(
    service: RemediationSchedulingService, engine: Engine
) -> None:
    repository_id, finding_ids, repository_ids = seeded(engine)
    _, other_findings, other_repos = seeded(engine)
    here = service.create(
        fork_of(engine, pairs(finding_ids, repository_ids)),
        BRANCH,
        pairs(finding_ids, repository_ids),
        PERSON,
    )
    service.create(
        fork_of(engine, pairs(other_findings, other_repos)),
        BRANCH,
        pairs(other_findings, other_repos),
        PERSON,
    )

    states = service.states_of(repository_id)

    assert states == [
        RemediationState(
            work_item_id=here.work_item.work_item_id,
            repository_id=repository_id,
            status=RemediationStatus("candidate"),
        )
    ]


# who may schedule (a verified person; a machine only within its recording.start grant)


def test_only_a_verified_person_or_a_granted_machine_may_schedule(
    context: Context, engine: Engine
) -> None:
    repository_id, finding_ids, repository_ids = seeded(engine, findings=3)
    service = context.services().remediation_scheduling
    unverified = PERSON.model_copy(update={"verified_by": None})
    for who in (unverified, MACHINE):
        with pytest.raises(ForbiddenError, match="not allowed to ask for remediate_finding"):
            service.create(
                fork_of(engine, pairs(finding_ids[:1], repository_ids[:1])),
                BRANCH,
                pairs(finding_ids[:1], repository_ids[:1]),
                who,
            )
    grant = RecordingStartScope(
        principal=MACHINE.ref, assets=(REMEDIATE_FINDING,), repository_ids=(repository_id,)
    )
    context.config = context.config.model_copy(
        update={"recording": context.config.recording.model_copy(update={"start": (grant,)})}
    )
    granted = context.services().remediation_scheduling
    made = granted.create(
        fork_of(engine, pairs(finding_ids[1:2], repository_ids[1:2])),
        BRANCH,
        pairs(finding_ids[1:2], repository_ids[1:2]),
        MACHINE,
    )
    assert made.status == "candidate"
    other = RecordingStartScope(
        principal=MACHINE.ref, assets=(REMEDIATE_FINDING,), repository_ids=(uuid4(),)
    )
    context.config = context.config.model_copy(
        update={"recording": context.config.recording.model_copy(update={"start": (other,)})}
    )
    with pytest.raises(ForbiddenError):  # a grant for another repository is no grant here
        context.services().remediation_scheduling.create(
            fork_of(engine, pairs(finding_ids[2:], repository_ids[2:])),
            BRANCH,
            pairs(finding_ids[2:], repository_ids[2:]),
            MACHINE,
        )


# the fork the request names is the fork the fix is prepared for


def test_prepare_hands_the_runner_the_scheduled_fork_and_branch(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    _, finding_ids, repository_ids = seeded(engine)
    scheduled = service.create(
        fork_of(engine, pairs(finding_ids, repository_ids)),
        BRANCH,
        pairs(finding_ids, repository_ids),
        PERSON,
    )
    prepared = context.services().remediation.prepare(scheduled.work_item.work_item_id)
    expected = fork_of(engine, pairs(finding_ids, repository_ids))
    assert (str(prepared.fork.url), prepared.fix_branch) == (expected, BRANCH)


def test_a_fork_other_than_the_repositorys_remediation_fork_is_refused(
    service: RemediationSchedulingService, engine: Engine
) -> None:
    # never a public repository: the fork is the policy's (the fork org's private patch
    # repository), not whatever the caller names, the upstream itself included — a public
    # target (the seeded upstream is) answers the sharper public refusal, the rest the
    # policy's
    _, finding_ids, repository_ids = seeded(engine)
    request = pairs(finding_ids, repository_ids)
    with SqlTraustUnitOfWork(engine) as uow:
        upstream = uow.repositories.get(repository_ids[0]).url
    for fork in (
        upstream,
        "https://github.com/someone-else/public-copy",
        "https://forge.example.net/o/r",
    ):
        with pytest.raises(ValidationError, match=r"remediation fork|public repository"):
            service.create(fork, BRANCH, request, PERSON)
    assert list(service.list(PageRequest()).items) == []


def test_the_conventions_collision_fallback_is_the_fork_the_provisioner_would_have_made(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    # SCI's provisioner takes sci-patch-<owner>-<name> when another upstream holds the plain
    # name: with no registered mirror the door accepts the candidate it actually provisioned,
    # and the order carries it — the convention is the fallback, the mirror the authority
    _, finding_ids, repository_ids = seeded(engine)
    request = pairs(finding_ids, repository_ids)
    with SqlTraustUnitOfWork(engine) as uow:
        name = uow.repositories.get(repository_ids[0]).url.rsplit("/", 1)[-1]
    collision = f"https://github.com/mirror-org/patch-example-org-{name}"
    scheduled = service.create(collision, BRANCH, request, PERSON)
    assert scheduled.fork_url == collision
    (order,) = queued_orders(engine, repository_ids[0])
    assert order.fork_url == collision
    prepared = context.services().remediation.prepare(scheduled.work_item.work_item_id)
    assert (str(prepared.fork.url), prepared.fix_branch) == (collision, BRANCH)
    with SqlTraustUnitOfWork(engine) as uow:  # a mirror registered since is the only answer
        Seed(uow).repository(
            url=f"https://github.com/mirror-org/patch-{name}",
            upstream_id=repository_ids[0],
            public=False,
        )
        uow.commit()
    with pytest.raises(ValidationError, match="remediation fork"):
        service.create(collision, BRANCH, request, PERSON)


def test_a_collision_name_registered_to_another_upstream_is_not_this_repositorys_fork(
    service: RemediationSchedulingService, engine: Engine
) -> None:
    # a/b-c and a-b/c owner-qualify to the same sci-patch-a-b-c; the one the inventory
    # knows as the other upstream's mirror is foreign to this repository's schedule —
    # authority over one upstream's findings must not steer its fix into another's fork
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        theirs = seed.repository(url="https://github.com/a-b/c")
        ours = seed.repository(url="https://github.com/a/b-c")
        findings = {}
        for repo in (theirs, ours):
            seed.repository_ref(repo, is_default=True)
            found = seed.finding(repo)
            seed.decision(found, validity="confirmed", severity="high", actor="human:a@example.com")
            findings[repo.id] = found.id
        seed.repository(  # the colliding name, the other upstream's registered mirror
            url="https://github.com/mirror-org/patch-a-b-c", upstream_id=theirs.id, public=False
        )
        uow.commit()
    ours_request = [RemediationFindingRequest(finding_id=findings[ours.id], repository_id=ours.id)]  # type: ignore[misc]
    with pytest.raises(ValidationError, match="remediation fork"):
        service.create("https://github.com/mirror-org/patch-a-b-c", BRANCH, ours_request, PERSON)
    theirs_request = [  # the same URL is their own mirror: the authoritative answer
        RemediationFindingRequest(finding_id=findings[theirs.id], repository_id=theirs.id)  # type: ignore[misc]
    ]
    scheduled = service.create(
        "https://github.com/mirror-org/patch-a-b-c", BRANCH, theirs_request, PERSON
    )
    assert scheduled.fork_url == "https://github.com/mirror-org/patch-a-b-c"


def test_a_public_plain_name_occupant_pushes_the_schedule_to_the_qualified_candidate(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    # the provisioner falls back to sci-patch-<owner>-<name> exactly when the plain name
    # is held by someone else — a public occupant of the plain name must not block the
    # qualified candidate's schedule, while the public name itself stays a refusal
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url="https://github.com/example-org/svc")
        seed.repository_ref(repo, is_default=True)
        found = seed.finding(repo)
        seed.decision(found, validity="confirmed", severity="high", actor="human:a@example.com")
        seed.repository(url="https://github.com/mirror-org/patch-svc", public=True)
        uow.commit()
    request = [RemediationFindingRequest(finding_id=found.id, repository_id=repo.id)]  # type: ignore[misc]
    with pytest.raises(ValidationError, match="public repository"):
        service.create("https://github.com/mirror-org/patch-svc", BRANCH, request, PERSON)
    qualified = "https://github.com/mirror-org/patch-example-org-svc"
    scheduled = service.create(qualified, BRANCH, request, PERSON)
    assert scheduled.fork_url == qualified
    prepared = context.services().remediation.prepare(scheduled.work_item.work_item_id)
    assert str(prepared.fork.url) == qualified


def test_the_door_couples_on_the_prefix_not_the_candidate_spelling(
    engine: Engine, tmp_path: Path
) -> None:
    # any patch-prefixed repository in the mirror org is a convention fork: the
    # provisioner owns the naming beyond the prefix, and core's candidates are its
    # expectation, never the contract
    repository_id, finding_ids, _ = seeded(engine)
    request = pairs(finding_ids, [repository_id])
    context = Context(Config(home=tmp_path, remediation=PRIVATE, process=GIT))
    context.__dict__["database"] = engine
    service = context.services().remediation_scheduling
    with SqlTraustUnitOfWork(engine) as uow:
        name = uow.repositories.get(repository_id).url.rsplit("/", 1)[-1]
    for refused in (
        f"https://github.com/mirror-org/{name}",  # bare: the shape before any prefix
        f"https://github.com/mirror-org/patchless-{name}",
        f"https://github.com/other-org/patch-{name}",
        "https://github.com/mirror-org/patch-svc/../escape",
    ):
        with pytest.raises(ValidationError, match="remediation fork"):
            service.create(refused, BRANCH, request, PERSON)
    retake = fork_of(engine, request) + "-retake-2"  # a name core would not compute
    scheduled = service.create(retake, BRANCH, request, PERSON)
    assert scheduled.fork_url == retake


def test_a_deployment_running_the_sci_provisioner_prefixes_its_forks(
    engine: Engine, tmp_path: Path
) -> None:
    # ours sets the prefix the provisioner names — sci-patch-, not the generic default —
    # and the door couples on the configured prefix alone
    repository_id, finding_ids, _ = seeded(engine)
    request = pairs(finding_ids, [repository_id])
    context = Context(
        Config(
            home=tmp_path,
            remediation=RemediationConfig(fork_org="mirror-org", patch_prefix="sci-patch-"),
            process=GIT,
        )
    )
    context.__dict__["database"] = engine
    service = context.services().remediation_scheduling
    with SqlTraustUnitOfWork(engine) as uow:
        name = uow.repositories.get(repository_id).url.rsplit("/", 1)[-1]
    ours = f"https://github.com/mirror-org/sci-patch-{name}"
    assert service.create(ours, BRANCH, request, PERSON).fork_url == ours
    with pytest.raises(ValidationError, match="remediation fork"):
        service.create(f"https://github.com/mirror-org/patch-{name}", BRANCH, request, PERSON)


def test_a_fork_the_inventory_cannot_prove_is_not_a_push_target(
    service: RemediationSchedulingService, engine: Engine
) -> None:
    # prefix shape is not ownership: a repository the inventory knows under a prefixed
    # name — another's, or a registration without provenance — is never a push target,
    # the upstream itself included; one the inventory does not know is the provisioner's
    # creation, and schedules
    repository_id, finding_ids, _ = seeded(engine)
    request = pairs(finding_ids, [repository_id])
    with SqlTraustUnitOfWork(engine) as uow:
        Seed(uow).repository(  # known, no provenance: not provably this repository's
            url="https://github.com/mirror-org/patch-someone-elses", public=False
        )
        seed = Seed(uow)
        self_named = seed.repository(url="https://github.com/mirror-org/patch-self", public=False)
        seed.repository_ref(self_named, is_default=True)
        found = seed.finding(self_named)
        seed.decision(found, validity="confirmed", severity="high", actor="human:a@example.com")
        uow.commit()
    with pytest.raises(ValidationError, match="remediation fork"):
        service.create("https://github.com/mirror-org/patch-someone-elses", BRANCH, request, PERSON)
    own = [RemediationFindingRequest(finding_id=found.id, repository_id=self_named.id)]  # type: ignore[misc]
    with pytest.raises(ValidationError, match="remediation fork"):  # the upstream itself
        service.create("https://github.com/mirror-org/patch-self", BRANCH, own, PERSON)
    made_up = fork_of(engine, request) + "-2"  # unknown: the provisioner's to have created
    assert service.create(made_up, BRANCH, request, PERSON).fork_url == made_up


def test_exhausted_candidates_do_not_block_a_valid_custom_fork(
    service: RemediationSchedulingService, engine: Engine
) -> None:
    # both names core would suggest registered to other upstreams, and the provisioner's
    # actual fork carrying a different prefixed name: the door judges the target, never
    # core's suggestions
    repository_id, finding_ids, _ = seeded(engine)
    request = pairs(finding_ids, [repository_id])
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        name = uow.repositories.get(repository_id).url.rsplit("/", 1)[-1]
        for candidate in (f"patch-{name}", f"patch-example-org-{name}"):
            other = seed.repository(url=f"https://github.com/example-org/{candidate}-upstream")
            seed.repository(  # both suggestions provably another upstream's
                url=f"https://github.com/mirror-org/{candidate}", upstream_id=other.id, public=False
            )
        uow.commit()
    custom = f"https://github.com/mirror-org/patch-{name}-retaken"
    assert service.create(custom, BRANCH, request, PERSON).fork_url == custom


def test_an_unstamped_bare_url_order_whose_fork_changed_ownership_no_longer_vouches(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    # the historical bare name stays vouchable only while nothing proves it another
    # upstream's: once the inventory does, the era's order binds to nothing
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    request = pairs(world.ids, [world.repo.id] * len(world.ids))
    scheduled = service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    unstamped(engine, scheduled)
    with SqlTraustUnitOfWork(engine) as uow:
        name = uow.repositories.get(world.repo.id).url.rsplit("/", 1)[-1]  # type: ignore[arg-type]
        bare = f"https://github.com/mirror-org/{name}"  # the policy's answer before the change
        order = uow.run_orders.get(scheduled.order_id)  # type: ignore[arg-type]
        uow.run_orders.update(order.model_copy(update={"fork_url": bare}))
        uow.commit()
    with SqlTraustUnitOfWork(engine) as uow:  # the bare name now another upstream's mirror
        other = Seed(uow).repository(url="https://github.com/example-org/other")
        Seed(uow).repository(url=bare, upstream_id=other.id, public=False)
        uow.commit()
    remediation = context.services().remediation
    assert remediation.scheduled_order(scheduled.work_item.work_item_id) is None
    with pytest.raises(ValidationError, match="can't vouch for"):
        remediation.record(
            pushed(scheduled, world.ids, fork__url=bare, fork__fix_commit=world.patched.sha),
            provenance(),
        )


def test_an_unstamped_order_scheduled_before_the_convention_still_vouches(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    # orders from before contracts#130's stamp carry the bare fork the policy answered
    # before the sci-patch convention: their door-set facts stay vouched across the change
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    request = pairs(world.ids, [world.repo.id] * len(world.ids))
    scheduled = service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    unstamped(engine, scheduled)
    with SqlTraustUnitOfWork(engine) as uow:
        name = uow.repositories.get(world.repo.id).url.rsplit("/", 1)[-1]  # type: ignore[arg-type]
        bare = f"https://github.com/mirror-org/{name}"  # the policy's answer before the change
        order = uow.run_orders.get(scheduled.order_id)  # type: ignore[arg-type]
        uow.run_orders.update(order.model_copy(update={"fork_url": bare}))
        uow.commit()
    remediation = context.services().remediation
    assert remediation.scheduled_order(scheduled.work_item.work_item_id) is not None
    assert service.get(scheduled.work_item.work_item_id).fork_url == bare
    recorded = remediation.record(
        pushed(scheduled, world.ids, fork__url=bare, fork__fix_commit=world.patched.sha),
        provenance(),
    )
    assert recorded.report is not None
    # nothing wider vouches: an unstamped URL the door never answered is still refused
    # (test_a_report_on_an_order_scheduling_no_longer_vouches_for_is_refused below)


# scheduling the same findings again


def test_a_retry_after_a_report_returns_the_effort_and_an_overlap_conflicts(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    repository_id, finding_ids, repository_ids = seeded(engine, findings=2)
    scheduled = service.create(
        fork_of(engine, pairs(finding_ids[:1], repository_ids[:1])),
        BRANCH,
        pairs(finding_ids[:1], repository_ids[:1]),
        PERSON,
    )
    context.services().remediation.record(pushed(scheduled, finding_ids[:1]), provenance())
    again = service.create(
        fork_of(engine, pairs(finding_ids[:1], repository_ids[:1])),
        BRANCH,
        pairs(finding_ids[:1], repository_ids[:1]),
        PERSON,
    )
    assert (
        again.work_item.work_item_id == scheduled.work_item.work_item_id
        and len(queued_orders(engine, repository_id)) == 1
    )
    with pytest.raises(ConflictError, match="already covers"):
        service.create(
            fork_of(engine, pairs(finding_ids, repository_ids)),
            BRANCH,
            pairs(finding_ids, repository_ids),
            PERSON,
        )


def test_a_second_request_waits_for_the_first_and_finds_its_effort(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    # the first request holds the findings' locks with its effort written but not committed;
    # a second request (its own engine) waits there instead of opening a second effort
    repository_id, finding_ids, repository_ids = seeded(engine)
    request = pairs(finding_ids, repository_ids)
    done: list[object] = []
    gate = threading.Event()
    original = RemediationSchedulingService._live

    def held(self: RemediationSchedulingService, *args: Any) -> Any:
        found = original(self, *args)
        if not gate.is_set():
            gate.set()
            time.sleep(1.5)  # still inside the first request's transaction
        return found

    def second() -> None:
        own = create_database_engine(engine.url.render_as_string(hide_password=False))
        try:
            ctx = Context(Config(home=context.config.home, remediation=PRIVATE, process=GIT))
            ctx.__dict__["database"] = own
            done.append(
                ctx.services().remediation_scheduling.create(
                    fork_of(engine, request), BRANCH, request, PERSON
                )
            )
        finally:
            own.dispose()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(RemediationSchedulingService, "_live", held)
        first = threading.Thread(
            target=lambda: done.append(
                service.create(fork_of(engine, request), BRANCH, request, PERSON)
            )
        )
        first.start()
        gate.wait(timeout=10)
        writer = threading.Thread(target=second)
        writer.start()
        first.join(timeout=30)
        writer.join(timeout=30)
    assert len(done) == 2 and done[0].work_item.work_item_id == done[1].work_item.work_item_id  # type: ignore[attr-defined]
    assert len(queued_orders(engine, repository_id)) == 1


# revalidation is the verified effort's, every finding's, and the latest verdict's


def test_a_verification_of_another_commit_leaves_the_effort(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    scheduled = service.create(
        fork_of(engine, pairs(world.ids, [world.repo.id] * len(world.ids))),
        BRANCH,
        pairs(world.ids, [world.repo.id] * len(world.ids)),
        PERSON,
    )
    context.services().remediation.record(
        pushed(scheduled, world.ids, fork__fix_commit="0" * 40), provenance()
    )
    context.services().verification.record(verification_report(world), verification_provenance())
    assert folded(service, scheduled) == "checks_passed"  # not this fix's commit


def test_a_verification_of_some_of_an_efforts_findings_leaves_it(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    world = World(engine, findings=2, patched_name="main")
    audited(engine, world, world.base)
    scheduled = service.create(
        fork_of(engine, pairs(world.ids, [world.repo.id] * len(world.ids))),
        world.patched.name,
        pairs(world.ids, [world.repo.id] * len(world.ids)),
        PERSON,
    )
    context.services().remediation.record(
        pushed(scheduled, world.ids, fork__fix_commit=world.patched.sha), provenance()
    )
    context.services().verification.record(
        verification_report(world, {world.ids[0]: "resolved"}), verification_provenance()
    )
    assert folded(service, scheduled) == "checks_passed"  # B unverified: not fixed yet


def test_list_applies_every_filter_given(
    service: RemediationSchedulingService, engine: Engine
) -> None:
    repository_id, finding_ids, repository_ids = seeded(engine, findings=2)
    a = service.create(
        fork_of(engine, pairs(finding_ids[:1], repository_ids[:1])),
        BRANCH,
        pairs(finding_ids[:1], repository_ids[:1]),
        PERSON,
    )
    service.create(
        fork_of(engine, pairs(finding_ids[1:], repository_ids[1:])),
        BRANCH,
        pairs(finding_ids[1:], repository_ids[1:]),
        PERSON,
    )
    assert list(
        service.list(PageRequest(), repository_id=repository_id, finding_id=finding_ids[0]).items
    ) == [a]
    assert service.list(PageRequest(), repository_id=uuid4(), finding_id=finding_ids[0]).items == ()


def test_replaying_an_older_verification_never_reverses_a_newer_one(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    world = World(engine, findings=2, patched_name="main")
    audited(engine, world, world.base)
    request = pairs(world.ids, [world.repo.id] * len(world.ids))
    scheduled = service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    context.services().remediation.record(
        pushed(scheduled, world.ids, fork__fix_commit=world.patched.sha), provenance()
    )
    verification = context.services().verification
    older = verification_report(world, {world.ids[0]: "resolved", world.ids[1]: "unresolved"})
    verification.record(older, verification_provenance())
    assert folded(service, scheduled) == "revalidated_still_vulnerable"
    verification.record(verification_report(world), verification_provenance())
    assert folded(service, scheduled) == "revalidated_fixed"
    verification.record(older, verification_provenance())  # the older report delivered again
    assert folded(service, scheduled) == "revalidated_fixed"


def test_the_right_commit_on_another_branch_leaves_the_effort(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    request = pairs(world.ids, [world.repo.id] * len(world.ids))
    scheduled = service.create(fork_of(engine, request), BRANCH, request, PERSON)
    context.services().remediation.record(
        pushed(scheduled, world.ids, fork__fix_commit=world.patched.sha), provenance()
    )
    context.services().verification.record(verification_report(world), verification_provenance())
    assert folded(service, scheduled) == "checks_passed"  # main is not the fix branch


def test_a_fork_the_inventory_records_as_public_takes_no_fix(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    _, finding_ids, repository_ids = seeded(engine)
    request = pairs(finding_ids, repository_ids)
    fork = fork_of(engine, request)
    with SqlTraustUnitOfWork(engine) as uow:
        Seed(uow).repository(url=fork, public=True)  # the forge says the mirror is public
        uow.commit()
    with pytest.raises(ValidationError, match="public repository"):
        service.create(fork, BRANCH, request, PERSON)
    # nor does a report on an unscheduled work item that pushed there
    remediation = context.services().remediation
    item = remediation.open(finding_ids, default_ref(engine, repository_ids[0]))
    with pytest.raises(ValidationError, match="public repository"):
        remediation.record(report(finding_ids, fork__url=fork), provenance())
    assert remediation.get(item.work_item_id).report is None


def test_a_report_pushed_elsewhere_than_scheduled_is_refused(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    _, finding_ids, repository_ids = seeded(engine)
    request = pairs(finding_ids, repository_ids)
    scheduled = service.create(fork_of(engine, request), BRANCH, request, PERSON)
    remediation = context.services().remediation
    elsewhere = {
        "another fork": report(finding_ids, fork__fix_branch=BRANCH),
        "another branch": pushed(scheduled, finding_ids, fork__fix_branch="fix/other"),
    }
    for case, doc in elsewhere.items():
        with pytest.raises(ValidationError, match="not the scheduled"):
            remediation.record(doc, provenance())
        assert folded(service, scheduled) == "candidate", case
    assert remediation.record(pushed(scheduled, finding_ids), provenance()).report is not None


def test_a_verification_that_fails_part_way_leaves_nothing_behind(
    service: RemediationSchedulingService,
    context: Context,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    request = pairs(world.ids, [world.repo.id] * len(world.ids))
    scheduled = service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    context.services().remediation.record(
        pushed(scheduled, world.ids, fork__fix_commit=world.patched.sha), provenance()
    )
    verification = context.services().verification

    def recorded() -> tuple[int, int]:
        with SqlTraustUnitOfWork(engine) as uow:
            runs = [
                a
                for a in uow.assessments.list_for_ref(world.patched.id)
                if a.kind == "verification"
            ]  # type: ignore[arg-type]
            return len(runs), len(uow.findings.list_for_repository(world.repo.id))  # type: ignore[arg-type]

    before = recorded()

    def broken(*_: Any, **__: Any) -> None:
        raise RuntimeError("verdict recording failed")

    decisions = context.services().findings.decisions
    monkeypatch.setattr(type(decisions), "record_resolution", broken)
    doc = verification_report(world)
    assert doc.regressions  # the report brings findings of its own
    with pytest.raises(RuntimeError, match="verdict recording failed"):
        verification.record(doc, verification_provenance())
    assert recorded() == before  # no assessment, report or regression stayed
    assert folded(service, scheduled) == "checks_passed"
    monkeypatch.undo()
    verification.record(doc, verification_provenance())  # the retry records it whole
    assert recorded()[0] == before[0] + 1
    assert folded(service, scheduled) == "revalidated_fixed"


def test_a_direct_order_names_only_a_work_item_of_its_own_repository(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    repository_id, finding_ids, repository_ids = seeded(engine)
    other_repository, _, _ = seeded(engine)
    request = pairs(finding_ids, repository_ids)
    scheduled = service.create(fork_of(engine, request), BRANCH, request, PERSON)
    assert scheduled.work_item.work_item_id is not None
    ops = context.services().ops
    with SqlTraustUnitOfWork(engine) as uow:
        not_a_work_item = Seed(uow).assessment(
            repository_ref_id=default_ref(engine, repository_id)
        )  # an audit, not a work item
        uow.commit()
    for repository, work_item in (
        (other_repository, scheduled.work_item.work_item_id),  # another repository's work item
        (repository_id, uuid4()),  # no such work item
        (repository_id, not_a_work_item.id),  # an assessment, not a remediation work item
        (None, scheduled.work_item.work_item_id),  # an order on no repository
    ):
        with pytest.raises(ValidationError, match="is not a remediation work item"):
            ops.submit(
                OrderRequest(
                    asset=REMEDIATE_FINDING,
                    priority=0,
                    repository_id=repository,
                    work_item_id=work_item,
                ),
                PERSON,
            )
    assert len(queued_orders(engine, repository_id)) == 1  # only the scheduled one
    assert queued_orders(engine, other_repository) == []
    named = ops.submit(
        OrderRequest(
            asset=REMEDIATE_FINDING,
            priority=0,
            repository_id=repository_id,
            work_item_id=scheduled.work_item.work_item_id,
        ),
        PERSON,
    )
    assert named.work_item_id == scheduled.work_item.work_item_id


def test_a_retry_after_a_failed_attempt_is_a_new_work_item(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    _, finding_ids, repository_ids = seeded(engine)
    request = pairs(finding_ids, repository_ids)
    first = service.create(fork_of(engine, request), BRANCH, request, PERSON)
    assert first.work_item.work_item_id is not None
    remediation = context.services().remediation
    remediation.record_progress(first.work_item.work_item_id, RemediationStatus("checks_failed"))
    retry = service.create(fork_of(engine, request), BRANCH, request, PERSON)
    assert (
        retry.work_item.work_item_id != first.work_item.work_item_id
        and retry.work_item.work_item_id not in (None, first.work_item.work_item_id)
    )
    assert retry.work_item.work_item_id is not None
    # each effort names its own work item, so lookups and syncs stay unambiguous
    assert remediation.prepare(retry.work_item.work_item_id).fix_branch == BRANCH
    remediation.record_progress(retry.work_item.work_item_id, RemediationStatus("forked"))
    assert (folded(service, first), folded(service, retry)) == (
        "checks_failed",
        "forked",
    )
    # both attempts await a report: the run names its own work item, never a guess
    with pytest.raises(ValidationError, match="name the work item"):
        remediation.record(pushed(retry, finding_ids), provenance())
    late = remediation.record(  # the failed attempt's worker reports after the retry opened
        pushed(first, finding_ids, summary__status="checks_failed"),
        provenance(),
        work_item_id=first.work_item.work_item_id,
    )
    assert late.work_item_id == first.work_item.work_item_id
    assert remediation.get(retry.work_item.work_item_id).report is None
    assert folded(service, retry) == "forked"  # the retry didn't run that report
    done = remediation.record(
        pushed(retry, finding_ids), provenance(), work_item_id=retry.work_item.work_item_id
    )
    assert done.work_item_id == retry.work_item.work_item_id
    with pytest.raises(ValidationError, match="not for exactly these findings"):
        remediation.record(pushed(retry, finding_ids), provenance(), work_item_id=uuid4())


def test_a_started_order_names_only_a_work_item_of_its_own_repository(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    repository_id, finding_ids, repository_ids = seeded(engine, findings=2)
    other_repository, _, _ = seeded(engine)
    one, two = (pairs(finding_ids[i : i + 1], repository_ids[i : i + 1]) for i in (0, 1))
    first = service.create(fork_of(engine, one), BRANCH, one, PERSON)
    second = service.create(fork_of(engine, two), "fix/second", two, PERSON)
    ops = context.services().ops

    def start(repository: UUID | None, work_item: UUID | None) -> Any:
        return ops.start(
            OrderRequest(
                asset=REMEDIATE_FINDING,
                priority=0,
                repository_id=repository,
                work_item_id=work_item,
            ),
            MACHINE,
            WorkerId("runner"),
            timedelta(minutes=5),
        )

    for repository, work_item in (
        (other_repository, first.work_item.work_item_id),
        (repository_id, uuid4()),
    ):
        with pytest.raises(ValidationError, match="is not a remediation work item"):
            start(repository, work_item)
    # the open order taken over runs the first effort's work item, never another's
    with pytest.raises(ConflictError, match="runs work item"):
        start(repository_id, second.work_item.work_item_id)
    taken = start(repository_id, first.work_item.work_item_id)
    assert (taken.state, taken.work_item_id) == (OrderState.LEASED, first.work_item.work_item_id)


def test_split_verification_reports_together_revalidate_the_effort(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    world = World(engine, findings=2, patched_name="main")
    audited(engine, world, world.base)
    request = pairs(world.ids, [world.repo.id] * len(world.ids))
    scheduled = service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    context.services().remediation.record(
        pushed(scheduled, world.ids, fork__fix_commit=world.patched.sha), provenance()
    )
    verification = context.services().verification
    a, b = world.ids
    verification.record(verification_report(world, {a: "resolved"}), verification_provenance())
    assert folded(service, scheduled) == "checks_passed"  # b not verified yet
    verification.record(verification_report(world, {b: "resolved"}), verification_provenance())
    assert folded(service, scheduled) == "revalidated_fixed"  # a's earlier verdict counts


def test_an_effort_that_is_over_stays_over_once_a_newer_one_covers_its_findings(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    world = World(engine, findings=2, patched_name="main")
    audited(engine, world, world.base)
    request = pairs(world.ids, [world.repo.id] * len(world.ids))
    first = service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    context.services().remediation.record(
        pushed(first, world.ids, fork__fix_commit=world.patched.sha), provenance()
    )
    verification = context.services().verification
    unfixed = verification_report(world, dict.fromkeys(world.ids, "unresolved"))
    verification.record(unfixed, verification_provenance())
    assert folded(service, first) == "revalidated_still_vulnerable"
    newer = service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    assert newer.work_item.work_item_id != first.work_item.work_item_id
    again = service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    assert (
        again.work_item.work_item_id == newer.work_item.work_item_id
    )  # the newer effort is the live one
    verification.record(verification_report(world), verification_provenance())  # late, fixed
    assert folded(service, first) == "revalidated_still_vulnerable"
    assert folded(service, newer) == "candidate"  # its own fix isn't reported yet


def test_opening_a_work_item_that_fails_part_way_leaves_no_assessment(
    context: Context, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository_id, finding_ids, _ = seeded(engine)
    remediation = context.services().remediation
    ref_id = default_ref(engine, repository_id)

    def broken(*_: Any, **__: Any) -> None:
        raise RuntimeError("decisions failed")

    decisions = context.services().findings.decisions
    monkeypatch.setattr(type(decisions), "record_resolution", broken)
    with pytest.raises(RuntimeError, match="decisions failed"):
        remediation.open(finding_ids, ref_id)
    with SqlTraustUnitOfWork(engine) as uow:
        assert [a for a in uow.assessments.list_for_ref(ref_id) if a.kind == "remediation"] == []


def test_a_verification_delivered_late_never_overrides_a_newer_one(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    world = World(engine, findings=2, patched_name="main")
    audited(engine, world, world.base)
    request = pairs(world.ids, [world.repo.id] * len(world.ids))
    scheduled = service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    context.services().remediation.record(
        pushed(scheduled, world.ids, fork__fix_commit=world.patched.sha), provenance()
    )
    verification = context.services().verification
    a, b = world.ids
    earlier, later = VERIFIED_AT, VERIFIED_AT + timedelta(hours=1)
    newer = verification_report(world, {a: "resolved"})
    verification.record(newer, verification_provenance(at=later))
    older = verification_report(world, {a: "unresolved", b: "resolved"})
    verification.record(older, verification_provenance(at=earlier))  # delivered late
    # a's newer fixed verdict stands, and b's (older, but its only one) completes the effort
    assert folded(service, scheduled) == "revalidated_fixed"


def test_a_failed_attempt_never_advances_once_over(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    _, finding_ids, repository_ids = seeded(engine)
    request = pairs(finding_ids, repository_ids)
    first = service.create(fork_of(engine, request), BRANCH, request, PERSON)
    assert first.work_item.work_item_id is not None
    remediation = context.services().remediation
    remediation.record_progress(first.work_item.work_item_id, RemediationStatus("checks_failed"))
    retry = service.create(fork_of(engine, request), BRANCH, request, PERSON)
    for later in ("checks_passed", "pr_opened", "revalidated_fixed"):
        with pytest.raises(ConflictError, match="can't move"):
            remediation.record_progress(first.work_item.work_item_id, RemediationStatus(later))
    again = remediation.record_progress(
        first.work_item.work_item_id, RemediationStatus("checks_failed")
    )
    assert again.status == "checks_failed"  # the same status again is a no-op
    assert (folded(service, first), folded(service, retry)) == (
        "checks_failed",
        "candidate",
    )
    closed = remediation.record_progress(
        first.work_item.work_item_id, RemediationStatus("abandoned")
    )
    assert closed.status == "abandoned"  # an over attempt can still be closed


def test_equal_time_verdicts_go_to_the_later_recorded_never_the_verdict_text(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    world = World(engine, findings=2, patched_name="main")
    audited(engine, world, world.base)
    request = pairs(world.ids, [world.repo.id] * len(world.ids))
    scheduled = service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    context.services().remediation.record(
        pushed(scheduled, world.ids, fork__fix_commit=world.patched.sha), provenance()
    )
    verification = context.services().verification
    a, b = world.ids
    same = verification_provenance(at=VERIFIED_AT)
    for verdicts in ({a: "unresolved"}, {a: "resolved"}, {b: "resolved"}):
        apart()
        verification.record(verification_report(world, verdicts), same.model_copy())
    # a's tie goes to the later recorded "resolved", so b's report completes the effort
    assert folded(service, scheduled) == "revalidated_fixed"


def test_the_orders_door_refuses_fork_facts_it_cannot_vouch_for(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    # fork facts are the scheduling door's to set (ForkPolicy, branch rules); the generic
    # orders door neither carries them for another asset nor half of a pair
    ops = context.services().ops
    with SqlTraustUnitOfWork(engine) as uow:
        item = Seed(uow).assessment(kind="remediation")
        uow.commit()
        assert item.id is not None
    for values in (
        {"asset": "diff_scan", "priority": 0, "fork_url": FORK, "fork_branch": BRANCH},
        # a branch-less pair would steer prepare without binding record's push guard
        {
            "asset": REMEDIATE_FINDING,
            "priority": 0,
            "work_item_id": item.id,
            "fork_url": FORK,
        },
        {
            "asset": REMEDIATE_FINDING,
            "priority": 0,
            "work_item_id": item.id,
            "fork_branch": BRANCH,
        },
        # a whole pair too: only the scheduling door, after its checks, sets fork facts
        {
            "asset": REMEDIATE_FINDING,
            "priority": 0,
            "work_item_id": item.id,
            "fork_url": "https://github.com/attacker/fork",
            "fork_branch": "fix/anything",
        },
    ):
        with pytest.raises(pydantic.ValidationError, match="Extra inputs are not permitted"):
            ops.submit(OrderRequest(**values), PERSON)  # type: ignore[arg-type]


def test_get_answers_not_found_for_what_was_never_scheduled(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    repository_id, finding_ids, _ = seeded(engine)
    remediation = context.services().remediation
    item = remediation.open(finding_ids, default_ref(engine, repository_id))
    with pytest.raises(NotFoundError, match="schedules no remediation"):
        service.get(item.work_item_id)


@pytest.mark.parametrize(
    "fork",
    [
        {"fork_url": "https://github.com/attacker/fork", "fork_branch": "fix/anything"},
        {"fork_branch": "../../etc"},  # the policy's fork, a branch git refuses
    ],
)
def test_fork_facts_scheduling_never_checked_steer_nothing(
    service: RemediationSchedulingService,
    context: Context,
    engine: Engine,
    fork: dict[str, str],
) -> None:
    """Orders from the generic door before it lost its fork fields carry unchecked facts."""
    repository_id, finding_ids, _ = seeded(engine)
    remediation = context.services().remediation
    item = remediation.open(finding_ids, default_ref(engine, repository_id))
    policy = str(remediation.resolve_fork(repository_id).url)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        at = {"asset": "remediate_finding", "state": "queued", "repository_id": repository_id}
        seed.run_order(**at, work_item_id=item.work_item_id)  # bare, older
        apart()
        seed.run_order(**at, work_item_id=item.work_item_id, **{"fork_url": policy, **fork})
        uow.commit()
    with pytest.raises(NotFoundError, match="schedules no remediation"):
        service.get(item.work_item_id)
    assert service.list(PageRequest()).items == ()
    assert remediation.scheduled_order(item.work_item_id) is None
    prepared = remediation.prepare(item.work_item_id)
    assert prepared.fix_branch != fork["fork_branch"]  # the policy's branch, not the order's


def unstamped(engine: Engine, effort: ScheduledEffort) -> None:
    """The effort's order as one from before contracts#130: fork facts without the scheduling
    stamp, so they're checked against the fork policy of the day."""
    with SqlTraustUnitOfWork(engine) as uow:
        order = uow.run_orders.get(effort.order_id)  # type: ignore[arg-type]
        uow.run_orders.update(order.model_copy(update={"fork_scheduled_at": None}))
        uow.commit()


def test_a_stamped_effort_keeps_its_fork_facts_whatever_the_policy_says_since(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    request = pairs(world.ids, [world.repo.id] * len(world.ids))
    scheduled = service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    remediation = context.services().remediation
    order = remediation.scheduled_order(scheduled.work_item.work_item_id)
    assert order is not None and order.fork_scheduled_at is not None
    with SqlTraustUnitOfWork(engine) as uow:  # the policy moves: a private mirror now, and
        Seed(uow).repository(  # the scheduled fork turned public
            url="https://github.com/mirror-org/registered-since",
            upstream_id=world.repo.id,
            public=False,
        )
        Seed(uow).repository(url=str(scheduled.fork_url), public=True)
        uow.commit()
    assert service.get(scheduled.work_item.work_item_id).order_id == scheduled.order_id
    assert [e.order_id for e in service.list(PageRequest()).items] == [scheduled.order_id]
    assert remediation.scheduled_order(scheduled.work_item.work_item_id) == order
    with pytest.raises(ConflictError, match="already schedules these findings"):  # no duplicate
        service.create(
            "https://github.com/mirror-org/registered-since", world.patched.name, request, PERSON
        )


def test_a_stamped_effort_prepares_and_records_on_its_scheduled_fork(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    request = pairs(world.ids, [world.repo.id] * len(world.ids))
    scheduled = service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    with SqlTraustUnitOfWork(engine) as uow:  # the policy moves to a private mirror since
        Seed(uow).repository(
            url="https://github.com/mirror-org/registered-since",
            upstream_id=world.repo.id,
            public=False,
        )
        uow.commit()
    remediation = context.services().remediation
    prepared = remediation.prepare(scheduled.work_item.work_item_id)
    assert (str(prepared.fork.url), prepared.fix_branch) == (
        scheduled.fork_url,
        scheduled.fork_branch,
    )
    recorded = remediation.record(
        pushed(scheduled, world.ids, fork__fix_commit=world.patched.sha), provenance()
    )
    assert recorded.report is not None
    with SqlTraustUnitOfWork(engine) as uow:  # and the scheduled fork turned public: no push
        Seed(uow).repository(url=str(scheduled.fork_url), public=True)
        uow.commit()
    with pytest.raises(ValidationError, match="public repository"):
        remediation.prepare(scheduled.work_item.work_item_id)


def test_a_repository_whose_fork_policy_fails_drops_out_of_the_listing_alone(
    service: RemediationSchedulingService,
    engine: Engine,
    caplog: pytest.LogCaptureFixture,
) -> None:
    efforts = []
    for _ in range(2):
        _, finding_ids, repository_ids = seeded(engine)
        request = pairs(finding_ids, repository_ids)
        efforts.append(service.create(fork_of(engine, request), BRANCH, request, PERSON))
        apart()
    broken, kept = efforts
    unstamped(engine, broken)
    with SqlTraustUnitOfWork(engine) as uow:  # its mirror turned public: no fork for it now
        Seed(uow).repository(
            url=str(broken.fork_url), upstream_id=broken.repository_id, public=True
        )
        uow.commit()
    with caplog.at_level(logging.WARNING, logger="traust_core.v1.services.remediation"):
        listed = service.list(PageRequest()).items
    assert [e.work_item.work_item_id for e in listed] == [kept.work_item.work_item_id]
    assert f"repository {broken.repository_id}: remediation fork unresolved" in caplog.text
    with pytest.raises(NotFoundError, match="schedules no remediation"):
        service.get(broken.work_item.work_item_id)


def test_a_report_on_an_order_scheduling_no_longer_vouches_for_is_refused(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    """Policy changed after the order was leased: its report binds to nothing, so never lands."""
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    request = pairs(world.ids, [world.repo.id] * len(world.ids))
    scheduled = service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    unstamped(engine, scheduled)
    with SqlTraustUnitOfWork(engine) as uow:
        Seed(uow).repository(url=str(scheduled.fork_url), public=True)
        uow.commit()
    elsewhere = pushed(
        scheduled,
        world.ids,
        fork__url="https://github.com/mirror-org/elsewhere",
        fork__fix_branch="fix/elsewhere",
        fork__fix_commit=world.patched.sha,
    )
    with pytest.raises(ValidationError, match="can't vouch for"):
        context.services().remediation.record(elsewhere, provenance())
    assert context.services().remediation.get(scheduled.work_item.work_item_id).report is None


def test_an_attached_report_still_finishes_its_resolution_after_the_policy_changed(
    service: RemediationSchedulingService,
    context: Context,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from traust_core.v1.services.findings.decisions import FindingDecisions

    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    request = pairs(world.ids, [world.repo.id] * len(world.ids))
    scheduled = service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    unstamped(engine, scheduled)
    doc = pushed(scheduled, world.ids, fork__fix_commit=world.patched.sha)
    write = FindingDecisions.record_resolution

    def interrupted(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("connection lost")

    monkeypatch.setattr(FindingDecisions, "record_resolution", interrupted)
    with pytest.raises(RuntimeError):
        context.services().remediation.record(doc, provenance())  # attached, unresolved
    monkeypatch.setattr(FindingDecisions, "record_resolution", write)
    with SqlTraustUnitOfWork(engine) as uow:  # a private mirror registered since: a new fork
        Seed(uow).repository(
            url="https://github.com/mirror-org/registered-since",
            upstream_id=world.repo.id,
            public=False,
        )
        uow.commit()
    remediation = context.services().remediation
    assert remediation.scheduled_order(scheduled.work_item.work_item_id) is None
    finished = remediation.record(doc, provenance())
    assert finished.report is not None and finished.status == "checks_passed"


def test_the_listing_follows_its_cursor_page_after_page(
    service: RemediationSchedulingService, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_core.v1.services import remediation_scheduling

    monkeypatch.setattr(remediation_scheduling, "_BATCH", 2)  # several rounds per page
    _, finding_ids, repository_ids = seeded(engine, findings=5)
    made = []
    for finding_id, repository_id in zip(finding_ids, repository_ids, strict=True):
        request = pairs([finding_id], [repository_id])
        made.append(service.create(fork_of(engine, request), BRANCH, request, PERSON))
        apart()
    seen, cursor = [], None
    while True:
        page = service.list(PageRequest(limit=2, cursor=cursor))
        seen += [e.work_item.work_item_id for e in page.items]
        if page.next is None:
            break
        cursor = page.next
    assert seen == [e.work_item.work_item_id for e in made]  # every effort once, in order


def test_create_and_the_reads_agree_on_a_failed_attempt_later_verified_fixed(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    request = pairs(world.ids, [world.repo.id] * len(world.ids))
    scheduled = service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    context.services().remediation.record(
        pushed(
            scheduled,
            world.ids,
            fork__fix_commit=world.patched.sha,
            summary__status="checks_failed",
        ),
        provenance(),
    )
    assert folded(service, scheduled) == "checks_failed"
    context.services().verification.record(verification_report(world), verification_provenance())
    assert folded(service, scheduled) == "revalidated_fixed"
    (listed,) = service.list(PageRequest()).items
    assert listed.status == "revalidated_fixed"
    with pytest.raises(ValidationError, match="closed"):  # no retry beside a fixed effort
        service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    assert [e.work_item.work_item_id for e in service.list(PageRequest()).items] == [
        scheduled.work_item.work_item_id
    ]


def test_a_listing_reads_each_repositorys_history_once_across_batches(
    service: RemediationSchedulingService, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_core.v1.services import remediation_scheduling
    from traust_core.v1.services.remediation import RemediationService

    monkeypatch.setattr(remediation_scheduling, "_BATCH", 1)
    _, finding_ids, repository_ids = seeded(engine, findings=3)
    for finding_id, repository_id in zip(finding_ids, repository_ids, strict=True):
        request = pairs([finding_id], [repository_id])
        service.create(fork_of(engine, request), BRANCH, request, PERSON)
        apart()
    reads: list[UUID] = []
    items_of = RemediationService.items_of
    monkeypatch.setattr(
        RemediationService,
        "items_of",
        lambda self, repository_id: reads.append(repository_id) or items_of(self, repository_id),
    )
    # a sparse filter: every batch is read, none matches
    assert service.list(PageRequest(), status=RemediationStatus("merged")).items == ()
    assert reads == [repository_ids[0]]


def test_the_listing_shows_a_work_item_once_at_the_order_get_reads(
    service: RemediationSchedulingService,
    context: Context,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from traust_core.v1.services import remediation_scheduling

    monkeypatch.setattr(remediation_scheduling, "_BATCH", 1)  # the two orders in two batches
    repository_id, finding_ids, repository_ids = seeded(engine)
    request = pairs(finding_ids, repository_ids)
    scheduled = service.create(fork_of(engine, request), BRANCH, request, PERSON)
    apart()
    context.services().ops.schedule_fix(
        OrderRequest(
            asset=REMEDIATE_FINDING,
            priority=0,
            repository_id=repository_id,
            work_item_id=scheduled.work_item.work_item_id,
        ),
        PERSON,
        "https://github.com/mirror-org/elsewhere",
        "fix/elsewhere",
    )
    seen = []
    cursor = None
    while True:
        page = service.list(PageRequest(limit=1, cursor=cursor))
        seen += page.items
        if page.next is None:
            break
        cursor = page.next
    assert [e.order_id for e in seen] == [service.get(scheduled.work_item.work_item_id).order_id]
    assert seen[0].fork_url == scheduled.fork_url


def test_schedule_fix_sets_fork_facts_only_on_a_work_items_remediation_order(
    context: Context,
) -> None:
    with pytest.raises(ValidationError, match="fork facts ride only a remediate_finding order"):
        context.services().ops.schedule_fix(
            OrderRequest(asset=REMEDIATE_FINDING, priority=0), PERSON, "https://x.test/a", "fix/a"
        )


def test_a_verification_recorded_before_the_effort_was_scheduled_never_revalidates_it(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    context.services().verification.record(
        verification_report(world, dict.fromkeys(world.ids, "unresolved")),
        verification_provenance(),
    )  # an older check of the same branch and commit
    apart()
    request = pairs(world.ids, [world.repo.id] * len(world.ids))
    scheduled = service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    context.services().remediation.record(
        pushed(scheduled, world.ids, fork__fix_commit=world.patched.sha), provenance()
    )
    assert folded(service, scheduled) == "checks_passed"  # not that earlier check's verdict


def test_a_verification_recorded_before_a_late_report_still_revalidates_the_fix(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    request = pairs(world.ids, [world.repo.id] * len(world.ids))
    scheduled = service.create(fork_of(engine, request), world.patched.name, request, PERSON)
    apart()
    context.services().verification.record(verification_report(world), verification_provenance())
    apart()
    context.services().remediation.record(
        pushed(scheduled, world.ids, fork__fix_commit=world.patched.sha), provenance()
    )
    assert folded(service, scheduled) == "revalidated_fixed"


def test_tied_verifications_break_by_id_never_by_verdict() -> None:
    from datetime import UTC, datetime

    from traust_core.v1.models.assessment import Assessment
    from traust_core.v1.services.remediation import _verdict_order

    at = datetime(2026, 11, 6, tzinfo=UTC)
    a, b = (
        Assessment(
            id=uuid4(),
            created_at=at,
            repository_ref_id=uuid4(),
            kind="verification",
            status="completed",
            assessor="skill:verify",
            assessor_version="1",
            occurred_at=at,
        )
        for _ in range(2)
    )
    assert _verdict_order(a) != _verdict_order(b)  # same times: the id breaks the tie
    assert (_verdict_order(a) < _verdict_order(b)) == (a.id < b.id)  # type: ignore[operator]
