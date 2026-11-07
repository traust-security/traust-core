"""RemediationSchedulingService over SQLite and Postgres: the door that starts the pipeline,
and the status sync that keeps the remediation row beside the decisions that move it."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pydantic
import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed, apart
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
    WorkerId,
)
from traust_core.v1.models.remediation_scheduling import (
    RemediationFindingRequest,
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
    """The repository's remediation fork under PRIVATE (ForkPolicy: the fork org's mirror)."""
    if not request:  # refused before any fork is resolved
        return "https://github.com/mirror-org/none"
    with SqlTraustUnitOfWork(engine) as uow:
        url = uow.repositories.get(request[0].repository_id).url
    return f"https://github.com/mirror-org/{url.rsplit('/', 1)[-1]}"


def folded(service: RemediationSchedulingService, effort: ScheduledEffort) -> RemediationStatus:
    """The effort's effective status, folded from its decisions and the verification verdicts
    on its fix (what the removed scheduled row's status sync kept)."""
    return service.get(effort.work_item.work_item_id).status


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
    second = service.create(
        fork_of(engine, pairs(finding_ids[1:], repository_ids[1:])),
        BRANCH,
        pairs(finding_ids[1:], repository_ids[1:]),
        PERSON,
    )
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
    # never a public repository: the fork is the policy's (the fork org's private mirror),
    # not whatever the caller names, the upstream itself included
    _, finding_ids, repository_ids = seeded(engine)
    request = pairs(finding_ids, repository_ids)
    with SqlTraustUnitOfWork(engine) as uow:
        upstream = uow.repositories.get(repository_ids[0]).url
    for fork in (
        upstream,
        "https://github.com/someone-else/public-copy",
        "https://forge.example.net/o/r",
    ):
        with pytest.raises(ValidationError, match="remediation fork"):
            service.create(fork, BRANCH, request, PERSON)
    assert list(service.list(PageRequest()).items) == []


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
    ):
        with pytest.raises(pydantic.ValidationError, match="together"):
            ops.submit(OrderRequest(**values), PERSON)  # type: ignore[arg-type]


def test_get_answers_not_found_for_what_was_never_scheduled(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    repository_id, finding_ids, _ = seeded(engine)
    remediation = context.services().remediation
    item = remediation.open(finding_ids, default_ref(engine, repository_id))
    with pytest.raises(NotFoundError, match="schedules no remediation"):
        service.get(item.work_item_id)
