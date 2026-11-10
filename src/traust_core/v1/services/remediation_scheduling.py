"""Scheduling remediation: the door that starts the pipeline (SCI's trigger, the console's
button) and the state reports consumers plan work off (the engine's trigger). One call opens
the work item (candidate decisions, one per finding) and submits the order that runs the fix,
carrying the fork facts — nothing before it started remediation alone. There is no scheduling
table (contracts#117): the effort is the work item, its status folded from its decisions; the
fork facts ride the order until the run's report records them; a verification's verdicts fold
back at read (VerificationService.revalidated_verdicts)."""

from __future__ import annotations

import logging
from collections.abc import Collection, Sequence
from typing import TYPE_CHECKING
from uuid import UUID

from traust_core.v1.errors import ConflictError, NotFoundError, ValidationError
from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.operations import REMEDIATE_FINDING, OrderRequest, RunOrder
from traust_core.v1.models.remediation import OVER, Fork, WorkItem, furthest
from traust_core.v1.models.remediation_scheduling import (
    RemediationFindingRequest,
    RemediationState,
    ScheduledEffort,
)
from traust_core.v1.models.vocabulary import RemediationStatus
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.findings.service import FindingService
from traust_core.v1.services.portfolio import Inventory, PortfolioService
from traust_core.v1.services.remediation import (
    RemediationService,
    VerificationService,
    check_fix_branch,
)

if TYPE_CHECKING:
    from datetime import datetime

    from traust_core.v1.services.operations import OpsService

log = logging.getLogger(__name__)

# The two revalidated verdicts rank alike: between them, the latest verification wins.
_REVALIDATED = frozenset({"revalidated_fixed", "revalidated_still_vulnerable"})
# Orders read per listing round: a page folds batches until it is full, never all history.
_BATCH = 200
# A scheduled fix is asked for now, like onboarding's baseline orders.
_ASKED_NOW = 0


class RemediationSchedulingService:
    def __init__(
        self,
        uow: TraustUnitOfWork,
        findings: FindingService,
        remediation: RemediationService,
        verification: VerificationService,
        ops: OpsService,
        portfolio: PortfolioService,
    ) -> None:
        self._uow = uow
        self._inventory = Inventory(uow)
        self._portfolio = portfolio
        self._findings = findings
        self._remediation = remediation
        self._verification = verification
        self._ops = ops

    def create(
        self,
        fork_url: str,
        fork_branch: str,
        findings: Sequence[RemediationFindingRequest],
        principal: Principal,
    ) -> ScheduledEffort:
        """Schedule one remediation effort: the work item it opens (candidate decisions, one
        per finding) and the order that runs the fix, carrying the fork facts — one
        transaction. The fork must be the repository's remediation fork (`ForkPolicy`: never a
        public repository; with no registered mirror, any of the sci-patch convention's
        candidates — the provisioner's plain name or its collision fallback). Scheduling the
        same findings again returns the live effort covering them; another target for them, or
        an overlap, is a conflict."""
        wanted = tuple(dict.fromkeys((f.finding_id, f.repository_id) for f in findings))
        if not wanted:
            raise ValidationError("a remediation needs at least one finding")
        check_fix_branch(fork_branch)
        finding_ids = {f for f, _ in wanted}
        with self._uow.write():
            # a second request for any of these findings waits here, then finds this effort
            self._findings.lock_findings(finding_ids)
            views = {v.finding.id: v for v in self._findings.list_by_ids(list(finding_ids))}
            for finding_id, repository_id in wanted:
                view = views[finding_id]
                if view.finding.repository_id != repository_id:
                    raise ValidationError(
                        f"finding {finding_id} is not in repository {repository_id}"
                    )
                if not view.is_open():
                    raise ValidationError(f"finding {finding_id} is closed")
            repositories = {v.finding.repository_id for v in views.values()}
            if len(repositories) != 1:
                # a fork branches from one upstream: the effort patches that repository
                listed = ", ".join(sorted(map(str, repositories)))
                raise ValidationError(
                    f"a remediation schedules one repository's findings, not {listed}"
                )
            (repository_id,) = repositories
            self._ops.authorize_request(REMEDIATE_FINDING, repository_id, principal)
            forks = self._remediation.resolve_forks(repository_id)
            target = fork_url.rstrip("/").removesuffix(".git")
            if target not in {str(f.url) for f in forks}:
                listed = " or ".join(str(f.url) for f in forks)
                raise ValidationError(
                    f"fork_url must be the repository's remediation fork, {listed}"
                )
            # the chosen target only: a public occupant of the plain name is exactly when
            # the provisioner falls back to the owner-qualified candidate
            self._remediation.refuse_public(target)
            if (
                existing := self._live(finding_ids, repository_id, target, fork_branch)
            ) is not None:
                return existing
            patch = self._patch_ref(repository_id)
            assert patch.id is not None
            item = self._remediation.open(list(finding_ids), patch.id)
            # the order names the work item it runs and carries the fork facts: the runner
            # prepares that one, never the repository's oldest pending item, and reads where
            # the fix lives off the order it claims
            order = self._ops.schedule_fix(
                OrderRequest(
                    asset=REMEDIATE_FINDING,
                    priority=_ASKED_NOW,
                    repository_id=repository_id,
                    work_item_id=item.work_item_id,
                ),
                principal,
                target,
                fork_branch,
            )
            self._uow.commit()
        self._uow.after_commit(
            lambda: log.info(
                "work item %s scheduled for %d findings, order %s",
                item.work_item_id,
                len(wanted),
                order.id,
            )
        )
        return ScheduledEffort(
            work_item=item,
            repository_id=repository_id,
            fork_url=target,
            fork_branch=fork_branch,
            status=item.status,
            order_id=order.id,
            scheduled_at=order.created_at,
        )

    def get(self, work_item_id: UUID) -> ScheduledEffort:
        """One scheduled effort: its work item (the effort itself) and the fork facts of the
        order that runs it."""
        item = self._remediation.get(work_item_id)
        order = self._remediation.scheduled_order(work_item_id)
        if order is None:
            raise NotFoundError(f"work item {work_item_id} schedules no remediation")
        # A work-item order's repository is never null: the pairing trigger holds it to the
        # work item's commit's repository (contracts#117's run_order_work_item_of_repository).
        assert order.repository_id is not None
        effort = ScheduledEffort(
            work_item=item,
            repository_id=order.repository_id,
            fork_url=order.fork_url,
            fork_branch=order.fork_branch,
            status=item.status,
            order_id=order.id,
            scheduled_at=order.created_at,
        )
        return effort.model_copy(update={"status": self._status(effort, order.repository_id)})

    def list(
        self,
        page: PageRequest,
        *,
        status: RemediationStatus | None = None,
        repository_id: UUID | None = None,
        finding_id: UUID | None = None,
    ) -> Page[ScheduledEffort]:
        """Scheduled efforts in the order they were scheduled, a page at a time: at a status (its
        effective one — the work item's, or its revalidation verdict), on a repository, on a
        finding (every filter given applies). Orders are read and folded in bounded batches
        until the page is full, never the whole history."""
        after = page.position()
        found: list[ScheduledEffort] = []
        history: dict[UUID, list[WorkItem]] = {}  # each repository folded once per listing
        forks: dict[UUID, Fork | None] = {}
        while len(found) <= page.limit:
            orders = self._ops.orders_after(REMEDIATE_FINDING, repository_id, after, _BATCH)
            found += [
                e
                for e in self._efforts(orders, history, forks)
                if (status is None or e.status == status)
                and (finding_id is None or finding_id in e.work_item.finding_ids)
            ]
            if len(orders) < _BATCH:
                break
            after = (orders[-1].created_at, orders[-1].id)  # type: ignore[assignment]
        return Page.of(
            found[: page.limit + 1],
            page.limit,
            lambda e: (e.scheduled_at, e.order_id),
        )

    def state_of(self, work_item_id: UUID) -> RemediationState | None:
        """One effort's state report; None when the work item schedules no effort, or a newer
        effort over the same findings superseded its still-vulnerable one."""
        try:
            effort = self.get(work_item_id)
        except NotFoundError:
            return None
        lineage = self._lineage(effort)
        mine = next(i for i, e in enumerate(lineage) if e.work_item.work_item_id == work_item_id)
        if (
            effort.status == RemediationStatus.REVALIDATED_STILL_VULNERABLE
            and mine != len(lineage) - 1
        ):
            return None
        return self._state(effort, lineage[:mine])

    def states_of(self, repository_id: UUID) -> list[RemediationState]:
        """The repository's efforts as state reports, one per lineage: the newest effort over
        a finding set reports for it with the lineage's over attempts as its `reattempts`;
        an over attempt a newer one over the same findings supersedes is not reported."""
        lineages: dict[frozenset[UUID], list[ScheduledEffort]] = {}
        history: dict[UUID, list[WorkItem]] = {}
        forks: dict[UUID, Fork | None] = {}
        after: tuple[datetime, UUID] | None = None
        while True:
            orders = self._ops.orders_after(REMEDIATE_FINDING, repository_id, after, _BATCH)
            for effort in self._efforts(orders, history, forks):
                lineages.setdefault(frozenset(effort.work_item.finding_ids), []).append(effort)
            if len(orders) < _BATCH:
                break
            after = (orders[-1].created_at, orders[-1].id)  # type: ignore[assignment]
        # Orders stamp one value per statement (milliseconds on SQLite), so a door-separated
        # retry can share its prior's stamp with an adverse id: members fold by lineage
        # chronology instead — over attempts before the live one, then attempt creation — so
        # a tie never chooses the head (qodo #400: a rapid retry once reported its prior).
        for efforts in lineages.values():
            efforts.sort(key=_created)
        return [self._state(efforts[-1], efforts[:-1]) for efforts in lineages.values()]

    def _lineage(self, effort: ScheduledEffort) -> list[ScheduledEffort]:
        # the efforts over the effort's finding set, in scheduling order: the keyed read
        # folds one lineage, never the repository
        wanted = set(effort.work_item.finding_ids)
        covering = self._remediation.covering(effort.repository_id, wanted)
        members = [item for item in covering if set(item.finding_ids) == wanted]
        orders = self._ops.scheduling_orders({i.work_item_id for i in members})
        forks: dict[UUID, Fork | None] = {}
        made: list[ScheduledEffort] = []
        for item in members:
            order = orders.get(item.work_item_id)
            if order is None or not self._remediation.vouched(order, forks):
                continue  # opened by hand, or by no order scheduling vouches for
            assert order.repository_id is not None
            assert order.fork_url is not None and order.fork_branch is not None
            member = ScheduledEffort(
                work_item=item,
                repository_id=order.repository_id,
                fork_url=order.fork_url,
                fork_branch=order.fork_branch,
                status=item.status,
                order_id=order.id,
                scheduled_at=order.created_at,
            )
            made.append(
                member.model_copy(
                    update={"status": self._status(member, order.repository_id, covering)}
                )
            )
        return sorted(made, key=_created)

    def _state(
        self, effort: ScheduledEffort, priors: Collection[ScheduledEffort]
    ) -> RemediationState:
        return RemediationState(
            work_item_id=effort.work_item.work_item_id,
            repository_id=effort.repository_id,
            status=effort.status,
            reattempts=sum(1 for other in priors if other.status in OVER),
        )

    def _efforts(
        self,
        orders: Sequence[RunOrder],
        history: dict[UUID, list[WorkItem]],
        forks: dict[UUID, Fork | None],
    ) -> list[ScheduledEffort]:
        """The efforts a batch of orders schedules, in their order: each work item once, at the
        order `get` reads for it (the oldest carrying both fork facts — an order naming no fork
        runs no scheduled fix), with its effective status folded over the repository's work
        items, read once per listing into `history`."""
        named = {o.work_item_id for o in orders if o.work_item_id}
        items = {i.work_item_id: i for i in self._remediation.items_for(named)}
        scheduling = self._ops.scheduling_orders(named)
        made: list[ScheduledEffort] = []
        for order in orders:
            item = None if order.work_item_id is None else items.get(order.work_item_id)
            chosen = None if item is None else scheduling.get(item.work_item_id)
            if item is None or chosen is None or chosen.id != order.id:
                continue
            # A work-item order's repository is never null (contracts#117's pairing trigger).
            assert order.repository_id is not None
            if not self._remediation.vouched(order, forks):
                continue
            assert order.fork_url is not None and order.fork_branch is not None
            made.append(
                ScheduledEffort(
                    work_item=item,
                    repository_id=order.repository_id,
                    fork_url=order.fork_url,
                    fork_branch=order.fork_branch,
                    status=item.status,
                    order_id=order.id,
                    scheduled_at=order.created_at,
                )
            )
        for repository in {e.repository_id for e in made} - history.keys():
            history[repository] = self._remediation.items_of(repository)
        return [
            e.model_copy(
                update={"status": self._status(e, e.repository_id, history[e.repository_id])}
            )
            for e in made
        ]

    def _status(
        self,
        effort: ScheduledEffort,
        repository_id: UUID,
        candidates: list[WorkItem] | None = None,
    ) -> RemediationStatus:
        """The effort's effective status: its work item's, then each verification's verdict on
        its fix as it happened — the two revalidated verdicts rank alike, so the latest
        verification wins between them; otherwise the furthest, never stepping back. An effort
        that is over stays over once a newer one covers any of its findings."""
        item = effort.work_item
        others = (
            candidates
            if candidates is not None
            else self._remediation.covering(repository_id, item.finding_ids)
        )
        newer = any(
            other.opened_at > item.opened_at
            and other.work_item_id != item.work_item_id
            and set(other.finding_ids).intersection(item.finding_ids)
            for other in others
        )
        standing = item.status
        for verdict in self._verification.revalidated_verdicts(
            item, effort.fork_branch, effort.scheduled_at
        ):
            if standing in OVER and newer:
                break
            standing = (
                verdict if {standing, verdict} <= _REVALIDATED else furthest((standing, verdict))
            )
        return standing

    def _live(
        self, finding_ids: set[UUID], repository_id: UUID, fork_url: str, fork_branch: str
    ) -> ScheduledEffort | None:
        """The live effort covering exactly these findings for this target (a retry, a report
        recorded since); the same findings for another target, or an overlap, conflict."""
        covering = self._remediation.covering(repository_id, finding_ids)
        # the newer-effort check shares this one repository fold across the candidates
        candidates = self._remediation.covering(
            repository_id, {f for item in covering for f in item.finding_ids}
        )
        for item in covering:
            order = self._remediation.scheduled_order(item.work_item_id)
            if order is None:  # opened by hand, or by no order scheduling vouches for
                continue
            assert order.fork_url is not None and order.fork_branch is not None
            effort = ScheduledEffort(
                work_item=item,
                repository_id=repository_id,
                fork_url=order.fork_url,
                fork_branch=order.fork_branch,
                status=item.status,
                order_id=order.id,
                scheduled_at=order.created_at,
            )
            effective = self._status(effort, repository_id, candidates)
            if effective in OVER:
                continue
            if set(item.finding_ids) != finding_ids:
                listed = ", ".join(sorted(map(str, set(item.finding_ids) & finding_ids)))
                raise ConflictError(f"work item {item.work_item_id} already covers {listed}")
            if (order.fork_url, order.fork_branch) != (fork_url, fork_branch):
                raise ConflictError(
                    f"work item {item.work_item_id} already schedules these findings on "
                    f"{order.fork_url} {order.fork_branch}"
                )
            return effort.model_copy(update={"status": effective})
        return None

    def _patch_ref(self, repository_id: UUID) -> RepositoryRef:
        """The commit the work item patches: the default branch's current head."""
        ref = self._portfolio.current_default_ref(repository_id)
        if ref is None:
            raise ValidationError(
                f"repository {repository_id} has no single default ref: a fix needs the "
                "commit to patch"
            )
        return ref


def _created(effort: ScheduledEffort) -> tuple[bool, datetime, UUID | None]:
    """One effort's place in its lineage's chronology: an over attempt before every live one
    (the door opens no attempt over findings a live effort covers, so a lineage's live
    attempt is its head), then attempt creation — the work item's opening, the order's id
    breaking ties: an order's statement stamp never chooses the lineage's head."""
    return (effort.status not in OVER, effort.work_item.opened_at, effort.order_id)
