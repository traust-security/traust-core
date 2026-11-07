"""Scheduling remediation: the door that starts the pipeline (SCI's trigger, the console's
button). One call opens the work item (candidate decisions, one per finding) and submits the
order that runs the fix, carrying the fork facts — nothing before it started remediation
alone. There is no scheduling table (contracts#117): the effort is the work item, its status
folded from its decisions; the fork facts ride the order until the run's report records them;
a verification's verdicts fold back at read (VerificationService.revalidated_verdicts)."""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from typing import TYPE_CHECKING
from uuid import UUID

from traust_core.v1.errors import ConflictError, NotFoundError, ValidationError
from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.operations import REMEDIATE_FINDING, OrderRequest
from traust_core.v1.models.remediation import OVER, WorkItem, furthest
from traust_core.v1.models.remediation_scheduling import (
    RemediationFindingRequest,
    ScheduledEffort,
)
from traust_core.v1.models.vocabulary import RemediationStatus
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.findings.service import FindingService
from traust_core.v1.services.portfolio import Inventory
from traust_core.v1.services.remediation import RemediationService, VerificationService

if TYPE_CHECKING:
    from traust_core.v1.services.operations import OpsService

log = logging.getLogger(__name__)

# The two revalidated verdicts rank alike: between them, the latest verification wins.
_REVALIDATED = frozenset({"revalidated_fixed", "revalidated_still_vulnerable"})
# A scheduled fix is asked for now, like onboarding's baseline orders.
_ASKED_NOW = 0
# The remediation report's `fork.fix_branch` (traust-contracts remediation schema): a branch
# scheduled here becomes that field, so it must pass it as well as git's rules.
_FIX_BRANCH = re.compile(r"[A-Za-z0-9._/-]{1,200}")


class RemediationSchedulingService:
    def __init__(
        self,
        uow: TraustUnitOfWork,
        findings: FindingService,
        remediation: RemediationService,
        verification: VerificationService,
        ops: OpsService,
    ) -> None:
        self._uow = uow
        self._inventory = Inventory(uow)
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
        public repository). Scheduling the same findings again returns the live effort covering
        them; another target for them, or an overlap, is a conflict."""
        wanted = tuple(dict.fromkeys((f.finding_id, f.repository_id) for f in findings))
        if not wanted:
            raise ValidationError("a remediation needs at least one finding")
        _branch(fork_branch)
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
            fork = self._remediation.resolve_fork(repository_id)
            if fork_url.rstrip("/").removesuffix(".git") != str(fork.url):
                raise ValidationError(
                    f"fork_url must be the repository's remediation fork, {fork.url}"
                )
            if (
                existing := self._live(finding_ids, repository_id, str(fork.url), fork_branch)
            ) is not None:
                return existing
            patch = self._patch_ref(repository_id)
            assert patch.id is not None
            item = self._remediation.open(list(finding_ids), patch.id)
            # the order names the work item it runs and carries the fork facts: the runner
            # prepares that one, never the repository's oldest pending item, and reads where
            # the fix lives off the order it claims
            order = self._ops.submit(
                OrderRequest(
                    asset=REMEDIATE_FINDING,
                    priority=_ASKED_NOW,
                    repository_id=repository_id,
                    work_item_id=item.work_item_id,
                    fork_url=str(fork.url),
                    fork_branch=fork_branch,
                ),
                principal,
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
            fork_url=str(fork.url),
            fork_branch=fork_branch,
            status=item.status,
            order_id=order.id,
        )

    def get(self, work_item_id: UUID) -> ScheduledEffort:
        """One scheduled effort: its work item (the effort itself) and the fork facts of the
        order that runs it."""
        item = self._remediation.get(work_item_id)
        order = self._ops.order_for_work_item(work_item_id)
        if order is None or order.fork_url is None or order.fork_branch is None:
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
        """Scheduled efforts, oldest first, a page at a time: at a status (its effective one —
        the work item's, or its revalidation verdict), on a repository, on a finding (every
        filter given applies)."""
        after = page.position()
        efforts = [
            e
            for e, _ in self._efforts(repository_id)
            if (status is None or e.status == status)
            and (finding_id is None or finding_id in e.work_item.finding_ids)
            and (
                after is None
                or (e.work_item.opened_at, str(e.work_item.work_item_id))
                > (after[0], str(after[1]))
            )
        ]
        return Page.of(
            efforts[: page.limit + 1],
            page.limit,
            lambda e: (e.work_item.opened_at, e.work_item.work_item_id),
        )

    def _efforts(self, repository_id: UUID | None) -> list[tuple[ScheduledEffort, UUID | None]]:
        """Every scheduled effort, oldest first: the orders that run one, each with its work
        item and its effective status folded (an item whose findings were never recorded — a
        run that stopped between open()'s commits — is nothing to work on, not an error). One
        order per work item — the oldest's, the one that scheduled it: a second order for the
        same work item is not a second effort."""
        orders = sorted(
            self._ops.work_item_orders(REMEDIATE_FINDING, repository_id),
            key=lambda o: (o.created_at, o.id),
        )
        items = {
            i.work_item_id: i
            for i in self._remediation.items_for({o.work_item_id for o in orders if o.work_item_id})
        }
        made: list[tuple[ScheduledEffort, UUID | None]] = []
        seen: set[UUID] = set()
        for order in orders:
            if order.work_item_id is None or order.work_item_id in seen:
                continue
            if (item := items.get(order.work_item_id)) is None:
                continue
            if order.fork_url is None or order.fork_branch is None:
                continue  # an order that names no fork runs no scheduled fix
            seen.add(order.work_item_id)
            # A work-item order's repository is never null (the pairing trigger); the
            # effort carries it so consumers that did not ask by repository read no ref.
            assert order.repository_id is not None
            made.append(
                (
                    ScheduledEffort(
                        work_item=item,
                        repository_id=order.repository_id,
                        fork_url=order.fork_url,
                        fork_branch=order.fork_branch,
                        status=item.status,
                        order_id=order.id,
                    ),
                    order.repository_id,
                )
            )
        # one covering fold per repository, shared by its efforts (their newer-effort check)
        covering: dict[UUID, list[WorkItem]] = {}
        for repository in {repo for _, repo in made if repo is not None}:
            wanted = {
                f
                for effort, repo in made
                if repo == repository
                for f in effort.work_item.finding_ids
            }
            covering[repository] = self._remediation.covering(repository, wanted)
        efforts = [
            (
                effort.model_copy(
                    update={"status": self._status(effort, repository, covering[repository])}
                ),
                repository,
            )
            if repository is not None
            else (effort, repository)
            for effort, repository in made
        ]
        return sorted(
            efforts, key=lambda e: (e[0].work_item.opened_at, e[0].work_item.work_item_id)
        )

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
        for verdict in self._verification.revalidated_verdicts(item, effort.fork_branch):
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
            order = self._ops.order_for_work_item(item.work_item_id)
            if (
                order is None or order.fork_url is None or order.fork_branch is None
            ):  # a manually opened work item, or one no order ever ran: not a scheduled effort
                continue
            effort = ScheduledEffort(
                work_item=item,
                repository_id=repository_id,
                fork_url=order.fork_url,
                fork_branch=order.fork_branch,
                status=item.status,
                order_id=order.id,
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
        """The commit the work item patches: the repository's default line."""
        ref = self._inventory.default_line(repository_id)
        if ref is None:
            raise ValidationError(
                f"repository {repository_id} has no single default ref: a fix needs the "
                "commit to patch"
            )
        return ref


def _branch(name: str) -> None:
    """Reject what `git check-ref-format --branch` rejects, and what the remediation report's
    `fork.fix_branch` pattern does."""
    parts = name.split("/")
    bad = (
        not _FIX_BRANCH.fullmatch(name)
        or name == "@"
        or name.startswith("-")
        or ".." in name
        or name.endswith(".")
        # per component: not empty (no leading, trailing or doubled /), no leading dot,
        # no .lock ending
        or any(not p or p.startswith(".") or p.endswith(".lock") for p in parts)
    )
    if bad:
        raise ValidationError(f"fork_branch is not a branch name: {name!r}")
