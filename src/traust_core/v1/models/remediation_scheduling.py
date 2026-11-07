"""Scheduling remediation: the door's shapes. An effort is a work item (a `remediation`
assessment, its status folded from its decisions) plus the order that runs it, which carries
the fork facts; there is no scheduling table (contracts#117)."""

from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.base import Model
from traust_core.v1.models.remediation import WorkItem
from traust_core.v1.models.vocabulary import RemediationStatus


class RemediationFindingRequest(Model):
    """A finding to schedule, named with the repository it belongs to."""

    finding_id: UUID
    repository_id: UUID


class RemediationRequest(Model):
    """What the scheduling door takes: the fork the fix lands on and the findings to fix."""

    fork_url: str
    fork_branch: str
    findings: tuple[RemediationFindingRequest, ...]


class ScheduledEffort(Model):
    """One scheduled remediation effort: the work item (the effort itself — its findings, its
    report once recorded) and the fork facts of the order that runs it, with the effort's
    effective status — the work item's, or past it a verification's verdict on its fix. The
    handle is `work_item.work_item_id`.

    `repository_id` names the repository the effort's findings belong to (the order's, which
    the work-item pairing keeps equal to the work item's commit): consumers that did not ask
    by repository — the engine's feed-driven trigger, the console's unfiltered lists — read
    it here instead of resolving the work item's ref."""

    work_item: WorkItem
    repository_id: UUID
    fork_url: str
    fork_branch: str
    status: RemediationStatus
    order_id: UUID | None = None
