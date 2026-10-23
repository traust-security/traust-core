from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from traust_core.v1.models.base import Model
from traust_core.v1.models.common import ArtifactRef
from traust_core.v1.models.findings import SkillInput
from traust_core.v1.models.inventory import OrgName
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import (
    CrossRepoPropagation,
    FixStrategy,
    FleetFixMatcherKind,
    ForkHost,
    ForkVisibility,
    PatchEvidenceKind,
    RemediationEffort,
    RemediationStatus,
    VerificationVerdict,
)


class EvidenceStatus(StrEnum):
    ATTEMPTED = "attempted"
    REFUSED = "refused"
    NOT_ATTEMPTED = "not_attempted"


# Shapes land with their implementation slice.
class ExternalRef(Model):
    """A thing in another system: a merge request, a commit or a ticket, by URL or key."""

    system: str
    ref: str


class FleetFixSpec(Model): ...


class FleetTarget(Model): ...


class PatchResult(Model): ...


class PropagationEvidence(Model): ...


class WorkItemFilter(Model): ...


class VerificationFilter(Model): ...


class RemediationInput(SkillInput): ...


class VerificationInput(SkillInput): ...


class FleetFixMatcher(Model):
    kind: FleetFixMatcherKind


class EvidenceItem(Model):
    kind: PatchEvidenceKind
    status: EvidenceStatus
    artifact: ArtifactRef | None = None
    reason: str | None = None

    @classmethod
    def not_attempted(cls, kind: PatchEvidenceKind, reason: str) -> EvidenceItem:
        raise NotImplementedError("stub: replaces the 3 duplicated _not_attempted helpers")


class Fork(Model):
    host: ForkHost
    owner: OrgName
    url: HttpsRepoUrl
    visibility: ForkVisibility


class WorkItem(Model):
    finding_ids: tuple[UUID, ...]
    component_id: UUID
    status: RemediationStatus
    strategy: FixStrategy | None = None
    fork: Fork | None = None
    effort: RemediationEffort | None = None
    tracker: ExternalRef | None = None
    evidence: tuple[EvidenceItem, ...] = ()

    def advance(self, status: RemediationStatus) -> WorkItem:
        raise NotImplementedError("stub: replaces update_remediation_progress.py")

    def is_done(self) -> bool:
        raise NotImplementedError("stub: replaces next_pending_remediation.is_done")


class FleetFix(Model):
    matcher: FleetFixMatcher
    spec: FleetFixSpec
    target_ids: tuple[UUID, ...] = ()
    approval_id: UUID | None = None


class Verification(Model):
    work_item_id: UUID
    repository_ref_id: UUID
    verdict: VerificationVerdict
    regression_ids: tuple[UUID, ...] = ()
    artifact: ArtifactRef


class Propagation(Model):
    work_item_id: UUID
    component_id: UUID
    status: CrossRepoPropagation
    evidence: tuple[PropagationEvidence, ...] = ()
