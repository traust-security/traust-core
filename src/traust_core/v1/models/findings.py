from __future__ import annotations

from collections.abc import Mapping
from uuid import UUID

from traust_core.v1.models.base import Entity, Model
from traust_core.v1.models.integrity import Fingerprint


class FindingCandidate(Model):
    label: str
    repository_id: UUID
    cwes: tuple[str, ...] = ()


class Finding(Entity):
    repository_id: UUID
    match_key: Fingerprint
    cwes: tuple[str, ...] = ()


class Occurrence(Entity):
    finding_id: UUID
    assessment_id: UUID
    label: str


# Decision and Disposition fields are pending Q3 and the classifier plan's vocabulary.
class Decision(Entity):
    finding_id: UUID


class Disposition(Model):
    finding_id: UUID


class TriageVerdict(Model):
    binding_id: str
    artifact_digest: str
    finding_id: str
    source_finding_id: str | None = None
    triage_completed: str
    verdict: str
    severity: str | None = None
    vote_breakdown: Mapping[str, int] | None = None
    rationale: str | None = None
