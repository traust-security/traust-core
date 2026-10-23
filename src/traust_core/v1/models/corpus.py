from __future__ import annotations

import json

from traust_core.v1.models.artifacts import CorpusRegistryArtifact
from traust_core.v1.models.base import Model
from traust_core.v1.models.vocabulary import OwnershipClass, RefKind


class CorpusSubject(Model):
    """One corpus-registry subject; extra="forbid" so a newer contract field fails loudly
    rather than being dropped on rewrite."""

    subject_id: str
    tree: str
    ownership: OwnershipClass
    business_unit: str
    label: str | None = None
    product: str | None = None
    repo_url: str | None = None
    ref: str | None = None
    ref_kind: RefKind | None = None
    is_branch_audit: bool | None = None


class CorpusRegistry(Model):
    version: int = 1
    updated: str | None = None
    note: str | None = None
    subjects: tuple[CorpusSubject, ...] = ()

    @classmethod
    def of(cls, artifact: CorpusRegistryArtifact) -> CorpusRegistry:
        return cls.model_validate(json.loads(artifact.payload))

    def to_artifact(self) -> CorpusRegistryArtifact:
        return CorpusRegistryArtifact.from_document(self.model_dump(mode="json", exclude_none=True))

    def with_subject(self, subject: CorpusSubject) -> CorpusRegistry:
        """Replace or add by subject_id; the rest stay as stored, ordered by subject_id."""
        others = [s for s in self.subjects if s.subject_id != subject.subject_id]
        subjects = tuple(sorted([*others, subject], key=lambda s: s.subject_id))
        return self.model_copy(update={"subjects": subjects})

    def subject(self, subject_id: str) -> CorpusSubject | None:
        return next((s for s in self.subjects if s.subject_id == subject_id), None)
