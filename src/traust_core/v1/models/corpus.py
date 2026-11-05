from __future__ import annotations

import json

from traust_core.v1.errors import ValidationError
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

    def subject_note(self, subject_id: str) -> str | None:
        return self._notes()[1].get(subject_id)

    def with_subject_note(self, subject_id: str, note: str) -> CorpusRegistry:
        """Keep subject-labelled caveats in the contract's existing document note."""
        if self.subject(subject_id) is None:
            raise ValidationError(f"corpus subject {subject_id} has no registration")
        original, notes = self._notes()
        if note:
            notes[subject_id] = note
        else:
            notes.pop(subject_id, None)
        rendered = original + _SUBJECT_NOTES + json.dumps(notes, ensure_ascii=False, sort_keys=True)
        return self.model_copy(update={"note": rendered if notes else original or None})

    def _notes(self) -> tuple[str, dict[str, str]]:
        original, marker, encoded = (self.note or "").rpartition(_SUBJECT_NOTES)
        if not marker:
            return self.note or "", {}
        try:
            notes = json.loads(encoded)
        except json.JSONDecodeError as e:
            raise ValidationError("invalid subject caveats in corpus registry note") from e
        if not isinstance(notes, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in notes.items()
        ):
            raise ValidationError("corpus registry subject caveats must map subject IDs to text")
        return original, notes


_SUBJECT_NOTES = "\n\ntraust-subject-notes-v1:\n"
