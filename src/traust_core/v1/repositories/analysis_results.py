from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Protocol, TypeVar

from traust_core.v1.artifacts import Artifact
from traust_core.v1.domain.analysis_results import ResultKind, Subject
from traust_core.v1.domain.errors import ConfigError
from traust_core.v1.repositories.object_store import ObjectKey, ObjectRef, ObjectStore

A = TypeVar("A", bound=Artifact)


def artifact_kind(artifact: type[Artifact]) -> ResultKind:
    if artifact.kind is None:
        raise ConfigError(f"artifact {artifact.name!r} has no analysis-results file kind")
    return artifact.kind


# Today's on-disk convention as-is; to move into a traust-contracts layout contract.
class ResultsLayout:
    def key_for(self, subject: Subject, kind: ResultKind) -> ObjectKey:
        return ObjectKey.parse(f"{subject.key}-{kind.value}")

    def parse(self, key: ObjectKey) -> tuple[Subject, ResultKind] | None:
        *dirs, filename = key.value.split("/")
        if len(dirs) not in (2, 3):
            return None
        for kind in sorted(ResultKind, key=lambda k: len(k.value), reverse=True):
            if filename.endswith(f"-{kind.value}"):
                base = filename.removesuffix(f"-{kind.value}")
                tree, *product, repo_dir = dirs
                return Subject(
                    tree=tree, product=product[0] if product else None, repo_dir=repo_dir, base=base
                ), kind
        return None


class ResultsRepository(Protocol):
    def put(self, subject: Subject, kind: ResultKind, payload: bytes) -> ObjectRef: ...
    def get(self, subject: Subject, kind: ResultKind) -> bytes: ...
    def exists(self, subject: Subject, kind: ResultKind) -> bool: ...
    def find(self, kind: ResultKind, tree: str | None = None) -> Iterator[Subject]: ...


class AnalysisResultsRepository:
    def __init__(
        self,
        objects: ObjectStore,
        artifacts: Mapping[ResultKind, type[Artifact]] | None = None,
        layout: ResultsLayout | None = None,
    ) -> None:
        self._objects = objects
        self._artifacts = dict(artifacts or {})
        self._layout = layout or ResultsLayout()

    def put(self, subject: Subject, kind: ResultKind, payload: bytes) -> ObjectRef:
        if (artifact := self._artifacts.get(kind)) is not None:
            artifact.parse(payload)
        return self._objects.put(self._layout.key_for(subject, kind), payload)

    def get(self, subject: Subject, kind: ResultKind) -> bytes:
        key = self._layout.key_for(subject, kind)
        return self._objects.get(self._objects.stat(key))

    def exists(self, subject: Subject, kind: ResultKind) -> bool:
        return self._objects.exists(self._layout.key_for(subject, kind))

    def find(self, kind: ResultKind, tree: str | None = None) -> Iterator[Subject]:
        for key in self._objects.list(tree or ""):
            parsed = self._layout.parse(key)
            if parsed is not None and parsed[1] is kind:
                yield parsed[0]

    def read(self, artifact: type[A], subject: Subject) -> A:
        return artifact.parse(self.get(subject, artifact_kind(artifact)))

    def read_all(self, artifact: type[A], tree: str | None = None) -> Iterator[tuple[Subject, A]]:
        for subject in self.find(artifact_kind(artifact), tree):
            yield subject, self.read(artifact, subject)
