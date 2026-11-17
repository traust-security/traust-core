"""Per-identifier feed documents kept daily: one manifest snapshot per source (D11)."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from dataclasses import replace
from uuid import UUID

from traust_core.v1.errors import NotFoundError, ServiceError, ValidationError
from traust_core.v1.models.assessment import Artifact
from traust_core.v1.models.feed_documents import (
    DocumentFailure,
    DocumentRefresh,
    FeedDocument,
    FeedDocumentManifest,
    StoredDocument,
)
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.operations import FeedSnapshot
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.feeds import FeedSource
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey, ObjectStore
from traust_core.v1.services.artifact_publishing import record_artifact, stored_bytes

log = logging.getLogger(__name__)

FEED_ARTIFACT_KIND = "feed"
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _key(identifier: str) -> str:
    """The manifest's spelling of an identifier: a CVE id upper-cased, any other as given."""
    return identifier.upper() if _CVE.fullmatch(identifier) else identifier


def documents_feed(source: str) -> str:
    """The `feed_snapshot.feed` a source's manifests are recorded under."""
    return f"{source}-documents"


class FeedDocuments:
    def __init__(
        self,
        uow: TraustUnitOfWork,
        objects: ObjectStore,
        sources: ProviderRegistry[FeedSource],
        clock: Clock,
    ) -> None:
        self._uow = uow
        self._objects = objects
        self._sources = sources
        self._clock = clock

    def refresh(
        self, source: str, identifiers: Iterable[str], run_order_id: UUID | None = None
    ) -> DocumentRefresh:
        """Snapshot a manifest of exactly these identifiers' documents, a failed fetch keeping the
        last one; nothing fetched (or nothing asked) raises and writes nothing."""
        provider = self._source(source)
        wanted = list(dict.fromkeys(map(_key, identifiers)))
        if not wanted:
            raise ValidationError(f"{source}: no identifiers to refresh documents for")
        latest, previous = self._latest(source)
        held = {} if previous is None else previous.documents
        documents: dict[str, FeedDocument] = {}
        fetched: list[str] = []
        failed: list[DocumentFailure] = []
        for identifier in wanted:
            try:
                documents[identifier] = self._fetch(provider, identifier)
                fetched.append(identifier)
            except (ServiceError, ValidationError) as e:
                failed.append(DocumentFailure(identifier=identifier, error=str(e)))
                if identifier in held:
                    documents[identifier] = held[identifier]
        if not fetched:
            raise ServiceError(
                f"{source}: no document fetched ({len(failed)} failed; first: {failed[0].error})"
            )
        if failed:
            total = len(failed) + len(fetched)
            log.warning("%s: %d of %d documents not fetched", source, len(failed), total)
        manifest = FeedDocumentManifest(source=source, documents=documents)
        retried = (
            run_order_id is not None
            and latest is not None
            and latest.run_order_id == run_order_id
            and previous is not None
            and _digests(previous) == _digests(manifest)
        )
        if not retried:  # a retry in the same order that kept the same documents adds nothing
            self._snapshot(source, manifest.to_bytes(), run_order_id)
        return DocumentRefresh(
            source=source,
            fetched=tuple(fetched),
            failed=tuple(failed),
            carried=tuple(f.identifier for f in failed if f.identifier in held),
        )

    def manifest(self, source: str) -> FeedDocumentManifest | None:
        """The source's latest manifest; None before its first refresh."""
        return self._latest(source)[1]

    def _latest(self, source: str) -> tuple[FeedSnapshot | None, FeedDocumentManifest | None]:
        with self._uow as uow:
            latest = uow.feed_snapshots.latest(documents_feed(source))
            artifact = None if latest is None else uow.artifacts.get(latest.artifact_id)
        if artifact is None:
            return latest, None
        manifest = FeedDocumentManifest.from_bytes(stored_bytes(self._objects, artifact))
        if manifest.source != source:
            raise ValidationError(f"{documents_feed(source)}: its manifest is {manifest.source}'s")
        return latest, manifest

    def stored(self, source: str, identifier: str) -> StoredDocument | None:
        """The identifier's document in the source's latest manifest, checked against its digest;
        None when the manifest doesn't name it."""
        manifest = self.manifest(source)
        entry = None if manifest is None else manifest.documents.get(_key(identifier))
        if entry is None:
            return None
        ref = self._objects.stat(_document_key(source, entry.digest))
        return StoredDocument(
            source=source,
            identifier=_key(identifier),
            digest=entry.digest,
            acquired_at=entry.acquired_at,
            data=self._objects.get(replace(ref, sha256=entry.digest)),
        )

    def _source(self, source: str) -> FeedSource:
        if source not in self._sources.names():
            raise NotFoundError(
                f"feed source {source}: not registered "
                f"({', '.join(self._sources.names()) or 'none registered'})"
            )
        return self._sources.get(source)

    def _fetch(self, provider: FeedSource, identifier: str) -> FeedDocument:
        result = provider.document(identifier)
        try:
            body = json.loads(result.data)
        except ValueError as e:
            raise ValidationError(f"{provider.name}: {identifier}: not a JSON document") from e
        if not isinstance(body, dict):
            raise ValidationError(f"{provider.name}: {identifier}: not a JSON object")
        ref = self._objects.put(_document_key(provider.name, sha256_hex(result.data)), result.data)
        return FeedDocument(digest=ref.sha256, acquired_at=result.acquisition.acquired_at)

    def _snapshot(self, source: str, raw: bytes, run_order_id: UUID | None) -> None:
        key = ObjectKey.parse(f"feeds/{source}/manifests/{sha256_hex(raw)}.json")
        ref = self._objects.put(key, raw)
        feed = documents_feed(source)
        with self._uow as uow:
            artifact = record_artifact(
                uow, Artifact(digest=ref.sha256, kind=FEED_ARTIFACT_KIND, uri=str(ref.key))
            )
            assert artifact.id is not None
            uow.feed_snapshots.add(
                FeedSnapshot(
                    run_order_id=run_order_id,
                    artifact_id=artifact.id,
                    feed=feed,
                    retrieved_at=self._clock.now(),
                )
            )
            uow.commit()


def _digests(manifest: FeedDocumentManifest) -> dict[str, str]:
    return {identifier: d.digest for identifier, d in manifest.documents.items()}


def _document_key(source: str, digest: str) -> ObjectKey:
    return ObjectKey.parse(f"feeds/{source}/documents/{digest}.json")
