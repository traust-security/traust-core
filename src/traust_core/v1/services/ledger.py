from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import UUID

from traust_ledger.integrity import (
    LEAF_FORMAT_CURRENT,
    IntegrityFinding,
    Severity,
    SigningConfig,
    canonical_event_bytes,
    sign_if_configured,
    stamp_merkle_metadata,
    verify_merkle_integrity,
    verify_merkle_signature,
)

from traust_core.v1.errors import (
    ForbiddenError,
    IntegrityError,
    NotFoundError,
    ServiceError,
    ValidationError,
)
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import Cursor, Page, PageRequest
from traust_core.v1.models.findings import Decision
from traust_core.v1.models.identity import Principal, Role
from traust_core.v1.models.ledger import (
    AppendReceipt,
    Checkpoint,
    Event,
    Layer,
    Signing,
    VerifyResult,
)
from traust_core.v1.repositories.traust_ledger import LedgerUnitOfWork

_MERKLE = (
    "merkle_root",
    "merkle_epoch",
    "merkle_size",
    "merkle_root_signature",
    "merkle_signing_method",
    "merkle_signature_format",
)


class LedgerConfig(Model):
    """The `ledger:` config section. Keypair (cosign) signing; no key means layers stay unsigned."""

    key_path: Path | None = None
    public_key_path: Path | None = None
    previous_public_key_path: Path | None = (
        None  # during a key rotation: old signatures still verify
    )
    required: bool = False


class LedgerService:
    """Proof that decisions weren't changed: traust-ledger computes, these tables store.

    Optional: decisions live in the decision table either way. Share the caller's unit of
    work to append in the decision's transaction.
    """

    def __init__(self, uow: LedgerUnitOfWork, config: LedgerConfig) -> None:
        self._uow = uow
        key = None if config.key_path is None else str(config.key_path)
        self._signing = SigningConfig(method="keypair", key_path=key)
        keys = (config.public_key_path, config.previous_public_key_path)
        self._public_keys = tuple(str(k) for k in keys if k is not None)
        self._signing_required = config.required

    def append_decision(self, decision: Decision, repository_id: UUID) -> AppendReceipt:
        """Append the decision's event to the repository layer, then restamp and sign it.

        Refuses (IntegrityError) a layer whose stored root no longer matches its events.
        """
        if decision.id is None:
            raise ValidationError("ledger: append a saved decision")
        with self._uow:
            layer = self._uow.layers.find_for_update(repository_id) or self._uow.layers.add(
                Layer(repository_id=repository_id, merkle_signing_method=self._signing.method)
            )
            assert layer.id is not None
            event = self._uow.events.find_by_decision(decision.id)
            document = self._document(layer)
            if document["events"]:  # a new layer has nothing to verify yet
                self._refuse_unless_intact(layer, verify_merkle_integrity(document))
            if event is None:
                last = self._uow.events.last_seq(layer.id)
                event = self._uow.events.add(
                    Event(
                        layer_id=layer.id,
                        decision_id=decision.id,
                        seq=0 if last is None else last + 1,
                        event_payload=canonical_event_bytes(decision.model_dump(mode="json")),
                    )
                )
                document["events"].append(json.loads(event.event_payload))
            checkpoint = self._finalize(layer, document)
            self._uow.commit()
        return AppendReceipt(event=event, checkpoint=checkpoint)

    def layers(self, repository_id: UUID) -> list[Layer]:
        """A repository's layers: the repository's own, then one per line."""
        with self._uow:
            return self._uow.layers.list_for_repository(repository_id)

    def layer(self, layer_id: UUID) -> Layer:
        with self._uow:
            return self._uow.layers.get(layer_id)

    def events(self, layer_id: UUID, page: PageRequest) -> Page[Event]:
        """A layer's events in `seq` order; the cursor is the last `seq` returned."""
        after = None
        if page.cursor is not None:
            if not page.cursor.isdigit():
                raise ValidationError(f"ledger events: cursor {page.cursor!r} is not a seq")
            after = int(page.cursor)
        with self._uow:
            self._uow.layers.get(layer_id)
            found = self._uow.events.page_for_layer(layer_id, after, page.limit + 1)
        items, more = found[: page.limit], len(found) > page.limit
        return Page(items=tuple(items), next=Cursor(str(items[-1].seq)) if more else None)

    def checkpoint(self, repository_id: UUID, principal: Principal) -> Checkpoint:
        """Restamp and sign the repository layer, e.g. once a signing key is configured."""
        if not principal.has_role(Role.ADMIN):
            raise ForbiddenError(f"{principal.ref}: a ledger checkpoint is an admin's")
        with self._uow:
            layer = self._uow.layers.find_for_update(repository_id)
            if layer is None:
                raise NotFoundError(f"ledger layer for repository {repository_id}")
            document = self._document(layer)
            # a missing signature is fine: adding one is what a checkpoint is for
            self._refuse_unless_intact(layer, self._issues(document, required=False))
            checkpoint = self._finalize(layer, document)
            self._uow.commit()
        return checkpoint

    def verify(self, layer_id: UUID) -> VerifyResult:
        """Recompute the layer's root from its stored events and check the signature."""
        with self._uow:
            document = self._document(self._uow.layers.get(layer_id))
        issues = self._issues(document, required=self._signing_required)
        return VerifyResult(
            layer_id=layer_id,
            errors=tuple(i.message for i in issues if i.severity is Severity.ERROR),
            warnings=tuple(i.message for i in issues if i.severity is not Severity.ERROR),
        )

    @staticmethod
    def _refuse_unless_intact(layer: Layer, issues: list[IntegrityFinding]) -> None:
        """Never restamp or sign over a layer that doesn't verify: that would launder the edit."""
        problems = [i.message for i in issues if i.severity is Severity.ERROR]
        if problems:
            raise IntegrityError(
                f"ledger layer {layer.id} does not verify, so it won't be re-signed: "
                + "; ".join(problems)
            )

    def _issues(self, document: dict[str, Any], *, required: bool) -> list[IntegrityFinding]:
        """Root against events, then the signature against any configured public key."""
        integrity = verify_merkle_integrity(document)
        tries = [
            verify_merkle_signature(document, key, required=required)
            for key in self._public_keys or (None,)
        ]
        passing = next((t for t in tries if all(i.severity is not Severity.ERROR for i in t)), None)
        return [*integrity, *(tries[0] if passing is None else passing)]

    def _finalize(self, layer: Layer, document: dict[str, Any] | None = None) -> Checkpoint:
        document = document or self._document(layer)
        dropped = stamp_merkle_metadata(document)
        attempt = sign_if_configured(document, self._signing)
        if dropped and attempt.status != Signing.SIGNED:
            attempt = replace(attempt, stale_signature_dropped=True)
        signing = Signing(attempt.status)
        if self._signing_required and signing is not Signing.SIGNED:
            raise ServiceError(f"ledger: layer {layer.id} not signed ({attempt.error or signing})")
        meta = document["metadata"]
        meta.setdefault("merkle_signing_method", layer.merkle_signing_method)  # NOT NULL column
        saved = self._uow.layers.update(layer.model_copy(update={k: meta.get(k) for k in _MERKLE}))
        return Checkpoint(layer=saved, signing=signing, warning=attempt.warning())

    def _document(self, layer: Layer) -> dict[str, Any]:
        assert layer.id is not None
        meta = {k: v for k in _MERKLE if (v := getattr(layer, k)) is not None}
        meta["leaf_format"] = LEAF_FORMAT_CURRENT  # the only format core writes; not a column
        events = [json.loads(e.event_payload) for e in self._uow.events.list_for_layer(layer.id)]
        return {"events": events, "metadata": meta}
