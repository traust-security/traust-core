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
    compute_frontier,
    extend_frontier,
    frontier_root,
    sign_if_configured,
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

AUDIT_BATCH = 1000
_SIGNATURE = ("merkle_root_signature", "merkle_signature_format")
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

    def append_decision(
        self, decision: Decision, repository_id: UUID, *, sign: bool = True
    ) -> AppendReceipt:
        """Append the decision's event, growing the tree from its stored frontier.

        Earlier events are never reread, so an edit made to them stays a mismatch for `verify`
        instead of being folded into the new root. sign=False leaves the root for `seal`, when a
        caller appends several decisions in a row (a triage record).
        """
        if decision.id is None:
            raise ValidationError("ledger: append a saved decision")
        with self._uow:
            layer = self._uow.layers.find_for_update(repository_id) or self._uow.layers.add(
                Layer(repository_id=repository_id, merkle_signing_method=self._signing.method)
            )
            assert layer.id is not None
            event = self._uow.events.find_by_decision(decision.id)
            if event is not None:  # already proved: a retry changes nothing
                return AppendReceipt(
                    event=event, checkpoint=Checkpoint(layer=layer, signing=_signed(layer))
                )
            frontier, size = self._frontier(layer)
            if self._uow.events.last_seq(layer.id) != (size - 1 if size else None):
                raise IntegrityError(f"ledger layer {layer.id}: its size and its events disagree")
            payload = canonical_event_bytes(decision.model_dump(mode="json"))
            event = self._uow.events.add(
                Event(layer_id=layer.id, decision_id=decision.id, seq=size, event_payload=payload)
            )
            frontier = extend_frontier(frontier, size, canonical_event_bytes(json.loads(payload)))
            grown = layer.model_copy(
                update={
                    "merkle_root": frontier_root(frontier).hex(),
                    "merkle_size": size + 1,
                    "merkle_epoch": 0,
                    "merkle_frontier": ",".join(h.hex() for h in frontier),
                    "merkle_root_signature": None,
                    "merkle_signature_format": None,
                }
            )
            stale = layer.merkle_root_signature is not None
            checkpoint = self._sign(grown, stale) if sign else self._unsigned(grown, stale)
            self._uow.commit()
        return AppendReceipt(event=event, checkpoint=checkpoint)

    def seal(self, repository_id: UUID) -> Checkpoint:
        """Sign the repository layer's current root, after appends made with sign=False."""
        with self._uow:
            layer = self._uow.layers.find_for_update(repository_id)
            if layer is None:
                raise NotFoundError(f"ledger layer for repository {repository_id}")
            if layer.merkle_root_signature is not None:
                return Checkpoint(layer=layer, signing=Signing.SIGNED)
            checkpoint = self._sign(layer, stale=False)
            self._uow.commit()
        return checkpoint

    def require_signable(self) -> None:
        """Refuse up front when signing is required but no key is configured (nothing written)."""
        key = self._signing.key_path
        if self._signing_required and not (key and Path(key).is_file()):
            raise ServiceError(f"ledger: not signed: signing is required but no key is at {key}")

    def layers(self, repository_id: UUID) -> list[Layer]:
        """A repository's layers: the repository's own, then one per line."""
        with self._uow:
            return self._uow.layers.list_for_repository(repository_id)

    def audit(self) -> list[VerifyResult]:
        """Verify every layer: an edit to stored events changes no layer row, so each is read."""
        results: list[VerifyResult] = []
        after: UUID | None = None
        while True:
            with self._uow:
                batch = self._uow.layers.list_after(after, AUDIT_BATCH)
            ids = [layer.id for layer in batch if layer.id is not None]
            results += [self.verify(layer_id) for layer_id in ids]
            if len(batch) < AUDIT_BATCH:
                return results
            after = ids[-1]

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
            frontier = compute_frontier([canonical_event_bytes(e) for e in document["events"]])
            refreshed = layer.model_copy(
                update={"merkle_frontier": ",".join(h.hex() for h in frontier) or None}
            )
            checkpoint = self._sign(refreshed, stale=False)
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

    def _frontier(self, layer: Layer) -> tuple[tuple[bytes, ...], int]:
        """The stored frontier, checked against the root; computed once for an older layer."""
        if layer.merkle_epoch not in (None, 0):
            raise IntegrityError(
                f"ledger layer {layer.id} has a pre-epoch prefix; core appends to epoch 0"
            )
        if layer.merkle_frontier is None:
            document = self._document(layer)
            if not document["events"]:
                return (), 0
            self._refuse_unless_intact(layer, verify_merkle_integrity(document))
            events = [canonical_event_bytes(e) for e in document["events"]]
            return compute_frontier(events), len(events)
        frontier = tuple(bytes.fromhex(h) for h in layer.merkle_frontier.split(","))
        size = layer.merkle_size or 0
        if len(frontier) != size.bit_count() or frontier_root(frontier).hex() != layer.merkle_root:
            raise IntegrityError(f"ledger layer {layer.id}: its frontier and root disagree")
        return frontier, size

    def _sign(self, layer: Layer, stale: bool) -> Checkpoint:
        meta = {k: v for k in _MERKLE if (v := getattr(layer, k)) is not None}
        document = {"events": [], "metadata": {**meta, "leaf_format": LEAF_FORMAT_CURRENT}}
        attempt = sign_if_configured(document, self._signing)
        if stale and attempt.status != Signing.SIGNED:
            attempt = replace(attempt, stale_signature_dropped=True)
        signing = Signing(attempt.status)
        if self._signing_required and signing is not Signing.SIGNED:
            raise ServiceError(f"ledger: layer {layer.id} not signed ({attempt.error or signing})")
        signed = {k: document["metadata"].get(k) for k in _SIGNATURE}
        saved = self._uow.layers.update(layer.model_copy(update=signed))
        return Checkpoint(layer=saved, signing=signing, warning=attempt.warning())

    def _unsigned(self, layer: Layer, stale: bool) -> Checkpoint:
        warning = "the previous root's signature no longer applies; seal to sign" if stale else None
        saved = self._uow.layers.update(layer)
        return Checkpoint(layer=saved, signing=Signing.UNCONFIGURED, warning=warning)

    def _document(self, layer: Layer) -> dict[str, Any]:
        assert layer.id is not None
        meta = {k: v for k in _MERKLE if (v := getattr(layer, k)) is not None}
        meta["leaf_format"] = LEAF_FORMAT_CURRENT  # the only format core writes; not a column
        events = [json.loads(e.event_payload) for e in self._uow.events.list_for_layer(layer.id)]
        return {"events": events, "metadata": meta}


def _signed(layer: Layer) -> Signing:
    return Signing.SIGNED if layer.merkle_root_signature else Signing.UNCONFIGURED
