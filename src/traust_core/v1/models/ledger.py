from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from pydantic import computed_field

from traust_core.v1.models.base import AppendOnly, Entity, Model


class Layer(Entity):
    """5 · one Merkle tree of decision events for a repository (or one line), signed per root."""

    repository_id: UUID
    line: str | None = None
    merkle_root: str | None = None
    merkle_epoch: int | None = None
    merkle_size: int | None = None
    merkle_root_signature: str | None = None
    merkle_signing_method: str
    merkle_signature_format: int | None = None
    merkle_frontier: str | None = None


class Event(AppendOnly):
    """5 · the proof of one decision: its leaf in a layer."""

    layer_id: UUID
    decision_id: UUID
    seq: int
    event_payload: bytes


class Signing(StrEnum):
    """How signing a layer's root went (traust-ledger `SignAttempt.status`)."""

    UNCONFIGURED = "unconfigured"
    SIGNED = "signed"
    FAILED = "failed"


class Checkpoint(Model):
    """A layer after restamping its root; `warning` is what the caller must surface."""

    layer: Layer
    signing: Signing
    warning: str | None = None


class AppendReceipt(Model):
    event: Event
    checkpoint: Checkpoint


class VerifyResult(Model):
    layer_id: UUID
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def passed(self) -> bool:
        return not self.errors and not self.warnings
