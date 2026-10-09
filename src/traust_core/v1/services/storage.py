from __future__ import annotations

from collections.abc import Sequence

from traust_core.v1 import contracts
from traust_core.v1.errors import ConflictError, NotFoundError, ValidationError
from traust_core.v1.models.base import Dto
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.storage import (
    ArtifactBinding,
    BindingContext,
    Evidence,
    binding_id,
    identifier_bytes,
)
from traust_core.v1.providers.clock import Clock
from traust_core.v1.repositories.storage import StorageUnitOfWork


class RecordResult(Dto):
    digest: str
    binding_id: str
    already_bound: bool


def _check_context(name: str, context: BindingContext) -> None:
    profile = contracts.storage_profile(name)
    if not context.scope_id:
        raise ValidationError("scope_id: required")
    if missing := [f for f in profile.get("required", ()) if getattr(context, f) in (None, "")]:
        raise ValidationError(f"artifact {name}: requires {', '.join(missing)}")
    if context.role is not None and context.role not in profile.get("roles", ()):
        raise ValidationError(f"artifact {name}: role {context.role!r} not allowed")


def _references(references: Sequence[str]) -> tuple[str, ...]:
    for ref in references:
        if not ref:
            raise ValidationError("references: empty reference")
        identifier_bytes("references", ref)
    return tuple(dict.fromkeys(references))


def bind_artifact(
    uow: StorageUnitOfWork,
    name: str,
    payload: bytes,
    clock: Clock,
    context: BindingContext | None = None,
    references: Sequence[str] = (),
) -> RecordResult:
    context = context or BindingContext()
    contracts.validate_json(name, payload)
    _check_context(name, context)
    refs = _references(references)
    digest = sha256_hex(payload)
    bid = binding_id(digest, name, context)
    now = clock.now()
    if uow.evidence.find_binding(bid) is not None:
        uow.evidence.add_locations(bid, refs, now)
        return RecordResult(digest=digest, binding_id=bid, already_bound=True)
    if context.supersedes_binding_id is not None:
        previous = uow.evidence.find_binding(context.supersedes_binding_id)
        if previous is None or (previous.artifact_name, previous.context.scope_id) != (
            name,
            context.scope_id,
        ):
            raise ConflictError(
                f"artifact {name}: supersedes unknown or unrelated binding "
                f"{context.supersedes_binding_id}"
            )
    uow.evidence.add(
        Evidence(digest=digest, byte_size=len(payload), first_ingested_at=now),
        ArtifactBinding(
            binding_id=bid,
            artifact_digest=digest,
            artifact_name=name,
            context=context,
            bound_at=now,
        ),
    )
    uow.evidence.add_locations(bid, refs, now)
    return RecordResult(digest=digest, binding_id=bid, already_bound=False)


def record_artifact(
    uow: StorageUnitOfWork,
    name: str,
    payload: bytes,
    clock: Clock,
    context: BindingContext | None = None,
    references: Sequence[str] = (),
) -> RecordResult:
    with uow:
        result = bind_artifact(uow, name, payload, clock, context, references)
        uow.commit()
    return result


def get_binding(uow: StorageUnitOfWork, binding_id_value: str) -> ArtifactBinding:
    with uow:
        binding = uow.evidence.find_binding(binding_id_value)
    if binding is None:
        raise NotFoundError(f"binding {binding_id_value}")
    return binding
