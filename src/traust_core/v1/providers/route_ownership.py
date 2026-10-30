"""Whether an authenticated id route ties the object it acts on to the caller, decided from the
facts each route enumerator reads out of the handler."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from traust_core.v1.models.code_facts import OwnershipEvidence, RouteOwnership
from traust_core.v1.models.common import CodeSpan

PATH_PARAM_RX = re.compile(r"\{(\w+)[^}]*\}|:(\w+)|<(?:\w+:)?(\w+)>")
# A privileged role acts on any record by design, so its routes are out of scope.
PRIVILEGED_RX = re.compile(r"(?i)(admin|operator|superuser|staff)")
OWNER_FIELD_RX = re.compile(
    r"(?i)^_?(owner|user|tenant|team|org|organi[sz]ation|account|customer|member|workspace|"
    r"author|created_?by)(_?id)?$"
)
MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
JUDGED = frozenset({RouteOwnership.CALLER_BLIND, RouteOwnership.UNCHECKED})


@dataclass(frozen=True, slots=True)
class Lookup:
    """A load of a record by a path id; `scoped` when the query itself names the caller."""

    span: CodeSpan
    scoped: bool = False
    record_type: str | None = None


@dataclass(frozen=True, slots=True)
class HandlerFacts:
    """What a handler, followed one same-repository hop, does with the caller and the object."""

    lookups: tuple[Lookup, ...] = ()
    caller: CodeSpan | None = None
    check: CodeSpan | None = None
    hop: CodeSpan | None = None
    handoff: CodeSpan | None = None


def path_params(pattern: str) -> tuple[str, ...]:
    return tuple(next(g for g in m.groups() if g) for m in PATH_PARAM_RX.finditer(pattern))


def owner_field(record_type: str | None, fields: Mapping[str, Sequence[str]]) -> str | None:
    return next((f for f in fields.get(record_type or "", ()) if OWNER_FIELD_RX.match(f)), None)


def classify(
    method: str,
    pattern: str,
    guards: Sequence[str],
    facts: HandlerFacts,
    fields: Mapping[str, Sequence[str]],
) -> tuple[RouteOwnership, OwnershipEvidence | None]:
    """`fields` maps each record type the checkout declares to its field names."""
    if not path_params(pattern) or not guards or any(PRIVILEGED_RX.search(g) for g in guards):
        return RouteOwnership.NOT_APPLICABLE, None
    lookup = next((x for x in facts.lookups if x.scoped), None) or next(
        iter(sorted(facts.lookups, key=lambda x: owner_field(x.record_type, fields) is None)),
        None,
    )
    record_type = lookup.record_type if lookup else None
    owner = owner_field(record_type, fields)
    evidence = OwnershipEvidence(
        lookup=lookup.span if lookup else None,
        caller=facts.caller,
        check=facts.check,
        hop=facts.hop,
        record_type=record_type,
        owner_field=owner,
    )
    if lookup and lookup.scoped:
        return RouteOwnership.SCOPED, evidence
    if facts.check:
        return RouteOwnership.CHECKED, evidence
    if facts.lookups and all(
        x.record_type in fields and owner_field(x.record_type, fields) is None
        for x in facts.lookups
    ):
        return RouteOwnership.NONE, evidence
    if facts.handoff:
        return RouteOwnership.UNKNOWN, evidence
    if facts.caller is None:
        acts = facts.lookups or facts.hop or method.upper() in MUTATING
        return (RouteOwnership.CALLER_BLIND if acts else RouteOwnership.NOT_APPLICABLE), evidence
    return (RouteOwnership.UNCHECKED if owner else RouteOwnership.UNKNOWN), evidence


def rank(ownership: RouteOwnership | None, evidence: OwnershipEvidence | None) -> int:
    """Judged rows on a record with an owner field first, then judged rows on unresolved stores."""
    if ownership not in JUDGED:
        return 2
    return 0 if evidence and evidence.owner_field else 1
