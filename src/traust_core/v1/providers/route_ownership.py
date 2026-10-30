"""Whether an authenticated id route ties the object it acts on to the caller, decided from the
facts each route enumerator reads out of the handler."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from traust_core.v1.models.code_facts import OwnershipEvidence, RouteOwnership
from traust_core.v1.models.common import CodeSpan

# `{id}`, `{id:path}`, `:id`, `<int:id>`, `(?P<pk>…)`; not regex counts (`{8}`) or `(?:…)` groups
PATH_PARAM_RX = re.compile(
    r"\{([A-Za-z_]\w*)[^}]*\}|(?<![?\w]):([A-Za-z_]\w*)|<(?:\w+:)?([A-Za-z_]\w*)>"
)
# A guard that admits only a privileged role acts on any record by design: out of scope.
PRIVILEGED_RX = re.compile(r"(?i)(admin|operator|superuser|staff)")
_QUOTED_RX = re.compile(r"'([^'\"]*)'|\"([^'\"]*)\"")
_ALTERNATIVE_RX = re.compile(r"(?i)(\bor\b|\|\||_or_|#\w|principal|authentication\.)")
OWNER_FIELD_RX = re.compile(
    r"(?i)^_?(owner|user|tenant|team|org|organi[sz]ation|account|customer|member|workspace|"
    r"author|created_?by)(_?id)?$"
)
MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
JUDGED = frozenset({RouteOwnership.CALLER_BLIND, RouteOwnership.UNCHECKED})


@dataclass(frozen=True, slots=True)
class Lookup:
    """A load of a record by a path id: `scoped` when the query itself names the caller,
    `checked` when the loaded record is compared with the caller."""

    span: CodeSpan
    scoped: bool = False
    checked: bool = False
    record_type: str | None = None


@dataclass(frozen=True, slots=True)
class HandlerFacts:
    """What a handler, followed one same-repository hop, does with the caller and the object;
    `check` is an authorization covering the object itself (method security naming the id)."""

    lookups: tuple[Lookup, ...] = ()
    caller: CodeSpan | None = None
    check: CodeSpan | None = None
    hop: CodeSpan | None = None
    handoff: CodeSpan | None = None


def path_params(pattern: str) -> tuple[str, ...]:
    return tuple(next(g for g in m.groups() if g) for m in PATH_PARAM_RX.finditer(pattern))


def privileged_only(guard: str) -> bool:
    """A guard naming a privileged role with no ordinary role or other way in."""
    if not PRIVILEGED_RX.search(guard) or _ALTERNATIVE_RX.search(guard):
        return False
    if guard.count("'") % 2 or guard.count('"') % 2:
        return False  # a label cut short may have lost a role
    quoted = (a or b for a, b in _QUOTED_RX.findall(guard))
    roles = [r for q in quoted for r in re.split(r"[,\s]+", q) if r]
    return all(PRIVILEGED_RX.search(r) for r in roles)


def owner_field(record_type: str | None, fields: Mapping[str, Sequence[str]]) -> str | None:
    return next((f for f in fields.get(record_type or "", ()) if OWNER_FIELD_RX.match(f)), None)


def classify(
    method: str,
    pattern: str,
    guards: Sequence[str],
    facts: HandlerFacts,
    fields: Mapping[str, Sequence[str]],
) -> tuple[RouteOwnership, OwnershipEvidence | None]:
    """`guards` are the route's effective guards; `fields` maps each record type the checkout
    declares to its field names."""
    if not path_params(pattern) or not guards or any(privileged_only(g) for g in guards):
        return RouteOwnership.NOT_APPLICABLE, None

    def ownerless(x: Lookup) -> bool:
        return x.record_type in fields and owner_field(x.record_type, fields) is None

    exposed = [x for x in facts.lookups if not (x.scoped or x.checked or ownerless(x))]
    # the most concerning access decides: an unprotected owner-bearing record, then any other
    lookup = next(
        iter(
            sorted(exposed, key=lambda x: owner_field(x.record_type, fields) is None)
            or [x for x in facts.lookups if x.checked]
            or [x for x in facts.lookups if x.scoped]
            or facts.lookups
        ),
        None,
    )
    owner = owner_field(lookup.record_type, fields) if lookup else None
    evidence = OwnershipEvidence(
        lookup=lookup.span if lookup else None,
        caller=facts.caller,
        check=facts.check,
        hop=facts.hop,
        record_type=lookup.record_type if lookup else None,
        owner_field=owner,
    )
    if facts.check:
        return RouteOwnership.CHECKED, evidence
    if exposed:
        if facts.caller is None:
            return RouteOwnership.CALLER_BLIND, evidence
        return (RouteOwnership.UNCHECKED if owner else RouteOwnership.UNKNOWN), evidence
    if facts.handoff:
        return RouteOwnership.UNKNOWN, evidence
    if facts.lookups:
        if any(x.checked for x in facts.lookups):
            return RouteOwnership.CHECKED, evidence
        if any(x.scoped for x in facts.lookups):
            return RouteOwnership.SCOPED, evidence
        return RouteOwnership.NONE, evidence
    if facts.caller is None:
        acts = facts.hop or method.upper() in MUTATING
        return (RouteOwnership.CALLER_BLIND if acts else RouteOwnership.NOT_APPLICABLE), evidence
    return RouteOwnership.UNKNOWN, evidence


def rank(ownership: RouteOwnership | None, evidence: OwnershipEvidence | None) -> int:
    """Judged rows on a record with an owner field first, then judged rows on unresolved stores."""
    if ownership not in JUDGED:
        return 2
    return 0 if evidence and evidence.owner_field else 1
