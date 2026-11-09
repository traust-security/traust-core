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
# a privileged role as a word: `ROLE_ADMIN`, `isAdmin`, `require_superuser`; not `COOPERATOR`
PRIVILEGED_RX = re.compile(
    r"(?:(?<![A-Za-z])(?i:admin|operator|superuser|staff)|(?<=[a-z])(?:Admin|Operator|Superuser|Staff))"
    r"(?:s|S)?(?![a-z])"
)
# an admin of one tenant can still reach another tenant's objects (owner decision 2026-11-02)
_TENANT_ADMIN_RX = re.compile(
    r"(?i)(tenant|org|organi[sz]ation|customer|team|project|workspace|group|account|company|"
    r"client|realm|site|store|shop|partner|department|channel|non|not|no)[_\-\s]?"
    r"(admin|staff|operator)"
)
_QUOTED_RX = re.compile(r"'([^'\"]*)'|\"([^'\"]*)\"")
_ALTERNATIVE_RX = re.compile(r"(?i:\bor\b|\|\||_or_|#\w|principal|authentication\.)|Or[A-Z]")
# owner-, tenant- or membership-shaped fields; broad on purpose, since a miss reads as ownerless
OWNER_FIELD_RX = re.compile(
    r"(?i)^_?(owner\w*|owned_?by\w*|user\w*|uid|tenant\w*|team\w*|org|orgs?_?id|"
    r"organi[sz]ation\w*|account\w*|customer\w*|member\w*|workspace\w*|author\w*|"
    r"creator\w*|created_?by\w*|project\w*|group\w*|company\w*|client\w*|realm\w*)$"
)
# the owner fields an ownership check may compare: narrower than OWNER_FIELD_RX, which only says
# a record might have an owner (`accountType` is no owner)
OWNER_CHECK_RX = re.compile(
    r"(?i)^_?(owner\w*|owned_?by\w*|user_?(id|name|email|uuid)?|username|uid|tenant(_?id)?|"
    r"created_?by(_?id)?|creator(_?id)?|author(_?id)?|(account|customer|member|org|organi[sz]ation|"
    r"workspace|team|client|group|project|company|realm)(_?(id|uuid|key))?)$"
)
# fields that tie a record to something else (`patientId`, `recipient`): not ownerless
_LINK_RX = re.compile(
    r"(?i)^(?!_?id$)(\w*(_id|id|_uuid|uuid|_key|key)|_?(recipient|sender|assignee|reporter|holder|"
    r"subscriber|buyer|seller|payer|payee|patient|email|login|principal|participant|requester|"
    r"approver|reviewer|parent|employee|staff|student|driver|worker|beneficiary|grantee|"
    r"uploader|poster|submitter|publisher|issuer|signer|person|people|contact)\w*|\w+_by(_\w+)?|"
    r"\w*_owner\w*|sub|from|to)$"
)
_SPEL_ROLE_CALL = re.compile(r"has(?:Any)?(?:Role|Authority)\((.*)\)")
_CONSTANT_ROLE = re.compile(r"\b(?:[A-Z]\w*\.)?[A-Z][A-Z0-9_]{2,}\b")
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
    takes_id: bool = False  # a path id reaches the handler, whatever the pattern shows
    ignores_id: bool = False  # the path ids reach only code that does nothing with them


def path_params(pattern: str) -> tuple[str, ...]:
    return tuple(next(g for g in m.groups() if g) for m in PATH_PARAM_RX.finditer(pattern))


def _privileged(role: str) -> bool:
    return bool(PRIVILEGED_RX.search(role)) and not _TENANT_ADMIN_RX.search(role)


def privileged_only(guard: str) -> bool:
    """A guard naming only privileged roles, quoted or as constants, with no other way in."""
    if guard.startswith("call:") or not PRIVILEGED_RX.search(guard):
        return False  # a call's name (`logAdminView`) says nothing about who gets in
    if _ALTERNATIVE_RX.search(guard) or "…" in guard:
        return False
    if guard.count("'") % 2 or guard.count('"') % 2:
        return False  # a label cut short may have lost a role
    name, _, args = guard.partition("(")
    if name.startswith("@"):
        roles = _annotation_roles(name, args.removesuffix(")"))
        return bool(roles) and all(_privileged(r) for r in roles)
    quoted = [a or b for a, b in _QUOTED_RX.findall(args)]
    roles = [r for q in quoted for r in re.split(r"[,\s]+", q) if r]
    roles += _CONSTANT_ROLE.findall(_QUOTED_RX.sub(" ", args))
    if not roles:
        return not args and _privileged(name)
    return all(_privileged(r) for r in roles)


def _annotation_roles(name: str, args: str) -> list[str] | None:
    """The roles a Java security annotation names, or None when any isn't a literal or constant
    (`hasRole(@roles.admin())`, `@RolesAllowed(adminRole)`)."""
    if not args:
        return [name] if _privileged(name) else None
    if name == "@PostAuthorize":
        return None  # runs after the handler
    if name == "@PreAuthorize":
        expression = re.fullmatch(r'\s*(?:value\s*=\s*)?"(.*)"\s*', args)
        call = expression and _SPEL_ROLE_CALL.fullmatch(expression.group(1).strip())
        return _literals(call.group(1), "'") if call else None
    return _literals(re.sub(r"^\s*(?:value\s*=\s*)?\{?|\}?\s*$", "", args), '"')


def _literals(text: str, quote: str) -> list[str] | None:
    items = [i.strip() for i in text.split(",")]
    if not all(
        (i[:1] == i[-1:] == quote and len(i) > 1) or _CONSTANT_ROLE.fullmatch(i) for i in items
    ):
        return None
    return [i.strip(quote) for i in items]


def owner_field(record_type: str | None, fields: Mapping[str, Sequence[str]]) -> str | None:
    return next((f for f in fields.get(record_type or "", ()) if OWNER_FIELD_RX.match(f)), None)


def record_ownerless(record_type: str | None, fields: Mapping[str, Sequence[str]]) -> bool:
    """A record type the checkout declares with no owner field and nothing linking it to anyone."""
    names = fields.get(record_type or "")
    return (
        names is not None
        and owner_field(record_type, fields) is None
        and not any(_LINK_RX.match(f) for f in names)
    )


def classify(
    method: str,
    pattern: str,
    guards: Sequence[str],
    facts: HandlerFacts,
    fields: Mapping[str, Sequence[str]],
) -> tuple[RouteOwnership, OwnershipEvidence | None]:
    """`guards` are the route's effective guards; `fields` maps each record type the checkout
    declares to its field names."""
    if not guards or any(privileged_only(g) for g in guards):
        return RouteOwnership.NOT_APPLICABLE, None
    if not path_params(pattern):
        # an unresolved pattern (`Routes.CARD_BY_ID`) may still carry the id
        return (RouteOwnership.UNKNOWN if facts.takes_id else RouteOwnership.NOT_APPLICABLE), None
    if facts.ignores_id and not facts.lookups and not facts.handoff:
        return RouteOwnership.NOT_APPLICABLE, None

    def ownerless(x: Lookup) -> bool:
        return record_ownerless(x.record_type, fields)

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
