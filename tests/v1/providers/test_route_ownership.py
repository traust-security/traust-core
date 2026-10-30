"""Ownership of the object an authenticated id route acts on, from a handler's facts."""

from __future__ import annotations

import pytest

from traust_core.v1.models.code_facts import RouteFamily, RouteOwnership
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.route_guards import _row
from traust_core.v1.providers.route_ownership import (
    HandlerFacts,
    Lookup,
    classify,
    owner_field,
    path_params,
    privileged_only,
    rank,
)

FIELDS = {
    "Item": ("id", "name", "tenantId"),
    "Unit": ("code", "label"),
    "Holiday": ("date", "name"),
}
AUTH = ("spring-security:authenticated",)


def at(line: int) -> CodeSpan:
    return CodeSpan(path=RepoPath("src/Handler.java"), line=line)


@pytest.mark.parametrize(
    ("pattern", "params"),
    [
        ("/api/items/{id}", ("id",)),
        ("/files/{name:path}", ("name",)),
        ("/api/items/{id:\\d+}/manual/{file}", ("id", "file")),
        ("/api/tickets/:id", ("id",)),
        ("/teams/<int:team_id>", ("team_id",)),
        ("^shifts/(?P<pk>\\d+)/$", ("pk",)),
        ("^codes/(?P<code>[A-Z]{8})/$", ("code",)),
        ("^v/(?:a|b)/(?P<pk>\\d+)/$", ("pk",)),
        ("^x/[0-9]{8}/$", ()),
        ("^y/[a-z]{2,4}/$", ()),
        ("/api/report.csv", ()),
        ("", ()),
    ],
)
def test_path_params_reads_every_framework_shape(pattern: str, params: tuple[str, ...]) -> None:
    assert path_params(pattern) == params


@pytest.mark.parametrize(
    ("record_type", "field"),
    [("Item", "tenantId"), ("Unit", None), ("Missing", None), (None, None)],
)
def test_owner_field_is_the_first_owner_shaped_field(
    record_type: str | None, field: str | None
) -> None:
    assert owner_field(record_type, FIELDS) == field


@pytest.mark.parametrize(
    "name",
    ["owner", "ownerId", "user_id", "tenant", "teamId", "organization_id", "account", "createdBy"],
)
def test_owner_shaped_names(name: str) -> None:
    assert owner_field("T", {"T": ("id", name)}) == name


CASES = [
    # (case, method, pattern, guards, facts, expected)
    ("no id in the path", "GET", "/api/items", AUTH, HandlerFacts(), RouteOwnership.NOT_APPLICABLE),
    (
        "unauthenticated route",
        "GET",
        "/api/items/{id}",
        (),
        HandlerFacts(lookups=(Lookup(at(3), record_type="Item"),)),
        RouteOwnership.NOT_APPLICABLE,
    ),
    (
        "admin-only route",
        "DELETE",
        "/api/admin/tenants/{id}",
        ("@PreAuthorize(\"hasRole('ADMIN')\")", *AUTH),
        HandlerFacts(),
        RouteOwnership.NOT_APPLICABLE,
    ),
    (
        "lookup filtered by the caller",
        "GET",
        "/api/suppliers/{id}",
        AUTH,
        HandlerFacts(lookups=(Lookup(at(3), scoped=True, record_type="Item"),), caller=at(3)),
        RouteOwnership.SCOPED,
    ),
    (
        "record compared with the caller after loading",
        "DELETE",
        "/api/suppliers/{id}",
        AUTH,
        HandlerFacts(lookups=(Lookup(at(3), checked=True, record_type="Item"),), caller=at(4)),
        RouteOwnership.CHECKED,
    ),
    (
        "method security naming the id covers the object",
        "PUT",
        "/api/suppliers/{id}",
        AUTH,
        HandlerFacts(lookups=(Lookup(at(3), record_type="Item"),), check=at(1), handoff=at(9)),
        RouteOwnership.CHECKED,
    ),
    (
        "a scoped lookup doesn't cover an unscoped owner-bearing one",
        "GET",
        "/api/items/{id}",
        AUTH,
        HandlerFacts(
            lookups=(
                Lookup(at(3), scoped=True, record_type="Unit"),
                Lookup(at(4), record_type="Item"),
            ),
            caller=at(3),
        ),
        RouteOwnership.UNCHECKED,
    ),
    (
        "a check on one record doesn't settle another",
        "DELETE",
        "/api/items/{id}",
        AUTH,
        HandlerFacts(
            lookups=(Lookup(at(3), checked=True), Lookup(at(5), record_type="Item")),
        ),
        RouteOwnership.CALLER_BLIND,
    ),
    (
        "scoped and reference-data lookups together",
        "GET",
        "/api/items/{id}",
        AUTH,
        HandlerFacts(
            lookups=(Lookup(at(3), scoped=True), Lookup(at(4), record_type="Unit")),
            caller=at(3),
        ),
        RouteOwnership.SCOPED,
    ),
    (
        "reference data seen, but the id goes on past the hop",
        "GET",
        "/api/units/{code}",
        AUTH,
        HandlerFacts(lookups=(Lookup(at(3), record_type="Unit"),), hop=at(2), handoff=at(9)),
        RouteOwnership.UNKNOWN,
    ),
    (
        "a privileged role among ordinary ones",
        "GET",
        "/api/items/{id}",
        ("@PreAuthorize(\"hasAnyRole('ADMIN', 'USER')\")",),
        HandlerFacts(lookups=(Lookup(at(3), record_type="Item"),)),
        RouteOwnership.CALLER_BLIND,
    ),
    (
        "a privileged role or the owner",
        "GET",
        "/api/items/{id}",
        ("require_admin_or_owner",),
        HandlerFacts(lookups=(Lookup(at(3), record_type="Item"),)),
        RouteOwnership.CALLER_BLIND,
    ),
    (
        "owner-bearing record loaded with no caller in sight",
        "GET",
        "/api/items/{id}",
        AUTH,
        HandlerFacts(lookups=(Lookup(at(3), record_type="Item"),)),
        RouteOwnership.CALLER_BLIND,
    ),
    (
        "unresolved store reached through one hop",
        "GET",
        "/shifts/{shift_id}",
        ("get_current_user>oauth2_scheme",),
        HandlerFacts(lookups=(Lookup(at(9)),), hop=at(3)),
        RouteOwnership.CALLER_BLIND,
    ),
    (
        "empty mutating handler",
        "DELETE",
        "/api/folders/{id}",
        ('@RolesAllowed("member")',),
        HandlerFacts(),
        RouteOwnership.CALLER_BLIND,
    ),
    (
        "read whose id reaches nothing",
        "GET",
        "/api/folders/{id}/export",
        AUTH,
        HandlerFacts(),
        RouteOwnership.NOT_APPLICABLE,
    ),
    (
        "shared reference data",
        "GET",
        "/api/units/{code}",
        AUTH,
        HandlerFacts(lookups=(Lookup(at(3), record_type="Unit"),)),
        RouteOwnership.NONE,
    ),
    (
        "reference data reached through one hop",
        "GET",
        "/holidays/{holiday_id}",
        AUTH,
        HandlerFacts(lookups=(Lookup(at(9), record_type="Holiday"),), hop=at(3)),
        RouteOwnership.NONE,
    ),
    (
        "one owner-bearing lookup among reference data",
        "GET",
        "/api/items/{id}",
        AUTH,
        HandlerFacts(
            lookups=(Lookup(at(3), record_type="Unit"), Lookup(at(4), record_type="Item"))
        ),
        RouteOwnership.CALLER_BLIND,
    ),
    (
        "caller referenced but the owner-bearing lookup isn't tied to it",
        "PUT",
        "/api/items/{id}",
        AUTH,
        HandlerFacts(lookups=(Lookup(at(3), record_type="Item"),), caller=at(2)),
        RouteOwnership.UNCHECKED,
    ),
    (
        "caller referenced, store unresolved",
        "PUT",
        "/api/items/{id}",
        AUTH,
        HandlerFacts(lookups=(Lookup(at(3)),), caller=at(2)),
        RouteOwnership.UNKNOWN,
    ),
    (
        "id handed on past the one hop",
        "GET",
        "/api/items/{id}",
        AUTH,
        HandlerFacts(hop=at(3), handoff=at(12)),
        RouteOwnership.UNKNOWN,
    ),
]


@pytest.mark.parametrize(
    ("method", "pattern", "guards", "facts", "expected"),
    [c[1:] for c in CASES],
    ids=[c[0] for c in CASES],
)
def test_classify(
    method: str,
    pattern: str,
    guards: tuple[str, ...],
    facts: HandlerFacts,
    expected: RouteOwnership,
) -> None:
    assert classify(method, pattern, guards, facts, FIELDS)[0] is expected


@pytest.mark.parametrize(
    ("guard", "privileged"),
    [
        ("@PreAuthorize(\"hasRole('ADMIN')\")", True),
        ('@RolesAllowed("admin")', True),
        ("require_admin", True),
        ("get_current_active_superuser", True),
        ("@PreAuthorize(\"hasAnyRole('ADMIN', 'USER')\")", False),
        ('@RolesAllowed({"admin", "member"})', False),
        ("require_admin_or_owner", False),
        ("@PreAuthorize(\"hasRole('ADMIN') or #id == principal.id\")", False),
        ("requireAuth", False),
    ],
)
def test_privileged_only_needs_every_way_in_to_be_privileged(guard: str, privileged: bool) -> None:
    assert privileged_only(guard) is privileged


def test_evidence_points_at_the_exposed_lookup_not_the_scoped_one() -> None:
    facts = HandlerFacts(
        lookups=(Lookup(at(3), scoped=True, record_type="Unit"), Lookup(at(4), record_type="Item")),
        caller=at(3),
    )
    _, evidence = classify("GET", "/api/items/{id}", AUTH, facts, FIELDS)
    assert evidence is not None and evidence.lookup == at(4) and evidence.owner_field == "tenantId"


def test_evidence_names_the_owner_bearing_lookup_and_what_was_absent() -> None:
    facts = HandlerFacts(
        lookups=(Lookup(at(3), record_type="Unit"), Lookup(at(4), record_type="Item")), hop=at(2)
    )
    _, evidence = classify("GET", "/api/items/{id}", AUTH, facts, FIELDS)
    assert evidence is not None
    assert evidence.lookup == at(4)
    assert (evidence.record_type, evidence.owner_field) == ("Item", "tenantId")
    assert (evidence.caller, evidence.check, evidence.hop) == (None, None, at(2))


def test_not_applicable_rows_carry_no_evidence() -> None:
    assert classify("GET", "/api/items", AUTH, HandlerFacts(), FIELDS) == (
        RouteOwnership.NOT_APPLICABLE,
        None,
    )


def test_rank_puts_owner_bearing_judged_rows_first() -> None:
    owned = classify(
        "GET", "/i/{id}", AUTH, HandlerFacts(lookups=(Lookup(at(1), record_type="Item"),)), FIELDS
    )
    untyped = classify("GET", "/i/{id}", AUTH, HandlerFacts(lookups=(Lookup(at(1)),)), FIELDS)
    scoped = classify(
        "GET", "/i/{id}", AUTH, HandlerFacts(lookups=(Lookup(at(1), scoped=True),)), FIELDS
    )
    assert [rank(*owned), rank(*untyped), rank(*scoped), rank(None, None)] == [0, 1, 2, 2]


def test_a_judged_ownership_row_is_judged_and_keeps_its_classification() -> None:
    row = _row(
        RouteFamily.SPRING,
        "GET",
        "/api/items/{id}",
        "ItemController.get",
        "a.java",
        3,
        [],
        list(AUTH),
        [],
    )
    assert not row.judgement_required
    row.own(HandlerFacts(lookups=(Lookup(at(3), record_type="Item"),)), FIELDS)
    model = row.model()
    assert model.judgement_required
    assert model.ownership is RouteOwnership.CALLER_BLIND
    assert (
        model.ownership_evidence is not None and model.ownership_evidence.owner_field == "tenantId"
    )


def test_a_settled_ownership_never_clears_an_existing_judgement() -> None:
    row = _row(RouteFamily.SPRING, "GET", "/api/items/{id}", "h", "a.java", 3, [], [], [])
    assert row.judgement_required
    row.own(HandlerFacts(lookups=(Lookup(at(3), scoped=True),)), FIELDS)
    assert row.judgement_required and row.ownership is RouteOwnership.NOT_APPLICABLE


def test_a_guard_beside_an_unguard_marker_is_not_authentication() -> None:
    row = _row(
        RouteFamily.SPRING,
        "GET",
        "/api/items/{id}",
        "h",
        "a.java",
        3,
        ['@PreAuthorize("isAuthenticated()")'],
        [],
        ["method-security-not-enabled"],
    )
    row.own(HandlerFacts(lookups=(Lookup(at(3), record_type="Item"),)), FIELDS)
    assert row.ownership is RouteOwnership.NOT_APPLICABLE and row.judgement_required


def test_rows_left_unclassified_carry_no_ownership() -> None:
    model = _row(
        RouteFamily.SPRING, "GET", "/api/items/{id}", "h", "a.java", 3, [], list(AUTH), []
    ).model()
    assert model.ownership is None and model.ownership_evidence is None
