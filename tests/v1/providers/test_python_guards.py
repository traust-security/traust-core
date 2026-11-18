"""Which decorators, mixins and permission classes count as authentication guards: a known
library guard the checkout doesn't redefine (D37)."""

from __future__ import annotations

import ast
from textwrap import dedent

import pytest

from traust_core.v1.providers.python_guards import (
    FLASK_LOGIN_GUARDS,
    GuardReader,
    requires_nothing,
)


def _reader(code: str = "", **kwargs: frozenset[str]) -> GuardReader:
    defs = {
        n.name: n
        for n in ast.parse(dedent(code)).body
        if isinstance(n, ast.FunctionDef | ast.ClassDef)
    }
    return GuardReader(lambda name: defs.get(name.split(".")[-1]), **kwargs)


CHECKOUT = """
def admin_required(f):
    def inner(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(403)
        return f(*args, **kwargs)
    return inner

def login_required(f):
    return f

class IsAuthenticated(BasePermission):
    def has_permission(self, request, view):
        return True

class IsMember(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)
"""


@pytest.mark.parametrize(
    ("name", "guards"),
    [
        ("permission_required", True),  # a library guard
        ("flask_login.fresh_login_required", True),
        ("LoginRequiredMixin", True),
        ("token_required", False),  # a name no auth library has
        ("admin_required", False),  # checkout code, however it reads
        ("login_required", False),  # a checkout definition shadowing a known guard
    ],
)
def test_a_guard_is_a_known_library_guard_the_checkout_doesnt_redefine(
    name: str, guards: bool
) -> None:
    assert _reader(CHECKOUT).guards(name) is guards


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("rest_framework.permissions.IsAdminUser", "guard"),
        ("IsAuthenticatedOrReadOnly", "read-only"),
        ("IsAuthenticated", "none"),  # the checkout's own class of that name admits anyone
        ("IsMember", "none"),  # checkout code, however it reads
        ("HasScope", "none"),  # a library class we don't know
    ],
)
def test_a_permission_class_is_a_known_library_class(name: str, kind: str) -> None:
    assert _reader(CHECKOUT).permission(name) == kind


def test_login_disabled_turns_flask_logins_guards_off() -> None:
    reader = _reader(disabled=FLASK_LOGIN_GUARDS)
    assert not reader.guards("login_required")
    assert reader.guards("jwt_required")


@pytest.mark.parametrize(
    ("decorator", "nothing"),
    [
        ("permission_required([])", True),
        ("permission_required(perm=())", True),
        ("security.roles_required()", True),
        ("roles_accepted(*ROLES)", False),  # what it is given is unknown
        ("permission_required('notes.view_note')", False),
        ("login_required()", False),  # no requirement guard
    ],
)
def test_a_requirement_guard_given_nothing_admits_anyone(decorator: str, nothing: bool) -> None:
    assert requires_nothing(ast.parse(decorator, mode="eval").body) is nothing


@pytest.mark.parametrize(
    ("full", "guards"),
    [
        ("django.contrib.auth.decorators.login_required", True),
        ("flask_login.login_required", True),  # imported under another name
        ("app.auth.login_required", True),  # a checkout module re-exporting one
        ("someauth.decorators.login_required", False),  # another library's of that name
        ("", True),  # not imported here: read by its name
    ],
)
def test_a_guard_is_read_through_its_import(full: str, guards: bool) -> None:
    reader = GuardReader(
        lambda name: None, origin=lambda name: full, local=lambda f: f.startswith("app.")
    )
    assert reader.guards("require_login" if full else "login_required") is guards
