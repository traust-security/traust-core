"""What counts as an authentication guard for Django, DRF and Flask routes (D37): a known
guard of those frameworks' auth libraries, and only when no checkout definition shadows its
name. Checkout decorators, mixins, permission classes and hooks are no guards."""

from __future__ import annotations

import ast
from collections.abc import Callable

# library decorators and mixins that refuse an anonymous caller
KNOWN_GUARDS = {
    "login_required", "permission_required", "staff_member_required", "superuser_required",
    "fresh_login_required", "jwt_required", "auth_required", "roles_required", "roles_accepted",
    "permissions_required", "permissions_accepted", "http_auth_required", "token_auth_required",
    "auth_token_required", "LoginRequiredMixin", "PermissionRequiredMixin",
}  # fmt: skip
# flask-login's guards, which `LOGIN_DISABLED` turns off
FLASK_LOGIN_GUARDS = frozenset({"login_required", "fresh_login_required"})
# DRF permission classes that refuse an anonymous caller, and those that let one read
KNOWN_PERMISSIONS = {
    "IsAuthenticated", "IsAdminUser", "DjangoModelPermissions", "DjangoObjectPermissions",
    "TokenHasScope", "TokenHasReadWriteScope", "TokenHasResourceScope", "HasAPIKey",
}  # fmt: skip
READ_ONLY_PERMISSIONS = {"IsAuthenticatedOrReadOnly", "DjangoModelPermissionsOrAnonReadOnly"}
# guards that check what they are given: given nothing, they admit anyone
REQUIREMENT_GUARDS = {
    "permission_required", "roles_required", "roles_accepted", "permissions_required",
    "permissions_accepted",
}  # fmt: skip
# the auth libraries those guards come from: a name imported from any other library is no guard
AUTH_LIBRARIES = (
    "django.", "rest_framework.", "rest_framework_api_key.", "oauth2_provider.", "braces.",
    "flask_login.", "flask_jwt_extended.", "flask_jwt.", "flask_httpauth.", "flask_security.",
    "flask_user.",
)  # fmt: skip
# a checkout binding that can't be read (an assignment, a module this interpreter can't parse)
UNREADABLE = ast.Module(body=[], type_ignores=[])

Resolve = Callable[[str], ast.AST | None]


def empty(node: ast.AST | None) -> bool:
    """An empty literal: `[]`, `()`, `""`."""
    if isinstance(node, ast.List | ast.Tuple | ast.Set | ast.Dict):
        return not getattr(node, "elts", getattr(node, "keys", None))
    return isinstance(node, ast.Constant) and node.value in ("", None)


def requires_nothing(d: ast.AST, called: str = "") -> bool:
    """`permission_required([])`, `roles_required()`: a requirement guard (`called`, else the
    name written) given nothing."""
    if not isinstance(d, ast.Call):
        return False
    if (called or ast.unparse(d.func)).split(".")[-1] not in REQUIREMENT_GUARDS:
        return False
    first = d.args[0] if d.args else next((k.value for k in d.keywords if k.arg == "perm"), None)
    return first is None or empty(first)


class GuardReader:
    """Whether a name is a known guard; `resolve` finds a checkout definition by the name used
    for it (None for a library's), which makes the name no known guard."""

    def __init__(
        self,
        resolve: Resolve,
        *,
        disabled: frozenset[str] = frozenset(),
        origin: Callable[[str], str] = lambda name: "",
        local: Callable[[str], bool] = lambda full: False,
    ) -> None:
        self.resolve = resolve
        self.disabled = disabled  # known guards configured off (flask-login's `LOGIN_DISABLED`)
        self.origin = origin  # the full name a name is imported as, "" for one not imported
        self.local = local  # whether a full name is in a checkout module

    def name(self, written: str) -> str:
        """The library name a written name stands for: an alias's original (`login_required as
        require_login`); "" for one another library exports (`from oauth.utils import ..`)."""
        full = self.origin(written)
        if full and not full.startswith(AUTH_LIBRARIES) and not self.local(full):
            return ""
        return (full or written).split(".")[-1]

    def guards(self, name: str) -> bool:
        """A decorator or mixin named `name` is a known guard the checkout doesn't redefine."""
        return self.name(name) in KNOWN_GUARDS - self.disabled and self.resolve(name) is None

    def permission(self, name: str) -> str:
        """`guard`, `read-only` (lets an anonymous caller read) or `none`."""
        last = self.name(name)
        if self.resolve(name) is not None:
            return "none"  # a checkout class, whatever its name
        if last in KNOWN_PERMISSIONS:
            return "guard"
        return "read-only" if last in READ_ONLY_PERMISSIONS else "none"
