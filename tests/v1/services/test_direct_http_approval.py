from datetime import UTC, datetime, timedelta

import pytest

from traust_core.v1.errors import ForbiddenError
from traust_core.v1.models.artifacts import SchemaView
from traust_core.v1.models.validation import (
    ClusterScope,
    HttpDiscovery,
    HttpTarget,
    OffLimit,
    ValidationScope,
)
from traust_core.v1.services.validation import _authorize_http_step

NOW = datetime(2026, 10, 22, 12, tzinfo=UTC)


@pytest.fixture
def scope() -> ValidationScope:
    return ValidationScope.bind(
        explicit=ValidationScope(
            clusters=(
                ClusterScope(context="lab", api="https://api.example", namespaces=("app",)),
            ),
            http_targets=(HttpTarget(host="app.example", context="lab", resource="http_targets"),),
        )
    )


def direct_step(
    *,
    url: str = "https://app.example:8443",
    context: str = "lab",
    namespace: str | None = None,
    name: str | None = None,
    method: str = "GET",
    scheme: str = "auto",
    port: int | None = None,
    authenticate: bool = False,
    csrf: bool = False,
    classification: str | None = None,
) -> SchemaView:
    if classification is None:
        classification = "destructive" if method in {"POST", "PUT", "PATCH", "DELETE"} else "safe"
    return SchemaView(
        [],
        {
            "adapter": "k8s",
            "verb": "port-forward+http",
            "classification": classification,
            "target": {
                "context": context,
                "namespace": namespace,
                "resource": "http_targets",
                "name": name,
                "http": {
                    "mode": "direct",
                    "url": url,
                    "name": name,
                    "namespaces": [namespace] if namespace else [],
                    "method": method,
                    "scheme": scheme,
                    "port": port,
                    "authenticate": authenticate,
                    "csrf": csrf,
                },
            },
        },
        "step",
    )


@pytest.mark.parametrize("name", [None, "web"])
@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"])
def test_approval_allows_namespace_less_direct_http(
    scope: ValidationScope, name: str | None, method: str
) -> None:
    grant = scope.http_targets[0].model_copy(update={"name": name})
    _authorize_http_step(
        direct_step(name=name, method=method),
        scope.model_copy(update={"http_targets": (grant,)}),
        NOW,
    )


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("classification", ["safe", "mutating"])
def test_approval_rejects_underclassified_http_writes(
    scope: ValidationScope, method: str, classification: str
) -> None:
    with pytest.raises(ForbiddenError, match="classification"):
        _authorize_http_step(direct_step(method=method, classification=classification), scope, NOW)


def test_named_grants_do_not_authorize_another_name(scope: ValidationScope) -> None:
    grant = scope.http_targets[0].model_copy(update={"name": "web"})
    named = scope.model_copy(update={"http_targets": (grant,)})
    _authorize_http_step(direct_step(name="web"), named, NOW)
    with pytest.raises(ForbiddenError):
        _authorize_http_step(direct_step(name="other"), named, NOW)
    with pytest.raises(ForbiddenError):
        _authorize_http_step(direct_step(), named, NOW)


@pytest.mark.parametrize(
    "url",
    [
        "https://other.example",
        "https://app.example/path",
        "https://user@app.example",
        "https://app.example:",
        "https://app.example?query",
        "https://app.example#fragment",
    ],
)
def test_approval_rejects_different_host_or_invalid_origin(
    scope: ValidationScope, url: str
) -> None:
    with pytest.raises(ForbiddenError):
        _authorize_http_step(direct_step(url=url), scope, NOW)


@pytest.mark.parametrize("scheme,port", [("http", None), ("https", 443), ("auto", 1234)])
def test_approval_rejects_scheme_and_port_mismatches(
    scope: ValidationScope, scheme: str, port: int | None
) -> None:
    with pytest.raises(ForbiddenError):
        _authorize_http_step(direct_step(scheme=scheme, port=port), scope, NOW)


def test_approval_requires_exact_context_pinned_api_and_explicit_binding(
    scope: ValidationScope,
) -> None:
    with pytest.raises(ForbiddenError):
        _authorize_http_step(direct_step(context="other"), scope, NOW)
    with pytest.raises(ForbiddenError):
        _authorize_http_step(direct_step(), scope.model_copy(update={"modes": frozenset()}), NOW)
    unpinned = scope.clusters[0].model_copy(update={"api": None})
    with pytest.raises(ForbiddenError):
        _authorize_http_step(direct_step(), scope.model_copy(update={"clusters": (unpinned,)}), NOW)
    with pytest.raises(ForbiddenError):
        _authorize_http_step(direct_step(), scope.model_copy(update={"http_targets": ()}), NOW)


def test_approval_checks_expiry_off_limits_and_both_verbs(scope: ValidationScope) -> None:
    for restricted in (
        scope.model_copy(update={"expires_at": NOW}),
        scope.model_copy(update={"off_limits": (OffLimit(resource="http_targets", verb="get"),)}),
        scope.model_copy(
            update={"off_limits": (OffLimit(resource="http_targets", verb="port-forward+http"),)}
        ),
    ):
        with pytest.raises(ForbiddenError):
            _authorize_http_step(direct_step(), restricted, NOW)
    for verb in ("port-forward+http", "get"):
        cluster = scope.clusters[0].model_copy(update={"verbs_denied": frozenset({verb})})
        with pytest.raises(ForbiddenError):
            _authorize_http_step(
                direct_step(), scope.model_copy(update={"clusters": (cluster,)}), NOW
            )
    _authorize_http_step(
        direct_step(), scope.model_copy(update={"expires_at": NOW + timedelta(seconds=1)}), NOW
    )


@pytest.mark.parametrize(
    "method,verb",
    [
        ("GET", "get"),
        ("HEAD", "get"),
        ("OPTIONS", "get"),
        ("POST", "create"),
        ("PUT", "update"),
        ("PATCH", "patch"),
        ("DELETE", "delete"),
    ],
)
def test_approval_checks_the_mapped_method_verb(
    scope: ValidationScope, method: str, verb: str
) -> None:
    cluster = scope.clusters[0].model_copy(update={"verbs_denied": frozenset({verb})})
    denied = scope.model_copy(update={"clusters": (cluster,)})
    with pytest.raises(ForbiddenError):
        _authorize_http_step(direct_step(method=method), denied, NOW)


def test_approval_keeps_credentials_bound_to_matching_direct_grant(scope: ValidationScope) -> None:
    policy = HttpDiscovery(session_check_path="/whoami", session_check_contains="alice")
    cluster = scope.clusters[0].model_copy(update={"http_discovery": policy})
    with_policy = scope.model_copy(update={"clusters": (cluster,)})
    for auth in ({"authenticate": True}, {"csrf": True}):
        with pytest.raises(ForbiddenError):
            _authorize_http_step(direct_step(**auth), with_policy, NOW)
        credential_grant = scope.http_targets[0].model_copy(update={"credentials": True})
        permitted = with_policy.model_copy(update={"http_targets": (credential_grant,)})
        _authorize_http_step(direct_step(**auth), permitted, NOW)
    with pytest.raises(ForbiddenError):
        _authorize_http_step(direct_step(authenticate=True), scope, NOW)


def test_namespaced_direct_http_still_uses_kubernetes_namespace_rules(
    scope: ValidationScope,
) -> None:
    _authorize_http_step(direct_step(namespace="app"), scope, NOW)
    with pytest.raises(ForbiddenError):
        _authorize_http_step(direct_step(namespace="private"), scope, NOW)
    cluster = scope.clusters[0].model_copy(update={"namespaces": ()})
    with pytest.raises(ForbiddenError):
        _authorize_http_step(
            direct_step(namespace="app"), scope.model_copy(update={"clusters": (cluster,)}), NOW
        )
