from datetime import UTC, date, datetime, timedelta

import pytest

from traust_core.v1.models.validation import (
    ClusterScope,
    HttpTarget,
    OffLimit,
    ValidationAction,
    ValidationActionKind,
    ValidationScope,
    ValidationTarget,
)

NOW = datetime(2026, 10, 22, 12, tzinfo=UTC)
HTTP = ValidationAction(kind=ValidationActionKind.HTTP, verb="get")
TARGET = ValidationTarget(
    context="lab", resource="http_targets", name="web", url="https://app.example:8443"
)


@pytest.fixture
def scope() -> ValidationScope:
    return ValidationScope.bind(
        explicit=ValidationScope(
            clusters=(
                ClusterScope(context="lab", api="https://api.example:6443", namespaces=("app",)),
            ),
            http_targets=(
                HttpTarget(
                    host="app.example", context="lab", resource="http_targets", name="web"
                ),
            ),
        )
    )


def permits(scope: ValidationScope, target: ValidationTarget = TARGET, verb: str = "get") -> bool:
    return scope.permits(
        ValidationAction(kind=ValidationActionKind.HTTP, verb=verb), target, as_of=NOW
    )


@pytest.mark.parametrize(
    "verb", ["port-forward+http", "get", "create", "update", "patch", "delete"]
)
def test_direct_http_allows_supported_verbs_for_exact_explicit_target(
    scope: ValidationScope, verb: str
) -> None:
    assert permits(scope, verb=verb)
    assert permits(scope, TARGET.model_copy(update={"url": "https://APP.EXAMPLE.:8443/"}), verb)


@pytest.mark.parametrize("verb", ["list", "watch", "exec", "port-forward", "GET"])
def test_direct_http_rejects_unrelated_verbs(scope: ValidationScope, verb: str) -> None:
    assert not permits(scope, verb=verb)


@pytest.mark.parametrize(
    "change",
    [
        {"url": "https://other.example:8443"},
        {"context": "other"},
        {"context": None},
        {"context": "__current__"},
        {"context": "lab context"},
        {"namespace": "app"},
        {"namespace": ""},
        {"resource": "routes"},
        {"resource": None},
        {"name": "other"},
        {"name": None},
        {"name": ""},
        {"image": "image.example/app"},
    ],
)
def test_direct_http_requires_the_granted_identity(
    scope: ValidationScope, change: dict[str, object]
) -> None:
    assert not permits(scope, TARGET.model_copy(update=change))


@pytest.mark.parametrize(
    "url",
    [
        None,
        "",
        "app.example",
        "ftp://app.example",
        "https://user@app.example",
        "https://app.example/path",
        "https://app.example?",
        "https://app.example?q=1",
        "https://app.example#",
        "https://app.example#fragment",
        "https://app.example:",
        "https://app.example:0",
        "https://app.example:65536",
        "https://app.example:bad",
        "https://app.example:443:80",
        "https://app.example\\@evil.example",
        "https://app.example\n.evil.example",
        "https://[::1]suffix",
        "https://[fe80::1%25eth0]",
        "https://[not-ipv6]",
    ],
)
def test_direct_http_rejects_invalid_or_non_origin_urls(
    scope: ValidationScope, url: str | None
) -> None:
    assert not permits(scope, TARGET.model_copy(update={"url": url}))


def test_direct_http_supports_exact_ipv6_grants(scope: ValidationScope) -> None:
    grant = HttpTarget(host="2001:db8::1", context="lab", resource="http_targets", name="web")
    scope = scope.model_copy(update={"http_targets": (grant,)})
    assert permits(scope, TARGET.model_copy(update={"url": "http://[2001:db8::1]:8080"}))
    assert not permits(scope, TARGET.model_copy(update={"url": "http://[2001:db8::2]:8080"}))


@pytest.mark.parametrize(
    "grant",
    [
        HttpTarget(host="other.example", context="lab"),
        HttpTarget(host="app.example", context="other"),
        HttpTarget(host="app.example", context="lab", namespace="app"),
        HttpTarget(host="app.example", context="lab", resource="routes"),
        HttpTarget(host="app.example", context="lab", name="other"),
    ],
)
def test_direct_http_rejects_nonmatching_explicit_grants(
    scope: ValidationScope, grant: HttpTarget
) -> None:
    assert not permits(scope.model_copy(update={"http_targets": (grant,)}))
    assert not permits(scope.model_copy(update={"http_targets": ()}))


@pytest.mark.parametrize("resource,name", [(None, None), ("http_targets", None), (None, "web")])
def test_direct_http_preserves_optional_grant_fields(
    scope: ValidationScope, resource: str | None, name: str | None
) -> None:
    grant = HttpTarget(host="app.example", context="lab", resource=resource, name=name)
    assert permits(scope.model_copy(update={"http_targets": (grant,)}))


def test_direct_http_requires_explicit_binding_and_does_not_promote_weaker_grants() -> None:
    layer = ValidationScope(
        clusters=(ClusterScope(context="lab", api="https://api.example"),),
        http_targets=(HttpTarget(host="app.example", context="lab"),),
    )
    assert not permits(ValidationScope.bind(inline=layer))
    assert not permits(ValidationScope.bind(inferred=layer))
    explicit = ValidationScope(clusters=(ClusterScope(context="lab"),))
    assert not permits(ValidationScope.bind(explicit=explicit, inline=layer))
    explicit_target_without_api = ValidationScope(
        clusters=(ClusterScope(context="lab"),), http_targets=layer.http_targets
    )
    assert not permits(ValidationScope.bind(explicit=explicit_target_without_api, inline=layer))
    explicit_api_without_target = ValidationScope(clusters=layer.clusters)
    assert not permits(ValidationScope.bind(explicit=explicit_api_without_target, inferred=layer))


@pytest.mark.parametrize("api", [None, "https://api.example/path", "https://api.example:"])
def test_direct_http_requires_valid_pinned_api(scope: ValidationScope, api: str | None) -> None:
    cluster = scope.clusters[0].model_copy(update={"api": api})
    assert not permits(scope.model_copy(update={"clusters": (cluster,)}))


def test_direct_http_never_uses_current_context_fallback(scope: ValidationScope) -> None:
    cluster = scope.clusters[0].model_copy(update={"context": "__current__"})
    assert not permits(scope.model_copy(update={"clusters": (cluster,)}))


def test_direct_http_obeys_expiry_and_clock(scope: ValidationScope) -> None:
    assert permits(scope.model_copy(update={"expires": NOW.date()}))
    assert not permits(scope.model_copy(update={"expires": NOW.date() - timedelta(days=1)}))
    deadline = scope.model_copy(update={"expires_at": NOW})
    assert deadline.permits(HTTP, TARGET, as_of=NOW - timedelta(microseconds=1))
    assert not deadline.permits(HTTP, TARGET, as_of=NOW)
    assert not deadline.permits(HTTP, TARGET, as_of=date(2026, 10, 22))
    assert not deadline.permits(HTTP, TARGET, as_of=NOW.replace(tzinfo=None))


def test_direct_http_obeys_off_limits_and_denied_verbs(scope: ValidationScope) -> None:
    restricted = scope.model_copy(
        update={"off_limits": (OffLimit(resource="http_targets", verb="get"),)}
    )
    assert not permits(restricted)
    assert permits(restricted, verb="patch")
    cluster = scope.clusters[0].model_copy(update={"verbs_denied": frozenset({"get"})})
    restricted = scope.model_copy(update={"clusters": (cluster,)})
    assert not permits(restricted)
    assert permits(restricted, verb="patch")


def test_direct_http_does_not_bypass_namespace_qualified_off_limits(scope: ValidationScope) -> None:
    restricted = scope.model_copy(update={"off_limits": (OffLimit(namespace="private"),)})
    assert not permits(restricted)


def test_direct_http_grant_does_not_authorize_generic_kubernetes(scope: ValidationScope) -> None:
    for verb in ("get", "port-forward+http", "exec", "delete"):
        action = ValidationAction(kind=ValidationActionKind.K8S, verb=verb)
        assert not scope.permits(action, TARGET, as_of=NOW)
        assert not scope.permits(action, TARGET.model_copy(update={"resource": "pods"}), as_of=NOW)
