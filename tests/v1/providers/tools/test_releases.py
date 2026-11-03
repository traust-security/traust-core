from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Mapping
from datetime import UTC, datetime
from email.message import Message

import pytest

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.providers.http import HttpFetcher, RetryPolicy
from traust_core.v1.providers.tools.releases import ToolRelease, ToolReleases
from traust_core.v1.providers.tools.toolchain import ToolUpstream, UpstreamKind

PUBLISHED = datetime(2026, 7, 1, 12, tzinfo=UTC)
GITHUB = "https://api.github.com/repos/example/scanner/releases/latest"
PYPI = "https://pypi.org/pypi/scanner/json"
GOPROXY = "https://proxy.golang.org/example.org/scanner/@latest"


class Response:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.body


class ReleaseHttp:
    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, answers: Mapping[str, bytes | Exception]
    ) -> None:
        self.answers = dict(answers)
        self.requests: list[urllib.request.Request] = []
        monkeypatch.setattr(urllib.request, "urlopen", self.open)
        self.lookup = ToolReleases(
            HttpFetcher("test", RetryPolicy(max_attempts=1)), github_token="fixture-token"
        )

    def open(self, request: urllib.request.Request, timeout: float) -> Response:
        self.requests.append(request)
        answer = self.answers[request.full_url]
        if isinstance(answer, Exception):
            raise answer
        return Response(answer)


def github(version: str = "v1.2.3", published: datetime = PUBLISHED) -> bytes:
    return json.dumps({"tag_name": version, "published_at": published.isoformat()}).encode()


def pypi(version: str = "1.2.3", published: datetime = PUBLISHED) -> bytes:
    return json.dumps(
        {
            "info": {"version": version},
            "urls": [{"upload_time_iso_8601": published.isoformat(), "yanked": False}],
        }
    ).encode()


@pytest.mark.parametrize(
    ("kind", "ref", "url", "body"),
    [
        (UpstreamKind.GITHUB, "example/scanner", GITHUB, github()),
        (UpstreamKind.PYPI, "scanner", PYPI, pypi()),
        (
            UpstreamKind.GOPROXY,
            "example.org/scanner",
            GOPROXY,
            b'{"Version":"v1.2.3","Time":"2026-07-01T12:00:00Z"}',
        ),
    ],
)
def test_manifest_registry_releases_have_normalized_versions_and_aware_publication_times(
    monkeypatch: pytest.MonkeyPatch, kind: UpstreamKind, ref: str, url: str, body: bytes
) -> None:
    http = ReleaseHttp(monkeypatch, {url: body})
    assert http.lookup.latest(ToolUpstream(kind=kind, ref=ref)) == ToolRelease("1.2.3", PUBLISHED)
    [request] = http.requests
    assert request.full_url == url
    assert request.get_header("Authorization") == (
        "Bearer fixture-token" if kind is UpstreamKind.GITHUB else None
    )


def test_go_module_uppercase_is_escaped_for_the_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://proxy.golang.org/example.org/!scanner/@latest"
    http = ReleaseHttp(monkeypatch, {url: b'{"Version":"v1.2.3","Time":"2026-07-01T12:00:00Z"}'})
    assert http.lookup.latest(
        ToolUpstream(kind=UpstreamKind.GOPROXY, ref="example.org/Scanner")
    ) == ToolRelease("1.2.3", PUBLISHED)


def test_pinned_publication_uses_the_earliest_non_yanked_upload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = "https://pypi.org/pypi/scanner/1.2.3/json"
    body = json.dumps(
        {
            "info": {"version": "1.2.3"},
            "urls": [
                {"upload_time_iso_8601": "2026-07-02T12:00:00Z"},
                {"upload_time_iso_8601": "2026-06-01T12:00:00Z", "yanked": True},
                {"upload_time_iso_8601": "2026-07-01T12:00:00Z"},
            ],
        }
    ).encode()
    http = ReleaseHttp(monkeypatch, {url: body})
    assert http.lookup.pinned("scanner", "1.2.3") == ToolRelease("1.2.3", PUBLISHED)
    assert http.requests[0].get_header("Authorization") is None


@pytest.mark.parametrize(
    "body",
    [
        b"not-json",
        b"[]",
        b'{"tag_name":"v1.2.3"}',
        b'{"tag_name":"v1.2.3","published_at":null}',
        b'{"tag_name":"v1.2.3","published_at":"2026-07-01T12:00:00"}',
        b'{"tag_name":"HEAD","published_at":"2026-07-01T12:00:00Z"}',
        github("v1.2.3-rc1"),
        b'{"tag_name":"v1.2.3","published_at":"2026-07-01T12:00:00Z","draft":true}',
        b'{"tag_name":"v1.2.3","published_at":"2026-07-01T12:00:00Z","prerelease":true}',
    ],
)
def test_unusable_release_metadata_is_a_typed_error(
    monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    lookup = ReleaseHttp(monkeypatch, {GITHUB: body}).lookup
    with pytest.raises(ValidationError):
        lookup.latest(ToolUpstream(kind=UpstreamKind.GITHUB, ref="example/scanner"))


@pytest.mark.parametrize(
    "body",
    [
        b'{"info":{"version":"1.2.3"},"urls":[]}',
        b'{"info":{"version":"1.2.3"},"urls":[{"upload_time_iso_8601":"bad"}]}',
        b'{"info":{"version":"1.2.3"},"urls":[{"upload_time_iso_8601":'
        b'"2026-07-01T12:00:00Z","yanked":true}]}',
        pypi("2.0.0"),
    ],
)
def test_missing_yanked_or_wrong_pypi_pin_does_not_invent_an_age(
    monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    url = "https://pypi.org/pypi/scanner/1.2.3/json"
    lookup = ReleaseHttp(monkeypatch, {url: body}).lookup
    with pytest.raises(ValidationError):
        lookup.pinned("scanner", "1.2.3")


@pytest.mark.parametrize("status", [403, 404, 429, 503])
def test_http_failure_preserves_the_transport_status(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    error = urllib.error.HTTPError(GITHUB, status, "fixture", Message(), None)
    lookup = ReleaseHttp(monkeypatch, {GITHUB: error}).lookup
    with pytest.raises(ServiceError) as failure:
        lookup.latest(ToolUpstream(kind=UpstreamKind.GITHUB, ref="example/scanner"))
    assert failure.value.status == (None if status == 503 else status)


def test_timeout_is_a_service_error_not_missing_release(monkeypatch: pytest.MonkeyPatch) -> None:
    lookup = ReleaseHttp(monkeypatch, {GITHUB: TimeoutError("fixture")}).lookup
    with pytest.raises(ServiceError) as failure:
        lookup.latest(ToolUpstream(kind=UpstreamKind.GITHUB, ref="example/scanner"))
    assert failure.value.status is None
