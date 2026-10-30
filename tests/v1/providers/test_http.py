import http.client as http_client
import logging
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from email.message import Message
from typing import Any

import pytest

from traust_core.v1.errors import ServiceError
from traust_core.v1.providers import http
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.correlation import correlation_scope
from traust_core.v1.providers.http import HttpFetcher, RetryPolicy


class _Resp:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> "_Resp":
        return self

    def __exit__(self, *a: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def _urlopen(actions: list[Any], calls: list[int]) -> Callable[..., _Resp]:
    """Walks ``actions``: bytes are returned as the body, exceptions are raised."""
    it = iter(actions)

    def _open(req: object, timeout: float | None = None) -> _Resp:
        calls.append(1)
        action = next(it)
        if isinstance(action, Exception):
            raise action
        return _Resp(action)

    return _open


def _http_error(code: int, retry_after: str | None = None) -> urllib.error.HTTPError:
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError("http://feed.test", code, "err", headers, None)


def _fetcher(slept: list[float], **policy: float) -> HttpFetcher:
    base: dict[str, float] = {"max_attempts": 3, "backoff_base_seconds": 0, "max_wait_seconds": 10}
    return HttpFetcher(
        "test-agent",
        RetryPolicy(**{**base, **policy}),  # type: ignore[arg-type]
        clock=FixedClock(datetime(2026, 1, 1, tzinfo=UTC)),
        sleep=slept.append,
    )


def _patch(monkeypatch: pytest.MonkeyPatch, actions: list[Any]) -> list[int]:
    calls: list[int] = []
    monkeypatch.setattr(http.urllib.request, "urlopen", _urlopen(actions, calls))
    return calls


def test_retries_5xx_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [_http_error(503), b"ok"])
    assert _fetcher([]).get("http://feed.test") == b"ok"


def test_completed_call_logs_only_safe_boundary_fields(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    secret = "synthetic-only-never-a-real-credential"
    url = f"https://feed.test/items?token={secret}"
    _patch(monkeypatch, [b"ok"])
    with caplog.at_level(logging.INFO, logger="traust_core.v1.providers.http"):
        assert _fetcher([]).get(url, {"Authorization": f"Bearer {secret}"}) == b"ok"
    (record,) = caplog.records
    assert (record.operation, record.outcome, record.attempts) == (
        "http.get",
        "completed",
        1,
    )
    assert len(record.target_hash) == 16 and record.duration_ms >= 0
    assert secret not in caplog.text
    assert "feed.test" not in caplog.text


def test_retries_timeout_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [TimeoutError("slow"), b"ok"])
    assert _fetcher([]).get("http://feed.test") == b"ok"


@pytest.mark.parametrize(
    ("retry_after", "expected"),
    [("2", 2.0), ("Thu, 01 Jan 2026 00:00:05 GMT", 5.0), ("999", 10.0)],
)
def test_429_honours_retry_after_capped(
    monkeypatch: pytest.MonkeyPatch, retry_after: str, expected: float
) -> None:
    _patch(monkeypatch, [_http_error(429, retry_after), b"ok"])
    slept: list[float] = []
    assert _fetcher(slept).get("http://feed.test") == b"ok"
    assert slept == [expected]


def test_backoff_doubles_and_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [_http_error(500)] * 4)
    slept: list[float] = []
    with pytest.raises(ServiceError):
        _fetcher(slept, max_attempts=4, backoff_base_seconds=3, max_wait_seconds=10).get("http://x")
    assert slept == [3.0, 6.0, 10.0]


def test_other_4xx_fails_fast(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch(monkeypatch, [_http_error(404)])
    with pytest.raises(ServiceError) as exc:
        _fetcher([]).get("http://feed.test")
    assert exc.value.status == 404
    assert len(calls) == 1


def test_gives_up_after_max_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch(monkeypatch, [TimeoutError("slow")] * 3)
    with pytest.raises(ServiceError, match="gave up after 3 attempts"):
        _fetcher([]).get("http://feed.test")
    assert len(calls) == 3


def test_truncated_body_retries_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    calls = _patch(monkeypatch, [http_client.IncompleteRead(b"partial", 100), b"the full body"])
    fetcher = _fetcher(slept)
    assert fetcher.get("http://feed.test/x") == b"the full body"
    assert len(calls) == 2


def test_truncated_body_gives_up_as_service_error(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    calls = _patch(monkeypatch, [http_client.IncompleteRead(b"partial", 100)] * 3)
    fetcher = _fetcher(slept)
    with pytest.raises(ServiceError):
        fetcher.get("http://feed.test/x")
    assert len(calls) == 3


def test_post_json_sends_the_document_as_json(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Any] = []

    def _open(req: Any, timeout: float | None = None) -> _Resp:
        seen.append(req)
        return _Resp(b'{"ok": true}')

    monkeypatch.setattr(http.urllib.request, "urlopen", _open)
    assert (
        _fetcher([]).post_json("http://osv.test/v1/querybatch", {"queries": []}) == b'{"ok": true}'
    )
    [req] = seen
    assert req.get_method() == "POST"
    assert req.data == b'{"queries": []}'
    assert req.get_header("Content-type") == "application/json"


def test_outbound_requests_carry_only_the_scoped_request_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str | None] = []

    def _open(req: Any, timeout: float | None = None) -> _Resp:
        seen.append(req.get_header("X-request-id"))
        return _Resp(b"ok")

    monkeypatch.setattr(http.urllib.request, "urlopen", _open)
    fetcher = _fetcher([])
    with correlation_scope("outbound-1"):
        assert fetcher.get("https://feed.test") == b"ok"
    assert fetcher.get("https://feed.test") == b"ok"
    assert seen == ["outbound-1", None]


def test_post_json_fails_fast_on_a_refused_request(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch(monkeypatch, [_http_error(400)])
    with pytest.raises(ServiceError) as exc:
        _fetcher([]).post_json("http://osv.test", {})
    assert (exc.value.status, len(calls)) == (400, 1)


@pytest.mark.parametrize(
    ("failures", "status"),
    [([429, 429, 429], 429), ([429, 429, 500], None), ([500, 500, 429], 429)],
)
def test_giving_up_still_throttled_says_429(
    monkeypatch: pytest.MonkeyPatch, failures: list[int], status: int | None
) -> None:
    _patch(monkeypatch, [_http_error(code) for code in failures])
    with pytest.raises(ServiceError, match="gave up") as exc:
        _fetcher([]).get("http://feed.test")
    assert exc.value.status == status


def test_fetch_reads_up_to_one_byte_past_the_limit_and_names_the_final_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Redirected(_Resp):
        def read(self, n: int = -1) -> bytes:  # type: ignore[override]
            return self._body[:n]

        def geturl(self) -> str:
            return "https://mirror.test/blob"

    monkeypatch.setattr(
        http.urllib.request, "urlopen", lambda req, timeout=None: _Redirected(b"abcdef")
    )
    assert _fetcher([]).fetch("https://feed.test/blob", 3) == (b"abcd", "https://mirror.test/blob")


def test_fetch_fails_fast_on_a_refused_request(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [_http_error(404)])
    with pytest.raises(ServiceError) as exc:
        _fetcher([]).fetch("https://feed.test/blob", 3)
    assert exc.value.status == 404


def test_stream_hands_the_body_to_the_consumer_with_its_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[Any] = []

    def _open(req: Any, timeout: float | None = None) -> _Resp:
        seen.append(req)
        return _Resp(b"archive")

    monkeypatch.setattr(http.urllib.request, "urlopen", _open)
    got = _fetcher([]).stream("https://forge.test/a", lambda r: r.read(), {"PRIVATE-TOKEN": "t"})
    assert got == b"archive"
    [req] = seen
    assert req.get_header("Private-token") == "t"
    assert req.get_header("User-agent") == "test-agent"


def test_stream_retries_a_5xx_and_fails_fast_on_a_4xx(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [_http_error(503), b"ok"])
    assert _fetcher([]).stream("https://forge.test/a", lambda r: r.read()) == b"ok"
    _patch(monkeypatch, [_http_error(404)])
    with pytest.raises(ServiceError, match="HTTP 404"):
        _fetcher([]).stream("https://forge.test/a", lambda r: r.read())


class _Paged(_Resp):
    def __init__(self, body: bytes, link: str | None) -> None:
        super().__init__(body)
        self.headers = Message()
        if link is not None:
            self.headers["Link"] = link


def test_pages_follow_the_next_link_and_keep_the_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    second = "https://forge.test/items?page=2"
    answers = {
        "https://forge.test/items": _Paged(b"[1]", f'<{second}>; rel="next", <x>; rel="last"'),
        second: _Paged(b"[2]", '<https://forge.test/items>; rel="first"'),
    }
    asked: list[tuple[str, str | None]] = []

    def _open(req: urllib.request.Request, timeout: float | None = None) -> _Paged:
        asked.append((req.full_url, req.get_header("Private-token")))
        return answers[req.full_url]

    monkeypatch.setattr(http.urllib.request, "urlopen", _open)
    got = list(_fetcher([]).pages("https://forge.test/items", {"PRIVATE-TOKEN": "t"}))
    assert got == [b"[1]", b"[2]"]
    assert asked == [("https://forge.test/items", "t"), (second, "t")]


def test_a_refused_page_is_a_typed_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [_http_error(401)])
    with pytest.raises(ServiceError) as raised:
        list(_fetcher([]).pages("https://forge.test/items"))
    assert raised.value.status == 401
