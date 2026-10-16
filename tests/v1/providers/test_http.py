import urllib.error
from collections.abc import Callable
from datetime import UTC, datetime
from email.message import Message
from typing import Any

import pytest

from traust_core.v1.errors import ServiceError
from traust_core.v1.providers import http
from traust_core.v1.providers.clock import FixedClock
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
