from __future__ import annotations

import random
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC
from email.utils import parsedate_to_datetime

from traust_core.v1.errors import ServiceError
from traust_core.v1.providers.clock import Clock, SystemClock


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 4
    timeout_seconds: float = 120.0
    backoff_base_seconds: float = 1.0
    max_wait_seconds: float = 60.0
    jitter_seconds: float = 0.0


class HttpFetcher:
    """Outbound GET for providers, with bounded retries.

    429 waits out Retry-After (capped by max_wait_seconds); 5xx and timeouts use
    capped exponential backoff; any other 4xx fails at once (retrying a 403/404
    just burns the rate-limit window).
    """

    def __init__(
        self,
        user_agent: str,
        policy: RetryPolicy | None = None,
        *,
        clock: Clock | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._user_agent = user_agent
        self._policy = policy or RetryPolicy()
        self._clock = clock or SystemClock()
        self._sleep = sleep

    def get(self, url: str) -> bytes:
        policy = self._policy
        last = ""
        for attempt in range(policy.max_attempts):
            req = urllib.request.Request(url, headers={"User-Agent": self._user_agent})
            try:
                with urllib.request.urlopen(req, timeout=policy.timeout_seconds) as r:
                    return r.read()
            except urllib.error.HTTPError as e:
                if e.code != 429 and not 500 <= e.code < 600:
                    raise ServiceError(f"{url}: HTTP {e.code}", status=e.code) from e
                last = f"HTTP {e.code}"
                after = self._retry_after(e.headers.get("Retry-After") if e.headers else None)
                delay = (
                    self._backoff(attempt) if after is None else min(after, policy.max_wait_seconds)
                )
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last = str(e)
                delay = self._backoff(attempt)
            if attempt + 1 < policy.max_attempts:
                self._sleep(delay)
        raise ServiceError(f"{url}: gave up after {policy.max_attempts} attempts ({last})")

    def _backoff(self, attempt: int) -> float:
        p = self._policy
        wait = min(p.backoff_base_seconds * 2**attempt, p.max_wait_seconds)
        return wait + (random.uniform(0, p.jitter_seconds) if p.jitter_seconds else 0.0)

    def _retry_after(self, value: str | None) -> float | None:
        """Retry-After as delta-seconds or an HTTP-date; None when absent or unparseable."""
        if not value:
            return None
        value = value.strip()
        if value.isdigit():
            return float(value)
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        return max(0.0, (when - self._clock.now()).total_seconds())
