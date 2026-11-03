from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import TracebackType
from typing import Self

import pytest

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.values import GitSha
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.http import HttpFetcher, RetryPolicy
from traust_core.v1.providers.osv import OsvAdvisoryLookup

NOW = datetime(2026, 11, 3, tzinfo=UTC)
SHA = "a" * 40
FIXTURE = Path(__file__).parents[2] / "fixtures/detection_quality/cve-replay-osv.json"


def advisory(**updates: object) -> dict[str, object]:
    return {**json.loads(FIXTURE.read_bytes()), **updates}


class OsvFixture:
    def __init__(self) -> None:
        self.responses: dict[tuple[str, str], tuple[int, object]] = {}
        self.records: dict[str, dict[str, object]] = {}
        self.requests: list[tuple[str, dict[str, object]]] = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                owner.requests.append((self.path, body))
                key = (body.get("commit", ""), body.get("page_token", ""))
                self.respond(*owner.responses.get(key, (200, {"vulns": []})))

            def do_GET(self) -> None:
                identifier = self.path.rsplit("/", 1)[-1]
                record = owner.records.get(identifier)
                self.respond(200 if record is not None else 404, record or {})

            def respond(self, status: int, body: object) -> None:
                payload = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args: object) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.lookup = OsvAdvisoryLookup(
            f"http://127.0.0.1:{self.server.server_port}/v1",
            http=HttpFetcher("cve-replay-test", RetryPolicy(max_attempts=1)),
            clock=FixedClock(NOW),
        )

    def __enter__(self) -> Self:
        self.thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()


def test_commit_discovery_follows_every_osv_http_page_and_preserves_provenance() -> None:
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory()], "next_page_token": "second"})
        osv.responses[(SHA, "second")] = (
            200,
            {"vulns": [advisory(id="GO-2026-99902", aliases=[])]},
        )
        result = osv.lookup.for_commit(GitSha.parse(SHA))
    assert [r.identifier for r in result.data] == ["GHSA-2345-6789-cfgh", "GO-2026-99902"]
    assert osv.requests == [
        ("/v1/query", {"commit": SHA}),
        ("/v1/query", {"commit": SHA, "page_token": "second"}),
    ]
    assert result.data[0].aliases == ("CVE-2026-99901",)
    assert result.acquisition.acquired_at == NOW
    assert result.acquisition.source.endswith("/v1/query")


def test_failed_later_osv_http_page_is_not_a_partial_commit_answer() -> None:
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (200, {"vulns": [advisory()], "next_page_token": "second"})
        osv.responses[(SHA, "second")] = (503, {"error": "temporarily unavailable"})
        with pytest.raises(ServiceError):
            osv.lookup.for_commit(GitSha.parse(SHA))
    assert len(osv.requests) == 2


@pytest.mark.parametrize(
    "response",
    [
        {"vulns": "not an advisory list"},
        {"vulns": [17]},
        {"vulns": [advisory(published="2026-11-02T12:00:00")]},
        {"vulns": [], "next_page_token": 42},
    ],
)
def test_malformed_http_commit_answers_cannot_advance_replay(response: object) -> None:
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (200, response)
        with pytest.raises(ValidationError):
            osv.lookup.for_commit(GitSha.parse(SHA))


def test_repeated_page_token_fails_instead_of_truncating_or_hanging() -> None:
    with OsvFixture() as osv:
        osv.responses[(SHA, "")] = (200, {"next_page_token": "loop"})
        osv.responses[(SHA, "loop")] = (200, {"next_page_token": "loop"})
        with pytest.raises(ValidationError):
            osv.lookup.for_commit(GitSha.parse(SHA))
    assert len(osv.requests) == 2
