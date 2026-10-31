"""ForgeApi: each forge's REST base, its token only in a header, JSON answers and pages."""

from __future__ import annotations

import base64
import json
import threading
from collections.abc import Iterator, Mapping
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.providers.forge_api import ForgeApi
from traust_core.v1.providers.http import HttpFetcher
from traust_core.v1.providers.process import ProcessError, ProcessRunner

HOSTS = {"github.com": "github", "ghe.example": "github", "gitlab.example": "gitlab"}


class Replay(HttpFetcher):
    def __init__(self, answers: Mapping[str, Any]) -> None:
        super().__init__("test")
        self.answers, self.asked = dict(answers), []

    def _answer(self, url: str, headers: Mapping[str, str] | None) -> Any:
        self.asked.append((url, dict(headers or {})))
        answer = self.answers[url]
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def get(self, url: str, headers: Mapping[str, str] | None = None) -> bytes:
        return self._answer(url, headers)

    def pages(self, url: str, headers: Mapping[str, str] | None = None) -> Iterator[bytes]:
        yield from self._answer(url, headers)


@pytest.mark.parametrize(
    ("host", "tokens", "url", "headers"),
    [
        ("github.com", {}, "https://api.github.com/repos/o/r", {}),
        (
            "github.com",
            {"github.com": "t"},
            "https://api.github.com/repos/o/r",
            {"Authorization": "Bearer t"},
        ),
        (
            "ghe.example",
            {"ghe.example": "t"},
            "https://ghe.example/api/v3/repos/o/r",
            {"Authorization": "Bearer t"},
        ),
        (
            "gitlab.example",
            {"gitlab.example": "t"},
            "https://gitlab.example/api/v4/repos/o/r",
            {"PRIVATE-TOKEN": "t"},
        ),
        ("gitlab.example", {"github.com": "t"}, "https://gitlab.example/api/v4/repos/o/r", {}),
    ],
)
def test_each_forge_gets_its_base_and_only_its_own_token(
    host: str, tokens: dict[str, str], url: str, headers: dict[str, str]
) -> None:
    http = Replay({url: b'{"ok": true}'})
    assert ForgeApi(http, HOSTS, tokens).get(host, "repos/o/r") == {"ok": True}
    assert http.asked == [(url, headers)]


def test_an_unknown_host_is_refused_before_any_request() -> None:
    http = Replay({})
    api = ForgeApi(http, {**HOSTS, "forge.test": "gitea"}, {"forge.test": "t"})
    assert (api.kind("gitlab.example"), api.kind("forge.test"), api.kind("nowhere")) == (
        "gitlab",
        None,
        None,
    )
    with pytest.raises(ValidationError, match="not a known forge"):
        api.get("forge.test", "x")
    assert http.asked == []


def test_find_is_none_only_when_the_forge_says_not_found() -> None:
    url = "https://api.github.com/x"
    api = lambda answer: ForgeApi(Replay({url: answer}), HOSTS)  # noqa: E731
    assert api(ServiceError("gone", status=404)).find("github.com", "x") is None
    with pytest.raises(ServiceError):
        api(ServiceError("denied", status=403)).find("github.com", "x")
    with pytest.raises(ServiceError):
        api(ServiceError("unreachable")).find("github.com", "x")


def test_an_answer_that_is_not_json_is_a_service_error() -> None:
    api = ForgeApi(Replay({"https://api.github.com/x": b"<html>"}), HOSTS)
    with pytest.raises(ServiceError, match="no JSON"):
        api.get("github.com", "x")


def test_items_walk_every_page_and_refuse_a_page_that_is_not_a_list() -> None:
    url = "https://gitlab.example/api/v4/projects/1/notes"
    pages = [json.dumps([1, 2]).encode(), json.dumps([3]).encode(), b"[]"]
    assert list(
        ForgeApi(Replay({url: pages}), HOSTS).items("gitlab.example", "projects/1/notes")
    ) == [1, 2, 3]
    bad = ForgeApi(Replay({url: [b'{"message": "x"}']}), HOSTS)
    with pytest.raises(ServiceError, match="expected a list"):
        list(bad.items("gitlab.example", "projects/1/notes"))


@pytest.mark.parametrize(
    ("url", "endpoint", "answer", "expected", "headers"),
    [
        (
            "https://github.com/o/r",
            "https://api.github.com/repos/o/r/commits/{sha}/pulls?per_page=100",
            [{"number": 7, "base": {"repo": {"full_name": "o/r"}}}],
            ("refs/pull/7/head",),
            {"Authorization": "Bearer t"},
        ),
        (
            "https://ghe.example/o/r",
            "https://ghe.example/api/v3/repos/o/r/commits/{sha}/pulls?per_page=100",
            [{"number": 8, "base": {"repo": {"full_name": "o/r"}}}],
            ("refs/pull/8/head",),
            {"Authorization": "Bearer t"},
        ),
        (
            "https://gitlab.example/group/sub/r",
            "https://gitlab.example/api/v4/projects/group%2Fsub%2Fr/repository/commits/"
            "{sha}/merge_requests?per_page=100",
            [{"iid": 9}],
            ("refs/merge-requests/9/head",),
            {"PRIVATE-TOKEN": "t"},
        ),
    ],
)
def test_review_refs_are_scoped_to_the_repository_and_forge(
    url: str,
    endpoint: str,
    answer: list[dict[str, Any]],
    expected: tuple[str, ...],
    headers: dict[str, str],
) -> None:
    sha = "a" * 40
    repo = HttpsRepoUrl.parse(url, HOSTS)
    endpoint = endpoint.format(sha=sha)
    http = Replay({endpoint: [json.dumps(answer).encode()]})
    assert ForgeApi(http, HOSTS, {repo.host: "t"}).review_refs(repo, sha) == expected
    assert http.asked == [(endpoint, headers)]


def test_review_refs_reject_invalid_answers_and_unrelated_base_repositories() -> None:
    sha = "a" * 40
    repo = HttpsRepoUrl.parse("https://github.com/o/r", HOSTS)
    endpoint = f"https://api.github.com/repos/o/r/commits/{sha}/pulls?per_page=100"
    other = Replay({endpoint: [b'[{"number": 7, "base": {"repo": {"full_name": "other/r"}}}]']})
    assert ForgeApi(other, HOSTS).review_refs(repo, sha) == ()
    invalid = Replay({endpoint: [b'[{"number": true, "base": {"repo": {"full_name": "o/r"}}}]']})
    with pytest.raises(ServiceError, match="positive review number"):
        ForgeApi(invalid, HOSTS).review_refs(repo, sha)
    gone = Replay({endpoint: ServiceError("not found", status=404)})
    assert ForgeApi(gone, HOSTS).review_refs(repo, sha) == ()


@pytest.mark.parametrize(
    ("host", "username"),
    [
        ("github.com", "x-access-token"),
        ("ghe.example", "x-access-token"),
        ("gitlab.example", "oauth2"),
    ],
)
def test_git_can_read_an_authenticated_forges_advertised_commit(host: str, username: str) -> None:
    sha, token = "a" * 40, "test-forge-token"
    authorization = "Basic " + base64.b64encode(f"{username}:{token}".encode()).decode()

    def packet(data: bytes) -> bytes:
        return f"{len(data) + 4:04x}".encode() + data

    advertisement = (
        packet(b"# service=git-upload-pack\n")
        + b"0000"
        + packet(f"{sha} refs/heads/main\0multi_ack\n".encode())
        + b"0000"
    )

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.headers.get("Authorization") != authorization:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="forge"')
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/x-git-upload-pack-advertisement")
            self.send_header("Content-Length", str(len(advertisement)))
            self.end_headers()
            self.wfile.write(advertisement)

        def log_message(self, *args: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/repo.git"

    def read(secret: str) -> bytes:
        headers = ForgeApi(Replay({}), HOSTS, {host: secret}).git_headers(host)
        result = ProcessRunner(("git",)).run(
            ["git", "ls-remote", url, "refs/heads/main"],
            env={
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": f"http.{url}.extraheader",
                "GIT_CONFIG_VALUE_0": "\n".join(f"{k}: {v}" for k, v in headers.items()),
            },
        )
        return result.stdout

    try:
        with pytest.raises(ProcessError):
            read("wrong-token")
        assert read(token).decode().strip() == f"{sha}\trefs/heads/main"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
