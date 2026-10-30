"""ForgeApi: each forge's REST base, its token only in a header, JSON answers and pages."""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator, Mapping
from typing import Any

import pytest

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.providers.forge_api import ForgeApi
from traust_core.v1.providers.http import HttpFetcher

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


def test_git_transport_auth_is_basic_for_gitlab_and_bearer_for_github() -> None:
    """Git's smart-HTTP transport takes Basic auth; the REST PRIVATE-TOKEN header fails there."""
    api = ForgeApi(Replay({}), HOSTS, {"gitlab.example": "glpat-x", "github.com": "gh-x"})
    assert api.git_headers("gitlab.example") == {
        "Authorization": "Basic " + base64.b64encode(b"oauth2:glpat-x").decode()
    }
    assert api.git_headers("github.com") == {"Authorization": "Bearer gh-x"}
    assert api.git_headers("example.org") == {}
