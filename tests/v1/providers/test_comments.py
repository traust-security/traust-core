"""Comment sources over canned forge REST answers and jira output."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any

import pytest

from tests.v1.observation_support import HOSTS, NOW
from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.remediation import ExternalRef
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.comments import FORGE, JIRA, ForgeCommentSource, JiraCommentSource
from traust_core.v1.providers.forge_api import ForgeApi
from traust_core.v1.providers.http import HttpFetcher
from traust_core.v1.providers.process import ProcessResult


class Replay:
    """Answers each argv by the first rule whose key is in it: (stdout, returncode)."""

    def __init__(self, rules: Sequence[tuple[str, Any]]) -> None:
        self.rules, self.calls = rules, []

    def run(self, argv: Sequence[str], **kwargs: Any) -> ProcessResult:
        self.calls.append(tuple(argv))
        for key, answer in self.rules:
            if any(key in a for a in argv):
                out, rc = answer if isinstance(answer, tuple) else (answer, 0)
                body = out if isinstance(out, str) else json.dumps(out)
                return ProcessResult(tuple(argv), rc, body.encode(), b"boom" if rc else b"", 0)
        raise AssertionError(f"unexpected call {argv}")


class Pages(list):  # type: ignore[type-arg]
    """A paginated answer: one JSON list per page."""


class Forge(HttpFetcher):
    """Answers each URL by the first rule whose key is in it: a JSON value, `Pages`, or
    (body, HTTP status) for a refusal."""

    def __init__(self, rules: Sequence[tuple[str, Any]]) -> None:
        super().__init__("test")
        self.rules, self.calls = rules, []

    def _answer(self, url: str, headers: Mapping[str, str] | None) -> Any:
        self.calls.append((url, dict(headers or {})))
        for key, answer in self.rules:
            if key in url:
                if isinstance(answer, tuple):
                    raise ServiceError(f"{url}: HTTP {answer[1]} boom", status=answer[1])
                return answer
        raise AssertionError(f"unexpected call {url}")

    def get(self, url: str, headers: Mapping[str, str] | None = None) -> bytes:
        return json.dumps(self._answer(url, headers)).encode()

    def pages(self, url: str, headers: Mapping[str, str] | None = None) -> Iterator[bytes]:
        out = self._answer(url, headers)
        yield from (
            json.dumps(page).encode() for page in (out if isinstance(out, Pages) else [out])
        )


def forge(
    *rules: tuple[str, Any], tokens: Mapping[str, str] | None = None
) -> tuple[ForgeCommentSource, Forge]:
    http = Forge(rules)
    return ForgeCommentSource(ForgeApi(http, HOSTS, tokens), FixedClock(NOW)), http


def gh_comment(login: str, body: str, at: str, **user: Any) -> dict[str, Any]:
    return {
        "user": {"login": login, **user},
        "body": body,
        "created_at": at,
        "html_url": f"https://github.com/o/r/pull/7#c-{login}",
    }


def test_a_github_pr_reads_issue_and_review_comments_with_each_authors_permission() -> None:
    issue = [gh_comment("maint", "/traust confirmed X-1 reproduced", "2026-10-23T10:00:00Z")]
    review = [gh_comment("ci", "lint", "2026-10-23T09:00:00Z", type="Bot")]
    src, replay = forge(
        ("issues/7/comments", issue),
        ("pulls/7/comments", review),
        ("collaborators/maint/permission", {"permission": "maintain"}),
        ("collaborators/ci/permission", ("", 404)),
    )
    got = src.comments(ExternalRef(system=FORGE, ref="https://github.com/o/r/pull/7")).data
    assert [(c.author, c.bot, c.maintainer, c.source) for c in got] == [
        ("ci", True, False, SourceType.MR_COMMENT),
        ("maint", False, True, SourceType.MR_COMMENT),
    ]
    assert got[1].body.startswith("/traust") and got[1].at.tzinfo is not None
    assert sum("permission" in url for url, _ in replay.calls) == 2


def test_github_paginated_output_is_several_arrays() -> None:
    page1 = [gh_comment("a", "one", "2026-10-23T10:00:00Z")]
    page2 = [gh_comment("a", "two", "2026-10-23T11:00:00Z")]
    src, _ = forge(
        ("issues/7/comments", Pages([page1, page2])),
        ("pulls/7/comments", []),
        ("permission", {"permission": "write"}),
    )
    got = src.comments(ExternalRef(system=FORGE, ref="https://github.com/o/r/pull/7")).data
    assert [c.body for c in got] == ["one", "two"]
    assert not any(c.maintainer for c in got)


def test_a_github_commit_is_one_commit_statement() -> None:
    commit = {
        "commit": {
            "message": "fix\n\nFixes: X-1",
            "author": {"name": "J", "date": "2026-10-23T08:00:00Z"},
        },
        "author": {"login": "jdoe", "type": "User"},
        "html_url": "https://github.com/o/r/commit/abc1234",
    }
    src, _ = forge(("commits/abc1234", commit))
    (c,) = src.comments(ExternalRef(system=FORGE, ref="https://github.com/o/r/commit/abc1234")).data
    assert (c.source, c.author, c.body) == (SourceType.COMMIT, "jdoe", "fix\n\nFixes: X-1")


def test_a_gitlab_mr_skips_system_notes_and_asks_who_is_a_maintainer() -> None:
    notes = [
        {
            "id": 1,
            "system": True,
            "body": "added 1 commit",
            "author": {"id": 5, "username": "j"},
            "created_at": "2026-10-23T08:00:00Z",
        },
        {
            "id": 2,
            "system": False,
            "body": "/traust resolved X-1 merged the fix",
            "author": {"id": 5, "username": "jdoe"},
            "created_at": "2026-10-23T09:00:00.000Z",
        },
        {
            "id": 3,
            "system": False,
            "body": "+1",
            "author": {"id": 6, "username": "dev"},
            "created_at": "2026-10-23T09:30:00Z",
        },
    ]
    src, _ = forge(
        ("merge_requests/17/notes", notes),
        ("users/5", {"bot": False}),
        ("users/6", {"bot": False}),
        ("members/all/5", {"access_level": 40}),
        ("members/all/6", ("", 404)),
    )
    url = "https://gitlab.com/g/sub/r/-/merge_requests/17"
    got = src.comments(ExternalRef(system=FORGE, ref=url)).data
    assert [(c.author, c.maintainer, c.url) for c in got] == [
        ("jdoe", True, f"{url}#note_2"),
        ("dev", False, f"{url}#note_3"),
    ]


def test_a_gitlab_commit() -> None:
    commit = {
        "message": "Fixes X-1",
        "authored_date": "2026-10-23T08:00:00+00:00",
        "author_name": "J",
        "author_email": "j@example.com",
        "web_url": "u",
    }
    src, _ = forge(("repository/commits/abc1234", commit))
    (c,) = src.comments(
        ExternalRef(system=FORGE, ref="https://gitlab.com/g/r/-/commit/abc1234")
    ).data
    assert (c.source, c.author) == (SourceType.COMMIT, "j@example.com")


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/o/r/issues/7",
        "https://unknown.example.com/o/r/pull/7",
        "https://gitlab.com/g/r/merge_requests/17",
    ],
)
def test_anything_else_is_refused(url: str) -> None:
    src, _ = forge()
    with pytest.raises(ValidationError):
        src.comments(ExternalRef(system=FORGE, ref=url))


def test_a_failing_forge_read_is_a_service_error() -> None:
    src, _ = forge(("issues/7/comments", ("", 500)))
    with pytest.raises(ServiceError, match="boom"):
        src.comments(ExternalRef(system=FORGE, ref="https://github.com/o/r/pull/7"))


def test_a_permission_the_token_cannot_read_is_not_a_maintainer() -> None:
    src, _ = forge(
        ("issues/7/comments", [gh_comment("m", "x", "2026-10-23T10:00:00Z")]),
        ("pulls/7/comments", []),
        ("permission", ("", 403)),
    )
    (c,) = src.comments(ExternalRef(system=FORGE, ref="https://github.com/o/r/pull/7")).data
    assert c.maintainer is False


def test_an_unanswered_permission_fails_rather_than_guessing() -> None:
    src, _ = forge(
        ("issues/7/comments", [gh_comment("m", "x", "2026-10-23T10:00:00Z")]),
        ("pulls/7/comments", []),
        ("permission", ("", 502)),
    )
    with pytest.raises(ServiceError, match="502"):
        src.comments(ExternalRef(system=FORGE, ref="https://github.com/o/r/pull/7"))


def test_each_forge_read_carries_that_hosts_token_only() -> None:
    commit = {"message": "m", "authored_date": "2026-10-23T08:00:00Z", "author_name": "J"}
    src, http = forge(("repository/commits/abc1234", commit), tokens={"gitlab.com": "gl"})
    src.comments(ExternalRef(system=FORGE, ref="https://gitlab.com/g/r/-/commit/abc1234"))
    assert http.calls == [
        (
            "https://gitlab.com/api/v4/projects/g%2Fr/repository/commits/abc1234",
            {"PRIVATE-TOKEN": "gl"},
        )
    ]
    assert src.check().ready


def jira(issue: Any) -> JiraCommentSource:
    return JiraCommentSource(Replay([("view", issue)]), FixedClock(NOW))  # type: ignore[arg-type]


ADF: Callable[[str], dict[str, Any]] = lambda text: {  # noqa: E731
    "type": "doc",
    "content": [{"type": "paragraph", "content": [{"type": "text", "text": text}]}],
}


def test_a_jira_ticket_is_its_status_then_its_comments() -> None:
    issue = {
        "self": "https://example.atlassian.net/rest/api/3/issue/1",
        "fields": {
            "description": ADF("Finding OPERATOR-abcdef0-001"),
            "status": {"name": "Closed"},
            "resolution": {"name": "Not a Bug"},
            "resolutiondate": "2026-10-23T09:00:00.000+0000",
            "updated": "2026-10-23T10:00:00.000+0000",
            "comment": {
                "comments": [
                    {
                        "id": "10",
                        "author": {"emailAddress": "j@example.com", "accountType": "atlassian"},
                        "body": ADF("/traust confirmed OPERATOR-abcdef0-001 reproduced it"),
                        "created": "2026-10-23T08:00:00.000+0000",
                    },
                ]
            },
        },
    }
    status, note = jira(issue).comments(ExternalRef(system=JIRA, ref="SEC-12")).data
    assert (status.status, status.author, status.body.strip()) == (
        "Not a Bug",
        "",
        "Finding OPERATOR-abcdef0-001",
    )
    assert status.url == "https://example.atlassian.net/browse/SEC-12"
    assert (note.author, note.status, note.url) == (
        "j@example.com",
        None,
        "https://example.atlassian.net/browse/SEC-12?focusedCommentId=10",
    )


def test_an_open_ticket_without_status_has_only_comments() -> None:
    issue = {"self": "https://x/rest/api/2/issue/1", "fields": {"comment": {"comments": []}}}
    assert jira(issue).comments(ExternalRef(system=JIRA, ref="SEC-1")).data == []


def test_not_a_jira_key_is_refused() -> None:
    with pytest.raises(ValidationError):
        jira({}).comments(ExternalRef(system=JIRA, ref="https://x/browse/SEC-1"))
