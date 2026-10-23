"""Comment sources: what people wrote in merge requests, commits and tickets, read through the
forge and Jira CLIs (their own logins, never a token on argv)."""

from __future__ import annotations

import json
import re
import shutil
from collections.abc import Iterator, Mapping, Sequence
from datetime import datetime
from typing import Any
from urllib.parse import quote, urlsplit

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.attestation import Comment, ExternalHandle
from traust_core.v1.models.remediation import ExternalRef
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner

FORGE, JIRA = "forge", "jira"
_GITHUB_PR = re.compile(r"^/(?P<repo>[^/]+/[^/]+)/pull/(?P<n>\d+)/?$")
_GITHUB_COMMIT = re.compile(r"^/(?P<repo>[^/]+/[^/]+)/commit/(?P<sha>[0-9a-f]{7,40})/?$")
_GITLAB_MR = re.compile(r"^/(?P<repo>.+?)/-/merge_requests/(?P<n>\d+)/?$")
_GITLAB_COMMIT = re.compile(r"^/(?P<repo>.+?)/-/commit/(?P<sha>[0-9a-f]{7,40})/?$")
_JIRA_KEY = re.compile(r"^[A-Z][A-Z0-9]+-\d+$")
_MAINTAINER = 40  # GitLab access level: Maintainer and above


def _values(text: str) -> Iterator[Any]:
    """Every JSON value in `text`; paginated CLI output is several arrays back to back."""
    decoder, at = json.JSONDecoder(), 0
    while (at := _skip(text, at)) < len(text):
        value, at = decoder.raw_decode(text, at)
        yield from value if isinstance(value, list) else (value,)


def _skip(text: str, at: int) -> int:
    while at < len(text) and text[at].isspace():
        at += 1
    return at


def _when(raw: str) -> datetime:
    when = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if when.tzinfo is None:
        raise ValidationError(f"timestamp without a zone: {raw}")
    return when


class _Cli:
    def __init__(self, process: ProcessRunner, clock: Clock, name: str) -> None:
        self._process, self._clock, self.name = process, clock, name

    def _run(self, argv: Sequence[str]) -> str:
        done = self._process.run(argv, check=False)
        if done.returncode:
            err = (
                done.stderr.decode(errors="replace")
                if isinstance(done.stderr, bytes)
                else done.stderr
            )
            raise ServiceError(f"{argv[0]} failed: {err.strip()[:200] or done.returncode}")
        out = done.stdout
        return out.decode(errors="replace") if isinstance(out, bytes) else out

    def _try(self, argv: Sequence[str]) -> str | None:
        """Output, or None when the command fails (a lookup with no answer)."""
        done = self._process.run(argv, check=False)
        if done.returncode:
            return None
        out = done.stdout
        return out.decode(errors="replace") if isinstance(out, bytes) else out

    def _result(self, comments: list[Comment], ref: ExternalRef) -> Result[list[Comment]]:
        acquired = Acquisition(provider=self.name, acquired_at=self._clock.now(), source=ref.ref)
        return Result(comments, acquired)


class ForgeCommentSource(_Cli):
    """GitHub pull-request and GitLab merge-request comments, and commit messages."""

    def __init__(self, process: ProcessRunner, clock: Clock, hosts: Mapping[str, str]) -> None:
        super().__init__(process, clock, FORGE)
        self._hosts = dict(hosts)

    def check(self) -> Readiness:
        missing = [b for b in ("gh", "glab") if shutil.which(b) is None]
        return Readiness(ready=not missing, detail=", ".join(missing))

    def comments(self, ref: ExternalRef) -> Result[list[Comment]]:
        url = urlsplit(ref.ref)
        kind = self._hosts.get((url.hostname or "").lower())
        host, path = url.hostname or "", url.path
        if kind == "github" and (m := _GITHUB_PR.match(path)):
            got = self._github_pr(host, m["repo"], m["n"])
        elif kind == "github" and (m := _GITHUB_COMMIT.match(path)):
            got = [self._github_commit(host, m["repo"], m["sha"])]
        elif kind == "gitlab" and (m := _GITLAB_MR.match(path)):
            got = self._gitlab_mr(host, m["repo"], m["n"], ref.ref)
        elif kind == "gitlab" and (m := _GITLAB_COMMIT.match(path)):
            got = [self._gitlab_commit(host, m["repo"], m["sha"])]
        else:
            raise ValidationError(f"not a merge request, pull request or commit URL: {ref.ref}")
        return self._result(got, ref)

    def _github_pr(self, host: str, repo: str, n: str) -> list[Comment]:
        api = ["gh", "api", "--hostname", host, "--paginate"]
        raw = [
            *_values(self._run([*api, f"repos/{repo}/issues/{n}/comments"])),
            *_values(self._run([*api, f"repos/{repo}/pulls/{n}/comments"])),
        ]
        maintainers: dict[str, bool] = {}
        out = []
        for c in raw:
            login = c["user"]["login"]
            if login not in maintainers:
                # No permission answer (not a collaborator, or unreachable) is not a maintainer.
                permission = [
                    "gh",
                    "api",
                    "--hostname",
                    host,
                    f"repos/{repo}/collaborators/{login}/permission",
                    "--jq",
                    ".permission",
                ]
                answer = self._try(permission) or ""
                maintainers[login] = answer.strip() in ("admin", "maintain")
            out.append(
                Comment(
                    source=SourceType.MR_COMMENT,
                    author=ExternalHandle(login),
                    body=c.get("body") or "",
                    at=_when(c["created_at"]),
                    url=c.get("html_url"),
                    bot=c["user"].get("type") == "Bot",
                    maintainer=maintainers[login],
                )
            )
        return sorted(out, key=lambda c: c.at)

    def _github_commit(self, host: str, repo: str, sha: str) -> Comment:
        (c,) = _values(self._run(["gh", "api", "--hostname", host, f"repos/{repo}/commits/{sha}"]))
        user = c.get("author") or {}
        return Comment(
            source=SourceType.COMMIT,
            author=ExternalHandle(user.get("login") or c["commit"]["author"]["name"]),
            body=c["commit"]["message"],
            at=_when(c["commit"]["author"]["date"]),
            url=c.get("html_url"),
            bot=user.get("type") == "Bot",
        )

    def _gitlab_mr(self, host: str, repo: str, n: str, mr_url: str) -> list[Comment]:
        project = quote(repo, safe="")
        notes = _values(
            self._run(
                [
                    "glab",
                    "api",
                    "--hostname",
                    host,
                    "--paginate",
                    f"projects/{project}/merge_requests/{n}/notes?per_page=100&sort=asc",
                ]
            )
        )
        people: dict[int, tuple[bool, bool]] = {}
        out = []
        for note in notes:
            if note.get("system"):
                continue
            author = note["author"]
            if author["id"] not in people:
                people[author["id"]] = self._gitlab_person(host, project, author["id"])
            bot, maintainer = people[author["id"]]
            out.append(
                Comment(
                    source=SourceType.MR_COMMENT,
                    author=ExternalHandle(author["username"]),
                    body=note.get("body") or "",
                    at=_when(note["created_at"]),
                    url=f"{mr_url.rstrip('/')}#note_{note['id']}",
                    bot=bot,
                    maintainer=maintainer,
                )
            )
        return out

    def _gitlab_person(self, host: str, project: str, user_id: int) -> tuple[bool, bool]:
        """(bot, maintainer); no member record means not a maintainer."""
        (user,) = _values(self._run(["glab", "api", "--hostname", host, f"users/{user_id}"]))
        member = ["glab", "api", "--hostname", host, f"projects/{project}/members/all/{user_id}"]
        answer = self._try(member)
        level = next(_values(answer)).get("access_level", 0) if answer else 0
        return bool(user.get("bot")), level >= _MAINTAINER

    def _gitlab_commit(self, host: str, repo: str, sha: str) -> Comment:
        project = quote(repo, safe="")
        (c,) = _values(
            self._run(
                ["glab", "api", "--hostname", host, f"projects/{project}/repository/commits/{sha}"]
            )
        )
        return Comment(
            source=SourceType.COMMIT,
            author=ExternalHandle(c.get("author_email") or c["author_name"]),
            body=c["message"],
            at=_when(c["authored_date"]),
            url=c.get("web_url"),
        )


class JiraCommentSource(_Cli):
    """A Jira ticket's comments and its status. jira-cli gives no changelog, so who moved the
    ticket is unknown (the transition statement has no author)."""

    def __init__(self, process: ProcessRunner, clock: Clock) -> None:
        super().__init__(process, clock, JIRA)

    def check(self) -> Readiness:
        return Readiness(ready=shutil.which("jira") is not None, detail="jira")

    def comments(self, ref: ExternalRef) -> Result[list[Comment]]:
        if not _JIRA_KEY.match(ref.ref):
            raise ValidationError(f"not a Jira key: {ref.ref}")
        (issue,) = _values(
            self._run(["jira", "issue", "view", ref.ref, "--raw", "--comments", "100"])
        )
        fields = issue.get("fields") or {}
        browse = f"{str(issue.get('self', '')).split('/rest/')[0]}/browse/{ref.ref}"
        out = []
        status = (fields.get("resolution") or {}).get("name") or (fields.get("status") or {}).get(
            "name"
        )
        if status:
            out.append(
                Comment(
                    source=SourceType.JIRA,
                    author=ExternalHandle(""),
                    body=_text(fields.get("description")),
                    at=_jira_when(fields.get("resolutiondate") or fields["updated"]),
                    url=browse,
                    status=status,
                )
            )
        for c in (fields.get("comment") or {}).get("comments") or ():
            author = c.get("author") or {}
            out.append(
                Comment(
                    source=SourceType.JIRA,
                    author=ExternalHandle(
                        author.get("emailAddress") or author.get("displayName", "")
                    ),
                    body=_text(c.get("body")),
                    at=_jira_when(c["created"]),
                    url=f"{browse}?focusedCommentId={c['id']}",
                    bot=author.get("accountType") == "app",
                )
            )
        return self._result(out, ref)


def _text(value: Any) -> str:
    """Plain text from a Jira field: a string, or an Atlassian document (its text nodes)."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        own = value.get("text", "") if value.get("type") == "text" else ""
        inner = "".join(_text(v) for v in value.get("content") or ())
        return own + inner + ("\n" if value.get("type") == "paragraph" else "")
    return ""


def _jira_when(raw: str) -> datetime:
    """Jira writes `2026-10-23T09:00:00.000+0000`."""
    return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%f%z")
