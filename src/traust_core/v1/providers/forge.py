from __future__ import annotations

import base64
import binascii
import json
import os
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any
from urllib.parse import quote

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.inventory import OrgName
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.values import GitSha, HttpsRepoUrl, RepoPath
from traust_core.v1.providers.base import Acquisition, Readiness, Result, on_path
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.sources import (
    ChangedFile,
    CheckoutRequest,
    Commit,
    CommitFile,
    Comparison,
    OwnerHint,
    OwnerOrigin,
    Quota,
    RepoInfo,
    RepoTree,
    SourceError,
    Workspace,
)

GH_COMPARE_FILE_CAP = 300
GITLAB_DIFF_CAP = 1000
TRIPWIRE_PATCH_CAP = 2_000_000
OWNERS_FILES = ("OWNERS", "CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS")
TOP_CONTRIBUTORS = 5
_BOT = re.compile(r"\[bot\]$|^web-flow$|-bot$|-robot$|^dependabot", re.IGNORECASE)
_SPACE = re.compile(r"\s*")
_ORG_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def approvers_from_owners(text: str) -> list[str]:
    """The `approvers:` of an OWNERS file, or the handles a CODEOWNERS file names, in order."""
    found: list[str] = []
    in_block = False
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if re.match(r"^approvers\s*:", s):
            rest = s.split(":", 1)[1].strip()
            in_block = not rest.startswith("[")
            found += [x.strip(" '\"") for x in rest.strip("[]").split(",") if x.strip()]
            continue
        if in_block and s.startswith("- "):
            found.append(s[2:].strip(" '\""))
            continue
        in_block = False
        found += [h[1:] for h in re.findall(r"@[A-Za-z0-9_./-]+", s)]
    return list(dict.fromkeys(a for a in found if a))


def _failure(stderr: str) -> ComparisonStatus:
    s = stderr.lower()
    if any(word in s for word in ("401", "unauthorized", "authentication")):
        return ComparisonStatus.NO_CREDENTIALS
    if any(
        word in s
        for word in (
            "dial tcp",
            "no such host",
            "connection refused",
            "i/o timeout",
            "could not resolve",
            "network is unreachable",
            "tls handshake timeout",
        )
    ):
        return ComparisonStatus.UNREACHABLE
    return ComparisonStatus.ERROR


def _text(value: bytes | str) -> str:
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def _json_values(text: str) -> Iterator[Mapping[str, Any]]:
    """Objects from JSON lines (`gh --jq`) or concatenated pages of arrays (`glab --paginate`)."""
    decoder, at = json.JSONDecoder(), _SPACE.match(text, 0).end()
    while at < len(text):
        value, at = decoder.raw_decode(text, at)
        yield from value if isinstance(value, list) else [value]
        at = _SPACE.match(text, at).end()


def _base64(content: str) -> str:
    try:
        return base64.b64decode("".join(content.split()), validate=True).decode(errors="replace")
    except (binascii.Error, ValueError) as exc:
        raise SourceError("malformed forge response", ComparisonStatus.ERROR) from exc


def _check_baseline(baseline: str) -> None:
    # Existing audit reports contain abbreviated SHAs; do not weaken GitSha.parse().
    if not re.fullmatch(r"[0-9a-f]{7,40}", baseline):
        raise SourceError("unsafe comparison baseline", ComparisonStatus.ERROR)


def _gitlab_listing(project: Mapping[str, Any]) -> Mapping[str, Any]:
    return dict(
        url=project["web_url"],
        archived=project["archived"],
        visibility=project["visibility"],
        fork=bool(project.get("forked_from_project")),
    )


def _github_content(answer: Any) -> str | None:
    """The decoded content of a contents-API answer, or None when the path is
    not a plain file (the caller falls through to the next candidate)."""
    try:
        if answer.get("type") != "file" or not isinstance(answer.get("content"), str):
            return None
        return _base64(answer["content"])
    except AttributeError as exc:
        raise SourceError("malformed forge response", ComparisonStatus.ERROR) from exc


# GitHub hosts are called over the network, not through the gh CLI: no binary
# to ship per image, no subprocess per read, and the token is read per call
# (rotation). GitHub Enterprise Server exposes the same REST API under
# /api/v3; github.com's lives at its own host.
def _github_base(host: str) -> str:
    return "https://api.github.com" if host == "github.com" else f"https://{host}/api/v3"


def _http_fetch(url: str, headers: Mapping[str, str]) -> tuple[int, str]:
    """One network read: (status, body). Transport failures raise OSError."""
    request = urllib.request.Request(url, headers=dict(headers))
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")


# A fetch answer is (status, body); injected by tests.
Fetch = Callable[[str, Mapping[str, str]], tuple[int, str]]


class CommandSourceProvider:
    name = "forge-cli"

    def __init__(
        self,
        process: ProcessRunner,
        clock: Clock,
        hosts: Mapping[str, str],
        fetch: Fetch | None = None,
    ) -> None:
        self._process, self._clock, self._hosts = process, clock, dict(hosts)
        self._fetch = fetch or _http_fetch

    def check(self) -> Readiness:
        # GitHub hosts read the REST API over the network; the CLI remains
        # only where a use case is truly minimal (gitlab hosts, checkouts).
        if any(kind == "gitlab" for kind in self._hosts.values()):
            return on_path("glab", missing=" (gitlab hosts still read through the CLI)")
        return Readiness(ready=True)

    def _kind(self, repo: HttpsRepoUrl) -> str:
        checked = HttpsRepoUrl.parse(str(repo), self._hosts)
        kind = self._hosts[checked.host]
        if kind == "github" and len(checked.path.split("/")) != 2:
            raise ValidationError("GitHub source requires an owner/repository URL")
        if kind not in ("github", "gitlab"):
            raise ValidationError(f"unsupported forge kind: {kind}")
        return kind

    def _run(self, argv: Sequence[str]) -> str:
        try:
            result = self._process.run(argv, check=False)
        except ServiceError as exc:
            status = ComparisonStatus.UNREACHABLE
            if argv[0] == "glab" and isinstance(exc.__cause__, FileNotFoundError):
                status = ComparisonStatus.NO_CREDENTIALS
            raise SourceError(str(exc)[:120], status) from exc
        if result.returncode:
            stderr = _text(result.stderr)
            raise SourceError(stderr.strip()[:120] or "api-error", _failure(stderr))
        return _text(result.stdout)

    def _github_headers(self, accept: str) -> dict[str, str]:
        headers = {
            "Accept": accept,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "traust-core",
        }
        if token := os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"):
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _github_status(self, status: int, body: str) -> None:
        """Raise for a failed HTTP status, mapped like the CLI's stderr was."""
        if status in (401, 403, 429):
            # 403 also carries GitHub's rate limit; the body names it when so.
            raise SourceError(f"HTTP {status}: {body.strip()[:80]}", _failure(body))
        if status >= 400:
            raise SourceError(f"HTTP {status}", ComparisonStatus.ERROR)

    def _github_text(self, host: str, endpoint: str, accept: str) -> str:
        """One GitHub REST read as text, over the network."""
        url = f"{_github_base(host)}/{endpoint}"
        try:
            status, body = self._fetch(url, self._github_headers(accept))
        except OSError as exc:
            raise SourceError(str(exc)[:120], ComparisonStatus.UNREACHABLE) from exc
        self._github_status(status, body)
        return body

    def _github(self, host: str, endpoint: str) -> Any:
        """One GitHub REST read, parsed."""
        body = self._github_text(host, endpoint, "application/vnd.github+json")
        try:
            return json.loads(body)
        except ValueError as exc:
            raise SourceError("malformed forge response", ComparisonStatus.ERROR) from exc

    def _github_object(self, host: str, endpoint: str) -> Mapping[str, Any]:
        """One GitHub REST read, parsed as an object; a non-object answer is malformed."""
        payload = self._github(host, endpoint)
        if not isinstance(payload, dict):
            raise SourceError("malformed forge response", ComparisonStatus.ERROR)
        return payload

    def _github_optional(self, host: str, endpoint: str) -> Any | None:
        """One GitHub REST read, parsed; None only when the forge answers 404."""
        try:
            return self._github(host, endpoint)
        except SourceError as exc:
            if exc.observation_status != ComparisonStatus.ERROR or "HTTP 404" not in str(exc):
                raise
            return None

    def _payload(self, argv: Sequence[str]) -> Mapping[str, Any]:
        try:
            value = json.loads(self._run(argv))
            if not isinstance(value, dict):
                raise TypeError("expected a JSON object")
            return value
        except (ValueError, TypeError) as exc:
            raise SourceError("malformed forge response", ComparisonStatus.ERROR) from exc

    def _result(self, data: Any, repo: HttpsRepoUrl) -> Result[Any]:
        return Result(
            data, Acquisition(provider=self.name, acquired_at=self._clock.now(), source=str(repo))
        )

    def info(self, repo: HttpsRepoUrl) -> Result[RepoInfo]:
        kind = self._kind(repo)
        if kind == "github":
            payload = self._github_object(repo.host, f"repos/{repo.path}")
            try:
                parent = (payload.get("parent") or {}).get("full_name")
            except (AttributeError, TypeError) as exc:
                raise SourceError("malformed forge response", ComparisonStatus.ERROR) from exc
            data = {
                "pushed_at": payload.get("pushed_at"),
                "archived": payload.get("archived"),
                "default_branch": payload.get("default_branch"),
                "visibility": payload.get("visibility"),
                "fork": payload.get("fork"),
                "parent": parent,
            }
        else:
            payload = self._payload(
                ["glab", "api", "--hostname", repo.host, f"projects/{quote(repo.path, safe='')}"]
            )
            try:
                parent = (payload.get("forked_from_project") or {}).get("path_with_namespace")
            except (AttributeError, TypeError) as exc:
                raise SourceError("malformed forge response", ComparisonStatus.ERROR) from exc
            data = dict(
                pushed_at=payload.get("last_activity_at"),
                archived=payload.get("archived"),
                default_branch=payload.get("default_branch"),
                visibility=payload.get("visibility"),
                fork=bool(parent),
                parent=parent,
            )
        try:
            info = RepoInfo.model_validate(dict(repo=repo, **data), strict=True)
        except (ValueError, TypeError) as exc:
            raise SourceError("malformed forge response", ComparisonStatus.ERROR) from exc
        return self._result(info, repo)

    def owners(self, repo: HttpsRepoUrl) -> Result[list[OwnerHint]]:
        """Approvers from the first OWNERS / CODEOWNERS file found, then top contributors."""
        github = self._kind(repo) == "github"
        project = quote(repo.path, safe="")
        hints: list[OwnerHint] = []
        for name in OWNERS_FILES:
            if github:
                answer = self._github_optional(repo.host, f"repos/{repo.path}/contents/{name}")
                text = None if answer is None else _github_content(answer)
            else:
                text = self._api(
                    repo, f"projects/{project}/repository/files/{quote(name, safe='')}/raw?ref=HEAD"
                )
            if text is not None:
                hints += [
                    OwnerHint(handle=h, origin=OwnerOrigin.OWNERS_FILE, file=name)
                    for h in approvers_from_owners(text)
                ]
                break
        if github:
            answer = self._github_optional(repo.host, f"repos/{repo.path}/contributors?per_page=10")
            try:
                names = [c["login"] for c in answer or []]
            except (TypeError, KeyError) as exc:
                raise SourceError("malformed forge response", ComparisonStatus.ERROR) from exc
        else:
            raw = self._api(repo, f"projects/{project}/repository/contributors?per_page=10")
            try:
                names = [c.get("name") or c.get("email") or "" for c in json.loads(raw or "[]")]
            except (ValueError, TypeError, AttributeError) as exc:
                raise SourceError("malformed forge response", ComparisonStatus.ERROR) from exc
        people = [n for n in names if n and not _BOT.search(n)][:TOP_CONTRIBUTORS]
        hints += [OwnerHint(handle=n, origin=OwnerOrigin.CONTRIBUTOR) for n in people]
        return self._result(hints, repo)

    def file(self, repo: HttpsRepoUrl, path: RepoPath, sha: GitSha) -> Result[str | None]:
        """One file's text at a commit; None when the forge has no such file there."""
        if not isinstance(path, RepoPath) or not isinstance(sha, GitSha):
            raise ValidationError("a forge file read needs a RepoPath and a full GitSha")
        GitSha.parse(sha.value)
        if self._kind(repo) == "github":
            answer = self._github_optional(
                repo.host, f"repos/{repo.path}/contents/{path}?ref={sha}"
            )
            text = None if answer is None else self._github_file(answer, path)
        else:
            project, name = quote(repo.path, safe=""), quote(str(path), safe="")
            text = self._api(repo, f"projects/{project}/repository/files/{name}/raw?ref={sha}")
        return self._result(text, repo)

    def _github_file(self, answer: Any, path: RepoPath) -> str:
        try:
            kind, encoding, content = answer["type"], answer["encoding"], answer["content"]
        except (ValueError, TypeError, KeyError) as exc:
            raise SourceError("malformed forge response", ComparisonStatus.ERROR) from exc
        if (kind, encoding) != ("file", "base64") or not isinstance(content, str):
            # Directories, symlinks and files over the contents API's 1 MB cap come back so.
            raise SourceError(
                f"{path} is a {kind} the forge returns as {encoding}", ComparisonStatus.ERROR
            )
        return _base64(content)

    def _api(self, repo: HttpsRepoUrl, endpoint: str, jq: str | None = None) -> str | None:
        """One gitlab API read; None only when the forge answers HTTP 404."""
        argv = ["glab", "api", "--hostname", repo.host, endpoint]
        try:
            return self._run(argv)
        except SourceError as exc:
            if exc.observation_status != ComparisonStatus.ERROR or not re.search(
                r"\bHTTP\s+404\b", str(exc)
            ):
                raise
            return None

    def list_org(self, org: OrgName, host: str) -> Result[list[RepoInfo]]:
        """An organisation's (GitLab: group's, with subgroups) non-archived, non-fork repos."""
        kind = self._hosts.get(host)
        segments = org.split("/")
        if kind not in ("github", "gitlab") or not all(map(_ORG_SEGMENT.fullmatch, segments)):
            raise ValidationError(f"cannot list {org!r} on {host!r}")
        if kind == "github":
            if len(segments) != 1:
                raise ValidationError("a GitHub organization has no subgroups")
            rows: list[Mapping[str, Any]] = []
            page = 1
            while True:
                batch = self._github(host, f"orgs/{org}/repos?type=sources&per_page=100&page={page}")
                if not isinstance(batch, list):
                    raise SourceError("malformed forge response", ComparisonStatus.ERROR)
                rows.extend(
                    {
                        "url": row.get("html_url"),
                        "archived": row.get("archived"),
                        "visibility": row.get("visibility"),
                        "fork": row.get("fork"),
                    }
                    for row in map(dict, batch)
                )
                if len(batch) < 100:
                    break
                page += 1
        else:
            endpoint = (
                f"groups/{quote(org, safe='')}/projects?"
                "include_subgroups=true&archived=false&per_page=100"
            )
            argv = ["glab", "api", "--paginate", "--hostname", host, endpoint]
            rows = [_gitlab_listing(row) for row in _json_values(self._run(argv))]
        try:
            infos = [
                RepoInfo.model_validate(
                    {**row, "repo": HttpsRepoUrl.parse(row.pop("url"), (host,))}, strict=True
                )
                for row in map(dict, rows)
            ]
        except (ValueError, TypeError, KeyError, AttributeError, ValidationError) as exc:
            raise SourceError("malformed forge response", ComparisonStatus.ERROR) from exc
        kept = sorted((i for i in infos if not (i.archived or i.fork)), key=lambda i: str(i.repo))
        return Result(
            kept,
            Acquisition(provider=self.name, acquired_at=self._clock.now(), source=f"{host}/{org}"),
        )

    def compare(self, repo: HttpsRepoUrl, baseline: str, branch: str) -> Result[Comparison]:
        kind = self._kind(repo)
        _check_baseline(baseline)
        if kind == "github":
            payload = self._github_object(repo.host, f"repos/{repo.path}/compare/{baseline}...HEAD")
        else:
            endpoint = (
                f"projects/{quote(repo.path, safe='')}/repository/compare?"
                f"from={baseline}&to={quote(branch or 'HEAD', safe='')}"
            )
            payload = self._payload(["glab", "api", "--hostname", repo.host, endpoint])
        try:
            if kind == "github":
                files = tuple(
                    ChangedFile.model_validate(f, strict=True) for f in payload.get("files") or []
                )
                # Boolean/float/null ahead_by must not coerce into a measurement.
                ahead = payload.get("ahead_by")
                if isinstance(ahead, bool) or not isinstance(ahead, int):
                    raise ValueError("ahead_by must be an integer")
                result = Comparison(
                    ahead_by=ahead, files=files, truncated=len(files) >= GH_COMPARE_FILE_CAP
                )
            else:
                diffs = payload.get("diffs") or []
                files = tuple(
                    ChangedFile(
                        filename=d.get("new_path") or d.get("old_path") or "",
                        changes=sum(
                            line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
                            for line in (d.get("diff") or "").splitlines()
                        ),
                    )
                    for d in diffs
                )
                # GitLab omits diff content under collapsed / too_large: the comparison
                # is incomplete, never a complete zero-line measurement.
                omitted = bool(payload.get("too_large")) or any(
                    d.get("collapsed") or d.get("too_large") for d in diffs
                )
                result = Comparison(
                    ahead_by=len(payload.get("commits") or []),
                    files=files,
                    truncated=omitted
                    or bool(payload.get("compare_timeout"))
                    or len(diffs) >= GITLAB_DIFF_CAP,
                    patch="\n".join(d.get("diff") or "" for d in diffs)[:TRIPWIRE_PATCH_CAP],
                )
        except (ValueError, TypeError, AttributeError, KeyError) as exc:
            raise SourceError("malformed forge response", ComparisonStatus.ERROR) from exc
        return self._result(result, repo)

    def compare_patch(self, repo: HttpsRepoUrl, baseline: str) -> Result[str]:
        """The unified diff from the baseline to HEAD, capped (GitHub only: GitLab's `compare`
        already carries it)."""
        if self._kind(repo) != "github":
            raise ValidationError("a compare patch fetch needs a GitHub repository")
        _check_baseline(baseline)
        patch = self._github_text(
            repo.host,
            f"repos/{repo.path}/compare/{baseline}...HEAD",
            "application/vnd.github.v3.diff",
        )
        return self._result(patch[:TRIPWIRE_PATCH_CAP], repo)

    def tree(self, repo: HttpsRepoUrl, ref: str) -> Result[RepoTree]:
        """Every file path in a branch's or commit's tree, paginating GitLab listings."""
        if self._kind(repo) == "github":
            payload = self._github_object(
                repo.host, f"repos/{repo.path}/git/trees/{quote(ref, safe='')}?recursive=1"
            )
            try:
                payload = {
                    "truncated": payload["truncated"],
                    "paths": [t["path"] for t in payload["tree"] if t["type"] == "blob"],
                }
            except (TypeError, KeyError) as exc:
                raise SourceError("malformed forge response", ComparisonStatus.ERROR) from exc
        else:
            endpoint = (
                f"projects/{quote(repo.path, safe='')}/repository/tree?"
                f"ref={quote(ref, safe='')}&recursive=true&per_page=100"
            )
            try:
                rows = _json_values(
                    self._run(["glab", "api", "--paginate", "--hostname", repo.host, endpoint])
                )
                paths = []
                for row in rows:
                    if row["type"] not in ("blob", "tree", "commit") or not isinstance(
                        row["path"], str
                    ):
                        raise TypeError("expected a repository tree entry")
                    if row["type"] == "blob":
                        paths.append(row["path"])
                payload = {"paths": paths, "truncated": False}
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                raise SourceError("malformed forge response", ComparisonStatus.ERROR) from exc
        try:
            tree = RepoTree.model_validate(
                {"paths": tuple(payload.get("paths") or ()), "truncated": payload["truncated"]},
                strict=True,
            )
        except (ValueError, TypeError, KeyError) as exc:
            raise SourceError("malformed forge response", ComparisonStatus.ERROR) from exc
        return self._result(tree, repo)

    def head(self, repo: HttpsRepoUrl, branch: str) -> Result[GitSha]:
        """The commit a branch points at."""
        name = quote(branch, safe="")
        if self._kind(repo) == "github":
            payload = self._github_object(repo.host, f"repos/{repo.path}/branches/{name}")
            try:
                sha = (payload.get("commit") or {}).get("sha")
            except (AttributeError, TypeError) as exc:
                raise SourceError("malformed forge response", ComparisonStatus.ERROR) from exc
        else:
            endpoint = f"projects/{quote(repo.path, safe='')}/repository/branches/{name}"
            sha = (
                self._payload(["glab", "api", "--hostname", repo.host, endpoint]).get("commit")
                or {}
            ).get("id")
        try:
            return self._result(GitSha.parse(sha), repo)
        except (ValidationError, TypeError) as exc:
            raise SourceError("malformed forge response", ComparisonStatus.ERROR) from exc

    def commit(self, repo: HttpsRepoUrl, sha: str) -> Result[Commit]:
        """One commit's changed files and their patches."""
        if not re.fullmatch(r"[0-9a-f]{7,40}", sha):
            raise SourceError("unsafe commit sha", ComparisonStatus.ERROR)
        if self._kind(repo) == "github":
            payload = self._github_object(repo.host, f"repos/{repo.path}/commits/{sha}")
            files = [(f.get("filename"), f.get("patch")) for f in payload.get("files") or ()]
        else:
            endpoint = f"projects/{quote(repo.path, safe='')}/repository/commits/{sha}/diff"
            try:
                diffs = json.loads(self._run(["glab", "api", "--hostname", repo.host, endpoint]))
                if not isinstance(diffs, list):
                    raise TypeError("expected a list of diffs")
                files = [(d.get("new_path") or d.get("old_path"), d.get("diff")) for d in diffs]
            except (ValueError, TypeError, AttributeError) as exc:
                raise SourceError("malformed forge response", ComparisonStatus.ERROR) from exc
        commit = Commit(
            sha=sha,
            files=tuple(
                CommitFile(filename=name, patch=patch or "") for name, patch in files if name
            ),
        )
        return self._result(commit, repo)

    def quota(self, repo: HttpsRepoUrl) -> Result[Quota]:
        if self._kind(repo) != "github":
            return self._result(Quota(remaining=None), repo)
        try:
            answer = self._github(repo.host, "rate_limit")
            remaining = int(answer["resources"]["core"]["remaining"])
        except (SourceError, ValueError, TypeError, KeyError):
            remaining = None
        return self._result(Quota(remaining=remaining), repo)

    def checkout(self, request: CheckoutRequest) -> Result[Workspace]:
        raise ServiceError("forge-cli only observes repositories; inject a checkout provider")

    def release(self, workspace: Workspace) -> None:
        raise ServiceError("forge-cli does not own checkout workspaces")
