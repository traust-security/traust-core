from __future__ import annotations

import base64
import binascii
import json
import re
import shutil
from collections.abc import Iterator, Mapping, Sequence
from typing import Any
from urllib.parse import quote

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.inventory import OrgName
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.providers.base import Acquisition, Readiness, Result
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


def _gitlab_listing(project: Mapping[str, Any]) -> Mapping[str, Any]:
    return dict(
        url=project["web_url"],
        archived=project["archived"],
        visibility=project["visibility"],
        fork=bool(project.get("forked_from_project")),
    )


class CommandSourceProvider:
    name = "forge-cli"

    def __init__(self, process: ProcessRunner, clock: Clock, hosts: Mapping[str, str]) -> None:
        self._process, self._clock, self._hosts = process, clock, dict(hosts)

    def check(self) -> Readiness:
        missing = [binary for binary in ("gh", "glab") if shutil.which(binary) is None]
        return Readiness(ready=not missing, detail=", ".join(missing))

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
            payload = self._payload(
                [
                    "gh",
                    "api",
                    f"repos/{repo.path}",
                    "--hostname",
                    repo.host,
                    "--jq",
                    "{pushed_at, archived, default_branch, visibility, "
                    "fork, parent: .parent.full_name}",
                ]
            )
            data = {
                k: payload.get(k)
                for k in ("pushed_at", "archived", "default_branch", "visibility", "fork", "parent")
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
            text = (
                self._api(repo, f"repos/{repo.path}/contents/{name}", ".content")
                if github
                else self._api(
                    repo, f"projects/{project}/repository/files/{quote(name, safe='')}/raw?ref=HEAD"
                )
            )
            if text is not None:
                text = _base64(text) if github else text
                hints += [
                    OwnerHint(handle=h, origin=OwnerOrigin.OWNERS_FILE, file=name)
                    for h in approvers_from_owners(text)
                ]
                break
        if github:
            raw = self._api(repo, f"repos/{repo.path}/contributors?per_page=10", ".[].login")
            names = (raw or "").split()
        else:
            raw = self._api(repo, f"projects/{project}/repository/contributors?per_page=10")
            try:
                names = [c.get("name") or c.get("email") or "" for c in json.loads(raw or "[]")]
            except (ValueError, TypeError, AttributeError) as exc:
                raise SourceError("malformed forge response", ComparisonStatus.ERROR) from exc
        people = [n for n in names if n and not _BOT.search(n)][:TOP_CONTRIBUTORS]
        hints += [OwnerHint(handle=n, origin=OwnerOrigin.CONTRIBUTOR) for n in people]
        return self._result(hints, repo)

    def _api(self, repo: HttpsRepoUrl, endpoint: str, jq: str | None = None) -> str | None:
        """One forge API read; None when the forge answers with an error such as a missing file.
        Credential and network failures still raise."""
        if self._hosts[repo.host] == "github":
            argv = ["gh", "api", endpoint, "--hostname", repo.host, *(["--jq", jq] if jq else [])]
        else:
            argv = ["glab", "api", "--hostname", repo.host, endpoint]
        try:
            return self._run(argv)
        except SourceError as exc:
            if exc.observation_status != ComparisonStatus.ERROR:
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
            argv = ["gh", "api", "--paginate", "--hostname", host]
            argv += [f"orgs/{org}/repos?type=sources&per_page=100"]
            argv += ["--jq", ".[] | {url: .html_url, archived, visibility, fork}"]
        else:
            endpoint = (
                f"groups/{quote(org, safe='')}/projects?"
                "include_subgroups=true&archived=false&per_page=100"
            )
            argv = ["glab", "api", "--paginate", "--hostname", host, endpoint]
        try:
            rows = [
                row if kind == "github" else _gitlab_listing(row)
                for row in _json_values(self._run(argv))
            ]
            infos = [
                RepoInfo(
                    repo=HttpsRepoUrl.parse(row["url"], (host,)),
                    archived=row["archived"],
                    visibility=row["visibility"],
                    fork=row["fork"],
                )
                for row in rows
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
        # Existing audit reports contain abbreviated SHAs; do not weaken GitSha.parse().
        if not re.fullmatch(r"[0-9a-f]{7,40}", baseline):
            raise SourceError("unsafe comparison baseline", ComparisonStatus.ERROR)
        if kind == "github":
            payload = self._payload(
                [
                    "gh",
                    "api",
                    f"repos/{repo.path}/compare/{baseline}...HEAD",
                    "--hostname",
                    repo.host,
                    "--jq",
                    "{ahead_by, status, files: [.files[] | {filename, changes}]}",
                ]
            )
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

    def head(self, repo: HttpsRepoUrl, branch: str) -> Result[GitSha]:
        """The commit a branch points at."""
        name = quote(branch, safe="")
        if self._kind(repo) == "github":
            argv = ["gh", "api", f"repos/{repo.path}/branches/{name}", "--hostname", repo.host]
            argv += ["--jq", "{sha: .commit.sha}"]
            sha = self._payload(argv).get("sha")
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
            payload = self._payload(
                ["gh", "api", f"repos/{repo.path}/commits/{sha}", "--hostname", repo.host]
            )
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
            remaining = int(
                self._run(
                    [
                        "gh",
                        "api",
                        "rate_limit",
                        "--hostname",
                        repo.host,
                        "--jq",
                        ".resources.core.remaining",
                    ]
                ).strip()
            )
        except (SourceError, ValueError):
            remaining = None
        return self._result(Quota(remaining=remaining), repo)

    def checkout(self, request: CheckoutRequest) -> Result[Workspace]:
        raise ServiceError("forge-cli only observes repositories; inject a checkout provider")

    def release(self, workspace: Workspace) -> None:
        raise ServiceError("forge-cli does not own checkout workspaces")
