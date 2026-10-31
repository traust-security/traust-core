"""REST reads from a repository's forge over `HttpFetcher`: no forge CLI on the runner. A host's
kind comes from `forge_hosts`, its token from `Config.forge_tokens`, sent only as a header."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Iterator, Mapping
from typing import Any, BinaryIO, TypeVar
from urllib.parse import quote

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.providers.http import HttpFetcher

T = TypeVar("T")
GITHUB, GITLAB = "github", "gitlab"


class ForgeApi:
    """GitHub (`api.github.com`, Enterprise `/api/v3`) and GitLab (`/api/v4`) REST, one client."""

    def __init__(
        self, http: HttpFetcher, hosts: Mapping[str, str], tokens: Mapping[str, str] | None = None
    ) -> None:
        self._http, self._hosts, self._tokens = http, dict(hosts), dict(tokens or {})

    def kind(self, host: str) -> str | None:
        """`github` or `gitlab` for a host in `forge_hosts`; None for any other host."""
        kind = self._hosts.get(host)
        return kind if kind in (GITHUB, GITLAB) else None

    def url(self, host: str, endpoint: str) -> str:
        kind = self.kind(host)
        if kind is None:
            raise ValidationError(f"{host} is not a known forge (forge_hosts)")
        if kind == GITLAB:
            return f"https://{host}/api/v4/{endpoint}"
        base = "https://api.github.com" if host == "github.com" else f"https://{host}/api/v3"
        return f"{base}/{endpoint}"

    def headers(self, host: str) -> dict[str, str]:
        token = self._tokens.get(host)
        if not token:
            return {}
        return (
            {"PRIVATE-TOKEN": token}
            if self.kind(host) == GITLAB
            else {"Authorization": f"Bearer {token}"}
        )

    def git_headers(self, host: str) -> dict[str, str]:
        """Auth for git's smart-HTTP transport, which takes HTTP Basic, not REST headers."""
        token = self._tokens.get(host)
        if not token:
            return {}
        username = "oauth2" if self.kind(host) == GITLAB else "x-access-token"
        basic = base64.b64encode(f"{username}:{token}".encode()).decode()
        return {"Authorization": f"Basic {basic}"}

    def review_refs(self, repo: HttpsRepoUrl, sha: str) -> tuple[str, ...]:
        """Review refs associated with a commit by the repository's forge, not by shared objects."""
        kind = self.kind(repo.host)
        if kind is None:
            return ()
        project = quote(repo.path, safe="")
        endpoint = (
            f"repos/{repo.path}/commits/{sha}/pulls?per_page=100"
            if kind == GITHUB
            else f"projects/{project}/repository/commits/{sha}/merge_requests?per_page=100"
        )
        try:
            items = list(self.items(repo.host, endpoint))
        except ServiceError as e:
            if e.status == 404:
                return ()
            raise
        refs = []
        for item in items:
            if not isinstance(item, dict):
                raise ServiceError(f"{endpoint}: expected a review object")
            number = item.get("number" if kind == GITHUB else "iid")
            if not isinstance(number, int) or isinstance(number, bool) or number < 1:
                raise ServiceError(f"{endpoint}: expected a positive review number")
            if kind == GITHUB:
                base = item.get("base")
                if not isinstance(base, dict) or not isinstance(base.get("repo"), dict):
                    raise ServiceError(f"{endpoint}: expected a base repository")
                if base["repo"].get("full_name") != repo.path:
                    continue
            refs.append(
                f"refs/pull/{number}/head"
                if kind == GITHUB
                else f"refs/merge-requests/{number}/head"
            )
        return tuple(refs)

    def get(self, host: str, endpoint: str, headers: Mapping[str, str] | None = None) -> Any:
        sent = {**self.headers(host), **(headers or {})}
        return _json(self._http.get(self.url(host, endpoint), sent), endpoint)

    def find(self, host: str, endpoint: str) -> Any | None:
        """The answer, or None when the forge says there is none (404)."""
        try:
            return self.get(host, endpoint)
        except ServiceError as e:
            if e.status == 404:
                return None
            raise

    def items(self, host: str, endpoint: str) -> Iterator[Any]:
        """Every item of a paginated list endpoint, page after page. A
        non-list answer chains a ValueError, like _json's parse failures:
        shape errors stay distinguishable from transport give-ups."""
        for body in self._http.pages(self.url(host, endpoint), self.headers(host)):
            page = _json(body, endpoint)
            if not isinstance(page, list):
                raise ServiceError(
                    f"{host} {endpoint}: expected a list, got {type(page).__name__}"
                ) from ValueError("the forge answered with no list")
            yield from page

    def stream(
        self,
        host: str,
        endpoint: str,
        consume: Callable[[BinaryIO], T],
        headers: Mapping[str, str] | None = None,
    ) -> T:
        sent = {**self.headers(host), **(headers or {})}
        return self._http.stream(self.url(host, endpoint), consume, sent)


def _json(body: bytes, endpoint: str) -> Any:
    try:
        return json.loads(body)
    except ValueError as e:
        raise ServiceError(f"{endpoint}: the forge answered with no JSON: {e}") from e
