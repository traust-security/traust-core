"""REST reads from a repository's forge over `HttpFetcher`: no forge CLI on the runner. A host's
kind comes from `forge_hosts`, its token from `Config.forge_tokens`, sent only as a header."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from typing import Any, BinaryIO, TypeVar

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.providers.http import HttpFetcher

T = TypeVar("T")
GITHUB, GITLAB = "github", "gitlab"


class ForgeApi:
    """GitHub (`api.github.com`, Enterprise `/api/v3`) and GitLab (`/api/v4`) REST, one client."""

    def __init__(
        self, http: HttpFetcher, hosts: Mapping[str, str], tokens: Mapping[str, str] | None = None
    ) -> None:
        self._http, self._hosts, self._tokens = http, dict(hosts), dict(tokens or {})

    def kind(self, host: str) -> str:
        kind = self._hosts.get(host)
        if kind not in (GITHUB, GITLAB):
            raise ValidationError(f"{host} is not a known forge (forge_hosts)")
        return kind

    def url(self, host: str, endpoint: str) -> str:
        if self.kind(host) == GITLAB:
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

    def get(self, host: str, endpoint: str) -> Any:
        return _json(self._http.get(self.url(host, endpoint), self.headers(host)), endpoint)

    def find(self, host: str, endpoint: str) -> Any | None:
        """The answer, or None when the forge says there is none (404)."""
        try:
            return self.get(host, endpoint)
        except ServiceError as e:
            if e.status == 404:
                return None
            raise

    def items(self, host: str, endpoint: str) -> Iterator[Any]:
        """Every item of a paginated list endpoint, page after page."""
        for body in self._http.pages(self.url(host, endpoint), self.headers(host)):
            page = _json(body, endpoint)
            if not isinstance(page, list):
                raise ServiceError(f"{host} {endpoint}: expected a list, got {type(page).__name__}")
            yield from page

    def stream(self, host: str, endpoint: str, consume: Callable[[BinaryIO], T]) -> T:
        return self._http.stream(self.url(host, endpoint), consume, self.headers(host))


def _json(body: bytes, endpoint: str) -> Any:
    try:
        return json.loads(body)
    except ValueError as e:
        raise ServiceError(f"{endpoint}: the forge answered with no JSON: {e}") from e
