"""A commit's tree from its forge's archive API, kept to the files a reader needs: no git and no
forge CLI on the runner, and only kept files ever touch its disk."""

from __future__ import annotations

import logging
import shutil
import tarfile
import tempfile
from collections.abc import Mapping
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from urllib.parse import quote

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.http import HttpFetcher
from traust_core.v1.providers.sources import CheckoutRequest, Workspace

log = logging.getLogger(__name__)

KEPT_CAP_BYTES = 64 * 1024 * 1024


class ArchiveCheckout:
    """`SourceProvider`'s checkout seam over the archive API: GitHub `tarball/{sha}`, GitLab
    `repository/archive.tar.gz?sha=`; a host's token (from `Config`) goes only in a header."""

    name = "forge-archive"

    def __init__(
        self,
        http: HttpFetcher,
        clock: Clock,
        hosts: Mapping[str, str],
        tokens: Mapping[str, str] | None = None,
        cap_bytes: int = KEPT_CAP_BYTES,
    ) -> None:
        self._http, self._clock = http, clock
        self._hosts, self._tokens = dict(hosts), dict(tokens or {})
        self._cap = cap_bytes

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def checkout(self, request: CheckoutRequest) -> Result[Workspace]:
        if request.ref is None:
            raise ValidationError("an archive checkout needs the commit's sha")
        sha = str(request.ref)
        url, headers = self._archive(request.repo, sha)
        dest = Path(tempfile.mkdtemp(prefix="checkout-"))
        try:
            kept = self._http.stream(
                url, lambda body: _extract(body, dest, request.keep, self._cap), headers
            )
        except BaseException:
            shutil.rmtree(dest, ignore_errors=True)
            raise
        log.info("checked out %s@%s: %d bytes kept", request.repo, sha, kept)
        return Result(
            Workspace(repo=request.repo, sha=request.ref, path=dest),
            Acquisition(provider=self.name, acquired_at=self._clock.now(), source=url),
        )

    def release(self, workspace: Workspace) -> None:
        shutil.rmtree(workspace.path, ignore_errors=True)

    def _archive(self, repo: HttpsRepoUrl, sha: str) -> tuple[str, dict[str, str]]:
        token = self._tokens.get(repo.host)
        kind = self._hosts.get(repo.host)
        if kind == "github":
            api = (
                "https://api.github.com"
                if repo.host == "github.com"
                else f"https://{repo.host}/api/v3"
            )
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            return f"{api}/repos/{repo.path}/tarball/{sha}", headers
        if kind == "gitlab":
            project = quote(repo.path, safe="")
            headers = {"PRIVATE-TOKEN": token} if token else {}
            url = (
                f"https://{repo.host}/api/v4/projects/{project}/repository/archive.tar.gz?sha={sha}"
            )
            return url, headers
        raise ValidationError(f"{repo.host} is not a known forge (forge_hosts)")


def _extract(body: BinaryIO, dest: Path, keep: tuple[str, ...] | None, cap: int) -> int:
    """The kept regular files of a gzipped tar stream under `dest`; their total size."""
    for child in dest.iterdir():  # a retry starts over
        shutil.rmtree(child) if child.is_dir() else child.unlink()
    kept = 0
    with tarfile.open(fileobj=body, mode="r|gz") as tar:
        for member in tar:
            rel = _relative(member.name)
            if rel is None or not member.isfile():
                continue
            if keep is not None and not any(
                fnmatchcase(str(rel) if "/" in g else rel.name, g) for g in keep
            ):
                continue
            kept += member.size
            if kept > cap:
                raise ServiceError(f"the kept files exceed the {cap}-byte workspace cap")
            target = dest.joinpath(*rel.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            assert source is not None
            with target.open("wb") as out:
                shutil.copyfileobj(source, out)
    return kept


def _relative(name: str) -> PurePosixPath | None:
    """The member's path below the archive's top directory; absolute or `..` paths are refused."""
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValidationError(f"unsafe archive member {name!r}")
    return PurePosixPath(*path.parts[1:]) if len(path.parts) > 1 else None
