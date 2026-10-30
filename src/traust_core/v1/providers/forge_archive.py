"""A commit's tree from its forge's archive API, kept to the files a reader needs: no git and no
forge CLI on the runner, and only kept files ever touch its disk."""

from __future__ import annotations

import hashlib
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
from traust_core.v1.providers.forge_api import GITLAB, ForgeApi
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
        self._api, self._clock, self._cap = ForgeApi(http, hosts, tokens), clock, cap_bytes

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def checkout(self, request: CheckoutRequest) -> Result[Workspace]:
        sha = str(request.ref)
        host, endpoint = request.repo.host, self._archive(request.repo, sha)
        url = self._api.url(host, endpoint)
        dest = Path(tempfile.mkdtemp(prefix="checkout-"))
        try:
            kept = self._api.stream(
                host, endpoint, lambda body: _extract(body, dest, request.keep, self._cap)
            )
        except BaseException:
            shutil.rmtree(dest, ignore_errors=True)
            raise
        repo_hash = hashlib.sha256(str(request.repo).encode()).hexdigest()[:16]
        log.info("checked out repo_hash=%s ref=%s: %d bytes kept", repo_hash, sha, kept)
        return Result(
            Workspace(repo=request.repo, sha=request.ref, path=dest, provider=self.name),
            Acquisition(provider=self.name, acquired_at=self._clock.now(), source=url),
        )

    def release(self, workspace: Workspace) -> None:
        shutil.rmtree(workspace.path, ignore_errors=True)

    def _archive(self, repo: HttpsRepoUrl, sha: str) -> str:
        if self._api.kind(repo.host) == GITLAB:
            return f"projects/{quote(repo.path, safe='')}/repository/archive.tar.gz?sha={sha}"
        return f"repos/{repo.path}/tarball/{sha}"


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
