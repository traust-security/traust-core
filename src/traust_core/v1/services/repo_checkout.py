"""The one door for a commit's files: picks the provider a `CheckoutRequest` asks for and owns
the mirror cache behind it; the providers only do I/O."""

from __future__ import annotations

from typing import Protocol

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.providers.base import Readiness, Result
from traust_core.v1.providers.mirror import MirrorCheckout
from traust_core.v1.providers.sources import CheckoutRequest, Workspace


class CheckoutProvider(Protocol):
    """The I/O seam the service routes between; providers never choose."""

    name: str

    def check(self) -> Readiness: ...

    def checkout(self, request: CheckoutRequest) -> Result[Workspace]: ...

    def release(self, workspace: Workspace) -> None: ...


class RepoCheckoutService:
    """Kept files through the archive; whole trees, history and writable checkouts through the
    mirror."""

    def __init__(self, archive: CheckoutProvider, mirror: MirrorCheckout) -> None:
        self._archive, self._mirror = archive, mirror

    def checkout(self, request: CheckoutRequest) -> Result[Workspace]:
        if isinstance(request.history, int) and request.history < 1:
            raise ValidationError(f"history depth must be at least 1, got {request.history}")
        if request.keep is not None and not request.keep:
            raise ValidationError(
                "a keep set must name at least one pattern; None keeps the whole tree"
            )
        return self._provider_for(request).checkout(request)

    def release(self, workspace: Workspace) -> None:
        if workspace.provider == self._archive.name:
            self._archive.release(workspace)
        elif workspace.provider == self._mirror.name:
            self._mirror.release(workspace)
        else:
            raise ValidationError(
                f"workspace {workspace.path} came from {workspace.provider!r}, "
                "not this service's providers"
            )

    def refresh(self, repo: HttpsRepoUrl, head: GitSha) -> None:
        """Fetch a moved head into the repository's mirror."""
        self._mirror.refresh(repo, head)

    def evict(self, idle_days: int) -> list[HttpsRepoUrl]:
        """Drop mirrors with no checkout in `idle_days` days."""
        return self._mirror.evict(idle_days)

    def _provider_for(self, request: CheckoutRequest) -> CheckoutProvider:
        if request.keep is None:
            return self._mirror
        if request.history is None and not request.writable:
            return self._archive
        raise ValidationError(
            f"a keep set is served read-only with no history by {self._archive.name}; "
            f"history and writable checkouts get the whole tree from {self._mirror.name}"
        )
