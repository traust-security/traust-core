from __future__ import annotations

from collections.abc import Callable, Iterable

from tests.v1.example.continuous_ops.repository import RepoStateUnitOfWork
from tests.v1.example.continuous_ops.services import observe_repo
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.operations import AssetRequest, JobResult
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.sources import SourceProvider


class RepoStateMaterializer:
    asset = "repo_state"

    def __init__(
        self,
        uow: Callable[[], RepoStateUnitOfWork],
        source: SourceProvider,
        clock: Clock,
        allowed_hosts: Iterable[str],
    ) -> None:
        self._uow = uow
        self._source = source
        self._clock = clock
        self._allowed_hosts = tuple(allowed_hosts)

    def materialize(self, request: AssetRequest) -> JobResult:
        try:
            repo = HttpsRepoUrl.parse(request.partition or "", self._allowed_hosts)
            audited = request.params.get("audited_head")
            audited_head = GitSha.parse(audited) if audited else None
        except ValidationError as e:
            return JobResult.failed(f"bad request: {e}")
        return observe_repo(self._uow(), self._source, self._clock, repo, audited_head)
