from __future__ import annotations

from tests.v1.example.continuous_ops.model import ObserveStatus, RepoState
from tests.v1.example.continuous_ops.repository import RepoStateUnitOfWork
from traust_core.v1.errors import ServiceError
from traust_core.v1.models.operations import JobResult
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.sources import SourceProvider


def observe_repo(
    uow: RepoStateUnitOfWork,
    source: SourceProvider,
    clock: Clock,
    repo: HttpsRepoUrl,
    audited_head: GitSha | None,
) -> JobResult:
    try:
        head = source.info(repo).data.head
        state = RepoState(
            repo=repo,
            status=ObserveStatus.OK,
            head=head,
            audited_head=audited_head,
            observed_at=clock.now(),
        )
    except ServiceError:
        state = RepoState(
            repo=repo,
            status=ObserveStatus.UNREACHABLE,
            audited_head=audited_head,
            observed_at=clock.now(),
        )
    with uow:
        uow.repo_state.save(state)
        uow.commit()
    if state.status is ObserveStatus.UNREACHABLE:
        return JobResult.partly({ObserveStatus.UNREACHABLE.value: 1})
    return JobResult.succeeded()
