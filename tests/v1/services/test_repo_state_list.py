"""RepoStateQuery.list: each repository's routing state, paged; one the router must observe first
comes back network-skipped, saying why."""

from __future__ import annotations

from uuid import UUID

import pytest

from tests.v1.observation_support import observer
from traust_core.v1.models.common import PageRequest, every_item
from traust_core.v1.models.inventory import Repository, RepositoryFilter
from traust_core.v1.models.observation import ComparisonStatus, ObservationTarget


def fleet():
    """The observer's audited repository plus one audited but unobserved and one never audited."""
    harness, service, assessment, _, _ = observer()
    observed = assessment.target
    targets = {observed.repository_id: observed}
    with service._uow as uow:
        for name, audited in (("unobserved", True), ("unaudited", False)):
            repo = uow.repositories.add(
                Repository(url=f"https://github.com/o/{name}", public=False)
            )
            assert repo.id is not None
            targets[repo.id] = (
                observed.model_copy(update={"repository_id": repo.id, "repo_url": repo.url})
                if audited
                else ObservationTarget(repository_id=repo.id, repo_url=repo.url, has_audit=False)
            )
        uow.commit()
    assessment.observation_target = lambda *, repository_id=None, repo_url=None: targets[
        repository_id
    ]
    harness.record_forge_facts(repository_id=observed.repository_id)
    return harness, observed.repository_id, targets


def states(harness, limit: int = 100) -> dict[UUID, object]:
    return {
        s.repository_id: s
        for s in every_item(lambda p: harness.query.list(RepositoryFilter(), p), limit)
    }


@pytest.mark.parametrize("limit", [1, 2, 100])
def test_every_repository_is_listed_once_across_pages(limit: int) -> None:
    harness, _, targets = fleet()
    listed = list(every_item(lambda p: harness.query.list(RepositoryFilter(), p), limit))
    assert sorted(s.repository_id for s in listed) == sorted(targets)


def test_each_state_says_what_the_router_needs() -> None:
    harness, observed_id, targets = fleet()
    by_id = states(harness)
    assert by_id[observed_id] == harness.repo_state(repository_id=observed_id)
    assert by_id[observed_id].status == ComparisonStatus.OK
    [unobserved, unaudited] = (i for i in targets if i != observed_id)
    skipped = by_id[unobserved]
    assert skipped.status == ComparisonStatus.NETWORK_SKIPPED
    assert "observe it first" in (skipped.error or "")
    assert by_id[unaudited].status == ComparisonStatus.NEVER_AUDITED
    assert by_id[unaudited].error is None


def test_a_page_holding_the_whole_fleet_has_no_next() -> None:
    harness, _, _ = fleet()
    first = harness.query.list(RepositoryFilter(), PageRequest(limit=3))
    assert len(first.items) == 3 and first.next is None
