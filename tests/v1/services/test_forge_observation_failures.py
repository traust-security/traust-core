from typing import NoReturn

import pytest

from tests.v1.services.test_portfolio_observation_store import (
    Observed,
    engine,
    observed,
    seed,
    uow,
)
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.providers.sources import SourceError

__all__ = ["engine", "observed", "seed", "uow"]


@pytest.mark.parametrize("has_previous", [False, True])
@pytest.mark.parametrize("operation", ["quota", "compare"])
@pytest.mark.parametrize(
    "status",
    [
        ComparisonStatus.UNREACHABLE,
        ComparisonStatus.ERROR,
        ComparisonStatus.NO_CREDENTIALS,
        ComparisonStatus.BAN_SUSPECTED,
    ],
)
def test_failed_forge_call_preserves_last_good_observation(
    observed: Observed,
    status: ComparisonStatus,
    has_previous: bool,
    operation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if has_previous:
        observed.observe()
    before = observed.observations()
    refs = observed.uow.repository_refs.list_for(observed.repository.id)

    def fail(*args: object) -> NoReturn:
        raise SourceError("source failed", status)

    monkeypatch.setattr(observed.source, operation, fail)

    assert (
        observed.observe(archived=True, head="c" * 40, pushed_at="2026-10-02T00:00:00Z") == status
    )
    assert observed.row().archived is True
    assert observed.observations() == before
    assert observed.uow.repository_refs.list_for(observed.repository.id) == refs
    facts = observed.service.forge_facts(observed.repository.id)
    if has_previous:
        assert facts is not None and facts.status == ComparisonStatus.OK
    else:
        assert facts is None
