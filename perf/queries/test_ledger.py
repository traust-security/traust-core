"""5 · Ledger at a year's volume: every recorded decision appends, restamps and signs its layer."""

from __future__ import annotations

from uuid import UUID

import pytest

from perf.conftest import Clocked
from perf.harness import Explained, Profile
from perf.seed import DECISIONS, HOT_REPOSITORY, TYPICAL_REPOSITORY, UNLEDGERED
from traust_core.v1.models.findings import Decision
from traust_core.v1.models.ledger import Event, Layer
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.ledger import LedgerConfig, LedgerService

LAYERS = {
    "hot (10k events)": (HOT_REPOSITORY, 1),
    "typical (~24)": (TYPICAL_REPOSITORY, 1 + UNLEDGERED),
}


def unledgered(uow: SqlTraustUnitOfWork, url: str, n: int) -> tuple[Decision, UUID]:
    """Seeded decision n (not in the ledger yet) and the repository whose layer it joins."""
    repo_id = _repo(uow, url)
    fingerprint = f"fp-{DECISIONS + n}"
    finding = uow.findings.find_by_fingerprint(repo_id, "v2", fingerprint)
    assert finding is not None and finding.id is not None
    decision = uow.decisions.find_by_statement(finding.id, f"sk-{fingerprint}")
    assert decision is not None
    return decision, repo_id


def append(uow: SqlTraustUnitOfWork, url: str, n: int) -> None:
    decision, repo_id = unledgered(uow, url, n)
    LedgerService(uow, LedgerConfig()).append_decision(decision, repo_id)


def append_without_restamp(uow: SqlTraustUnitOfWork, url: str, n: int) -> None:
    """The other option measured: append the event; the root waits for the next checkpoint."""
    decision, repo_id = unledgered(uow, url, n)
    layer = uow.layers.find_for_update(repo_id)
    assert layer is not None and layer.id is not None and decision.id is not None
    if uow.events.find_by_decision(decision.id) is None:
        last = uow.events.last_seq(layer.id)
        uow.events.add(
            Event(
                layer_id=layer.id,
                decision_id=decision.id,
                seq=0 if last is None else last + 1,
                event_payload=b"{}",
            )
        )


def fast(e: Explained, index: str, budget_ms: float) -> None:
    assert e.uses_index(index), e.plan
    assert not e.seq_scans(), e.plan
    assert e.execution_ms < budget_ms, e.plan


def test_append_reads_its_layer_by_index(explained: Profile) -> None:
    *_, lock, proved, events, last, _insert, _update = explained(
        lambda uow: append(uow, HOT_REPOSITORY, 1)
    )
    fast(lock, "uq_ledger_layers_repository", 1)
    fast(proved, "events_decision_id_key", 1)
    fast(last, "events_layer_id_seq_key", 1)
    fast(events, "events_layer_id_seq_key", 50)


def test_verify_reads_one_layer_by_index(explained: Profile) -> None:
    def verify(uow: SqlTraustUnitOfWork) -> None:
        layer = uow.layers.find_for_update(_repo(uow, HOT_REPOSITORY))
        assert isinstance(layer, Layer) and layer.id is not None
        LedgerService(uow, LedgerConfig()).verify(layer.id)

    *_, events = explained(verify)
    fast(events, "events_layer_id_seq_key", 50)


@pytest.mark.parametrize("layer", LAYERS)
def test_append_with_and_without_restamp(clocked: Clocked, layer: str) -> None:
    url, n = LAYERS[layer]
    today = clocked(f"{layer}: append + restamp (today)", lambda uow: append(uow, url, n))
    deferred = clocked(f"{layer}: append only", lambda uow: append_without_restamp(uow, url, n))
    assert deferred <= today


def _repo(uow: SqlTraustUnitOfWork, url: str) -> UUID:
    repo = uow.repositories.find_by_url(url)
    assert repo is not None and repo.id is not None
    return repo.id


def _layer_id(uow: SqlTraustUnitOfWork, url: str) -> UUID:
    layer = uow.layers.find_for_update(_repo(uow, url))
    assert layer is not None and layer.id is not None
    return layer.id


@pytest.mark.parametrize("after", [None, 9_000], ids=["first page", "a late page"])
def test_an_events_page_reads_by_index_in_seq_order(explained: Profile, after: int | None) -> None:
    *_, page = explained(
        lambda uow: uow.events.page_for_layer(_layer_id(uow, HOT_REPOSITORY), after, 101)
    )
    fast(page, "events_layer_id_seq_key", 5)
