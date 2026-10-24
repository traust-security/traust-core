"""5 · Ledger repositories: layers per repository and one event per decision."""

from __future__ import annotations

import pytest

from tests.v1.repositories.tables.conftest import Seed, same_rows
from traust_core.v1.errors import ConflictError


def test_layers_per_repository_and_line(seed: Seed) -> None:
    repo = seed.repository()
    repo_layer = seed.layer(repo)
    branch = seed.layer(repo, line="release-4.22")
    seed.layer()
    assert same_rows(seed.uow.layers.list_for_repository(repo.id), [repo_layer, branch])


def test_layers_list_in_id_order_after_a_layer(seed: Seed) -> None:
    repo = seed.repository()
    made = sorted(
        [seed.layer(repo), seed.layer(repo, line="release-4.22"), seed.layer()],
        key=lambda layer: layer.id,
    )
    layers = seed.uow.layers
    assert layers.list_after(None, 10) == made
    assert layers.list_after(None, 2) == made[:2]
    assert layers.list_after(made[1].id, 10) == made[2:]
    assert layers.list_after(made[2].id, 10) == []


def test_signing_a_root_updates_the_layer(seed: Seed) -> None:
    layer = seed.layer()
    signed = seed.uow.layers.update(
        layer.model_copy(
            update={"merkle_root": "ab12", "merkle_size": 1, "merkle_root_signature": "sig"}
        )
    )
    assert seed.uow.layers.get(layer.id) == signed


def test_events_append_in_sequence(seed: Seed) -> None:
    events = seed.uow.events
    layer = seed.layer()
    assert events.last_seq(layer.id) is None
    e0 = seed.event(layer, seq=0)
    e1 = seed.event(layer, seq=1, event_payload=b"\xff" * 64)
    assert events.last_seq(layer.id) == 1
    assert events.list_for_layer(layer.id) == [e0, e1]
    assert events.get(e1.id).event_payload == b"\xff" * 64


def test_event_for_a_decision(seed: Seed) -> None:
    layer, decision = seed.layer(), seed.decision()
    proof = seed.event(layer, decision, seq=0)
    assert seed.uow.events.find_by_decision(decision.id) == proof
    assert seed.uow.events.find_by_decision(seed.decision().id) is None


def test_one_repository_layer_found_for_update(seed: Seed) -> None:
    layers = seed.uow.layers
    repo = seed.repository()
    assert layers.find_for_update(repo.id) is None
    layer = seed.layer(repo)
    seed.layer(repo, line="release-4.22")
    seed.layer()
    assert layers.find_for_update(repo.id) == layer
    with pytest.raises(ConflictError):
        seed.layer(repo)
