from __future__ import annotations

from uuid import UUID

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.correlation import (
    correlation_scope,
    current_correlation,
    enrich_correlation,
    safe_request_id,
)


def test_scopes_are_isolated_restored_and_cleared_after_an_error() -> None:
    order_id = UUID("00000000-0000-4000-8000-000000000001")
    assert current_correlation() is None
    with correlation_scope("outer", order_id=order_id, actor_kind=ActorKind.MACHINE) as outer:
        assert current_correlation() == outer
        with pytest.raises(RuntimeError, match="failed"), correlation_scope("inner") as inner:
            assert inner.request_id == "inner" and inner.order_id is None
            raise RuntimeError("failed")
        assert current_correlation() == outer
    assert current_correlation() is None


@pytest.mark.parametrize("value", ["bad space", "line\nbreak", "é", "x" * 129, ""])
def test_invalid_request_ids_never_enter_the_context(value: str) -> None:
    assert not safe_request_id(value)
    with pytest.raises(ValidationError, match="invalid correlation ID"), correlation_scope(value):
        pass
    assert current_correlation() is None


def test_a_scope_can_be_enriched_without_replacing_known_fields() -> None:
    order_id = UUID("00000000-0000-4000-8000-000000000001")
    run_id = UUID("00000000-0000-4000-8000-000000000002")
    with correlation_scope("request-1", order_id=order_id):
        value = enrich_correlation(run_id=run_id, actor_kind=ActorKind.HUMAN)
        assert (value.request_id, value.order_id, value.run_id, value.actor_kind) == (
            "request-1",
            order_id,
            run_id,
            ActorKind.HUMAN,
        )
    assert current_correlation() is None


def test_enrichment_requires_an_entry_point_scope() -> None:
    with pytest.raises(ValidationError, match="scope is not set"):
        enrich_correlation(actor_kind=ActorKind.HUMAN)
