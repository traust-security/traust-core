"""A component order's provenance is a typed DSSE envelope, not an opaque mapping."""

from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError

from traust_core.v1.models.component_target import DsseEnvelope
from traust_core.v1.models.operations import AssetName, OrderRequest

ENVELOPE = {
    "payloadType": "application/vnd.in-toto+json",
    "payload": "e30=",
    "signatures": [{"keyid": "k", "sig": "c2ln"}],
}


def _order(provenance: object) -> OrderRequest:
    return OrderRequest(
        asset=AssetName("sci_scan"),
        priority=1,
        repository_id=uuid4(),
        target_purl="pkg:npm/a@1.0.0",
        target_sha="a" * 40,
        target_provenance=provenance,  # type: ignore[arg-type]
    )


def test_an_order_carries_a_dsse_envelope_in_its_wire_form() -> None:
    order = _order(ENVELOPE)
    assert isinstance(order.target_provenance, DsseEnvelope)
    assert order.model_dump(mode="json")["target_provenance"] == ENVELOPE


@pytest.mark.parametrize(
    "provenance",
    [
        {"purl": "pkg:npm/a@1.0.0"},
        {**ENVELOPE, "signatures": []},
        {**ENVELOPE, "signatures": [{"keyid": "k"}]},
        {**ENVELOPE, "extra": True},
    ],
    ids=["not-dsse", "unsigned", "signature-without-sig", "unknown-field"],
)
def test_an_order_refuses_provenance_that_is_no_dsse_envelope(provenance: object) -> None:
    with pytest.raises(ValidationError):
        _order(provenance)
