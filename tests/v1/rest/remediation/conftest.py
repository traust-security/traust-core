from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.services.test_verification import make_context
from traust_core.v1.context import Context
from traust_core.v1.context.config import RecordingConfig
from traust_core.v1.models.operations import RunOrder, WorkerId
from traust_core.v1.providers.clock import FixedClock, SystemClock
from traust_core.v1.providers.identity import LocalIssuer
from traust_core.v1.services.identity import IdentityConfig
from traust_core.v1.services.ledger import LedgerConfig


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    context = make_context(
        engine,
        tmp_path,
        identity=IdentityConfig(trust_local=True),
        ledger=LedgerConfig(),
        # The remediation door authorizes under the triage allowlist (NEED: contracts has
        # no recording.remediation section yet); its orders run the native scheduler asset.
        recording=RecordingConfig(verification=("verify",), triage=("remediate_finding",)),
    )
    context.__dict__["local_issuer"] = LocalIssuer(context.config.home, SystemClock())
    context.local_issuer.mint("remediation-runner", machine=True)
    return context


def reclaim(context: Context, order: RunOrder) -> RunOrder:
    assert order.id is not None and order.lease_expires_at is not None
    assert order.lease_holder is not None
    context.clock = FixedClock(order.lease_expires_at + timedelta(seconds=1))
    reclaimed = context.services().ops.claim(
        WorkerId(order.lease_holder), timedelta(hours=2), order_id=order.id
    )
    assert reclaimed is not None and reclaimed.id == order.id
    assert reclaimed.lease_generation > order.lease_generation
    return reclaimed
