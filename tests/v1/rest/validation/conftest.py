from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed, saved_id
from tests.v1.services.test_validation import NOW, PROVENANCE, ValidationHarness
from tests.v1.services.test_validation import engine as engine
from tests.v1.services.test_validation import harness as harness
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import DatabaseConfig, RecordingConfig
from traust_core.v1.models.artifacts import ValidationArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.identity import Credential, Principal
from traust_core.v1.models.operations import RunOrder
from traust_core.v1.models.validation import ValidationRecordInput
from traust_core.v1.providers.clock import FixedClock, SystemClock
from traust_core.v1.providers.identity import LocalIssuer
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.rest.validation.records import RecordValidation
from traust_core.v1.services.identity import IdentityConfig
from traust_core.v1.services.ledger import LedgerConfig


@dataclass(frozen=True)
class ValidationRun:
    order: RunOrder
    principal: Principal
    headers: dict[str, str]
    provenance: Provenance

    def body(
        self,
        doc: ValidationArtifact,
        bindings: ValidationRecordInput,
        provenance: Provenance | None = None,
    ) -> dict[str, object]:
        return RecordValidation(
            run_order_id=saved_id(self.order),
            payload=doc.payload.decode("utf-8"),
            provenance=provenance or self.provenance,
            bindings=bindings,
        ).model_dump(mode="json")


@pytest.fixture
def context(harness: ValidationHarness, tmp_path: Path) -> Iterator[Context]:
    context = Context(
        Config(
            home=tmp_path / "rest",
            database=DatabaseConfig(url=harness.engine.url.render_as_string(hide_password=False)),
            identity=IdentityConfig(trust_local=True),
            ledger=LedgerConfig(),
            recording=RecordingConfig(validation=("validate",)),
        ),
        object_store=harness.objects,
        clock=FixedClock(NOW),
    )
    context.__dict__["local_issuer"] = LocalIssuer(context.config.home, SystemClock())
    try:
        yield context
    finally:
        context.database.dispose()


@pytest.fixture
def run(context: Context, client: TestClient, harness: ValidationHarness) -> ValidationRun:
    credential = Credential(
        token=context.local_issuer.mint("validation-runner", machine=True).token
    )
    assert context.identity is not None
    principal = context.identity.authenticate(credential)
    headers = {"Authorization": f"Bearer {credential.token.get_secret_value()}"}
    with SqlTraustUnitOfWork(context.database) as uow:
        order = Seed(uow).run_order(
            asset="validate", repository_id=harness.findings[0].repository_id
        )
        uow.commit()
    response = client.post(
        "/v1/orders/claim", json={"lease_seconds": 300, "assets": ["validate"]}, headers=headers
    )
    assert response.status_code == 200, response.text
    claimed = RunOrder.model_validate(response.json())
    assert claimed.id == order.id and claimed.lease_holder == principal.ref
    return ValidationRun(
        claimed, principal, headers, PROVENANCE.model_copy(update={"run_id": saved_id(claimed)})
    )
