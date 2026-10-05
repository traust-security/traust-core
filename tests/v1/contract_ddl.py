from __future__ import annotations

from sqlalchemy.engine import Engine

from traust_core.v1 import contracts
from traust_core.v1.repositories import apply_schema
from traust_core.v1.repositories.sql import contract_dialect


def apply_contract_ddl(engine: Engine, area: contracts.Area) -> None:
    apply_schema(engine, contracts.ddl(area, contract_dialect(engine)))
