"""Recording the reviewed product map through Context on SQLite and Postgres: each recording is
the next version, and product lookups read the newest."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.artifacts import ProductDefinitionsMapArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

PROVENANCE = Provenance(run_id=uuid4(), source=SourceType.INTERACTIVE, occurred_at=T0)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def portfolio(engine: Engine, tmp_path: Path) -> PortfolioService:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0))
    ctx.__dict__["database"] = engine
    return ctx.services().portfolio


def product_map(**mappings: Any) -> ProductDefinitionsMapArtifact:
    return ProductDefinitionsMapArtifact.from_document({"mappings": mappings})


def test_the_newest_recorded_map_is_the_one_read(portfolio: PortfolioService) -> None:
    assert portfolio.product_mappings().packages == {}
    portfolio.record_product_map(product_map(packages={"widget": "gizmo"}), PROVENANCE)
    later = product_map(packages={"widget": "relic"}, repos={"github.com/acme/api": "relic"})
    portfolio.record_product_map(later, PROVENANCE)
    mappings = portfolio.product_mappings()
    assert (mappings.packages, mappings.repos) == (
        {"widget": "relic"},
        {"github.com/acme/api": "relic"},
    )


def test_re_recording_the_same_map_adds_nothing(portfolio: PortfolioService) -> None:
    first = portfolio.record_product_map(product_map(repos={"a": "b"}), PROVENANCE)
    again = portfolio.record_product_map(product_map(repos={"a": "b"}), PROVENANCE)
    assert first.artifact_id == again.artifact_id


def test_a_map_without_pairs_reads_as_none(portfolio: PortfolioService) -> None:
    portfolio.record_product_map(product_map(), PROVENANCE)
    mappings = portfolio.product_mappings()
    assert (mappings.packages, mappings.repos) == ({}, {})


def test_without_an_artifact_store_the_map_is_a_config_error(engine: Engine) -> None:
    bare = PortfolioService(SqlTraustUnitOfWork(engine), PortfolioPolicy())
    with pytest.raises(ConfigError, match="product map"):
        bare.product_mappings()
    with pytest.raises(ConfigError, match="product map"):
        bare.record_product_map(product_map(), PROVENANCE)
