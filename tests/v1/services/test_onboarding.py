"""OnboardingService: plan (dry run) and onboard over the portfolio, sync and ops services, on
SQLite and Postgres."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0
from tests.v1.services.test_portfolio_sync import Forge, listed, url
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.inventory import OrgName, ProductSlug, RefName, TeamName
from traust_core.v1.models.onboarding import (
    Gap,
    OnboardingRequest,
    PlannedOrder,
    RepositorySpec,
)
from traust_core.v1.models.operations import AssetName, OrderState
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects.store import InMemoryObjectStore
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpecs
from traust_core.v1.services.onboarding import OnboardingService
from traust_core.v1.services.operations import OpsService
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService, PortfolioSync

OPERATOR = Principal(identity="operator@example.com", kind=ActorKind("human"), display="operator")
AUDIT = AssetName("secure-code-audit")
API, CLI, WEB = url("example-org/api"), url("example-org/cli"), url("example-org/web")


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def uow(engine: Engine) -> SqlTraustUnitOfWork:
    return SqlTraustUnitOfWork(engine)


@pytest.fixture
def portfolio(uow: SqlTraustUnitOfWork) -> PortfolioService:
    return PortfolioService(uow, PortfolioPolicy())


@pytest.fixture
def forge() -> Forge:
    return Forge(listed("example-org/api", "example-org/cli"), heads={"main": "c" * 40})


@pytest.fixture
def onboarding(
    uow: SqlTraustUnitOfWork, portfolio: PortfolioService, forge: Forge
) -> OnboardingService:
    clock = FixedClock(T0)
    ops = OpsService(uow, clock, ArtifactPublisher(PublishSpecs(), InMemoryObjectStore(), uow))
    sync = PortfolioSync(portfolio, forge, clock=clock)  # type: ignore[arg-type]
    return OnboardingService(portfolio, sync, ops, clock=clock)


def request(**kw: object) -> OnboardingRequest:
    return OnboardingRequest.model_validate({"product": "example", **kw})


def counts(uow: SqlTraustUnitOfWork) -> tuple[int, int]:
    with uow:
        products = len(uow.products.list_after(None, 100))
        repositories = len(uow.repositories.search(limit=100, after=None))
    return products, repositories


def test_an_unregistered_product_without_a_label_is_a_gap_and_onboards_nothing(
    onboarding: OnboardingService, uow: SqlTraustUnitOfWork
) -> None:
    ask = request(repositories=[{"url": API}])
    gap = Gap(subject="example", reason="product is not registered: give a label to register it")
    assert onboarding.plan(ask).gaps == (gap,)
    with pytest.raises(ValidationError, match="give a label"):
        onboarding.onboard(ask, OPERATOR)
    assert counts(uow) == (0, 0)


def test_plan_merges_named_and_org_repositories_and_writes_nothing(
    onboarding: OnboardingService, portfolio: PortfolioService, uow: SqlTraustUnitOfWork
) -> None:
    known = portfolio.register_repository(API, public=True)
    named = RepositorySpec(url=API, refs=(RefName("main"),), team=TeamName("API Team"))
    ask = request(
        label="Example",
        repositories=[named, {"url": WEB}, {"url": WEB}],
        org="example-org",
        baseline=[AUDIT],
    )
    plan = onboarding.plan(ask)
    assert plan.gaps == ()
    assert plan.new == (RepositorySpec(url=WEB), RepositorySpec(url=CLI))
    assert plan.existing_repository_ids == (known.id,)
    assert plan.orders == tuple(PlannedOrder(asset=AUDIT, repo=r) for r in (API, WEB, CLI))
    assert counts(uow) == (0, 1)


def test_onboard_registers_everything_and_plans_the_baseline_once(
    onboarding: OnboardingService, uow: SqlTraustUnitOfWork, forge: Forge
) -> None:
    ask = request(
        label="Example",
        repositories=[{"url": API, "refs": ["main"], "team": "API Team"}],
        org=OrgName("example-org"),
        baseline=[AUDIT],
    )
    result = onboarding.onboard(ask, OPERATOR)
    with uow:
        product = uow.products.get(result.product_id)
        repositories = [uow.repositories.get(i) for i in result.repository_ids]
        ref = uow.repository_refs.default(result.repository_ids[0])
        refs = uow.repository_refs.list_for(result.repository_ids[0])
        owners = uow.ownerships.current(result.repository_ids[0])
        orders = [uow.run_orders.get(i) for i in result.order_ids]
    assert (product.slug, product.name) == ("example", "Example")
    assert [r.url for r in repositories] == [str(API), str(CLI)]
    assert ref is None and [(r.name, r.sha) for r in refs] == [("main", "c" * 40)]
    assert len(owners) == 1 and owners[0].valid_from == T0
    assert [(o.asset, o.repository_id, o.state, o.requested_by) for o in orders] == [
        (AUDIT, r.id, OrderState.PLANNED, OPERATOR.ref) for r in repositories
    ]
    assert onboarding.onboard(ask, OPERATOR) == result
    assert forge.calls.count("list_org github.com/example-org") == 2


def test_a_registered_product_onboards_without_a_label(
    onboarding: OnboardingService, portfolio: PortfolioService
) -> None:
    product = portfolio.register_product(ProductSlug.parse("example"), "Example")
    result = onboarding.onboard(request(), OPERATOR)
    assert (result.product_id, result.repository_ids, result.order_ids) == (product.id, (), ())
