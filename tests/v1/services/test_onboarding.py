"""OnboardingService: plan (dry run) and onboard over the portfolio, sync and ops services, on
SQLite and Postgres."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0
from tests.v1.services.test_portfolio_sync import Forge, listed, url
from traust_core.v1.errors import ForbiddenError, NotFoundError, ValidationError
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.inventory import OrgName, ProductSlug, RefName, TeamName
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.onboarding import (
    Gap,
    OnboardingRequest,
    PlannedOrder,
    RepositorySpec,
)
from traust_core.v1.models.operations import (
    REMEDIATE_FINDING,
    AssetName,
    OrderRequest,
    OrderState,
)
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import ActorKind, LivenessStatus
from traust_core.v1.providers.base import Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.sources import RepoInfo, SourceError
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects.store import InMemoryObjectStore
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpecs
from traust_core.v1.services.onboarding import OnboardingService
from traust_core.v1.services.operations import OpsService
from traust_core.v1.services.portfolio import (
    Inventory,
    PortfolioPolicy,
    PortfolioService,
    PortfolioSync,
)

OPERATOR = Principal(
    identity="operator@example.com",
    kind=ActorKind("human"),
    display="operator",
    verified_by=IdentitySource.OIDC,
)
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


def onboarding_service(
    uow: SqlTraustUnitOfWork, portfolio: PortfolioService, forge: Forge
) -> OnboardingService:
    clock = FixedClock(T0)
    ops = OpsService(
        uow,
        clock,
        ArtifactPublisher(PublishSpecs(), InMemoryObjectStore(), uow),
        inventory=Inventory(uow),
    )
    sync = PortfolioSync(portfolio, forge, clock=clock)  # type: ignore[arg-type]
    return OnboardingService(portfolio, sync, ops, clock=clock)


@pytest.fixture
def onboarding(
    uow: SqlTraustUnitOfWork, portfolio: PortfolioService, forge: Forge
) -> OnboardingService:
    return onboarding_service(uow, portfolio, forge)


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


def test_onboarding_refuses_a_door_only_asset_in_its_baseline(
    onboarding: OnboardingService, uow: SqlTraustUnitOfWork
) -> None:
    """The baseline plans through the same door as the engine, so a door-only asset in it is
    refused there, naming the scheduling door — never planned as an unscheduled fix."""
    ask = request(label="Example", repositories=[{"url": API}], baseline=[REMEDIATE_FINDING])
    with pytest.raises(ForbiddenError, match="POST /v1/remediations"):
        onboarding.onboard(ask, OPERATOR)
    with uow:
        assert uow.run_orders.search(limit=10) == []


def test_a_registered_product_onboards_without_a_label(
    onboarding: OnboardingService, portfolio: PortfolioService
) -> None:
    product = portfolio.register_product(ProductSlug.parse("example"), "Example")
    result = onboarding.onboard(request(), OPERATOR)
    assert (result.product_id, result.repository_ids, result.order_ids) == (product.id, (), ())


def test_onboarding_a_known_repository_whose_forge_wont_answer_fails_closed(
    onboarding: OnboardingService,
    portfolio: PortfolioService,
    uow: SqlTraustUnitOfWork,
    forge: Forge,
) -> None:
    portfolio.register_repository(API, public=True)  # no upstream linked yet
    forge.info_error = SourceError("forge down", ComparisonStatus.UNREACHABLE)
    with pytest.raises(SourceError, match=str(API)) as raised:
        onboarding.onboard(request(label="Example", repositories=[{"url": API}]), OPERATOR)
    assert "unreachable" in str(raised.value)  # the reason the caller sees
    assert counts(uow) == (1, 1)  # the product and the known repository, nothing more


def test_an_onboarded_repository_is_a_subject_when_the_forge_names_a_default_branch(
    onboarding: OnboardingService, uow: SqlTraustUnitOfWork, forge: Forge
) -> None:
    """The import records the default branch's line, so a run may be asked for right after
    onboarding — no observation needed first (Qodo 392: subject gate after onboarding)."""
    forge.described = RepoInfo(repo=API, default_branch="main", visibility="public")
    result = onboarding.onboard(
        request(label="Example", repositories=[{"url": API, "refs": ["main"]}]), OPERATOR
    )
    repository_id = result.repository_ids[0]
    with uow:
        ref = uow.repository_refs.default(repository_id)
        assert ref is not None and (ref.name, ref.sha) == ("main", "c" * 40)
    order = onboarding._ops.submit(
        OrderRequest(asset=AUDIT, priority=0, repository_id=repository_id), OPERATOR
    )
    assert order.state is OrderState.PLANNED


def test_a_default_line_the_forge_couldnt_give_fails_closed_and_a_retry_imports_it(
    onboarding: OnboardingService, uow: SqlTraustUnitOfWork, forge: Forge
) -> None:
    forge.described = RepoInfo(repo=API, default_branch="main", visibility="public")
    forge.head_error = SourceError("forge down", ComparisonStatus.UNREACHABLE)
    ask = request(label="Example", repositories=[{"url": API}])
    with pytest.raises(SourceError, match="forge down"):
        onboarding.onboard(ask, OPERATOR)
    assert counts(uow) == (1, 0)  # the product only: no half-registered repository
    forge.head_error = None
    result = onboarding.onboard(ask, OPERATOR)
    with uow:
        assert uow.repository_refs.default(result.repository_ids[0]) is not None


def test_an_empty_repository_onboards_without_a_default_ref(
    onboarding: OnboardingService, uow: SqlTraustUnitOfWork, forge: Forge
) -> None:
    """The forge answered that the repository is empty: registered as before, just no
    default line yet — an empty repository is not an outage."""
    forge.described = RepoInfo(repo=API, default_branch="main", visibility="public")
    forge.head_error = SourceError(
        f"{API}: no commit on branch main", ComparisonStatus.ERROR, empty_repository=True
    )
    result = onboarding.onboard(request(label="Example", repositories=[{"url": API}]), OPERATOR)
    with uow:
        assert uow.repositories.get(result.repository_ids[0]).url == str(API)
        assert uow.repository_refs.default(result.repository_ids[0]) is None


def test_a_new_url_the_forge_says_does_not_exist_is_the_callers_not_found(
    onboarding: OnboardingService, uow: SqlTraustUnitOfWork, forge: Forge
) -> None:
    """The forge's own no-such-repository names a request core can't satisfy: the caller's
    404, not a relayed outage (a known repository's MISSING stays the #474 carve-out)."""
    forge.info_error = SourceError(
        f"{API}: the forge reports no such repository",
        ComparisonStatus.ERROR,
        liveness_status=LivenessStatus.MISSING,
    )
    with pytest.raises(NotFoundError, match="no such repository"):
        onboarding.onboard(request(label="Example", repositories=[{"url": API}]), OPERATOR)
    assert counts(uow) == (1, 0)  # the product only: no repository was written


def test_a_branch_named_in_the_spec_with_no_commit_is_the_callers_not_found(
    onboarding: OnboardingService, uow: SqlTraustUnitOfWork, forge: Forge
) -> None:
    """The forge answered that the branch the spec names has no commit: the caller's 404
    naming what the forge said, not a 502."""
    forge.described = RepoInfo(repo=API, default_branch="main", visibility="public")
    forge.head_error = SourceError(
        f"{API}: no commit on branch dev", ComparisonStatus.ERROR, empty_repository=True
    )
    with pytest.raises(NotFoundError, match="no commit on branch dev"):
        onboarding.onboard(
            request(label="Example", repositories=[{"url": API, "refs": ["dev"]}]), OPERATOR
        )


class Outage(Forge):
    """Answers every repository but one, the way an outage would."""

    def __init__(
        self, listing: Sequence[RepoInfo], heads: dict[str, str], down: HttpsRepoUrl
    ) -> None:
        super().__init__(listing, heads=heads)
        self._down = down

    def info(self, repo: HttpsRepoUrl) -> Result[RepoInfo]:
        if repo == self._down:
            raise SourceError(f"{repo.host}: connection refused", ComparisonStatus.UNREACHABLE)
        return super().info(repo)


def test_a_forge_failure_on_one_repository_aborts_the_onboarding(
    uow: SqlTraustUnitOfWork, portfolio: PortfolioService
) -> None:
    """The service's per-repository failure mode is the one it already had for a ref the
    forge couldn't give: the request fails, repositories already onboarded stay."""
    forge = Outage(listed("example-org/api"), {"main": "c" * 40}, CLI)
    onboarding = onboarding_service(uow, portfolio, forge)
    ask = request(label="Example", repositories=[{"url": API}, {"url": CLI}])
    with pytest.raises(SourceError, match="example-org/cli"):
        onboarding.onboard(ask, OPERATOR)
    with uow:
        urls = [r.url for r in uow.repositories.search(limit=100, after=None)]
    assert urls == [str(API)]  # api onboarded before the failure, cli never written
