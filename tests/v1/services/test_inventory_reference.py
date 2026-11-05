from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0
from tests.v1.services.test_portfolio_sync import Forge
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.artifacts import ProductDefinitionsMapArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.inventory import VersionLabel
from traust_core.v1.models.inventory_reference import IntakeKind, RepositoryDeclaration
from traust_core.v1.models.values import GitSha, HttpsRepoUrl, ProductSlug
from traust_core.v1.models.vocabulary import OwnershipClass, SourceType
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.services.portfolio import PortfolioSync

URL = "https://github.com/example-org/api"
OTHER = "https://github.com/example-org/unmapped"


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    config = Config.model_validate(
        {
            "home": tmp_path / "home",
            "locations": {
                "feeds_cache": str(tmp_path / "feeds"),
            },
        }
    )
    ctx = Context(config, clock=FixedClock(T0))
    ctx.__dict__["database"] = engine
    return ctx


def test_inventory_exports_declared_contacts_routes_ownership_and_shipped_versions(
    context: Context, engine: Engine, tmp_path: Path
) -> None:
    cache = tmp_path / "feeds"
    cache.mkdir()
    (cache / "product_definitions.json").write_text(
        json.dumps(
            {
                "ps_products": {"widget": {"ps_modules": ["module"]}},
                "ps_modules": {"module": {"private_tracker_cc": ["alice"], "default_cc": ["bob"]}},
                "ps_update_streams": {},
            }
        )
    )
    (cache / "feeds-meta.json").write_text(
        json.dumps(
            {
                "product-definitions": {"retrieved_at": T0.strftime("%Y-%m-%dT%H:%M:%SZ")},
            }
        )
    )
    portfolio = context.services().portfolio
    repository = portfolio.register_repository(
        HttpsRepoUrl.parse(URL, context.config.forge_hosts), True
    )
    other = portfolio.register_repository(
        HttpsRepoUrl.parse(OTHER, context.config.forge_hosts), True
    )
    product, _ = portfolio.register_corpus_product(
        ProductSlug.parse("widget"),
        "Widget",
        OwnershipClass("owned"),
        "Commerce",
    )
    ref = portfolio.register_ref(repository.id, GitSha.parse("a" * 40), None, None)
    release = portfolio.record_release(product.id, VersionLabel("1.0"))
    portfolio.add_component(release.id, ref.id)
    portfolio.assign_owner(repository.id, "Payments", T0)
    portfolio.declare_inventory(
        (
            RepositoryDeclaration(
                repo_url=URL,
                service="Gateway",
                resource_type=IntakeKind.ADHOC,
                manager="morgan",
                ownership_source="reviewed org directory",
                jira_project="PAY",
                jira_component="API",
                escalation_contact="oncall@example.com",
            ),
        )
    )
    portfolio.record_product_map(
        ProductDefinitionsMapArtifact.from_document(
            {
                "mappings": {"repos": {URL: "widget"}},
            }
        ),
        Provenance(run_id=uuid4(), source=SourceType.INTERACTIVE, occurred_at=T0),
    )
    reloaded = Context(context.config, clock=FixedClock(T0))
    reloaded.__dict__["database"] = engine
    rows = {row.url: row for row in reloaded.services().portfolio.inventory_export()}
    row = rows[URL]
    assert row.owner_teams == ("Payments",)
    assert row.individual_owners == ("morgan",)
    assert row.ownership_source == "manager fallback: reviewed org directory"
    assert row.business_units == ("Commerce",)
    assert row.versions == ("widget:1.0",)
    assert row.declaration.service == "Gateway"
    assert row.declaration.resource_type == IntakeKind.ADHOC
    assert (row.declaration.jira_project, row.declaration.jira_component) == ("PAY", "API")
    assert row.declaration.escalation_contact == "oncall@example.com"
    assert [(c.kerberos_id, c.tier, c.embargo_cleared) for c in row.accountable_contacts] == [
        ("alice", 1, True),
        ("bob", 3, False),
    ]
    assert rows[OTHER].accountable_contacts == ()
    assert rows[OTHER].individual_owners == ()
    assert rows[OTHER].declaration.jira_project is None
    assert rows[OTHER].declaration.escalation_contact is None
    assert reloaded.services().portfolio.inventory_export((other.id,)) == (rows[OTHER],)
    portfolio.declare_inventory((RepositoryDeclaration(repo_url=URL, individual_owners=("dev",)),))
    updated = portfolio.inventory_export((repository.id,))[0]
    assert updated.individual_owners == ("dev",)
    assert updated.ownership_source == "reviewed org directory"


def test_unknown_reference_repository_cannot_create_an_orphan(context: Context) -> None:
    with pytest.raises(NotFoundError):
        context.services().portfolio.declare_inventory((RepositoryDeclaration(repo_url=URL),))
    assert context.inventory_reference.read().repositories == ()


def test_saved_forge_hints_keep_source_without_assigning_a_team(context: Context) -> None:
    portfolio = context.services().portfolio
    url = HttpsRepoUrl.parse(URL, context.config.forge_hosts)
    repo = portfolio.register_repository(url, public=True)
    sync = PortfolioSync(portfolio, Forge())  # type: ignore[arg-type]
    sync.owner_hints(url, retain=True)
    row = portfolio.inventory_export((repo.id,))[0]
    assert row.individual_owners == ("approver-a",)
    assert row.ownership_source == "approver-a: owners-file"
    assert row.owner_teams == ()
    assert row.declaration.jira_project is None
    portfolio.declare_inventory(
        (
            RepositoryDeclaration(
                repo_url=URL,
                individual_owners=("reviewed-owner",),
                ownership_source="reviewed service catalogue",
            ),
        )
    )
    sync.owner_hints(url, retain=True)
    updated = portfolio.inventory_export((repo.id,))[0]
    assert updated.individual_owners == ("reviewed-owner",)
    assert updated.ownership_source == "reviewed service catalogue"
    assert updated.declaration.owner_hints == ("approver-a",)
    assert updated.declaration.owner_hint_source == "approver-a: owners-file"
