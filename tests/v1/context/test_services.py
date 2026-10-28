from __future__ import annotations

from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
import sqlalchemy as sa

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed, saved_id
from tests.v1.settings_support import configure
from traust_core.v1 import contracts
from traust_core.v1.context import (
    Clock,
    Config,
    Context,
    FeedQuery,
    OpsService,
    Router,
    SpendService,
    validate_config,
)
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.findings import RecordDecision
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.operations import BudgetStatus, ConfigDigest, LaneName, OrderRequest
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers import clock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services import operations
from traust_core.v1.services.identity import IdentityConfig, LoginConfig
from traust_core.v1.services.ledger import LedgerConfig

OPERATOR = Principal(identity="operator@example.com", kind=ActorKind("human"), display="operator")
REVIEWER = Principal(
    identity="reviewer@example.com",
    kind=ActorKind.HUMAN,
    display="reviewer",
    verified_by=IdentitySource.LOCAL_USER,
)


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "traust.yaml"
    path.write_text(text)
    return path


@pytest.fixture(params=SQL_BACKENDS)
def configured(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Context]:
    with contract_db(request.param, tmp_path) as engine:
        url = engine.url.render_as_string(hide_password=False)
        yield Context.from_file(
            _write(tmp_path, f"home: {tmp_path / 'home'}\ndatabase:\n  url: {url}\n")
        )


def test_services_build_from_a_config_file(configured: Context) -> None:
    services = configured.services()
    order = services.ops.submit(OrderRequest(asset="feeds_cache", priority=1), OPERATOR)
    assert order.id is not None
    assert services.findings.open_count(uuid4(), []) == 0
    assert not (configured.config.home / "traust.db").exists()


@pytest.mark.parametrize(
    "text",
    ["hom: /x\n", "rating:\n  sla_days: 7\n", "database:\n  uri: x\n"],
)
def test_a_typo_in_config_is_rejected(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError):
        Context.from_file(_write(tmp_path, text))


def test_default_store_works_with_no_config(tmp_path: Path) -> None:
    config = Config(home=tmp_path / "home")
    first = Context(config).services()
    order = first.ops.submit(OrderRequest(asset="feeds_cache", priority=2), OPERATOR)

    assert (tmp_path / "home" / "traust.db").is_file()
    again = Context(config).services()
    with SqlTraustUnitOfWork(Context(config).database) as uow:
        assert uow.run_orders.get(order.id).asset == "feeds_cache"
    assert again.findings.open_count(uuid4(), []) == 0


def test_default_home_is_under_the_user_home_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    config = Config()
    assert config.home == tmp_path / ".traust"
    assert Config(home=Path("~/elsewhere")).home == tmp_path / "elsewhere"
    assert config.record_store_url().database == str(tmp_path / ".traust" / "traust.db")


def test_services_never_build_a_tool_or_read_its_floors(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path / "home"))

    def unbuildable() -> Any:
        raise AssertionError("built at wiring")

    ctx.tools.register("grype", unbuildable)
    ctx.tool_floors["grype"] = "0.110.0"
    ctx.services()


def test_a_configured_database_is_never_bootstrapped(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'empty.db'}"
    ctx = Context(Config(home=tmp_path / "home", database={"url": url}))  # type: ignore[arg-type]
    assert sa.inspect(ctx.database).get_table_names() == []
    assert not (tmp_path / "home").exists()


def test_no_ledger_section_leaves_the_ledger_off() -> None:
    services = Context(Config()).services()
    assert services.ledger is None


def test_a_typo_in_the_ledger_section_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        Config.from_file(_write(tmp_path, "ledger:\n  key_pth: /keys/cosign.key\n"))


def test_a_configured_ledger_proves_a_decision_once(configured: Context) -> None:
    config = configured.config.model_copy(update={"ledger": LedgerConfig()})
    ctx = Context(config)
    with SqlTraustUnitOfWork(ctx.database) as uow:
        finding = Seed(uow).finding()
        uow.commit()
    services = ctx.services()
    request = RecordDecision(
        finding_id=saved_id(finding),
        validity="confirmed",
        rationale="Reproduced the reported finding.",
        occurred_at=T0,
    )
    decision = services.findings.decisions.decide(request, REVIEWER)
    assert services.findings.decisions.decide(request, REVIEWER) == decision
    with SqlTraustUnitOfWork(ctx.database) as uow:
        (layer,) = uow.layers.list_for_repository(finding.repository_id)
        (event,) = uow.events.list_for_layer(saved_id(layer))
        assert event.decision_id == decision.id
        assert layer.merkle_size == 1
    assert services.ledger is not None
    assert services.ledger.verify(saved_id(layer)).passed


def test_context_wires_classifier_services_to_real_shared_owners(configured: Context) -> None:
    with SqlTraustUnitOfWork(configured.database) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref()
        finding = seed.finding(repository=uow.repositories.get(ref.repository_id))
        uow.commit()
    services = configured.services()
    saved = services.findings.decisions.decide(
        RecordDecision(
            finding_id=saved_id(finding),
            repository_ref_id=saved_id(ref),
            validity="confirmed",
            rationale="Reviewed the finding at its repository ref.",
            occurred_at=T0,
        ),
        REVIEWER,
    )
    assert services.findings.history(saved_id(finding)) == [saved]
    with SqlTraustUnitOfWork(configured.database) as uow:
        assert uow.decisions.get(saved_id(saved)) == saved


def test_no_identity_section_verifies_nobody() -> None:
    assert Context(Config()).services().identity is None


def test_an_identity_section_wires_the_trusted_issuers_and_local_keys(tmp_path: Path) -> None:
    path = tmp_path / "traust.yaml"
    path.write_text(
        f"home: {tmp_path}\n"
        "identity:\n"
        "  issuers:\n"
        "    - issuer: https://idp.example\n"
        "      jwks_url: https://idp.example/jwks\n"
        "      audience: traust\n"
        "  trust_local: true\n"
        "  admins: [alice@example.com]\n"
    )
    context = Context.from_file(path)
    identity = context.services().identity
    assert identity is not None and identity is context.identity
    assert identity._provider.check().detail == "https://idp.example, local"
    assert identity._provider._local_jwks == tmp_path / "local-jwks.json"
    assert identity._directory is None


def test_a_directory_program_that_does_not_exist_fails_at_wiring(tmp_path: Path) -> None:
    config = Config(identity=IdentityConfig(directory_command=("/no/such/validate",)))
    with pytest.raises(ConfigError, match="program not found"):
        _ = Context(config).identity
    script = tmp_path / "validate"
    script.write_text("")
    wired = Context(Config(identity=IdentityConfig(directory_command=(str(script),)))).identity
    assert wired is not None and wired._directory is not None


def test_a_typo_in_the_identity_section_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "traust.yaml"
    path.write_text("identity:\n  issuer: https://idp.example\n")
    with pytest.raises(ConfigError):
        Context.from_file(path)


def test_login_is_wired_only_when_configured(tmp_path: Path) -> None:
    assert Context(Config(home=tmp_path)).login is None
    login = LoginConfig(issuer="https://idp.example", client_id="traust-cli")
    context = Context(Config(home=tmp_path, identity=IdentityConfig(login=login)))
    assert context.login is not None
    assert (context.login.issuer, context.login.client_id) == ("https://idp.example", "traust-cli")
    assert context.local_jwks == tmp_path / "local-jwks.json"
    context.credentials.clear()
    assert context.credentials.load() is None


def test_spend_shares_the_unit_of_work_and_judges_the_configured_budgets(tmp_path: Path) -> None:
    context = Context(Config.from_file(_write(tmp_path, f"home: {tmp_path / 'home'}\n")))
    lanes = [{"lane": "full-audit", "monthly_usd": 100, "enforcement": "advisory"}]
    configure(context, "budget", {"lanes": lanes})
    services = context.services()
    assert services.spend._uow is services.ops._uow
    verdict = services.spend.check_budget(LaneName("full-audit"), Decimal("150"))
    assert (verdict.status, verdict.binding) == (BudgetStatus.OVER, True)
    assert services.spend.check_budget(LaneName("diff-scan"), None).status == BudgetStatus.NO_BUDGET


def test_ops_writes_run_manifests_to_the_configured_object_store(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path / "home"))
    services = ctx.services()
    pack = ConfigDigest(name="pack:security", digest="a" * 64)
    order = services.ops.plan(OrderRequest(asset="feeds_cache", priority=1), OPERATOR, [pack])
    assert order.artifact_id is not None
    assert services.ops._manifests is not None
    assert list(ctx.object_store.list("artifacts/run-manifest"))


def test_context_re_exports_the_ops_types_consumers_annotate_with(tmp_path: Path) -> None:
    services = Context(Config(home=tmp_path / "home")).services()
    assert (OpsService, SpendService, FeedQuery, Router) == (
        operations.OpsService,
        operations.SpendService,
        operations.FeedQuery,
        operations.Router,
    )
    assert (Clock, validate_config) == (clock.Clock, contracts.validate_config)
    assert isinstance(services.ops, OpsService)
    assert isinstance(services.spend, SpendService)
    assert isinstance(services.feed, FeedQuery)


def test_engine_registered_sources_reach_their_doors() -> None:
    ctx = Context(Config())
    services = ctx.services()
    assert services.compliance._adr_source is None and services.detection_quality._canaries is None
    adr, docs, packs, canaries = object(), object(), object(), object()
    ctx.adr_source, ctx.doc_source = adr, docs  # type: ignore[assignment]
    ctx.rule_packs, ctx.canaries = packs, canaries  # type: ignore[assignment]
    services = ctx.services()
    assert (services.compliance._adr_source, services.compliance._docs) == (adr, docs)
    quality = services.detection_quality
    assert (quality._rule_packs, quality._canaries) == (packs, canaries)
