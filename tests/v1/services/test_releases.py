from __future__ import annotations

import csv
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from traust_core.v1.context import Config, Context
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.inventory import VersionLabel
from traust_core.v1.models.operations import (
    AssetName,
    JobResult,
    OrderFilter,
    OrderState,
    WorkerId,
)
from traust_core.v1.models.release_inventory import ReleaseArtifactKind, ReleaseRouting
from traust_core.v1.models.values import HttpsRepoUrl, ProductSlug
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.release_inventory import ReleaseInventoryFeed
from traust_core.v1.services.releases import ReleaseDiscoveryService

REPO = "https://github.com/example/app"
PRINCIPAL = Principal(identity="release-watcher", kind=ActorKind.MACHINE, display="release watcher")
ROUTING = ReleaseRouting(
    passthrough=AssetName("release_passthrough"),
    container=AssetName("release_container_audit"),
    rpm=AssetName("release_rpm_audit"),
    threat_model=AssetName("threat_model_review"),
    priority=100,
)


class AdvancingClock:
    def __init__(self) -> None:
        self.at = datetime(2026, 10, 5, tzinfo=UTC)

    def now(self) -> datetime:
        at = self.at
        self.at += timedelta(seconds=1)
        return at


def write_inventory(root: Path, version: str, image: str) -> None:
    with (root / f"payload-{version}-payload-repos.csv").open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("GitHub URL", "Payload Image(s)"))
        writer.writerow((REPO, image))


def configured(tmp_path: Path) -> tuple[Context, ReleaseDiscoveryService, Path]:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    clock = AdvancingClock()
    core = Context(Config(home=tmp_path / "home"), clock=clock)
    core.feeds.register(
        ReleaseInventoryFeed.name,
        lambda: ReleaseInventoryFeed(
            inputs,
            ProcessRunner(()),
            clock,
            products={"payload-{V}-payload-repos.csv": "application"},
        ),
    )
    services = core.services()
    services.portfolio.register_product(ProductSlug.parse("application"), "Application")
    services.portfolio.register_repository(HttpsRepoUrl.parse(REPO, ["github.com"]), True)
    return (
        core,
        ReleaseDiscoveryService(services.portfolio, services.exposure, services.ops),
        inputs,
    )


def finish(core: Context, order_id: UUID) -> None:
    ops = core.services().ops
    ops.admit(order_id)
    worker = WorkerId("release-test")
    assert ops.claim(worker, timedelta(minutes=5), order_id=order_id) is not None
    ops.complete(order_id, worker, JobResult.succeeded())


def test_inventory_changes_record_versions_and_route_exact_artifact_and_threat_orders(
    tmp_path: Path,
) -> None:
    core, releases, inputs = configured(tmp_path)
    write_inventory(inputs, "1.0", "quay.io/example/app:old")
    baseline = releases.discover(PRINCIPAL, ROUTING)
    assert baseline.order_ids == ()
    assert releases.snapshot().observations == ()
    write_inventory(inputs, "1.1", "quay.io/example/app:new")
    report = releases.discover(PRINCIPAL, ROUTING)
    ops, portfolio = core.services().ops, core.services().portfolio
    orders = [ops.get(order_id) for order_id in report.order_ids]
    assert {o.asset for o in orders} == {ROUTING.passthrough, ROUTING.threat_model}
    review = next(o for o in orders if o.asset == ROUTING.threat_model)
    repository = portfolio.inventory.find_repository(REPO)
    assert repository is not None and review.repository_id == repository.id
    product = portfolio.find_product(ProductSlug.parse("application"))
    assert product is not None
    assert {r.version for r in portfolio.list_releases(product.id)} == {"1.0.0", "1.1.0"}
    native = portfolio.find_release(product.id, VersionLabel("1.1.0"))
    assert native is not None
    assert portfolio.list_release_refs(native.id) == []
    passthrough = next(o for o in orders if o.asset == ROUTING.passthrough)
    [audit] = releases.passthrough(PRINCIPAL, ROUTING, passthrough.id)
    assert audit.asset == ROUTING.container and audit.event_source == "release"
    assert audit.rule is None
    assert all(order.event_source == "release" and order.rule is None for order in orders)
    assert {c.digest for c in ops.manifest(audit.id).config} == {
        o.key for o in releases.snapshot().observations
    }
    assert audit.lane is None
    [target] = releases.targets(ReleaseArtifactKind.CONTAINER, audit.id)
    assert target.target == "quay.io/example/app:new"
    assert releases.targets(ReleaseArtifactKind.RPM, audit.id) == ()
    finish(core, audit.id)
    finish(core, review.id)
    finish(core, passthrough.id)
    assert releases.discover(PRINCIPAL, ROUTING).order_ids == ()
    assert (
        len(
            ops.list(
                OrderFilter(asset=ROUTING.container, states=tuple(OrderState)), PageRequest()
            ).items
        )
        == 1
    )


def test_new_observations_are_not_lost_when_an_earlier_audit_is_already_queued(
    tmp_path: Path,
) -> None:
    core, releases, inputs = configured(tmp_path)
    write_inventory(inputs, "1.0", "quay.io/example/app:one")
    releases.discover(PRINCIPAL, ROUTING)
    write_inventory(inputs, "1.0", "quay.io/example/app:two")
    [root_id] = releases.discover(PRINCIPAL, ROUTING).order_ids
    [old_audit] = releases.passthrough(PRINCIPAL, ROUTING, root_id)
    finish(core, root_id)
    core.services().ops.admit(old_audit.id)
    write_inventory(inputs, "1.0", "quay.io/example/app:three")
    [new_root_id] = releases.discover(PRINCIPAL, ROUTING).order_ids
    [kept] = releases.passthrough(PRINCIPAL, ROUTING, new_root_id)
    assert kept.id == old_audit.id
    [old_target] = releases.targets(ReleaseArtifactKind.CONTAINER, kept.id)
    assert old_target.target.endswith(":two")
    finish(core, new_root_id)
    worker = WorkerId("release-test")
    core.services().ops.claim(worker, timedelta(minutes=5), order_id=old_audit.id)
    core.services().ops.complete(old_audit.id, worker, JobResult.succeeded())
    [retry_root] = releases.discover(PRINCIPAL, ROUTING).order_ids
    [new_audit] = releases.passthrough(PRINCIPAL, ROUTING, retry_root)
    [new_target] = releases.targets(ReleaseArtifactKind.CONTAINER, new_audit.id)
    assert new_target.target.endswith(":three")


def test_budget_withholding_does_not_consume_an_artifact_observation(tmp_path: Path) -> None:
    core, releases, inputs = configured(tmp_path)
    write_inventory(inputs, "1.0", "quay.io/example/app:one")
    releases.discover(PRINCIPAL, ROUTING)
    write_inventory(inputs, "1.0", "quay.io/example/app:two")
    [root] = releases.discover(PRINCIPAL, ROUTING).order_ids
    [withheld] = releases.passthrough(PRINCIPAL, ROUTING, root)
    core.services().ops.withhold(withheld.id, "budget-exhausted")
    finish(core, root)
    [new_root] = releases.discover(PRINCIPAL, ROUTING).order_ids
    [replacement] = releases.passthrough(PRINCIPAL, ROUTING, new_root)
    assert replacement.id != withheld.id
    assert replacement.event_source == withheld.event_source == "release"
    assert replacement.rule is withheld.rule is None
    assert core.services().ops.manifest(replacement.id).config == (
        core.services().ops.manifest(withheld.id).config
    )
    assert releases.targets(ReleaseArtifactKind.CONTAINER, replacement.id) == (
        releases.targets(ReleaseArtifactKind.CONTAINER, withheld.id)
    )
