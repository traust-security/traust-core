from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.common import every_item
from traust_core.v1.models.dependencies import FeedName
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.inventory import ReleaseBump, VersionLabel
from traust_core.v1.models.operations import (
    AssetName,
    ConfigDigest,
    LaneName,
    OrderFilter,
    OrderRequest,
    OrderState,
    RunOrder,
)
from traust_core.v1.models.release_inventory import (
    RELEASE_INVENTORY_FEED,
    RELEASE_OBSERVATION_CONFIG,
    ReleaseArtifactKind,
    ReleaseDiscoveryReport,
    ReleaseInventorySnapshot,
    ReleaseObservation,
    ReleaseRouting,
)
from traust_core.v1.models.values import ProductSlug
from traust_core.v1.providers.release_inventory import parse_release_snapshot
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.operations import OpsService
from traust_core.v1.services.portfolio import PortfolioService


class ReleaseDiscoveryService:
    """Consume release observations through the inventory, feed and operations owners."""

    def __init__(
        self, portfolio: PortfolioService, exposure: ExposureService, ops: OpsService
    ) -> None:
        self._portfolio, self._exposure, self._ops = portfolio, exposure, ops

    def snapshot(self) -> ReleaseInventorySnapshot:
        raw = self._exposure.feed_payload(FeedName(RELEASE_INVENTORY_FEED))
        if raw is None:
            raise NotFoundError("release inventory has not been observed")
        return parse_release_snapshot(raw)

    def discover(
        self,
        principal: Principal,
        routing: ReleaseRouting,
        run_order_id: UUID | None = None,
    ) -> ReleaseDiscoveryReport:
        self._exposure.refresh_feed(FeedName(RELEASE_INVENTORY_FEED), run_order_id)
        snapshot = self.snapshot()
        releases, skipped = [], dict(snapshot.skipped)
        for observed in sorted(
            snapshot.releases, key=lambda r: tuple(map(int, r.version.split(".")))
        ):
            if observed.product is None:
                continue
            product = self._portfolio.find_product(ProductSlug.parse(observed.product))
            if product is None or product.id is None:
                skipped[observed.inventory] = f"unregistered product {observed.product}"
                continue
            release = self._portfolio.record_release(product.id, VersionLabel(observed.version))
            assert release.id is not None
            releases.append(release.id)
        orders = []
        pending = self._pending(snapshot.observations, routing)
        if pending:
            orders.append(
                self._plan(
                    routing.passthrough,
                    pending,
                    routing,
                    principal,
                    lane=LaneName("release-passthrough"),
                )
            )
        remodels = [
            observation
            for observation in snapshot.observations
            if observation.change in (ReleaseBump.MAJOR, ReleaseBump.MINOR)
            and observation.repository is not None
        ]
        repositories = {observation.repository for observation in remodels}
        for url in sorted(repositories):
            repository = self._portfolio.inventory.find_repository(url)
            if repository is None or repository.id is None:
                skipped[url] = "release source repository is not registered"
                continue
            held = self._recorded_keys(routing.threat_model, repository.id)
            wanted = [o for o in remodels if o.repository == url and o.key not in held]
            if wanted:
                orders.append(
                    self._plan(
                        routing.threat_model,
                        wanted,
                        routing,
                        principal,
                        repository.id,
                        LaneName("threat-model-review"),
                    )
                )
        return ReleaseDiscoveryReport(
            observations=len(snapshot.observations),
            release_ids=tuple(dict.fromkeys(releases)),
            order_ids=tuple(order.id for order in orders),
            skipped=skipped,
        )

    def passthrough(
        self,
        principal: Principal,
        routing: ReleaseRouting,
        run_order_id: UUID | None = None,
    ) -> tuple[RunOrder, ...]:
        observations = self._selected(run_order_id)
        if not observations:
            raise NotFoundError("release order has no observed container or RPM artifacts")
        orders = []
        for kind, asset in (
            (ReleaseArtifactKind.CONTAINER, routing.container),
            (ReleaseArtifactKind.RPM, routing.rpm),
        ):
            held = self._recorded_keys(asset)
            wanted = [o for o in observations if o.kind == kind and o.key not in held]
            if wanted:
                orders.append(self._plan(asset, wanted, routing, principal))
        return tuple(orders)

    def targets(
        self, kind: ReleaseArtifactKind, run_order_id: UUID | None = None
    ) -> tuple[ReleaseObservation, ...]:
        return tuple(o for o in self._selected(run_order_id) if o.kind == kind)

    def _selected(self, run_order_id: UUID | None) -> tuple[ReleaseObservation, ...]:
        observations = self.snapshot().observations
        if run_order_id is None:
            return observations
        order = self._ops.get(run_order_id)
        keys = self._observation_keys(order)
        if not keys:
            if order.event_source == "release" or order.repository_id is None:
                raise ValidationError("release order does not identify its observations")
            repository = self._portfolio.inventory.get_repository(order.repository_id)
            return tuple(o for o in observations if o.repository == repository.url)
        selected = tuple(o for o in observations if o.key in keys)
        if keys != {o.key for o in selected}:
            raise NotFoundError("release order references an unavailable observation")
        return selected

    def _pending(
        self, observations: Sequence[ReleaseObservation], routing: ReleaseRouting
    ) -> list[ReleaseObservation]:
        held = {
            ReleaseArtifactKind.CONTAINER: self._recorded_keys(routing.container),
            ReleaseArtifactKind.RPM: self._recorded_keys(routing.rpm),
        }
        return [
            observation
            for observation in observations
            if observation.key not in held[observation.kind]
        ]

    def _recorded_keys(self, asset: AssetName, repository_id: UUID | None = None) -> set[str]:
        orders = every_item(
            lambda page: self._ops.list(
                OrderFilter(
                    asset=asset,
                    repository_id=repository_id,
                    states=tuple(state for state in OrderState if state != OrderState.WITHHELD),
                ),
                page,
            )
        )
        return {key for order in orders for key in self._observation_keys(order)}

    def _observation_keys(self, order: RunOrder) -> set[str]:
        if order.event_source != "release":
            return set()
        return {
            config.digest
            for config in self._ops.manifest(order.id).config
            if config.name.startswith(RELEASE_OBSERVATION_CONFIG)
        }

    def _plan(
        self,
        asset: AssetName,
        observations: Sequence[ReleaseObservation],
        routing: ReleaseRouting,
        principal: Principal,
        repository_id: UUID | None = None,
        lane: LaneName | None = None,
    ) -> RunOrder:
        return self._ops.plan(
            OrderRequest(
                asset=asset,
                priority=routing.priority,
                repository_id=repository_id,
                lane=lane,
                event_source="release",
            ),
            principal,
            config=tuple(
                ConfigDigest(name=RELEASE_OBSERVATION_CONFIG + key, digest=key)
                for key in sorted({o.key for o in observations})
            ),
        )
