from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from uuid import UUID

from pydantic import Field

from traust_core.v1.models.base import Model
from traust_core.v1.models.inventory import ReleaseBump
from traust_core.v1.models.operations import AssetName

RELEASE_INVENTORY_FEED = "release-inventory"
RELEASE_OBSERVATION_CONFIG = "release-observation:"


class ReleaseRouting(Model):
    passthrough: AssetName
    container: AssetName
    rpm: AssetName
    threat_model: AssetName
    priority: int


class ReleaseArtifactKind(StrEnum):
    CONTAINER = "container"
    RPM = "rpm"


class InventoryRelease(Model):
    inventory: str
    family: str
    version: str
    product: str | None = None
    repositories: tuple[str, ...] = ()


class ReleaseObservation(Model):
    key: str
    kind: ReleaseArtifactKind
    target: str
    repository: str | None = None
    inventory: str | None = None
    family: str | None = None
    version: str | None = None
    change: ReleaseBump = ReleaseBump.UNKNOWN
    head: str | None = None


class ReleaseInventorySnapshot(Model):
    seen_images: tuple[str, ...] = ()
    distgit_heads: Mapping[str, str] = Field(default_factory=dict)
    versions: Mapping[str, str] = Field(default_factory=dict)
    releases: tuple[InventoryRelease, ...] = ()
    observations: tuple[ReleaseObservation, ...] = ()
    skipped: Mapping[str, str] = Field(default_factory=dict)


class ReleaseDiscoveryReport(Model):
    observations: int
    release_ids: tuple[UUID, ...] = ()
    order_ids: tuple[UUID, ...] = ()
    skipped: Mapping[str, str] = Field(default_factory=dict)
