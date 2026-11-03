from traust_core.v1.models.base import Model


class InputSegment(Model):
    name: str
    repository_urls: tuple[str, ...]


class InputInventoryRelation(Model):
    segment: str
    segment_label: str
    repository_url: str
    source: str
    product: str | None = None
    version: str | None = None
    release: str | None = None
    category: str | None = None
    branch: str | None = None
    sub_service: str | None = None
    resource_type: str | None = None


class InputSegmentInventory(Model):
    segments: tuple[InputSegment, ...]
    hierarchy: tuple[InputInventoryRelation, ...] = ()
