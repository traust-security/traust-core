from __future__ import annotations

from collections.abc import Collection
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.dependencies import Image
from traust_core.v1.repositories.tables import (
    TRAUST,
    RecordRepository,
    SqlAppendOnlyRepository,
    TableSpec,
    text_column,
    uuid_column,
)

IMAGE = TableSpec(
    TRAUST,
    "image",
    lambda: (
        text_column("digest"),
        text_column("platform", nullable=True),
        uuid_column("repository_ref_id", nullable=True),
        uuid_column("sbom_id", nullable=True),
    ),
    append_only=True,
)


class ImageRepository(RecordRepository[Image], Protocol):
    def find_by_digest(self, digest: str) -> Image | None: ...
    def list_built_from(self, repository_ref_id: UUID) -> list[Image]: ...
    def list_with_sbom(self, sbom_id: UUID) -> list[Image]: ...
    def list_with_sboms(self, sbom_ids: Collection[UUID]) -> list[Image]: ...


class SqlImageRepository(SqlAppendOnlyRepository[Image]):
    spec = IMAGE
    record = Image

    def find_by_digest(self, digest: str) -> Image | None:
        return self._one(f"find {digest}", self.table.c.digest == digest)

    def list_built_from(self, repository_ref_id: UUID) -> list[Image]:
        """Images whose declared provenance names this commit."""
        return self._many(
            f"list built from {repository_ref_id}",
            self.table.c.repository_ref_id == repository_ref_id,
        )

    def list_with_sbom(self, sbom_id: UUID) -> list[Image]:
        return self.list_with_sboms([sbom_id])

    def list_with_sboms(self, sbom_ids: Collection[UUID]) -> list[Image]:
        return self._many_in("list with sboms", self.table.c.sbom_id, sbom_ids)
