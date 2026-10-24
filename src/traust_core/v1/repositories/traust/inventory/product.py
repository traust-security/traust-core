from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.inventory import Product
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
)

PRODUCT = TableSpec(TRAUST, "product", lambda: (text_column("slug"), text_column("name")))


class ProductRepository(MutableRecordRepository[Product], Protocol):
    def get_or_add(self, record: Product) -> Product: ...
    def find_by_slug(self, slug: str) -> Product | None: ...
    def list_after(self, slug: str | None, limit: int) -> list[Product]: ...


class SqlProductRepository(SqlMutableRepository[Product]):
    spec = PRODUCT
    record = Product

    def get_or_add(self, record: Product) -> Product:
        return self._get_or_add(
            record,
            ("slug",),
            lambda: self.find_by_slug(record.slug),
        )

    def find_by_slug(self, slug: str) -> Product | None:
        return self._one(f"find {slug}", self.table.c.slug == slug)

    def list_after(self, slug: str | None, limit: int) -> list[Product]:
        c = self.table.c
        stmt = self._select().order_by(c.slug).limit(limit)
        if slug is not None:
            stmt = stmt.where(c.slug > slug)
        return [self._to_record(r) for r in self._execute("list", stmt).mappings()]
