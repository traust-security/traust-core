from unittest.mock import Mock

import pytest
import sqlalchemy as sa

from tests.v1.repositories.tables import conftest as table_fixtures
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.values import ProductSlug
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

engine = table_fixtures.engine


def test_product_slug_round_trips_as_text_and_preserves_identity(engine: sa.Engine) -> None:
    writer = PortfolioService(SqlTraustUnitOfWork(engine), PortfolioPolicy())
    slug = ProductSlug.parse("Example-4.16_x")
    product = writer.register_product(slug, "Example")
    assert product.slug == str(slug)
    assert writer.register_product(slug, "Different label") == product
    distinct = writer.register_product(ProductSlug(str(slug).lower()), "Lowercase")
    assert distinct.id != product.id

    reader = PortfolioService(SqlTraustUnitOfWork(engine), PortfolioPolicy())
    assert reader.find_product(slug) == product
    assert reader.find_product(ProductSlug(distinct.slug)) == distinct
    assert reader.find_product(ProductSlug("missing")) is None
    assert reader.get_product(product.id).model_dump(mode="json")["slug"] == str(slug)


@pytest.mark.parametrize("method", ["register_product", "find_product"])
@pytest.mark.parametrize("raw", ["example", "", None, 1, {"value": "example"}])
def test_product_service_requires_parsed_slugs_before_database_access(
    method: str, raw: object
) -> None:
    unit = Mock()
    service = PortfolioService(unit, PortfolioPolicy())
    with pytest.raises(ValidationError, match=r"product\.slug must be a ProductSlug"):
        getattr(service, method)(raw, *(["Example"] if method == "register_product" else []))
    assert unit.mock_calls == []
