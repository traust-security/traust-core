import pytest

from tests.v1.stubs import assert_stub, public_methods
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

SERVICE = PortfolioService(None, PortfolioPolicy())  # type: ignore[arg-type]
POLICY = PortfolioPolicy()


@pytest.mark.parametrize(
    "method", public_methods(SERVICE) + public_methods(POLICY), ids=lambda m: m.__qualname__
)
def test_method_is_a_stub(method) -> None:
    assert_stub(method)
