import pytest

from tests.v1.stubs import assert_stub, public_methods
from traust_core.v1.services.findings.transitions import TransitionPolicy


@pytest.mark.parametrize("method", public_methods(TransitionPolicy()), ids=lambda m: m.__name__)
def test_method_is_a_stub(method) -> None:
    assert_stub(method)
