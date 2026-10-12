import pytest

from tests.v1.stubs import assert_stub, public_methods
from traust_core.v1.services.assessment import AssessmentService

SERVICE = AssessmentService(None)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "method",
    [m for m in public_methods(SERVICE) if m.__name__ not in {"freshness", "observation_target"}],
    ids=lambda m: m.__name__,
)
def test_method_is_a_stub(method) -> None:
    assert_stub(method)
