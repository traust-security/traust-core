from tests.v1.stubs import assert_stub
from traust_core.v1.models.base import new_id


def test_new_id_is_a_stub() -> None:
    assert_stub(new_id)
