from __future__ import annotations

from traust_core.v1.context import Context
from traust_core.v1.rest.common import deps


def test_each_request_gets_its_own_unit_of_work(context: Context) -> None:
    first, second = deps.services(context), deps.services(context)
    assert first.findings._uow is not second.findings._uow
