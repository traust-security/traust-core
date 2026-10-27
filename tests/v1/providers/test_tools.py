from datetime import UTC, datetime
from pathlib import Path

import pytest

from traust_core.v1.errors import ServiceError
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.tools import acquire_over_text

NOW = datetime(2026, 10, 23, tzinfo=UTC)


class ListingTool:
    name = "lister"

    def __init__(self, fails=False):
        self.fails, self.workspaces = fails, []

    def check(self):
        return Readiness(ready=True)

    def acquire(self, request):
        self.workspaces.append(request.workspace)
        if self.fails:
            raise ServiceError("lister failed")
        files = {p.name: p.read_text(encoding="utf-8") for p in request.workspace.iterdir()}
        return Result(files, Acquisition(provider=self.name, acquired_at=NOW))


def test_a_tool_over_text_sees_one_file_holding_it():
    tool = ListingTool()
    found = acquire_over_text(tool, "change.patch", "+KEY = 'é'\n").data
    assert found == {"change.patch": "+KEY = 'é'\n"}
    assert not Path(tool.workspaces[0]).exists()


def test_the_scratch_directory_is_removed_when_the_tool_fails():
    tool = ListingTool(fails=True)
    with pytest.raises(ServiceError, match="lister failed"):
        acquire_over_text(tool, "change.patch", "x")
    assert not Path(tool.workspaces[0]).exists()
