import json

import pytest

from traust_core.v1.models.portfolio import Designation, DesignationRecord
from traust_core.v1.repositories.designations import (
    FileDesignationRepository,
    InMemoryDesignationRepository,
)


@pytest.mark.parametrize("backend", ["memory", "file"])
def test_designations_preserve_order_and_return_independent_lists(backend, tmp_path):
    rows = [
        DesignationRecord(match="https://github.com/o/", designation=Designation.EXTERNAL),
        DesignationRecord(match="https://github.com/o/r", designation=Designation.INTERNAL_TOOLING),
    ]
    path = tmp_path / "designations.json"
    path.write_text(
        json.dumps(
            {"designations": [{"match": row.match, "exposure": row.designation} for row in rows]}
        )
    )
    repo = (
        InMemoryDesignationRepository(rows)
        if backend == "memory"
        else FileDesignationRepository(path)
    )
    assert repo.entries() == rows
    repo.entries().clear()
    assert repo.entries() == rows


def test_missing_or_invalid_designations_do_not_invent_exposure(tmp_path):
    path = tmp_path / "designations.json"
    repo = FileDesignationRepository(path)
    assert repo.entries() == []
    path.write_text("{invalid")
    assert repo.entries() == []
    path.write_text('{"designations": [{"match": "x", "exposure": "not-a-designation"}]}')
    assert repo.entries() == []
