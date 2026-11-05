from __future__ import annotations

import pytest

from traust_core.v1.models.findings import CweId
from traust_core.v1.services.findings.taxonomy import TaxonomyPolicy


@pytest.mark.parametrize(
    ("cwes", "expected"),
    [
        ((), {}),
        ((CweId("CWE-79"),), {"asvs": ("V1.2",)}),
        ((CweId("CWE-79"), CweId("CWE-89")), {"asvs": ("V1.2",)}),
        ((CweId("CWE-999999"),), {}),
    ],
)
def test_labels_use_only_reviewed_crosswalks(
    cwes: tuple[CweId, ...], expected: dict[str, tuple[str, ...]]
) -> None:
    result = TaxonomyPolicy().labels(cwes)
    assert result.cwes == cwes
    assert result.labels == expected
