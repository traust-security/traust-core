"""TaxonomyPolicy.labels waits on the contracts label taxonomy: a typed ConfigError, never []."""

from __future__ import annotations

import pytest

from traust_core.v1.errors import ConfigError
from traust_core.v1.models.findings import CweId
from traust_core.v1.services.findings.taxonomy import TaxonomyPolicy


@pytest.mark.parametrize("cwes", [(), (CweId("CWE-79"),), (CweId("CWE-89"), CweId("CWE-20"))])
def test_labels_name_the_missing_taxonomy(cwes: tuple[CweId, ...]) -> None:
    with pytest.raises(ConfigError, match=r"NEED\(contracts: label-taxonomy\)"):
        TaxonomyPolicy().labels(cwes)
