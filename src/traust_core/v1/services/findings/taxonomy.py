from __future__ import annotations

from collections.abc import Sequence

from traust_core.v1.errors import ConfigError
from traust_core.v1.models.findings import CweId, WeaknessLabels


class TaxonomyPolicy:
    def labels(self, cwes: Sequence[CweId]) -> WeaknessLabels:
        """The taxonomy labels (ATT&CK techniques, ASVS requirements, ...) the CWEs map to."""
        # NEED(contracts: label-taxonomy): the closed taxonomy vocabulary and its CWE crosswalks
        # (enums/v1/label-taxonomy.json, control_refs) are not in traust-contracts yet; legacy
        # asvs_for / classify_axis / infer_techniques port onto them once they land.
        raise ConfigError(
            "NEED(contracts: label-taxonomy): no label-taxonomy vocabulary or CWE crosswalk "
            f"in traust-contracts to label {list(cwes)}"
        )
