from __future__ import annotations

from collections.abc import Sequence

from traust_core.v1.models.findings import CweId, CweReference, WeaknessLabels
from traust_core.v1.providers.cwe_reference import CweReferenceProvider


class TaxonomyPolicy:
    def __init__(self, references: CweReferenceProvider | None = None) -> None:
        self._references = references or CweReferenceProvider()

    def reference(self, cwe: str) -> CweReference | None:
        return self._references.get(cwe)

    def labels(self, cwes: Sequence[CweId]) -> WeaknessLabels:
        """Only reviewed ASVS crosswalks; unknown CWE mappings remain absent."""
        asvs = tuple(
            dict.fromkeys(ref.asvs for cwe in cwes if (ref := self.reference(cwe)) is not None)
        )
        return WeaknessLabels(cwes=tuple(cwes), labels={"asvs": asvs} if asvs else {})
