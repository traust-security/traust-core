from __future__ import annotations

from traust_core.v1.providers.cwe_reference import CweReferenceProvider


def test_reviewed_reference_preserves_curated_mapping_and_fix() -> None:
    reference = CweReferenceProvider().get("CWE-89")
    assert reference is not None
    assert (reference.identifier, reference.name, reference.asvs) == (
        "CWE-89",
        "SQL Injection",
        "V1.2",
    )
    assert reference.fix == (
        "Use parameterised queries / the ORM's bind API; never concatenate identifiers "
        "or values into SQL."
    )


def test_unknown_and_noncanonical_alias_have_no_fabricated_metadata() -> None:
    provider = CweReferenceProvider()
    assert provider.get("CWE-999999") is None
    assert provider.get("CWE-917-EL") is None
