from uuid import uuid4

from traust_core.v1.models.dependencies import AdvisoryNames


def test_names_split_into_cves_and_ghsas_once_each() -> None:
    names = AdvisoryNames(
        advisory_id=uuid4(),
        identifiers=(
            "GHSA-jfh8-c2jp-5v3q",
            "cve-2021-44228",
            "CVE-2021-44228",
            "GO-2021-0001",
            "PYSEC-2021-1",
            "GHSA-JFH8-C2JP-5V3Q",  # another spelling of the same one: kept in GitHub's
            "ghsa-jfh8-c2jp-5v3q",
            "GHSA-abcd-c2jp-5v3q",  # a, b and d are outside GitHub's id alphabet
            "CVE-2021-44228x",
        ),
    )
    assert names.cves == ("CVE-2021-44228",)
    assert names.ghsas == ("GHSA-jfh8-c2jp-5v3q",)


def test_a_name_set_with_neither_kind_has_none() -> None:
    names = AdvisoryNames(advisory_id=uuid4(), identifiers=("GO-2021-0001",))
    assert (names.cves, names.ghsas) == ((), ())
