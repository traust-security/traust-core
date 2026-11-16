"""CVSS from every advisory source, ranked: NIST > GHSA > CNA > ADP > Red Hat > scanner."""

from __future__ import annotations

import copy
import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.cvss import (
    CvssScore,
    CvssSource,
    csaf_scores,
    cve_list_scores,
    distinct,
    nvd_scores,
    osv_scores,
    rh_cve_scores,
    score_of,
)
from traust_core.v1.services.findings.cvss import effective

FIXTURES = Path(__file__).parents[2] / "fixtures" / "dependencies" / "cvss"
V31 = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 8.1
V31_CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
V30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"  # 9.1
V40 = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def _raw(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _doc(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text())


def parse_nvd(doc: Any) -> tuple[CvssScore, ...]:
    return nvd_scores(json.dumps(doc).encode())


def parse_osv(doc: Any) -> tuple[CvssScore, ...]:
    return osv_scores(json.dumps(doc).encode())


def parse_rh_cve(doc: Any) -> tuple[CvssScore, ...]:
    return rh_cve_scores(json.dumps(doc).encode())


def parse_cve_list(doc: Any) -> tuple[CvssScore, ...]:
    return cve_list_scores(json.dumps(doc).encode())


def parse_csaf(doc: Any, cve_id: str) -> tuple[CvssScore, ...]:
    return csaf_scores(json.dumps(doc).encode(), cve_id)


def _by(scores: tuple[CvssScore, ...]) -> set[tuple[str, str, Decimal | None]]:
    return {(s.source.value, s.version, s.score) for s in scores}


# ---- the public documents -----------------------------------------------------------------


def test_the_dashboard_case_takes_the_cnas_31_score_with_its_40_alongside() -> None:
    # CVE-2026-9277: NVD Deferred (no NIST score); the CNA scored 3.1 8.1 and 4.0 9.2
    scores = parse_nvd(_doc("nvd-CVE-2026-9277.json"))
    assert _by(scores) == {
        ("cna", "3.1", Decimal("8.1")),
        ("cna", "4.0", Decimal("9.2")),
        ("adp", "3.1", Decimal("8.1")),  # another source's Secondary metric
    }
    result = effective(scores)
    assert (result.source, result.score) == (CvssSource.CNA, Decimal("8.1"))
    assert result.v4 is not None and result.v4.score == Decimal("9.2")


def test_nist_wins_when_nvd_has_analysed_the_cve() -> None:
    scores = parse_nvd(_doc("nvd-CVE-2021-44228.json"))
    assert _by(scores) == {("nist", "3.1", Decimal("10.0")), ("adp", "3.1", Decimal("10.0"))}
    assert all(s.version != "2.0" for s in scores)  # CVSS 2 is never read
    assert effective(scores).source is CvssSource.NIST


def test_a_github_reviewed_advisory_is_ghsa_and_its_temporal_metrics_dont_change_the_base() -> None:
    (score,) = parse_osv(_doc("osv-GHSA-jfh8-c2jp-5v3q.json"))
    assert (score.source, score.version, score.score) == (CvssSource.GHSA, "3.1", Decimal("10.0"))
    assert score.vector.endswith("/E:H") and score.document == "osv:GHSA-jfh8-c2jp-5v3q"


def test_the_cve_list_record_names_the_cna_and_each_adp() -> None:
    scores = cve_list_scores(_raw("cve-list-CVE-2026-9277.json"))
    assert {(s.source.value, s.version, s.score, s.scored_by) for s in scores} == {
        ("cna", "3.1", Decimal("8.1"), "harborist"),
        ("cna", "4.0", Decimal("9.2"), "harborist"),
        ("adp", "3.1", Decimal("8.1"), "redhat-SADP"),
    }
    assert {s.document for s in scores} == {"cve-list:CVE-2026-9277"}
    result = effective(scores)
    assert (result.source, result.score) == (CvssSource.CNA, Decimal("8.1"))
    assert result.v4 is not None and result.v4.score == Decimal("9.2")


def test_osvs_copy_of_a_cve_record_ranks_nowhere() -> None:
    # it dropped the CNA's 3.1 score (8.1) and kept only 4.0; the CVE List record is the source
    assert parse_osv(_doc("osv-CVE-2026-9277.json")) == ()


def _cve_list(state: str = "PUBLISHED", **cvss: Any) -> dict[str, Any]:
    return {
        "cveMetadata": {"cveId": "CVE-2099-0001", "state": state},
        "containers": {
            "cna": {
                "providerMetadata": {"orgId": "org-1", "shortName": "cna-1"},
                "metrics": [cvss],
            },
            "adp": [{"providerMetadata": {"orgId": "adp-org"}, "metrics": [cvss]}],
        },
    }


def test_a_record_that_isnt_published_states_nothing() -> None:
    cvss = {"cvssV3_1": {"version": "3.1", "vectorString": V31, "baseScore": 8.1}}
    assert parse_cve_list(_cve_list("REJECTED", **cvss)) == ()


def test_an_adp_without_a_short_name_is_named_by_its_org_id() -> None:
    cvss = {"cvssV3_1": {"version": "3.1", "vectorString": V31, "baseScore": 8.1}}
    adp = [s for s in parse_cve_list(_cve_list(**cvss)) if s.source is CvssSource.ADP]
    assert [s.scored_by for s in adp] == ["adp-org"]


def test_a_cve_list_block_and_its_version_must_agree() -> None:
    mismatched = {"cvssV3_1": {"version": "3.0", "vectorString": V30, "baseScore": 9.1}}
    assert parse_cve_list(_cve_list(**mismatched)) == ()


def test_red_hats_two_documents() -> None:
    assert _by(parse_rh_cve(_doc("rhcve-CVE-2021-44228.json"))) == {
        ("red-hat", "3.1", Decimal("9.8"))
    }
    assert _by(parse_csaf(_doc("csaf-cve-2021-44228.json"), "CVE-2021-44228")) == {
        ("red-hat", "3.1", Decimal("9.8"))
    }
    assert parse_csaf(_doc("csaf-cve-2021-44228.json"), "CVE-2099-0001") == ()


def test_every_document_together_ranks_nist_first_and_keeps_every_source() -> None:
    every = [
        *parse_nvd(_doc("nvd-CVE-2021-44228.json")),
        *parse_osv(_doc("osv-GHSA-jfh8-c2jp-5v3q.json")),
        *parse_rh_cve(_doc("rhcve-CVE-2021-44228.json")),
        *parse_csaf(_doc("csaf-cve-2021-44228.json"), "CVE-2021-44228"),
    ]
    result = effective(every)
    assert result.source is CvssSource.NIST
    # every document's statement kept, in ranking order: Red Hat's two documents both survive
    assert [(s.source, s.document) for s in result.scores] == [
        (CvssSource.NIST, "nvd:CVE-2021-44228"),
        (CvssSource.GHSA, "osv:GHSA-jfh8-c2jp-5v3q"),
        (CvssSource.ADP, "nvd:CVE-2021-44228"),
        (CvssSource.RED_HAT, "rh-cve:CVE-2021-44228"),
        (CvssSource.RED_HAT, "csaf:CVE-2021-44228"),
    ]


# ---- precedence and ties --------------------------------------------------------------------


def _score(source: CvssSource, vector: str, stated: str | None = None) -> CvssScore:
    made = score_of(source, vector, document=f"test:{source.value}", stated=stated)
    assert made is not None
    return made


@pytest.mark.parametrize(
    ("vector", "version", "stated"),
    [
        ("CVSS:3.1/AV:N/AC:H", None, None),  # missing base metrics
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:Q", None, None),  # a value no metric has
        ("CVSS:3.1/AV:N/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", None, None),  # a repeated metric
        ("cvss:3.1/av:n/ac:h/pr:n/ui:n/s:u/c:h/i:h/a:h", None, None),  # not the canonical form
        (V31 + "\n", None, None),  # trailing text
        (V31, "3.0", None),  # stated version disagrees with the vector
        (V31, None, "9.8"),  # stated score disagrees with the vector (8.1)
        (V31, None, "11"),  # outside 0-10
        (V31, None, "-1"),
        (V31, None, "NaN"),
        (V31, None, True),
        ("AV:N/AC:M/Au:N/C:C/I:C/A:C", None, None),  # CVSS 2
        ("CVSS:4.0/AV:N/AC:L", None, "9.2"),  # 4.0 missing base metrics
        (V40, None, "12"),
        (5, None, None),  # not a string
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Q/C:H/I:H/A:H", None, None),  # a scope that isn't U or C
        (V31 + "/E:Z", None, None),  # a temporal value no metric has
        (V31 + "/XYZ:Q", None, None),  # a metric CVSS doesn't define
        ("CVSS:4.0/AV:Z/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", None, "9.2"),
        (V40 + "/U:Purple", None, "9.2"),  # an urgency no metric has
        (V31, None, "8.14"),  # stated more precisely than its vector computes
        (V31, None, "8.1000001"),
        (V31, None, "1e1"),
        (V31, None, " 8.1 "),
        (V31, None, "8_1"),
        (V31, None, float("nan")),
    ],
)
def test_an_untrustworthy_score_is_refused(vector: object, version: object, stated: object) -> None:
    assert score_of(CvssSource.CNA, vector, document="test", version=version, stated=stated) is None


def test_a_stated_31_score_that_matches_its_vector_is_kept() -> None:
    assert _score(CvssSource.CNA, V31, stated="8.1").score == Decimal("8.1")


def _nvd(metric_key: str, **metric: Any) -> dict[str, Any]:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-0001",
                    "sourceIdentifier": "cna@example.test",
                    "metrics": {metric_key: [metric]},
                }
            }
        ]
    }


def test_a_primary_metric_from_anyone_but_nist_is_not_nists() -> None:
    doc = _nvd(
        "cvssMetricV31",
        source="cna@example.test",
        type="Primary",
        cvssData={"version": "3.1", "vectorString": V31, "baseScore": 8.1},
    )
    assert parse_nvd(doc) == ()


def test_a_metric_filed_under_the_wrong_versions_block_is_refused() -> None:
    doc = _nvd(
        "cvssMetricV31",
        source="nvd@nist.gov",
        type="Primary",
        cvssData={"version": "3.0", "vectorString": V30, "baseScore": 9.1},
    )
    assert parse_nvd(doc) == ()


def test_an_unreviewed_ghsa_and_another_databases_record_rank_nowhere() -> None:
    reviewed = _doc("osv-GHSA-jfh8-c2jp-5v3q.json")
    unreviewed = copy.deepcopy(reviewed)
    unreviewed["database_specific"]["github_reviewed"] = False
    other = copy.deepcopy(reviewed)
    other["id"] = "PYSEC-2099-1"
    assert parse_osv(unreviewed) == () and parse_osv(other) == ()


@pytest.mark.parametrize(
    ("parse", "doc"),
    [
        (parse_nvd, {}),  # no vulnerabilities
        (parse_nvd, {"vulnerabilities": "x"}),
        (parse_nvd, {"vulnerabilities": [None]}),
        (
            parse_nvd,
            {"vulnerabilities": [{"cve": {"id": 5}}]},
        ),  # a mistyped field fails, never drops
        (parse_nvd, []),
        (parse_osv, {"id": 5}),
        (parse_osv, {"id": "GHSA-x", "severity": [None]}),
        (parse_osv, {"id": "GHSA-x", "database_specific": {"github_reviewed": "yes"}}),
        (parse_rh_cve, {"name": "CVE-2099-1", "cvss3": "x"}),
        (parse_rh_cve, {"cvss3": {}}),
        (parse_csaf, {"vulnerabilities": "x"}),
        (parse_cve_list, {"containers": {}}),  # no cveMetadata
        (parse_cve_list, {"cveMetadata": {"cveId": "CVE-2099-1"}}),  # no state
        (parse_cve_list, _cve_list(cvssV3_1={"version": "3.1", "baseScore": 8.1})),  # no vector
        # a score block that's present must carry its vector: a renamed field fails, never drops
        (
            parse_nvd,
            _nvd(
                "cvssMetricV31",
                source="nvd@nist.gov",
                type="Primary",
                cvssData={"version": "3.1", "baseScore": 8.1},
            ),
        ),
        (
            parse_nvd,
            _nvd(
                "cvssMetricV31",
                source="nvd@nist.gov",
                type="Primary",
                cvssData={"vectorString": V31, "baseScore": 8.1},
            ),
        ),
        (parse_rh_cve, {"name": "CVE-2099-1", "cvss3": {"cvss3_base_score": "8.1"}}),
        (
            parse_csaf,
            {
                "vulnerabilities": [
                    {
                        "cve": "CVE-2021-44228",
                        "scores": [{"cvss_v3": {"version": "3.1", "baseScore": 8.1}}],
                    }
                ]
            },
        ),
    ],
)
def test_a_document_that_doesnt_fit_its_shape_is_a_validation_error(parse: Any, doc: Any) -> None:
    args = (doc, "CVE-2021-44228") if parse is parse_csaf else (doc,)
    with pytest.raises(ValidationError, match=r"^not "):
        parse(*args)


def test_a_well_formed_document_with_no_scores_states_nothing() -> None:
    assert parse_nvd({"vulnerabilities": [{"cve": {"id": "CVE-2099-1"}}]}) == ()
    assert parse_osv({"id": "GHSA-x"}) == ()
    assert parse_rh_cve({"name": "CVE-2099-1"}) == ()
    assert parse_csaf({}, "CVE-2099-1") == ()


def test_a_well_formed_40_vector_with_its_supplemental_metrics_is_kept() -> None:
    score = score_of(CvssSource.CNA, V40 + "/E:X/AU:Y/U:Clear", document="test", stated="9.2")
    assert score is not None and score.score == Decimal("9.2")


def test_each_exact_statement_is_kept_once() -> None:
    nvd = score_of(CvssSource.CNA, V40, document="nvd:CVE-2099-1", stated="9.2")
    osv = score_of(CvssSource.CNA, V40, document="osv:CVE-2099-1")
    assert nvd is not None and osv is not None
    assert distinct([osv, nvd, osv, nvd]) == (osv, nvd)


def test_two_authorities_with_one_vector_are_both_kept_in_either_order() -> None:
    def adp(by: str, stated: str) -> CvssScore:
        made = score_of(CvssSource.ADP, V40, document="nvd:CVE-2099-1", stated=stated, scored_by=by)
        assert made is not None
        return made

    first, second = adp("adp-a", "9.2"), adp("adp-b", "8.7")
    assert set(distinct([first, second])) == set(distinct([second, first])) == {first, second}


def test_a_40_vector_out_of_the_specs_metric_order_is_refused() -> None:
    swapped = "CVSS:4.0/AC:L/AV:N/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    assert score_of(CvssSource.CNA, swapped, document="test", stated="9.2") is None
    late_base = V40.replace("/SA:N", "") + "/E:X/SA:N"
    assert score_of(CvssSource.CNA, late_base, document="test", stated="9.2") is None


def test_a_31_vector_may_list_its_metrics_in_any_order() -> None:
    reordered = "CVSS:3.1/AC:H/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score = score_of(CvssSource.CNA, reordered, document="test")
    assert score is not None and score.score == Decimal("8.1")


def test_an_osv_cvss_v3_entry_carrying_a_40_vector_is_refused() -> None:
    record = _doc("osv-GHSA-jfh8-c2jp-5v3q.json")
    record["severity"] = [{"type": "CVSS_V3", "score": V40}]
    assert parse_osv(record) == ()


def test_a_secondary_metric_from_nist_is_neither_nists_nor_an_adps() -> None:
    doc = _nvd(
        "cvssMetricV31",
        source="nvd@nist.gov",
        type="Secondary",
        cvssData={"version": "3.1", "vectorString": V31, "baseScore": 8.1},
    )
    assert parse_nvd(doc) == ()


def test_a_30_vector_rounds_as_30_does() -> None:
    from traust_core.v1.models.dependencies import cvss_base_score

    assert cvss_base_score(V30) == 9.1
    assert cvss_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:Q/C:H/I:H/A:H") is None
