"""CVSS from every advisory source, ranked: NIST > GHSA > CNA > ADP > Red Hat > scanner."""

from __future__ import annotations

import copy
import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.models.cvss import (
    CvssScore,
    CvssSource,
    csaf_scores,
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


def _doc(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text())


def _by(scores: tuple[CvssScore, ...]) -> set[tuple[str, str, Decimal | None]]:
    return {(s.source.value, s.version, s.score) for s in scores}


# ---- the public documents -----------------------------------------------------------------


def test_the_dashboard_case_takes_the_cnas_31_score_with_its_40_alongside() -> None:
    # CVE-2026-9277: NVD Deferred (no NIST score); the CNA scored 3.1 8.1 and 4.0 9.2
    scores = nvd_scores(_doc("nvd-CVE-2026-9277.json"))
    assert _by(scores) == {
        ("cna", "3.1", Decimal("8.1")),
        ("cna", "4.0", Decimal("9.2")),
        ("adp", "3.1", Decimal("8.1")),  # another source's Secondary metric
    }
    result = effective(scores)
    assert (result.source, result.score) == (CvssSource.CNA, Decimal("8.1"))
    assert result.v4 is not None and result.v4.score == Decimal("9.2")


def test_nist_wins_when_nvd_has_analysed_the_cve() -> None:
    scores = nvd_scores(_doc("nvd-CVE-2021-44228.json"))
    assert _by(scores) == {("nist", "3.1", Decimal("10.0")), ("adp", "3.1", Decimal("10.0"))}
    assert all(s.version != "2.0" for s in scores)  # CVSS 2 is never read
    assert effective(scores).source is CvssSource.NIST


def test_a_github_reviewed_advisory_is_ghsa_and_its_temporal_metrics_dont_change_the_base() -> None:
    (score,) = osv_scores(_doc("osv-GHSA-jfh8-c2jp-5v3q.json"))
    assert (score.source, score.version, score.score) == (CvssSource.GHSA, "3.1", Decimal("10.0"))
    assert score.vector.endswith("/E:H") and score.document == "osv:GHSA-jfh8-c2jp-5v3q"


def test_the_cve_list_record_through_osv_is_the_cnas_and_a_bare_40_vector_has_no_score() -> None:
    (score,) = osv_scores(_doc("osv-CVE-2026-9277.json"))
    assert (score.source, score.version, score.score) == (CvssSource.CNA, "4.0", None)
    assert score.scored_by == "harborist"
    result = effective([score])
    assert result.chosen is None and result.score is None  # 4.0 never sets the score
    assert result.v4 == score


def test_red_hats_two_documents() -> None:
    assert _by(rh_cve_scores(_doc("rhcve-CVE-2021-44228.json"))) == {
        ("red-hat", "3.1", Decimal("9.8"))
    }
    assert _by(csaf_scores(_doc("csaf-cve-2021-44228.json"), "CVE-2021-44228")) == {
        ("red-hat", "3.1", Decimal("9.8"))
    }
    assert csaf_scores(_doc("csaf-cve-2021-44228.json"), "CVE-2099-0001") == ()


def test_every_document_together_ranks_nist_first_and_keeps_every_source() -> None:
    every = [
        *nvd_scores(_doc("nvd-CVE-2021-44228.json")),
        *osv_scores(_doc("osv-GHSA-jfh8-c2jp-5v3q.json")),
        *rh_cve_scores(_doc("rhcve-CVE-2021-44228.json")),
        *csaf_scores(_doc("csaf-cve-2021-44228.json"), "CVE-2021-44228"),
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
    assert nvd_scores(doc) == ()


def test_a_metric_filed_under_the_wrong_versions_block_is_refused() -> None:
    doc = _nvd(
        "cvssMetricV31",
        source="nvd@nist.gov",
        type="Primary",
        cvssData={"version": "3.0", "vectorString": V30, "baseScore": 9.1},
    )
    assert nvd_scores(doc) == ()


def test_an_unreviewed_ghsa_and_another_databases_record_rank_nowhere() -> None:
    reviewed = _doc("osv-GHSA-jfh8-c2jp-5v3q.json")
    unreviewed = copy.deepcopy(reviewed)
    unreviewed["database_specific"]["github_reviewed"] = False
    other = copy.deepcopy(reviewed)
    other["id"] = "PYSEC-2099-1"
    not_cve_list = _doc("osv-CVE-2026-9277.json")
    not_cve_list["database_specific"]["osv_generated_from"] = "https://example.test/feed.json"
    assert osv_scores(unreviewed) == () and osv_scores(other) == ()
    assert osv_scores(not_cve_list) == ()


@pytest.mark.parametrize(
    "doc",
    [
        {},
        {"vulnerabilities": "x"},
        {"vulnerabilities": [None]},
        {"vulnerabilities": [{"cve": {"id": 5}}]},
        {"id": 5, "severity": [None]},
        {"name": "CVE-2099-1", "cvss3": "x"},
    ],
)
def test_a_malformed_document_states_nothing(doc: dict[str, Any]) -> None:
    assert nvd_scores(doc) == () and osv_scores(doc) == () and rh_cve_scores(doc) == ()
    assert csaf_scores(doc, "CVE-2021-44228") == ()


def test_a_well_formed_40_vector_with_its_supplemental_metrics_is_kept() -> None:
    score = score_of(CvssSource.CNA, V40 + "/E:X/AU:Y/U:Clear", document="test", stated="9.2")
    assert score is not None and score.score == Decimal("9.2")


def test_a_cna_vector_through_nvd_and_osv_is_kept_once_per_document_scored_first() -> None:
    nvd = score_of(CvssSource.CNA, V40, document="nvd:CVE-2099-1", stated="9.2")
    osv = score_of(CvssSource.CNA, V40, document="osv:CVE-2099-1")
    assert nvd is not None and osv is not None
    assert distinct([osv, nvd]) == (osv, nvd)  # both documents' statements kept
    unscored_first = score_of(CvssSource.CNA, V40, document="nvd:CVE-2099-1")
    assert distinct([unscored_first, nvd]) == (nvd,)  # the scored statement wins its document


def test_a_cve_list_lookalike_url_is_not_the_cve_list() -> None:
    record = _doc("osv-CVE-2026-9277.json")
    record["database_specific"]["osv_generated_from"] = "https://evil.example/cvelistV5/x.json"
    assert osv_scores(record) == ()


def test_an_osv_cvss_v3_entry_carrying_a_40_vector_is_refused() -> None:
    record = _doc("osv-GHSA-jfh8-c2jp-5v3q.json")
    record["severity"] = [{"type": "CVSS_V3", "score": V40}]
    assert osv_scores(record) == ()


def test_a_secondary_metric_from_nist_is_neither_nists_nor_an_adps() -> None:
    doc = _nvd(
        "cvssMetricV31",
        source="nvd@nist.gov",
        type="Secondary",
        cvssData={"version": "3.1", "vectorString": V31, "baseScore": 8.1},
    )
    assert nvd_scores(doc) == ()


def test_a_30_vector_rounds_as_30_does() -> None:
    from traust_core.v1.models.dependencies import cvss_base_score

    assert cvss_base_score(V30) == 9.1
    assert cvss_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:Q/C:H/I:H/A:H") is None
