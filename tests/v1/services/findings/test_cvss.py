"""The score a finding shows: NIST > GHSA > CNA > ADP > Red Hat > scanner, 3.1 before 3.0,
and 4.0 only when no source has a 3.x score."""

from __future__ import annotations

from decimal import Decimal

import pytest

from traust_core.v1.models.cvss import CvssScore, CvssSource, scanner_score, score_of
from traust_core.v1.services.findings.cvss import PRECEDENCE, effective

V31 = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 8.1
V31_CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
V30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"  # 9.1
V40 = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def _score(source: CvssSource, vector: str, stated: str | None = None) -> CvssScore:
    made = score_of(source, vector, document=f"test:{source.value}", stated=stated)
    assert made is not None
    return made


@pytest.mark.parametrize("winner", PRECEDENCE)
def test_each_tier_wins_over_every_tier_below_it(winner: CvssSource) -> None:
    below = PRECEDENCE[PRECEDENCE.index(winner) + 1 :]
    scores = [_score(winner, V31)] + [_score(s, V31_CRIT) for s in below]
    assert effective(scores).source is winner  # rank decides, never the higher number


def test_the_order_is_nist_ghsa_cna_adp_red_hat_scanner() -> None:
    assert PRECEDENCE == (
        CvssSource.NIST,
        CvssSource.GHSA,
        CvssSource.CNA,
        CvssSource.ADP,
        CvssSource.RED_HAT,
        CvssSource.SCANNER,
    )


def test_within_a_source_31_wins_over_30_even_when_lower() -> None:
    result = effective([_score(CvssSource.CNA, V30), _score(CvssSource.CNA, V31)])
    assert (result.chosen.version, result.score) == ("3.1", Decimal("8.1"))  # type: ignore[union-attr]


def test_a_sources_30_still_wins_over_a_lower_sources_31() -> None:
    result = effective([_score(CvssSource.CNA, V30), _score(CvssSource.RED_HAT, V31_CRIT)])
    assert (result.source, result.chosen.version) == (CvssSource.CNA, "3.0")  # type: ignore[union-attr]


def test_a_tie_within_a_source_and_version_takes_the_highest() -> None:
    result = effective([_score(CvssSource.ADP, V31), _score(CvssSource.ADP, V31_CRIT)])
    assert result.score == Decimal("9.8")


def test_no_score_anywhere_is_none_never_zero() -> None:
    result = effective([])
    assert result.chosen is None and result.score is None and result.v4 is None


def test_the_scanners_vector_ranks_last() -> None:
    scanner = scanner_score(V31_CRIT, document="occurrence:1")
    assert scanner is not None and scanner.source is CvssSource.SCANNER
    assert effective([scanner]).source is CvssSource.SCANNER
    assert effective([scanner, _score(CvssSource.RED_HAT, V31)]).source is CvssSource.RED_HAT
    assert scanner_score(None, document="occurrence:1") is None


# ---- adversarial twins: each looks like a score, none can be trusted -------------------------


def test_any_3x_score_beats_every_40_and_a_40_rides_alongside() -> None:
    four = score_of(CvssSource.NIST, V40, document="test", stated="9.2")
    assert four is not None
    # NIST's 4.0 outranks nothing that is 3.x: even the scanner's 3.1 wins over it
    beside = effective([four, _score(CvssSource.SCANNER, V31)])
    assert beside.source is CvssSource.SCANNER and beside.v4 == four


def test_with_no_3x_score_anywhere_the_40_score_is_the_findings() -> None:
    """Owner, 2026-11-19 (revising D2): a 4.0 score sets the score only when no 3.x one exists."""
    four = score_of(CvssSource.NIST, V40, document="test", stated="9.2")
    assert four is not None
    alone = effective([four])
    assert (alone.chosen, alone.score, alone.source, alone.v4) == (
        four,
        Decimal("9.2"),
        CvssSource.NIST,
        four,
    )


def test_the_40_fallback_takes_sources_in_the_same_order_and_the_highest_on_a_tie() -> None:
    ghsa = score_of(CvssSource.GHSA, V40, document="test:ghsa")  # 9.2, computed
    low = V40.replace("VC:H/VI:H/VA:H", "VC:L/VI:N/VA:N")
    cna_low = score_of(CvssSource.CNA, low, document="test:cna")
    adp_hi = score_of(CvssSource.ADP, V40, document="test:adp", stated="9.2")
    assert ghsa is not None and cna_low is not None and adp_hi is not None
    assert effective([cna_low, adp_hi, ghsa]).source is CvssSource.GHSA
    assert effective([cna_low, adp_hi]).source is CvssSource.CNA  # rank before score
    other = score_of(CvssSource.CNA, V40, document="test:cna-2")
    assert other is not None
    assert effective([cna_low, other]).chosen == other  # within one source, the highest


def test_a_zero_score_is_a_real_score_and_can_win() -> None:
    zero = _score(CvssSource.NIST, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert zero.score == Decimal("0.0")
    result = effective([zero, _score(CvssSource.RED_HAT, V31_CRIT)])
    assert (result.source, result.score) == (CvssSource.NIST, Decimal("0.0"))
