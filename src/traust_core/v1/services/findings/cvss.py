"""Which advisory source's CVSS a finding shows: independent sources first, 3.x before 4.0."""

from __future__ import annotations

from collections.abc import Sequence
from decimal import Decimal

from traust_core.v1.models.cvss import (
    CvssScore,
    CvssSource,
    CvssVersion,
    EffectiveCvss,
    distinct,
    score_of,
    severity_of,
)
from traust_core.v1.models.values import canonical_decimal

PRECEDENCE: tuple[CvssSource, ...] = (
    CvssSource.NIST,
    CvssSource.GHSA,
    CvssSource.CNA,
    CvssSource.ADP,
    CvssSource.RED_HAT,
    CvssSource.SCANNER,
)
RANKED_VERSIONS: tuple[CvssVersion, ...] = ("3.1", "3.0")
# used only when no source has a 3.x score (owner, 2026-11-19, revising D2)
FALLBACK_VERSION: CvssVersion = "4.0"


def effective(scores: Sequence[CvssScore]) -> EffectiveCvss:
    """The first source in PRECEDENCE with a 3.x score wins, its 3.1 before its 3.0, the
    highest on a tie; with no 3.x score anywhere, its 4.0 score does. The highest-ranked 4.0
    rides alongside either way."""
    kept = distinct(scores)
    return EffectiveCvss(chosen=_chosen(kept), v4=_v4(kept), scores=tuple(sorted(kept, key=_rank)))


def selection(
    authority: Sequence[CvssScore],
    vector: str | None,
    score: Decimal | None,
    *,
    reported: bool,
    document: str,
) -> EffectiveCvss:
    """`effective` over every authority's statement and the latest report's own: the scanner's
    only when it reported a score its vector computes. An unreported finding selects nothing."""
    if not reported:
        return effective(())
    scanner = None
    if score is not None:
        # the canonical form: SQLite reads 5.3 back as 5.3000000000
        stated = canonical_decimal(score)
        scanner = score_of(CvssSource.SCANNER, vector, document=document, stated=stated)
    return effective([*authority, *([scanner] if scanner is not None else [])])


def conflicting(scores: Sequence[CvssScore]) -> bool:
    """Whether two different authorities' scored statements of one 3.x version fall in
    different bands; one source's differing statements (two CVEs) are no conflict."""
    said = {
        (s.version, s.source, severity_of(s.vector))
        for s in scores
        if s.source is not CvssSource.SCANNER
        and s.version in RANKED_VERSIONS
        and s.score is not None
    }
    return any(
        v == w and source != other and band != theirs
        for v, source, band in said
        for w, other, theirs in said
    )


def _chosen(scores: Sequence[CvssScore]) -> CvssScore | None:
    for versions in (RANKED_VERSIONS, (FALLBACK_VERSION,)):
        for source in PRECEDENCE:
            for version in versions:
                tier = [
                    s
                    for s in scores
                    if (s.source, s.version) == (source, version) and s.score is not None
                ]
                if tier:
                    return max(tier, key=lambda s: (s.score, s.vector))
    return None


def _v4(scores: Sequence[CvssScore]) -> CvssScore | None:
    for source in PRECEDENCE:
        if tier := [s for s in scores if (s.source, s.version) == (source, "4.0")]:
            return max(tier, key=lambda s: (s.score is not None, s.score or 0, s.vector))
    return None


def _rank(score: CvssScore) -> tuple[int, int]:
    order = (*RANKED_VERSIONS, "4.0")
    return PRECEDENCE.index(score.source), order.index(score.version)
