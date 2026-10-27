"""How an OWASP risk rating is written in a threat model's Markdown and read back from it.

Section 4 of a rated model carries `severity | likelihood | impact` cells (`medium 4.375`,
`high 7.25 technical`); a threat not yet re-rated keeps its legacy labels as `legacy <label>`
under severity `unrated`. Section 11 lists every factor score. Legacy labels map onto OWASP
levels for ordering only, never written back as a rating (`legacy-crosswalk`). The arithmetic is
the contracts' `risk_rating`.
"""

from __future__ import annotations

import re
from typing import Any

from traust_core.v1.contracts import risk_rating as rr
from traust_core.v1.services.findings.rating import THREAT_IMPACT_LEVEL, THREAT_LIKELIHOOD_LEVEL

SEVERITY_ORDER = tuple(reversed(rr.SEVERITIES))
UNRATED = "unrated"

LEGACY_IMPACT = ("low", "medium", "high", "critical", "existential")
LEGACY_LIKELIHOOD = ("very_rare", "rare", "possible", "likely", "almost_certain")
_SCORE = r"(\d(?:\.\d{1,3})?)"
LIKELIHOOD_CELL = re.compile(rf"^(low|medium|high) {_SCORE}$")
IMPACT_CELL = re.compile(rf"^(low|medium|high) {_SCORE} (technical|business)$")
LEGACY_CELL = re.compile(r"^legacy (\S+)$")

FACTOR_COLUMNS = ["factor", "score", "reason"]
RATING_HEADING = re.compile(r"^### (T\d+)\b")
ALL_FACTORS = (*rr.LIKELIHOOD_FACTORS, *rr.TECHNICAL_IMPACT_FACTORS, *rr.BUSINESS_IMPACT_FACTORS)


def format_score(score: float) -> str:
    return f"{score:.3f}".rstrip("0").rstrip(".")


def likelihood_cell(rating: dict[str, Any]) -> str:
    likelihood = rating["likelihood"]
    return f"{likelihood['level']} {format_score(likelihood['score'])}"


def impact_cell(rating: dict[str, Any]) -> str:
    impact = rating["impact"]
    return f"{impact['level']} {format_score(impact['score'])} {impact['basis']}"


def threat_cells(threat: dict[str, Any]) -> dict[str, str]:
    """The severity, likelihood and impact cells for one JSON threat."""
    rating = threat.get("risk_rating")
    if rating:
        return {
            "severity": rating["severity"],
            "likelihood": likelihood_cell(rating),
            "impact": impact_cell(rating),
        }
    return {
        "severity": UNRATED,
        "likelihood": f"legacy {threat.get('likelihood', '')}".strip(),
        "impact": f"legacy {threat.get('impact', '')}".strip(),
    }


def legacy_severity(impact: str | None, likelihood: str | None) -> str | None:
    i_level = THREAT_IMPACT_LEVEL.get(impact or "")
    l_level = THREAT_LIKELIHOOD_LEVEL.get(likelihood or "")
    if i_level is None or l_level is None:
        return None
    return rr.severity(i_level, l_level)


def cell_problems(severity: str, likelihood: str, impact: str) -> list[str]:
    """Every way a rated row's three cells disagree: each level must be its score's, and the
    severity the table's for the two levels."""
    if severity == UNRATED:
        found = []
        lm, im = LEGACY_CELL.match(likelihood), LEGACY_CELL.match(impact)
        if not lm or lm.group(1) not in LEGACY_LIKELIHOOD:
            found.append(
                f"likelihood '{likelihood}' must be 'legacy <label>' with a label "
                f"in {list(LEGACY_LIKELIHOOD)} when severity is '{UNRATED}'"
            )
        if not im or im.group(1) not in LEGACY_IMPACT:
            found.append(
                f"impact '{impact}' must be 'legacy <label>' with a label "
                f"in {list(LEGACY_IMPACT)} when severity is '{UNRATED}'"
            )
        return found
    if severity not in rr.SEVERITIES:
        return [f"severity '{severity}' not in {[*SEVERITY_ORDER, UNRATED]}"]
    lm, im = LIKELIHOOD_CELL.match(likelihood), IMPACT_CELL.match(impact)
    found = []
    if not lm:
        found.append(f"likelihood '{likelihood}' must be '<low|medium|high> <score 0-9>'")
    if not im:
        found.append(
            f"impact '{impact}' must be '<low|medium|high> <score 0-9> <technical|business>'"
        )
    if found or lm is None or im is None:
        return found
    for name, match in (("likelihood", lm), ("impact", im)):
        want = rr.level(float(match.group(2)))
        if match.group(1) != want:
            found.append(
                f"{name} level '{match.group(1)}' should be '{want}' for score {match.group(2)}"
            )
    if not found:
        want = rr.severity(im.group(1), lm.group(1))
        if severity != want:
            found.append(
                f"severity '{severity}' should be '{want}' for impact "
                f"{im.group(1)} and likelihood {lm.group(1)}"
            )
    return found


def parse_row(row: dict[str, str]) -> dict[str, Any]:
    """Rating fields from one section 4 row of either table variant: severity and its source
    (`owasp`, `legacy-crosswalk` or None), the levels or legacy labels, and for rated rows the
    scores and impact basis."""
    if "severity" not in row:
        impact, likelihood = row.get("impact", ""), row.get("likelihood", "")
        severity = legacy_severity(impact, likelihood)
        return {
            "severity": severity,
            "severity_source": "legacy-crosswalk" if severity else None,
            "likelihood": likelihood,
            "impact": impact,
        }
    if row["severity"] == UNRATED:
        lm = LEGACY_CELL.match(row.get("likelihood", ""))
        im = LEGACY_CELL.match(row.get("impact", ""))
        likelihood = lm.group(1) if lm else ""
        impact = im.group(1) if im else ""
        severity = legacy_severity(impact, likelihood)
        return {
            "severity": severity,
            "severity_source": "legacy-crosswalk" if severity else None,
            "likelihood": likelihood,
            "impact": impact,
        }
    lm = LIKELIHOOD_CELL.match(row.get("likelihood", ""))
    im = IMPACT_CELL.match(row.get("impact", ""))
    if not lm or not im or row["severity"] not in rr.SEVERITIES:
        return {
            "severity": None,
            "severity_source": None,
            "likelihood": row.get("likelihood", ""),
            "impact": row.get("impact", ""),
        }
    return {
        "severity": row["severity"],
        "severity_source": "owasp",
        "likelihood": lm.group(1),
        "impact": im.group(1),
        "likelihood_score": float(lm.group(2)),
        "impact_score": float(im.group(2)),
        "impact_basis": im.group(3),
    }


def order_key(parsed: dict[str, Any]) -> tuple[int, int, float, float]:
    """Most severe first: severity, rated before crosswalked, then impact and likelihood scores."""
    return (
        -rr.severity_rank(parsed.get("severity")),
        0 if parsed.get("severity_source") == "owasp" else 1,
        -(parsed.get("impact_score") or 0.0),
        -(parsed.get("likelihood_score") or 0.0),
    )


def factor_rows(rating: dict[str, Any]) -> list[dict[str, str]]:
    """Section 11 table rows for one rating, in method order."""
    reasons = rating.get("rationale") or {}
    scores = dict(rating["likelihood"]["factors"])
    scores.update(rating["impact"]["technical"])
    scores.update(rating["impact"].get("business") or {})
    return [
        {"factor": name, "score": str(scores[name]), "reason": reasons.get(name, "")}
        for name in ALL_FACTORS
        if name in scores
    ]


def rating_from_factors(
    scores: dict[str, int], basis: str
) -> tuple[dict[str, Any] | None, list[str]]:
    """A rating recomputed from section 11 factor scores, and what stops it."""
    found = []
    missing = [n for n in (*rr.LIKELIHOOD_FACTORS, *rr.TECHNICAL_IMPACT_FACTORS) if n not in scores]
    if basis == "business":
        missing += [n for n in rr.BUSINESS_IMPACT_FACTORS if n not in scores]
    if missing:
        found.append(f"missing factor(s) {missing}")
    business_given = [n for n in rr.BUSINESS_IMPACT_FACTORS if n in scores]
    if business_given and len(business_given) != len(rr.BUSINESS_IMPACT_FACTORS):
        found.append(f"business factors must be all present or all absent, got {business_given}")
    if found:
        return None, found
    business = {n: scores[n] for n in rr.BUSINESS_IMPACT_FACTORS} if business_given else None
    try:
        rating = rr.rate(
            {n: scores[n] for n in rr.LIKELIHOOD_FACTORS},
            {n: scores[n] for n in rr.TECHNICAL_IMPACT_FACTORS},
            business,
            basis=basis,
        )
    except ValueError as exc:
        return None, [str(exc)]
    return rating, []
