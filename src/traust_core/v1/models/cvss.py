"""CVSS scores as each advisory source states them, read from its stored document."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Any, Literal

from traust_core.v1.models.base import Model
from traust_core.v1.models.dependencies import cvss_base_score


class CvssSource(StrEnum):
    """Who stated a score, in ranking order."""

    NIST = "nist"
    GHSA = "ghsa"
    CNA = "cna"
    ADP = "adp"
    RED_HAT = "red-hat"
    SCANNER = "scanner"


CvssVersion = Literal["3.0", "3.1", "4.0"]

_VECTOR: dict[CvssVersion, re.Pattern[str]] = {
    "3.0": re.compile(r"CVSS:3\.0(/[A-Z]{1,3}:[A-Z])+"),
    "3.1": re.compile(r"CVSS:3\.1(/[A-Z]{1,3}:[A-Z])+"),
    "4.0": re.compile(r"CVSS:4\.0(/[A-Z]{1,3}:[A-Za-z]{1,5})+"),
}
_CIA, _MOD = ("H", "L", "N"), ("X", "H", "M", "L")
# FIRST's metric values: 3.0 and 3.1 share one table, 4.0 has its own. Base metrics are required.
_V3_BASE = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "R"),
    "S": ("U", "C"),
    "C": _CIA,
    "I": _CIA,
    "A": _CIA,
}
_V3_METRICS = {
    **_V3_BASE,
    "E": ("X", "H", "F", "P", "U"),
    "RL": ("X", "U", "W", "T", "O"),
    "RC": ("X", "C", "R", "U"),
    "CR": _MOD,
    "IR": _MOD,
    "AR": _MOD,
    "MAV": ("X", "N", "A", "L", "P"),
    "MAC": ("X", "L", "H"),
    "MPR": ("X", "N", "L", "H"),
    "MUI": ("X", "N", "R"),
    "MS": ("X", "U", "C"),
    "MC": ("X", *_CIA),
    "MI": ("X", *_CIA),
    "MA": ("X", *_CIA),
}
_V4_BASE = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "AT": ("N", "P"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "P", "A"),
    "VC": _CIA,
    "VI": _CIA,
    "VA": _CIA,
    "SC": _CIA,
    "SI": _CIA,
    "SA": _CIA,
}
_V4_METRICS = {
    **_V4_BASE,
    "E": ("X", "A", "P", "U"),
    "CR": _MOD,
    "IR": _MOD,
    "AR": _MOD,
    "MAV": ("X", "N", "A", "L", "P"),
    "MAC": ("X", "L", "H"),
    "MAT": ("X", "N", "P"),
    "MPR": ("X", "N", "L", "H"),
    "MUI": ("X", "N", "P", "A"),
    "MVC": ("X", *_CIA),
    "MVI": ("X", *_CIA),
    "MVA": ("X", *_CIA),
    "MSC": ("X", *_CIA),
    "MSI": ("X", "S", *_CIA),
    "MSA": ("X", "S", *_CIA),
    "S": ("X", "N", "P"),
    "AU": ("X", "N", "Y"),
    "R": ("X", "A", "U", "I"),
    "V": ("X", "D", "C"),
    "RE": ("X", "L", "M", "H"),
    "U": ("X", "Clear", "Green", "Amber", "Red"),
}
_DECIMAL = re.compile(r"\d{1,2}(\.\d{1,3})?")
_CVE_LIST = "https://github.com/CVEProject/cvelistV5/"
_NIST = "nvd@nist.gov"
_NVD_BLOCKS: tuple[tuple[str, CvssVersion], ...] = (
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV40", "4.0"),
)
_OSV_TYPES: dict[str, CvssVersion | None] = {"CVSS_V3": None, "CVSS_V4": "4.0"}


class CvssScore(Model):
    """One score as one source stated it; `score` is None only for a 4.0 vector stated alone."""

    source: CvssSource
    version: CvssVersion
    vector: str
    score: Decimal | None
    document: str
    scored_by: str | None = None
    acquired_at: datetime | None = None


class EffectiveCvss(Model):
    """A finding's chosen 3.x score, the highest-ranked 4.0 beside it, and every source's."""

    chosen: CvssScore | None
    v4: CvssScore | None
    scores: tuple[CvssScore, ...]

    @property
    def score(self) -> Decimal | None:
        return self.chosen.score if self.chosen is not None else None

    @property
    def source(self) -> CvssSource | None:
        return self.chosen.source if self.chosen is not None else None


def score_of(
    source: CvssSource,
    vector: object,
    *,
    document: str,
    version: object = None,
    stated: object = None,
    scored_by: str | None = None,
    acquired_at: datetime | None = None,
) -> CvssScore | None:
    """A stated score, or None when it can't be trusted: never a guess at a malformed one.
    A 3.x score is the one its vector computes, which a stated score must agree with."""
    if not isinstance(vector, str) or (detected := _version(vector)) is None:
        return None
    if version is not None and str(version) != detected:
        return None
    claimed = _bounded(stated)
    if not _well_formed(vector, detected) or (stated is not None and claimed is None):
        return None
    if detected == "4.0":
        score = claimed
    else:
        if (computed := cvss_base_score(vector)) is None:
            return None
        score = Decimal(str(computed))
        if claimed is not None and claimed != score:
            return None
    return CvssScore(
        source=source,
        version=detected,
        vector=vector,
        score=score,
        document=document,
        scored_by=scored_by,
        acquired_at=acquired_at,
    )


def nvd_scores(
    document: Mapping[str, Any], *, acquired_at: datetime | None = None
) -> tuple[CvssScore, ...]:
    """An NVD CVE record's: NIST's "Primary", the CNA's "Secondary" (from the record's own
    `sourceIdentifier`), and any other "Secondary" as an ADP's."""
    found = []
    for vuln in _list(document.get("vulnerabilities")):
        cve = _map(_map(vuln).get("cve"))
        if not isinstance(ident := cve.get("id"), str):
            continue
        metrics = _map(cve.get("metrics"))
        for block, version in _NVD_BLOCKS:
            for metric in map(_map, _list(metrics.get(block))):
                by, kind = metric.get("source"), metric.get("type")
                if kind == "Primary" and by == _NIST:
                    source = CvssSource.NIST
                elif kind == "Secondary" and isinstance(by, str) and by != _NIST:
                    source = CvssSource.CNA if by == cve.get("sourceIdentifier") else CvssSource.ADP
                else:
                    continue
                data = _map(metric.get("cvssData"))
                if str(data.get("version")) != version:
                    continue
                found.append(
                    score_of(
                        source,
                        data.get("vectorString"),
                        document=f"nvd:{ident}",
                        version=version,
                        stated=data.get("baseScore"),
                        scored_by=by,
                        acquired_at=acquired_at,
                    )
                )
    return distinct(found)


def osv_scores(
    document: Mapping[str, Any], *, acquired_at: datetime | None = None
) -> tuple[CvssScore, ...]:
    """An OSV record's: a GitHub-reviewed GHSA's, or a CVE List record's (the CNA's). Any
    other OSV record ranks nowhere."""
    ident, extra = document.get("id"), _map(document.get("database_specific"))
    if not isinstance(ident, str):
        return ()
    if ident.startswith("GHSA-") and extra.get("github_reviewed") is True:
        source, by = CvssSource.GHSA, "github"
    elif ident.startswith("CVE-") and str(extra.get("osv_generated_from", "")).startswith(
        _CVE_LIST
    ):
        source, by = CvssSource.CNA, extra.get("cna_assigner")
    else:
        return ()
    found = []
    for entry in map(_map, _list(document.get("severity"))):
        kind, vector = str(entry.get("type")), entry.get("score")
        if kind == "CVSS_V3" and not (isinstance(vector, str) and vector.startswith("CVSS:3.")):
            continue
        if kind in _OSV_TYPES:
            found.append(
                score_of(
                    source,
                    vector,
                    document=f"osv:{ident}",
                    version=_OSV_TYPES[kind],
                    scored_by=by if isinstance(by, str) else None,
                    acquired_at=acquired_at,
                )
            )
    return distinct(found)


def rh_cve_scores(
    document: Mapping[str, Any], *, acquired_at: datetime | None = None
) -> tuple[CvssScore, ...]:
    """A Red Hat Security Data API CVE record's CVSS 3 score."""
    cvss3 = _map(document.get("cvss3"))
    if not isinstance(ident := document.get("name"), str) or not cvss3:
        return ()
    score = score_of(
        CvssSource.RED_HAT,
        cvss3.get("cvss3_scoring_vector"),
        document=f"rh-cve:{ident}",
        stated=cvss3.get("cvss3_base_score"),
        scored_by="redhat",
        acquired_at=acquired_at,
    )
    return distinct([score])


def csaf_scores(
    document: Mapping[str, Any], cve: str, *, acquired_at: datetime | None = None
) -> tuple[CvssScore, ...]:
    """A Red Hat CSAF VEX document's distinct CVSS 3 scores for `cve`, across its product sets."""
    tracking = _map(_map(document.get("document")).get("tracking")).get("id")
    name = tracking if isinstance(tracking, str) else cve
    found = []
    for vuln in map(_map, _list(document.get("vulnerabilities"))):
        if str(vuln.get("cve", "")).upper() != cve.upper():
            continue
        for entry in map(_map, _list(vuln.get("scores"))):
            data = _map(entry.get("cvss_v3"))
            if data:
                found.append(
                    score_of(
                        CvssSource.RED_HAT,
                        data.get("vectorString"),
                        document=f"csaf:{name}",
                        version=data.get("version"),
                        stated=data.get("baseScore"),
                        scored_by="redhat",
                        acquired_at=acquired_at,
                    )
                )
    return distinct(found)


def scanner_score(vector: str | None, *, document: str) -> CvssScore | None:
    """The vector a scanner reported on an occurrence, as reported."""
    return score_of(CvssSource.SCANNER, vector, document=document) if vector else None


def _version(vector: str) -> CvssVersion | None:
    return next((v for v, pattern in _VECTOR.items() if pattern.fullmatch(vector)), None)


def _well_formed(vector: str, version: CvssVersion) -> bool:
    metrics, base = (_V4_METRICS, _V4_BASE) if version == "4.0" else (_V3_METRICS, _V3_BASE)
    pairs = [pair.split(":", 1) for pair in vector.split("/")[1:]]
    keys = [key for key, _ in pairs]
    return (
        len(keys) == len(set(keys))
        and set(base) <= set(keys)
        and all(value in metrics.get(key, ()) for key, value in pairs)
    )


def _bounded(value: object) -> Decimal | None:
    """A plain decimal score in 0-10: never a bool, an exponent, padding or digit separators."""
    if isinstance(value, bool) or not isinstance(value, int | float | str | Decimal):
        return None
    text = str(value)
    if not _DECIMAL.fullmatch(text):
        return None
    try:
        number = Decimal(text)
    except InvalidOperation:
        return None
    return number if 0 <= number <= 10 else None


def distinct(scores: Iterable[CvssScore | None]) -> tuple[CvssScore, ...]:
    """The trusted scores, each document's (source, version, vector) once, a scored entry kept
    over an unscored one; every document's statement survives."""
    seen: dict[tuple[CvssSource, str, str, str], CvssScore] = {}
    for score in scores:
        if score is None:
            continue
        key = (score.source, score.version, score.vector, score.document)
        if key not in seen or (seen[key].score is None and score.score is not None):
            seen[key] = score
    return tuple(seen.values())


def _map(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []
