"""CVSS scores as each advisory source states them, read from its stored document."""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Literal, TypeVar

import pydantic
from pydantic import Field, StrictBool, StrictFloat, StrictInt, StrictStr

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import Dto, Model
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
_NIST = "nvd@nist.gov"
_NVD_BLOCKS: tuple[tuple[str, CvssVersion], ...] = (("v31", "3.1"), ("v30", "3.0"), ("v40", "4.0"))
_OSV_TYPES: dict[str, CvssVersion | None] = {"CVSS_V3": None, "CVSS_V4": "4.0"}
_Stated = StrictFloat | StrictInt | StrictStr | None
_D = TypeVar("_D", bound=Dto)


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


class _NvdCvssData(Dto):
    version: StrictStr
    vector: StrictStr = Field(alias="vectorString")
    stated: _Stated = Field(None, alias="baseScore")


class _NvdMetric(Dto):
    source: StrictStr | None = None
    type: StrictStr | None = None
    data: _NvdCvssData = Field(alias="cvssData")


class _NvdMetrics(Dto):
    """The CVSS blocks only; NVD's other metrics (SSVC, CVSS 2) are not read."""

    v31: tuple[_NvdMetric, ...] = Field((), alias="cvssMetricV31")
    v30: tuple[_NvdMetric, ...] = Field((), alias="cvssMetricV30")
    v40: tuple[_NvdMetric, ...] = Field((), alias="cvssMetricV40")


class _NvdCve(Dto):
    cve_id: StrictStr = Field(alias="id")
    cna: StrictStr | None = Field(None, alias="sourceIdentifier")
    metrics: _NvdMetrics = Field(default_factory=_NvdMetrics)


class _NvdVulnerability(Dto):
    cve: _NvdCve


class _NvdRecord(Dto):
    vulnerabilities: tuple[_NvdVulnerability, ...]


class _OsvSeverity(Dto):
    type: StrictStr
    score: StrictStr


class _OsvDatabase(Dto):
    github_reviewed: StrictBool | None = None


class _OsvRecord(Dto):
    record_id: StrictStr = Field(alias="id")
    severity: tuple[_OsvSeverity, ...] = ()
    database: _OsvDatabase = Field(default_factory=_OsvDatabase, alias="database_specific")


class _RhCvss3(Dto):
    stated: _Stated = Field(None, alias="cvss3_base_score")
    vector: StrictStr = Field(alias="cvss3_scoring_vector")


class _RhCveRecord(Dto):
    cve_id: StrictStr = Field(alias="name")
    cvss3: _RhCvss3 | None = None


class _CsafCvssV3(Dto):
    version: StrictStr
    vector: StrictStr = Field(alias="vectorString")
    stated: _Stated = Field(None, alias="baseScore")


class _CsafScore(Dto):
    cvss_v3: _CsafCvssV3 | None = None


class _CsafVulnerability(Dto):
    cve_id: StrictStr | None = Field(None, alias="cve")
    scores: tuple[_CsafScore, ...] = ()


class _CsafTracking(Dto):
    tracking_id: StrictStr | None = Field(None, alias="id")


class _CsafMeta(Dto):
    tracking: _CsafTracking = Field(default_factory=_CsafTracking)


class _CsafDocument(Dto):
    meta: _CsafMeta = Field(default_factory=_CsafMeta, alias="document")
    vulnerabilities: tuple[_CsafVulnerability, ...] = ()


def _parsed(shape: type[_D], raw: bytes, kind: str) -> _D:
    try:
        return shape.model_validate_json(raw)
    except pydantic.ValidationError as e:
        raise ValidationError(f"not {kind} ({e.error_count()} problem(s))") from e


class _CveListCvss(Dto):
    version: StrictStr
    vector: StrictStr = Field(alias="vectorString")
    stated: _Stated = Field(None, alias="baseScore")


class _CveListMetric(Dto):
    v31: _CveListCvss | None = Field(None, alias="cvssV3_1")
    v30: _CveListCvss | None = Field(None, alias="cvssV3_0")
    v40: _CveListCvss | None = Field(None, alias="cvssV4_0")


class _CveListProvider(Dto):
    org_id: StrictStr = Field(alias="orgId")
    short_name: StrictStr | None = Field(None, alias="shortName")


class _CveListContainer(Dto):
    provider: _CveListProvider = Field(alias="providerMetadata")
    metrics: tuple[_CveListMetric, ...] = ()


class _CveListContainers(Dto):
    cna: _CveListContainer
    adp: tuple[_CveListContainer, ...] = ()


class CveRecordState(StrEnum):
    """A CVE List record's lifecycle state (CVE JSON 5 `cveMetadata.state`)."""

    PUBLISHED = "PUBLISHED"
    REJECTED = "REJECTED"
    RESERVED = "RESERVED"


class _CveListMetadata(Dto):
    cve_id: StrictStr = Field(alias="cveId")
    state: CveRecordState


class _CveListRecord(Dto):
    metadata: _CveListMetadata = Field(alias="cveMetadata")
    containers: _CveListContainers | None = None

    @pydantic.model_validator(mode="after")
    def _published_records_carry_containers(self) -> _CveListRecord:
        # cve.org serves a RESERVED id without containers; a PUBLISHED one always has them
        if self.metadata.state is CveRecordState.PUBLISHED and self.containers is None:
            raise ValueError("a PUBLISHED CVE record carries its containers")
        return self


def cve_list_scores(raw: bytes, *, acquired_at: datetime | None = None) -> tuple[CvssScore, ...]:
    """A CVE List record's (CVE JSON 5): the CNA's container, then each ADP's, by name. A
    record that isn't PUBLISHED states nothing."""
    record = _parsed(_CveListRecord, raw, "a CVE List record")
    if record.metadata.state is not CveRecordState.PUBLISHED or record.containers is None:
        return ()
    containers = record.containers
    tagged = [(CvssSource.CNA, containers.cna), *((CvssSource.ADP, adp) for adp in containers.adp)]
    found = [
        score_of(
            source,
            cvss.vector,
            document=f"cve-list:{record.metadata.cve_id}",
            version=version,
            stated=cvss.stated,
            scored_by=container.provider.short_name or container.provider.org_id,
            acquired_at=acquired_at,
        )
        for source, container in tagged
        for metric in container.metrics
        for block, version in _NVD_BLOCKS
        if (cvss := getattr(metric, block)) is not None and cvss.version == version
    ]
    return distinct(found)


def nvd_scores(raw: bytes, *, acquired_at: datetime | None = None) -> tuple[CvssScore, ...]:
    """An NVD CVE record's: NIST's "Primary", the CNA's "Secondary" (from the record's own
    `sourceIdentifier`), and any other "Secondary" as an ADP's."""
    record = _parsed(_NvdRecord, raw, "an NVD API 2.0 CVE record")
    found = []
    for vulnerability in record.vulnerabilities:
        cve = vulnerability.cve
        for block, version in _NVD_BLOCKS:
            for metric in getattr(cve.metrics, block):
                if metric.type == "Primary" and metric.source == _NIST:
                    source = CvssSource.NIST
                elif metric.type == "Secondary" and metric.source not in (None, _NIST):
                    source = CvssSource.CNA if metric.source == cve.cna else CvssSource.ADP
                else:
                    continue
                if metric.data.version != version:
                    continue
                found.append(
                    score_of(
                        source,
                        metric.data.vector,
                        document=f"nvd:{cve.cve_id}",
                        version=version,
                        stated=metric.data.stated,
                        scored_by=metric.source,
                        acquired_at=acquired_at,
                    )
                )
    return distinct(found)


def osv_scores(raw: bytes, *, acquired_at: datetime | None = None) -> tuple[CvssScore, ...]:
    """A GitHub-reviewed GHSA record's. Any other OSV record ranks nowhere: the CNA's scores
    come from the CVE List record itself (`cve_list_scores`), never OSV's lossy copy of it."""
    record = _parsed(_OsvRecord, raw, "an OSV record")
    if not (record.record_id.startswith("GHSA-") and record.database.github_reviewed is True):
        return ()
    source, by = CvssSource.GHSA, "github"
    found = [
        score_of(
            source,
            entry.score,
            document=f"osv:{record.record_id}",
            version=_OSV_TYPES[entry.type],
            scored_by=by,
            acquired_at=acquired_at,
        )
        for entry in record.severity
        if entry.type in _OSV_TYPES
        and (entry.type != "CVSS_V3" or entry.score.startswith("CVSS:3."))
    ]
    return distinct(found)


def rh_cve_scores(raw: bytes, *, acquired_at: datetime | None = None) -> tuple[CvssScore, ...]:
    """A Red Hat Security Data API CVE record's CVSS 3 score."""
    record = _parsed(_RhCveRecord, raw, "a Red Hat Security Data CVE record")
    if record.cvss3 is None:
        return ()
    score = score_of(
        CvssSource.RED_HAT,
        record.cvss3.vector,
        document=f"rh-cve:{record.cve_id}",
        stated=record.cvss3.stated,
        scored_by="redhat",
        acquired_at=acquired_at,
    )
    return distinct([score])


def csaf_scores(
    raw: bytes, cve_id: str, *, acquired_at: datetime | None = None
) -> tuple[CvssScore, ...]:
    """A Red Hat CSAF VEX document's distinct CVSS 3 scores for `cve_id`, across product sets."""
    document = _parsed(_CsafDocument, raw, "a CSAF VEX document")
    name = document.meta.tracking.tracking_id or cve_id
    found = [
        score_of(
            CvssSource.RED_HAT,
            entry.cvss_v3.vector,
            document=f"csaf:{name}",
            version=entry.cvss_v3.version,
            stated=entry.cvss_v3.stated,
            scored_by="redhat",
            acquired_at=acquired_at,
        )
        for vulnerability in document.vulnerabilities
        if (vulnerability.cve_id or "").upper() == cve_id.upper()
        for entry in vulnerability.scores
        if entry.cvss_v3 is not None
    ]
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
    if version == "4.0":  # 4.0 requires the spec's order; 3.x allows any
        order = list(metrics)
        positions = [order.index(key) if key in metrics else -1 for key in keys]
        if positions != sorted(positions):
            return False
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
    """The trusted scores, each exact statement once: two authorities, or two scores for one
    vector, are both kept."""
    seen: dict[tuple[object, ...], CvssScore] = {}
    for score in scores:
        if score is not None:
            key = (score.source, score.version, score.vector, score.document, score.scored_by)
            seen.setdefault((*key, score.score), score)
    return tuple(seen.values())
