"""CVSS scores as each advisory source states them, read from its stored document."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from datetime import datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Literal, Self, TypeVar
from uuid import UUID

import pydantic
from cvss import CVSS3, CVSS4
from cvss.exceptions import CVSSError
from pydantic import Field, StrictBool, StrictFloat, StrictInt, StrictStr

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import Dto, Model
from traust_core.v1.models.values import canonical_decimal
from traust_core.v1.models.vocabulary import Severity


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
# The spec's 4.0 metric order, which the library doesn't check; it refuses every other malformation.
_V4_ORDER = (
    *("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA", "E", "CR", "IR", "AR"),
    *("MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"),
    *("S", "AU", "R", "V", "RE", "U"),
)
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


class CvssStatement(Model):
    """One source's statement as a view shows it: its score with FIRST's band beside it."""

    source: CvssSource
    version: CvssVersion
    vector: str
    score: Decimal | None
    band: Severity | None
    scored_by: str | None
    document: str
    acquired_at: datetime | None

    @classmethod
    def of(cls, stated: CvssScore) -> Self:
        band = severity_of(stated.vector) if stated.score is not None else None
        return cls(**stated.model_dump(), band=band)

    def stated(self) -> CvssScore:
        return CvssScore(**self.model_dump(exclude={"band"}))

    @pydantic.field_serializer("score", when_used="json")
    def _score(self, value: Decimal | None) -> str | None:
        return canonical_decimal(value)


class SelectedCvss(CvssStatement):
    """The statement a finding's score follows, chosen by precedence: never an unscored one."""

    score: Decimal
    band: Severity
    reason: Literal["precedence"] = "precedence"


class AdvisoryCvss(Model):
    """Every authority's scores for each linked advisory, ranked, from one day's kept documents,
    by canonical id and every id a finding names; `unreadable`: what scored nothing, and why."""

    scores: Mapping[UUID, tuple[CvssScore, ...]]
    unreadable: tuple[str, ...] = ()

    def to_bytes(self) -> bytes:
        # canonical: the same scores are the same bytes, so an unchanged day is one artifact
        body = self.model_dump(mode="json")
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    @classmethod
    def from_bytes(cls, raw: bytes) -> AdvisoryCvss:
        try:
            return cls.model_validate_json(raw)
        except pydantic.ValidationError as e:
            raise ValidationError(
                f"not an advisory CVSS build ({e.error_count()} problem(s))"
            ) from e


class EffectiveCvss(Model):
    """A finding's chosen score (3.x; 4.0 only when no source has 3.x), the highest-ranked 4.0
    beside it, and every source's."""

    chosen: CvssScore | None
    v4: CvssScore | None
    scores: tuple[CvssScore, ...]

    @property
    def score(self) -> Decimal | None:
        return self.chosen.score if self.chosen is not None else None

    @property
    def source(self) -> CvssSource | None:
        return self.chosen.source if self.chosen is not None else None


def cvss_base_score(vector: str) -> float | None:
    """A `CVSS:3.0/` or `CVSS:3.1/` vector's base score; None for any other, or one FIRST's
    formula refuses (`AdvisoryRecord.cvss_score` ranks 3.x vectors only)."""
    score = _v3_base_score(vector)
    return None if score is None else float(score)


def severity_of(vector: str | None) -> Severity | None:
    """A vector's qualitative rating — FIRST's bands, Red Hat's `cvss` — or None when the
    vector doesn't parse: never a guess at a malformed one. CVSS "None" reads informational."""
    if not isinstance(vector, str) or (version := _version(vector)) is None:
        return None
    # the spec's 4.0 metric order, the same refusal `score_of` applies — a vector the
    # scoring path rejects as malformed never supplies a computed label either
    if version == "4.0" and not _in_spec_order(vector, version):
        return None
    try:
        parsed = CVSS4(vector) if version == "4.0" else CVSS3(vector)
        label = parsed.severities()[0]
    except CVSSError:
        return None
    return Severity.INFORMATIONAL if label == "None" else Severity(label.lower())


def cvss_computed_score(vector: str) -> Decimal | None:
    """The base score FIRST's formula computes for a 3.x or 4.0 vector, or None when the
    vector doesn't parse — the number a stated score must agree with."""
    if (version := _version(vector)) is None:
        return None
    if version == "4.0":
        return _v4_base_score(vector) if _in_spec_order(vector, version) else None
    return _v3_base_score(vector)


def _v3_base_score(vector: str) -> Decimal | None:
    """FIRST's 3.0/3.1 formula, each version's own rounding (Red Hat's `cvss`)."""
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    try:
        return CVSS3(vector).base_score
    except CVSSError:
        return None


def _v4_base_score(vector: str) -> Decimal | None:
    """FIRST's 4.0 formula over the whole vector, as sources state it (Red Hat's `cvss`)."""
    try:
        return Decimal(str(CVSS4(vector).base_score))
    except CVSSError:
        return None


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
    """A score, or None when it can't be trusted: never a guess at a malformed one. The score
    is the one its vector computes (FIRST's formula), which a stated score must agree with."""
    if not isinstance(vector, str) or (detected := _version(vector)) is None:
        return None
    if version is not None and str(version) != detected:
        return None
    claimed = _bounded(stated)
    if not _in_spec_order(vector, detected) or (stated is not None and claimed is None):
        return None
    computed = _v4_base_score(vector) if detected == "4.0" else _v3_base_score(vector)
    if computed is None or (claimed is not None and claimed != computed):
        return None
    score = computed
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


class _CveListHeader(Dto):
    metadata: _CveListMetadata = Field(alias="cveMetadata")


class _CveListRecord(_CveListHeader):
    containers: _CveListContainers


def cve_list_scores(raw: bytes, *, acquired_at: datetime | None = None) -> tuple[CvssScore, ...]:
    """A CVE List record's (CVE JSON 5): the CNA's container, then each ADP's, by name. A
    record that isn't PUBLISHED states nothing."""
    # the state first: a reserved or rejected record's containers are never read
    if _parsed(_CveListHeader, raw, "a CVE List record").metadata.state is not (
        CveRecordState.PUBLISHED
    ):
        return ()
    record = _parsed(_CveListRecord, raw, "a CVE List record")
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


def _in_spec_order(vector: str, version: CvssVersion) -> bool:
    """4.0 requires the spec's metric order; 3.x allows any."""
    if version != "4.0":
        return True
    keys = [pair.split(":", 1)[0] for pair in vector.split("/")[1:]]
    if not set(keys) <= set(_V4_ORDER):
        return False
    positions = [_V4_ORDER.index(key) for key in keys]
    return positions == sorted(positions)


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


def record_ids(kind: str, raw: bytes) -> tuple[str, ...]:
    """The record ids a document names, `kind` being its scores' `document` prefix: each CVE an
    NVD response holds, else the one record's; checked against the id asked for."""
    if kind == "nvd":
        record = _parsed(_NvdRecord, raw, "an NVD API 2.0 CVE record")
        return tuple(v.cve.cve_id for v in record.vulnerabilities)
    if kind == "cve-list":
        return (_parsed(_CveListHeader, raw, "a CVE List record").metadata.cve_id,)
    if kind == "osv":
        return (_parsed(_OsvRecord, raw, "an OSV record").record_id,)
    if kind == "rh-cve":
        return (_parsed(_RhCveRecord, raw, "a Red Hat Security Data CVE record").cve_id,)
    raise ValidationError(f"{kind}: not a document kind with record ids")
