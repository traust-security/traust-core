from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal, NewType, Self
from uuid import UUID

import pydantic

from traust_core.v1.errors import ConflictError, ForbiddenError, ValidationError
from traust_core.v1.models import candidate_formats
from traust_core.v1.models.base import AppendOnly, Entity, Model
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.integrity import canonical_json, sha256_hex
from traust_core.v1.models.vocabulary import (
    ActorKind,
    AliasMatchedBy,
    DispositionAssurance,
    DispositionResolution,
    EvidenceGrade,
    FindingOrigin,
    OwaspImpactBasis,
    RestatementReason,
    ReviewReason,
    RiskRatingBand,
    ScannerSeverity,
    Severity,
    SourceType,
    Validity,
)

if TYPE_CHECKING:
    from traust_core.v1.models.assessment import Assessment

Label = NewType("Label", str)
RiskLevel = Literal["low", "medium", "high"]
CweId = NewType("CweId", str)
Category = NewType("Category", str)
Confidence = NewType("Confidence", float)
Rationale = NewType("Rationale", str)
StatementKey = NewType("StatementKey", str)
EvidenceRef = NewType("EvidenceRef", str)


class CandidateFormat(StrEnum):
    SARIF = "sarif"
    DEPENDABOT = "dependabot"
    GOVULNCHECK = "govulncheck"


class FindingDimension(StrEnum):
    SEVERITY = "severity"
    CWE = "cwe"
    CATEGORY = "category"
    LABEL = "label"
    ORIGIN = "origin"
    VALIDITY = "validity"
    RESOLUTION = "resolution"
    REPOSITORY = "repository"


# Shapes land with their implementation slice.
class WeaknessLabels(Model):
    """What a finding's CWEs map to in each public taxonomy (ATT&CK, ASVS, ...), by taxonomy."""

    cwes: tuple[CweId, ...]
    labels: Mapping[str, tuple[str, ...]] = {}


class PrecedentStrength(StrEnum):
    """What a precedent may save: a person's verdict earns fewer votes; a machine's annotates."""

    HUMAN = "human_countersigned"
    MACHINE = "machine_refuted_sound"


class PrecedentReason(Model):
    """Why a prior verdict applies: the same function in the same (vendor-normalized) file."""

    strength: PrecedentStrength
    path: str
    symbol: str


class IdentityMove(Model):
    """A recorded finding a re-audit reports under another identity: it keeps its id and takes
    the candidate's fingerprint once a person attests the mapping."""

    finding_id: UUID
    label: Label
    fingerprint_algo: str
    fingerprint: str
    matched_by: AliasMatchedBy
    similarity: float | None = None
    path_overlap: float | None = None


class IntakeResult(Model):
    """Each candidate's finding by its report label, and the findings this intake created."""

    findings: Mapping[Label, UUID]
    created: tuple[UUID, ...] = ()


class AssessedJudgment(Model):
    """An assessor's own statement on a finding it reported (an audit's disposition)."""

    validity: Validity
    rationale: str | None = None
    severity: Severity | None = None
    review: ReviewReason | None = None  # also ask a person, as for an undetermined verdict


class RecordDecision(Model):
    """A person's direct statement on a finding (a countersign, a re-rating): what they judged."""

    finding_id: UUID
    rationale: str
    validity: Validity | None = None
    resolution: DispositionResolution | None = None
    evidence_grade: EvidenceGrade | None = None
    severity: Severity | None = None
    reason: str | None = None
    source_channel: SourceType | None = None
    repository_ref_id: UUID | None = None
    fixed_repository_ref_id: UUID | None = None
    artifact_id: UUID | None = None
    occurred_at: datetime | None = None


# NEED(assessment-kind): contracts names the assessment kinds; validation and verification are
# the ones evidence precedence reads (every other kind is static, as triage reports were).
_REPORT = {
    "validation": SourceType.VALIDATION_REPORT,
    "verification": SourceType.VERIFICATION_REPORT,
}


def report_sources(assessments: Iterable[Assessment]) -> dict[UUID, SourceType]:
    """Each assessor's report kind, which tells execution proof from static review."""
    return {a.id: _REPORT[a.kind] for a in assessments if a.id and a.kind in _REPORT}


class ReviewCaseKind(StrEnum):
    """Why a person must look, worst first: the fold's states, then a pending review item."""

    AWAITING_SIGNOFF = "awaiting_signoff"
    FP_OVERRIDDEN = "fp_overridden"
    FP_REASSERTION_BLOCKED = "fp_reassertion_blocked"
    CONFLICT = "conflict"
    NEEDS_REVIEW = "needs_review"


class ReviewFilter(Model):
    repository_id: UUID | None = None
    kind: ReviewCaseKind | None = None


class FindingState(StrEnum):
    """Where a finding stands: open exposure, hardening debt, or closed one of three ways."""

    OPEN = "open"
    HARDENING = "hardening"
    ACCEPTED = "accepted"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class FindingFilter(Model):
    """A repository's findings; `validity` and `open` narrow by the folded disposition."""

    repository_id: UUID
    validity: Validity | None = None
    open: bool | None = None
    as_of: datetime | None = None

    def keeps(self, view: FindingView) -> bool:
        validity = view.disposition.validity if view.disposition else None
        return (self.validity is None or validity == self.validity) and (
            self.open is None or view.is_open() == self.open
        )


class FindingRollup(Model):
    """The findings in one group by state; key is None for findings without that dimension."""

    key: str | None = None
    findings: int
    open: int
    hardening: int
    accepted: int
    resolved: int
    false_positives: int
    open_by_severity: Mapping[Severity, int]


LIKELIHOOD_FACTORS = (
    "skill_level",
    "motive",
    "opportunity",
    "population_size",
    "ease_of_discovery",
    "ease_of_exploit",
    "awareness",
    "intrusion_detection",
)
TECHNICAL_IMPACT_FACTORS = ("confidentiality", "integrity", "availability", "accountability")
BUSINESS_IMPACT_FACTORS = ("financial", "reputation", "non_compliance", "privacy")
OWASP_METHOD = "owasp-risk-rating"


class OwaspFactors(Model):
    """A person's OWASP Risk Rating factor scores (0-9); everything derived from them is
    arithmetic. The impact basis is business when business factors are given."""

    likelihood: Mapping[str, pydantic.StrictInt]
    technical: Mapping[str, pydantic.StrictInt]
    business: Mapping[str, pydantic.StrictInt] | None = None
    basis: OwaspImpactBasis | None = None

    @classmethod
    def of_stated(cls, rating: Mapping[str, Any]) -> OwaspFactors:
        """The factors a contracts `owasp_risk_rating` states; its derived values are ignored."""
        impact = rating.get("impact") or {}
        return cls(
            likelihood=(rating.get("likelihood") or {}).get("factors") or {},
            technical=impact.get("technical") or {},
            business=impact.get("business"),
            basis=impact.get("basis"),
        )

    @pydantic.model_validator(mode="after")
    def _complete(self) -> Self:
        sets = [("likelihood", self.likelihood, LIKELIHOOD_FACTORS)]
        sets.append(("impact.technical", self.technical, TECHNICAL_IMPACT_FACTORS))
        if self.business is not None:
            sets.append(("impact.business", self.business, BUSINESS_IMPACT_FACTORS))
        found = []
        for where, factors, names in sets:
            missing = [n for n in names if n not in factors]
            extra = sorted(set(factors) - set(names))
            if missing or extra:
                found.append(f"{where}: missing factors {missing}, unknown factors {extra}")
            found += [
                f"{where}.{n}: must be an integer from 0 to 9, got {v!r}"
                for n, v in factors.items()
                if not 0 <= v <= 9
            ]
        if self.basis == "business" and self.business is None:
            found.append("impact.basis 'business' needs its factor set")
        if found:
            raise ValueError("; ".join(found))
        return self

    def impact_basis(self) -> OwaspImpactBasis:
        return self.basis or OwaspImpactBasis("business" if self.business else "technical")


class RatingInputs(Model):
    """What a finding is rated from: factor scores a person gave, else its CVSS v3 vector and
    exploitation evidence (KEV, EPSS), else its severity."""

    severity: Severity | None = None  # needed unless factors are given
    cvss_vector: str | None = None
    kev: bool = False
    epss: float | None = pydantic.Field(default=None, ge=0, le=1)
    factors: OwaspFactors | None = None

    @pydantic.model_validator(mode="after")
    def _rateable(self) -> Self:
        if self.severity is None and self.factors is None:
            raise ValueError("a rating needs factor scores or a severity")
        return self


class RiskRating(Model):
    """An OWASP Risk Rating: likelihood and impact scores (0-9), their levels and the band."""

    likelihood: float
    likelihood_level: RiskLevel
    impact: float
    impact_level: RiskLevel
    impact_basis: OwaspImpactBasis | None = None
    band: RiskRatingBand

    def stated(self, factors: OwaspFactors, rationale: Mapping[str, str] | None) -> dict[str, Any]:
        """The contracts `owasp_risk_rating` a document holds for these factors and this rating."""
        impact: dict[str, Any] = {
            "basis": str(factors.impact_basis()),
            "technical": dict(factors.technical),
            "score": self.impact,
            "level": self.impact_level,
        }
        if factors.business is not None:
            impact["business"] = dict(factors.business)
        likelihood = {
            "factors": dict(factors.likelihood),
            "score": self.likelihood,
            "level": self.likelihood_level,
        }
        rating = {
            "method": OWASP_METHOD,
            "likelihood": likelihood,
            "impact": impact,
            "severity": str(self.band),
        }
        return rating | ({"rationale": dict(rationale)} if rationale else {})


class ExposureKey(Model):
    """A finding a known advisory reaches is identified by (repository, advisory, package)."""

    advisory_id: UUID
    advisory: str
    ecosystem: str
    package: str


class FindingCandidate(Model):
    """A reported finding before intake; a scanner that gives no severity reports `unrated`."""

    label: Label
    repository_id: UUID
    title: str
    description: str = ""
    rule: str | None = None
    cwes: tuple[CweId, ...] = ()
    category: Category | None = None
    locations: tuple[CodeSpan, ...] = ()
    reported_severity: ScannerSeverity | None = None
    confidence: Confidence | None = None
    origin: FindingOrigin | None = None
    exposure: ExposureKey | None = None
    # A policy check: identity is `rule` on `resources` (every resource the check names, located
    # or not), on the locations' paths only when it names none.
    policy: bool = False
    resources: tuple[str, ...] = ()

    @classmethod
    def parse_many(
        cls, raw: bytes, format: CandidateFormat, repository_id: UUID, origin: FindingOrigin
    ) -> list[FindingCandidate]:
        """Third-party scanner output as candidates; labels are made unique within the document."""
        parse = {
            CandidateFormat.SARIF: candidate_formats.sarif,
            CandidateFormat.DEPENDABOT: candidate_formats.dependabot,
            CandidateFormat.GOVULNCHECK: candidate_formats.govulncheck,
        }[format]
        seen: dict[str, int] = {}
        out = []
        for i, f in enumerate(parse(raw)):
            base = str(f["label"] or f"{format.value}-{i + 1}")
            seen[base] = seen.get(base, 0) + 1
            out.append(
                cls(
                    label=Label(base if seen[base] == 1 else f"{base}#{seen[base]}"),
                    repository_id=repository_id,
                    title=f["title"],
                    description=f["description"],
                    rule=f["rule"],
                    category=Category(f["category"]) if f["category"] else None,
                    cwes=tuple(CweId(c) for c in f["cwes"]),
                    locations=(CodeSpan(path=f["path"], line=f["line"], symbol=f["symbol"]),)
                    if f["path"]
                    else (),
                    reported_severity=ScannerSeverity(f["severity"] or ScannerSeverity.UNRATED),
                    confidence=Confidence(f["confidence"]) if f["confidence"] is not None else None,
                    origin=origin,
                )
            )
        return out

    @classmethod
    def of_report(
        cls, entries: Iterable[Any], repository_id: UUID, origin: FindingOrigin | None = None
    ) -> list[FindingCandidate]:
        """The findings a contracts report states (`findings[]`, a verification's `regressions[]`),
        rated as the report rates them; a location keeps its first line."""
        return [
            cls(
                label=Label(e.id),
                repository_id=repository_id,
                title=e.title,
                description=e.description,
                cwes=tuple(CweId(c) for c in e.cwes),
                category=Category(e.category) if e.category else None,
                locations=tuple(
                    CodeSpan(
                        path=RepoPath(loc.path),
                        line=int(m.group()) if (m := _FIRST_LINE.search(loc.lines or "")) else None,
                    )
                    for loc in e.locations
                ),
                reported_severity=ScannerSeverity(e.severity),
                origin=origin,
            )
            for e in entries
        ]

    @classmethod
    def of_scan(
        cls, entries: Iterable[Any], repository_id: UUID, origin: FindingOrigin | None = None
    ) -> list[FindingCandidate]:
        """The unverified findings a vuln-scan states (vuln-findings `findings[]`), rated as the
        scan rates them; `known_findings` are the baseline's and stay out."""
        return [
            cls(
                label=Label(e.id),
                repository_id=repository_id,
                title=e.title,
                description=e.description,
                cwes=(CweId(e.cwe),) if e.cwe else (),
                category=Category(e.category),
                locations=(CodeSpan(path=RepoPath(e.file), line=e.line),),
                reported_severity=ScannerSeverity(e.severity),
                confidence=Confidence(e.confidence),
                origin=origin,
            )
            for e in entries
        ]


_FIRST_LINE = re.compile(r"\d+")


class Finding(Entity):
    """3b · one weakness or vulnerability in a repository, identified by fingerprint."""

    repository_id: UUID
    advisory_id: UUID | None = None
    advisory_match: str | None = None
    fingerprint_algo: str
    fingerprint: str
    kind: str | None = None
    title: str


# A report's claims can't change after the fact: occurrence and location rows are append-only and
# the report's artifact pins its bytes by digest. This replaced the claim hashes track-findings
# pinned on audit JSON (baseline_claims.py). Not covered: finding.title and finding_cwe are mutable.
class Occurrence(AppendOnly):
    """A finding as one assessment reported it."""

    finding_id: UUID
    assessment_id: UUID
    severity: str
    cvss_vector: str | None = None
    cvss_score: Decimal | None = None
    rule: str | None = None


class Location(AppendOnly):
    """The location table: where an occurrence was reported, relative to its commit."""

    occurrence_id: UUID
    path: str
    line_start: int | None = None
    line_end: int | None = None
    language: str | None = None
    symbol: str | None = None


class Cwe(Entity):
    """MITRE CWE catalog entry - reference data, loaded read-only."""

    identifier: str
    abstraction: str | None = None
    mapping_usage: str | None = None
    catalog_version: str | None = None


class FindingCwe(Entity):
    finding_id: UUID
    cwe_id: UUID


class FindingLabel(Entity):
    finding_id: UUID
    taxonomy: str
    label: str


class FindingExternalRef(Entity):
    finding_id: UUID
    system: str
    ref: str


class Decision(AppendOnly):
    """A judgement on a finding; corrections are new decisions (restates_id)."""

    finding_id: UUID
    assessment_id: UUID | None = None
    fixed_repository_ref_id: UUID | None = None
    repository_ref_id: UUID | None = None
    restates_id: UUID | None = None
    artifact_id: UUID | None = None
    statement_key: str
    validity: str | None = None
    resolution: str | None = None
    evidence_grade: str | None = None
    reason: str | None = None
    severity: str | None = None
    source_channel: str | None = None
    actor: str | None = None
    rationale: str | None = None
    ticket: str | None = None
    auto_accept_tier: bool = False
    occurred_at: datetime


class DecisionApprover(AppendOnly):
    """Someone other than its author who agreed to a restatement."""

    decision_id: UUID
    approver: str


class Restatement(Model):
    """An administrator's correction of one decision: the values it fixes and its authority."""

    decision_id: UUID
    reason: RestatementReason
    ticket: str
    rationale: str
    approvers: tuple[str, ...] = ()
    validity: Validity | None = None
    resolution: DispositionResolution | None = None
    evidence_grade: EvidenceGrade | None = None
    severity: Severity | None = None
    fixed_repository_ref_id: UUID | None = None

    def changes(self) -> dict[str, object]:
        return {f: v for f in RESTATABLE if (v := getattr(self, f)) is not None}

    def independent_approvers(self, author: Principal) -> frozenset[str]:
        """The approvers it names, normalised, without its author."""
        named = {a.strip().lower() for a in self.approvers if a.strip()}
        return frozenset(named - {author.identity.lower()})

    def correct(
        self,
        restated: Decision,
        history: Sequence[Decision],
        author: Principal,
        at: datetime,
        commit: UUID | None,
    ) -> Decision:
        """The correcting decision, if this is an attributed, real correction of the latest record.

        It copies the restated statement with the changes applied: the fold drops the original.
        """
        if not self.ticket.strip():
            raise ValidationError("a restatement names its authority: a ticket")
        if len(self.rationale) < RATIONALE_MIN_LENGTH:
            raise ValidationError(f"a rationale of at least {RATIONALE_MIN_LENGTH} characters")
        if any(d.restates_id == restated.id for d in history):
            raise ConflictError(
                f"decision {restated.id} was already restated: restate the correction"
            )
        changes = self.changes()
        if not changes:
            raise ValidationError("a restatement corrects at least one of " + ", ".join(RESTATABLE))
        by_id = {d.id: d for d in history}
        earlier, step = [], restated
        while step.restates_id is not None and (step := by_id.get(step.restates_id)) is not None:
            earlier.append(step)
        for field, value in changes.items():
            current = getattr(restated, field)
            if current is None:
                raise ValidationError(
                    f"nothing to restate: {field} has no value yet; record it instead"
                )
            if value == current:
                raise ValidationError(
                    f"the restatement changes nothing: {field} is already {value}"
                )
            if value in {getattr(d, field) for d in earlier} - {current}:
                raise ValidationError(
                    f"{field} {value} was already corrected away from; record why anew"
                )
        draft = restated.model_copy(
            update={
                **changes,
                "id": None,
                "created_at": None,
                "assessment_id": None,
                "repository_ref_id": commit,
                "restates_id": restated.id,
                "auto_accept_tier": False,
                "actor": author.ref,
                "reason": self.reason,
                "ticket": self.ticket.strip(),
                "rationale": self.rationale,
                "occurred_at": at,
            }
        )
        return draft.model_copy(update={"statement_key": statement_key(draft)})


RESTATABLE = ("validity", "resolution", "evidence_grade", "severity", "fixed_repository_ref_id")
_JUDGED = (
    "finding_id",
    "assessment_id",
    "actor",
    "repository_ref_id",
    "restates_id",
    "validity",
    "resolution",
    "evidence_grade",
    "reason",
    "severity",
    "fixed_repository_ref_id",
)


def statement_key(decision: Decision) -> StatementKey:
    """The hash of every judged column: a retried statement is the same decision."""
    judged = {k: str(v) for k in _JUDGED if (v := getattr(decision, k)) is not None}
    return StatementKey(sha256_hex(canonical_json(judged)))


class ReviewItem(Entity):
    finding_id: UUID
    decision_id: UUID | None = None
    resolved_by_decision_id: UUID | None = None
    reason: str | None = None
    status: str


RATIONALE_MIN_LENGTH = 10
FUTURE_LIMIT = timedelta(hours=24)
_NO_SOURCES: Mapping[UUID, SourceType] = MappingProxyType({})
_EXECUTION = frozenset({SourceType.VALIDATION_REPORT, SourceType.VERIFICATION_REPORT})
_RESOLUTION_TIERS = {SourceType.VERIFICATION_REPORT: 0, SourceType.JIRA: 1}
_CLOSED_VALIDITY = frozenset({Validity.FALSE_POSITIVE, "not_affected"})
_CLOSED_RESOLUTION = frozenset(
    {DispositionResolution.RESOLVED, DispositionResolution.RISK_ACCEPTED}
)


@dataclass(frozen=True, slots=True)
class _Statement:
    decision: Decision
    source: str | None

    @property
    def at(self) -> datetime:
        return self.decision.occurred_at

    @property
    def human(self) -> bool:
        return (self.decision.actor or "").startswith(f"{ActorKind.HUMAN}:")

    @property
    def auto_accepted(self) -> bool:
        return self.decision.auto_accept_tier

    @property
    def evidence_class(self) -> int:
        """1 execution-proven, 2 human, 3 machine static; E2/E3 evidence demotes to 3."""
        if self.decision.evidence_grade in ("E2", "E3"):
            return 3
        return 2 if self.human else 1 if self.source in _EXECUTION else 3

    @property
    def resolution_tier(self) -> int:
        return _RESOLUTION_TIERS.get(self.source, 2)


def _statements(
    decisions: Sequence[Decision], sources: Mapping[UUID, SourceType]
) -> list[_Statement]:
    """Decisions in judgement order, without those a restatement replaced."""
    restated = {d.restates_id for d in decisions if d.restates_id}
    kept = sorted(
        (d for d in decisions if d.id is None or d.id not in restated),
        key=lambda d: (d.occurred_at, d.created_at is None, d.created_at or d.occurred_at),
    )
    return [
        _Statement(d, sources.get(d.assessment_id) if d.assessment_id else d.source_channel)
        for d in kept
    ]


def _admit_statement(
    history: Sequence[Decision],
    decision: Decision,
    actor: Principal | None,
    now: datetime,
    sources: Mapping[UUID, SourceType],
) -> None:
    """The gates on a direct statement (no assessment), as traust-ledger enforced them."""
    if actor is None or decision.actor != actor.ref:
        raise ForbiddenError("a direct statement is made by the calling principal, as its actor")
    if actor.kind != ActorKind.HUMAN:
        raise ForbiddenError(f"{actor.ref}: a machine judges a finding through an assessment")
    if len(decision.rationale or "") < RATIONALE_MIN_LENGTH:
        raise ValidationError(f"a rationale of at least {RATIONALE_MIN_LENGTH} characters")
    if decision.occurred_at > now + FUTURE_LIMIT:
        raise ValidationError(f"occurred_at {decision.occurred_at} is more than a day ahead")
    if decision.validity != Validity.FALSE_POSITIVE:
        return
    if not actor.is_verified_human():
        raise ForbiddenError(f"{actor.ref}: a false positive needs a verified human")
    said = _statements(history, sources)
    proven = any(s.source in _EXECUTION and s.decision.validity == Validity.CONFIRMED for s in said)
    if proven and any(
        s.human and s.decision.validity == Validity.FALSE_POSITIVE and s.decision.actor == actor.ref
        for s in said
    ):
        raise ForbiddenError(
            f"{actor.ref}: execution confirmed this finding; a second verified human must concur"
        )


# Read models over the views (current_decision, current_resolution, finding_status).
class Disposition(Model):
    """A finding's merged judgement: evidence-class precedence, moved from traust-ledger."""

    finding_id: UUID
    line: str | None = None
    validity: Validity | None = None
    resolution: DispositionResolution | None = None
    assurance: DispositionAssurance
    conflict: bool = False
    fp_overridden: bool = False
    fp_reassertion_blocked: bool = False
    awaiting_signoff: bool = False
    severity: Severity | None = None
    last_decision_at: datetime | None = None

    @classmethod
    def fold(
        cls,
        finding_id: UUID,
        decisions: Sequence[Decision],
        sources: Mapping[UUID, SourceType] = _NO_SOURCES,
    ) -> Disposition:
        """Merge every decision; `sources` names each assessment's report kind (validation, ...)."""
        said = _statements(decisions, sources)
        valid = [s for s in said if s.decision.validity]
        execution = [s for s in valid if s.evidence_class == 1]
        human = [s for s in valid if s.evidence_class == 2]
        machine = [s for s in valid if s.evidence_class == 3]
        fp, confirmed = Validity.FALSE_POSITIVE, Validity.CONFIRMED

        validity: str | None = None
        if human:
            validity = human[-1].decision.validity
        elif machine and (machine[-1].decision.validity != fp or machine[-1].auto_accepted):
            validity = machine[-1].decision.validity
        overridden = blocked = False
        if proofs := [s for s in execution if s.decision.validity != fp]:
            proof = proofs[-1]
            validity = proof.decision.validity
            if validity == confirmed:
                human_fp = [s for s in human if s.decision.validity == fp]
                overridden = any(s.at <= proof.at for s in human_fp)
                later = [s for s in human_fp if s.at > proof.at]
                if len({s.decision.actor for s in later}) >= 2:
                    validity, overridden = fp, False
                elif later:
                    blocked = True

        seen = {s.decision.validity for s in valid}
        conflict = {confirmed, fp} <= seen
        awaiting = (
            any(s.decision.validity == fp and not s.human and not s.auto_accepted for s in valid)
            and validity != fp
            and not human
            and not conflict
        )
        assurance = (
            DispositionAssurance.EXECUTION_PROVEN
            if execution
            else DispositionAssurance.HUMAN_REVIEWED
            if human
            else DispositionAssurance.MACHINE_VERIFIED
            if machine
            else DispositionAssurance.CLAIMED
        )
        resolved = [s for s in said if s.decision.resolution]
        if resolved:
            tier = min(s.resolution_tier for s in resolved)
            resolution = [s for s in resolved if s.resolution_tier == tier][-1].decision.resolution
        rated = [s.decision.severity for s in said if s.decision.severity]
        return cls(
            finding_id=finding_id,
            validity=validity,
            resolution=resolution if resolved else None,
            assurance=assurance,
            conflict=conflict,
            fp_overridden=overridden,
            fp_reassertion_blocked=blocked,
            awaiting_signoff=awaiting,
            severity=rated[-1] if rated else None,
            last_decision_at=said[-1].at if said else None,
        )

    @classmethod
    def admit(
        cls,
        history: Sequence[Decision],
        decision: Decision,
        actor: Principal | None,
        now: datetime,
        sources: Mapping[UUID, SourceType] = _NO_SOURCES,
    ) -> Disposition:
        """The disposition with `decision` added, if its author may make it; else a typed error."""
        if decision.assessment_id is None:
            _admit_statement(history, decision, actor, now, sources)
        return cls.fold(decision.finding_id, [*history, decision], sources)

    def is_open(self) -> bool:
        """Not affirmatively closed; the same rule as the finding_status view."""
        return self.validity not in _CLOSED_VALIDITY and self.resolution not in _CLOSED_RESOLUTION


class Precedent(Model):
    decision: Decision
    similarity: float
    reason: PrecedentReason


class FindingView(Model):
    finding: Finding
    occurrence: Occurrence | None = None
    disposition: Disposition | None = None
    effective_severity: Severity
    sla_due: datetime | None = None
    locations: tuple[Location, ...] = ()
    cwes: tuple[str, ...] = ()
    labels: tuple[FindingLabel, ...] = ()

    def label(self, taxonomy: str) -> str | None:
        return next((fl.label for fl in self.labels if fl.taxonomy == taxonomy), None)

    def is_open(self) -> bool:
        return self.disposition is None or self.disposition.is_open()

    def state(self) -> FindingState:
        """Closed by validity, then by resolution; open splits off hardening (posture debt)."""
        d = self.disposition
        if d is None:
            return FindingState.OPEN
        if d.validity in _CLOSED_VALIDITY:
            return FindingState.FALSE_POSITIVE
        if d.resolution == DispositionResolution.RESOLVED:
            return FindingState.RESOLVED
        if d.resolution == DispositionResolution.RISK_ACCEPTED:
            return FindingState.ACCEPTED
        return FindingState.HARDENING if d.validity == Validity.HARDENING else FindingState.OPEN


class FindingClock(Model):
    """When a finding was first reported, first judged, first filed in a tracker and (when it
    stands resolved) last resolved: what SLA clocks start and stop on."""

    view: FindingView
    reported_at: datetime | None = None
    decided_at: datetime | None = None
    filed_at: datetime | None = None
    resolved_at: datetime | None = None


class ReviewCase(Model):
    """One thing for a person: a fold state on a finding, or a pending review item."""

    kind: ReviewCaseKind
    finding_id: UUID
    repository_id: UUID
    since: datetime
    disposition: Disposition | None = None
    review_item: ReviewItem | None = None


class SurfaceCoverage(Model):
    """One review surface after merging the audit and the scans that followed it."""

    status: str
    finding_ids: tuple[UUID, ...] = ()
    labels: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


class SubjectRef(Model):
    """What a skill works on: a commit of a repository, and the assessment when there is one."""

    repository_id: UUID
    repository_url: str
    repository_ref_id: UUID
    sha: str
    assessment_id: UUID | None = None


class FindingContext(Model):
    baseline: tuple[FindingView, ...] = ()
    precedents: tuple[Precedent, ...] = ()


class SkillInput(Model):
    subject: SubjectRef
    findings: FindingContext
    prepared_at: datetime


class TriageItem(Model):
    """One reported finding to judge: the finding, how this assessment reported it, and where."""

    finding: Finding
    occurrence: Occurrence
    locations: tuple[Location, ...] = ()
    precedents: tuple[Precedent, ...] = ()


class TriageInput(SkillInput):
    assessor: str
    items: tuple[TriageItem, ...]


class FindingSeriesPoint(Model):
    bucket: datetime
    open_by_severity: Mapping[Severity, int]
    new: int
    resolved: int
    accepted: int
    hardening: int
    false_positives: int
    regressions: int
    mttr_days: float | None = None
    risk_index: float
