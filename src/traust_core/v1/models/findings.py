from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Any, Literal, NewType, Self
from uuid import UUID

import pydantic
from pydantic import Field

from traust_core.v1 import contracts
from traust_core.v1.errors import ConflictError, ForbiddenError, ValidationError
from traust_core.v1.models import candidate_formats
from traust_core.v1.models.base import AppendOnly, Entity, Model
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.integrity import canonical_json, sha256_hex
from traust_core.v1.models.vocabulary import (
    ActorKind,
    AliasMatchedBy,
    DecisionReason,
    DispositionAssurance,
    DispositionResolution,
    EvidenceGrade,
    FindingKind,
    OwaspImpactBasis,
    OwaspLlmCategory,
    RestatementReason,
    ReviewItemStatus,
    ReviewReason,
    RiskRatingBand,
    ScannerSeverity,
    Severity,
    SourceChannel,
    Validity,
)

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

    validity: Validity | None
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
    reason: DecisionReason | None = None
    source_channel: SourceChannel | None = None
    repository_ref_id: UUID | None = None
    fixed_repository_ref_id: UUID | None = None
    artifact_id: UUID | None = None
    occurred_at: datetime | None = None


class ReviewCaseKind(StrEnum):
    """Why a person must look, worst first: the fold's states, then a pending review item."""

    AWAITING_SIGNOFF = "awaiting_signoff"
    FP_OVERRIDDEN = "fp_overridden"
    FP_REASSERTION_BLOCKED = "fp_reassertion_blocked"
    CONFLICT = "conflict"
    NEEDS_REVIEW = "needs_review"


class ReviewFilter(Model):
    finding_id: UUID | None = None
    reason: ReviewReason | str | None = Field(default=None, union_mode="left_to_right")
    status: ReviewItemStatus | str = Field(default="pending", union_mode="left_to_right")
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
    open_by_severity: Mapping[ScannerSeverity, int]


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


def _owasp_llm(entry: Any) -> tuple[OwaspLlmCategory, ...]:
    # Only report findings declare the field; a verification's regressions don't.
    if "owasp_llm_references" not in dir(entry):
        return ()
    return tuple(OwaspLlmCategory(c) for c in entry.owasp_llm_references)


class FindingCandidate(Model):
    """A reported finding before intake; a scanner that gives no severity reports `unrated`."""

    label: Label
    repository_id: UUID
    title: str
    kind: FindingKind | None = None
    description: str = ""
    rule: str | None = None
    cwes: tuple[CweId, ...] = ()
    category: Category | None = None
    owasp_llm_references: tuple[OwaspLlmCategory, ...] = ()
    locations: tuple[CodeSpan, ...] = ()
    reported_severity: ScannerSeverity | None = None
    confidence: Confidence | None = None
    exposure: ExposureKey | None = None
    # A policy check: identity is `rule` on `resources` (every resource the check names, located
    # or not), on the locations' paths only when it names none.
    policy: bool = False
    resources: tuple[str, ...] = ()
    finding_id: UUID | None = None  # the recorded finding this report confirms, not a new one

    @classmethod
    def parse_many(
        cls, raw: bytes, format: CandidateFormat, repository_id: UUID
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
                )
            )
        return out

    @classmethod
    def of_report(cls, entries: Iterable[Any], repository_id: UUID) -> list[FindingCandidate]:
        """The findings a contracts report states (`findings[]`, a verification's `regressions[]`),
        rated as the report rates them; a location keeps its first line."""
        return [
            cls(
                label=Label(e.id),
                repository_id=repository_id,
                title=e.title,
                kind=getattr(e, "kind", None),
                description=e.description,
                cwes=tuple(CweId(c) for c in e.cwes),
                category=Category(e.category) if e.category else None,
                owasp_llm_references=_owasp_llm(e),
                locations=tuple(
                    CodeSpan(
                        path=RepoPath(loc.path),
                        line=_first_line(loc.lines),
                    )
                    for loc in e.locations
                ),
                reported_severity=ScannerSeverity(e.severity),
            )
            for e in entries
        ]

    @classmethod
    def of_scan(cls, entries: Iterable[Any], repository_id: UUID) -> list[FindingCandidate]:
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
            )
            for e in entries
        ]

    @classmethod
    def of_fuzz(cls, crashers: Iterable[Any], repository_id: UUID) -> list[FindingCandidate]:
        """The crashers a fuzz report states, rated as the producer proposes; a crasher naming a
        finding confirms it."""
        return [
            cls(
                label=Label(c.id),
                repository_id=repository_id,
                title=c.title,
                cwes=tuple(CweId(w) for w in c.cwes),
                locations=(
                    (CodeSpan(path=RepoPath(c.location.path), line=_first_line(c.location.lines)),)
                    if c.location
                    else ()
                ),
                reported_severity=ScannerSeverity(c.severity_proposal),
                finding_id=UUID(c.finding_id) if c.finding_id else None,
            )
            for c in crashers
        ]


_FIRST_LINE = re.compile(r"\d+")


def _first_line(lines: str | None) -> int | None:
    return int(m.group()) if (m := _FIRST_LINE.search(lines or "")) else None


class Finding(Entity):
    """3b · one weakness or vulnerability in a repository, identified by fingerprint."""

    repository_id: UUID
    advisory_id: UUID | None = None
    advisory_match: str | None = None
    fingerprint_algo: str
    fingerprint: str
    kind: FindingKind | str | None = Field(default=None, union_mode="left_to_right")
    title: str


# A report's claims can't change after the fact: occurrence and location rows are append-only and
# the report's artifact pins its bytes by digest. This replaced the claim hashes track-findings
# pinned on audit JSON (baseline_claims.py). Not covered: finding.title and finding_cwe are mutable.
class Occurrence(AppendOnly):
    """A finding as one assessment reported it."""

    finding_id: UUID
    assessment_id: UUID
    severity: ScannerSeverity
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
    validity: Validity | str | None = Field(default=None, union_mode="left_to_right")
    resolution: DispositionResolution | str | None = Field(default=None, union_mode="left_to_right")
    evidence_grade: EvidenceGrade | str | None = Field(default=None, union_mode="left_to_right")
    reason: DecisionReason | str | None = Field(default=None, union_mode="left_to_right")
    severity: Severity | str | None = Field(default=None, union_mode="left_to_right")
    source_channel: SourceChannel | str | None = Field(default=None, union_mode="left_to_right")
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
        return frozenset(named - {author.identity.strip().lower()})

    def validate_authority(self) -> None:
        if not self.ticket.strip():
            raise ValidationError("a restatement names its authority: a ticket")
        if len(self.rationale.strip()) < RATIONALE_MIN_LENGTH:
            raise ValidationError(f"a rationale of at least {RATIONALE_MIN_LENGTH} characters")

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
        self.validate_authority()
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
    "fixed_repository_ref_id",
)


def statement_key(decision: Decision) -> StatementKey:
    """Hash normalized judged values without rewriting historical statement keys."""
    decision = Decision.model_validate(dict(decision))
    judged = {k: str(v) if (v := getattr(decision, k)) is not None else None for k in _JUDGED}
    judged["classifiers"] = sorted(
        {
            (pair.enum, pair.value)
            for field, name in _CLASSIFIERS.items()
            if field != "source_channel" and (value := getattr(decision, field)) is not None
            for normalized in (contracts.normalize_enum(name, value),)
            if not normalized.dropped
            for pair in normalized.pairs
            if pair.enum in _CLASSIFIERS.values() and pair.enum != "source_channel"
        }
    )
    return StatementKey(sha256_hex(canonical_json(judged)))


class ReviewItem(Entity):
    finding_id: UUID
    decision_id: UUID | None = None
    resolved_by_decision_id: UUID | None = None
    reason: ReviewReason | str | None = Field(default=None, union_mode="left_to_right")
    status: ReviewItemStatus | str = Field(union_mode="left_to_right")


RATIONALE_MIN_LENGTH = 10
FUTURE_LIMIT = timedelta(hours=24)
_EVIDENCE_RANK = {value: rank for rank, value in enumerate(("E0", "E1", "E2", "E3"))}
_CLASSIFIERS = {
    "validity": "validity",
    "resolution": "disposition_resolution",
    "evidence_grade": "evidence_grade",
    "reason": "decision_reason",
    "severity": "severity",
    "source_channel": "source_channel",
}
_JUDGEMENTS = {
    "validity": frozenset(Validity),
    "resolution": frozenset(DispositionResolution),
    "severity": frozenset(Severity),
}
_CLOSED_VALIDITY = frozenset({Validity.FALSE_POSITIVE, "not_affected"})
_CLOSED_RESOLUTION = frozenset(
    {DispositionResolution.RESOLVED, DispositionResolution.RISK_ACCEPTED}
)


def normalize_finding(finding: Finding, history: Sequence[Decision]) -> Finding:
    """Interpret historical kind claims without rewriting the finding or decisions."""
    kind = finding.kind
    if kind is None:
        for decision in history:
            if decision.validity is None:
                continue
            for pair in contracts.normalize_enum("validity", decision.validity).pairs:
                if pair.enum == "finding_kind":
                    kind = pair.value
    else:
        normalized = contracts.normalize_enum("finding_kind", kind)
        kind = next((pair.value for pair in normalized.pairs if pair.enum == "finding_kind"), kind)
    return (
        finding if kind == finding.kind else Finding.model_validate({**dict(finding), "kind": kind})
    )


def normalize_decision(decision: Decision) -> Decision:
    """Interpret historical classifiers without changing the saved statement or its key."""
    values = decision.model_dump()
    fields = {name: field for field, name in _CLASSIFIERS.items()}
    for field, name in _CLASSIFIERS.items():
        if (value := getattr(decision, field)) is None:
            continue
        normalized = contracts.normalize_enum(name, value)
        if normalized.dropped:
            values[field] = None
            continue
        for pair in normalized.pairs:
            target = fields.get(pair.enum)
            if target is not None and (target == field or values[target] is None):
                values[target] = pair.value
    return Decision.model_validate(values)


@dataclass(frozen=True, slots=True)
class _Statement:
    decision: Decision

    @property
    def at(self) -> datetime:
        return self.decision.occurred_at

    @property
    def human(self) -> bool:
        return (self.decision.actor or "").startswith(f"{ActorKind.HUMAN}:")

    @property
    def strength(self) -> int:
        return _EVIDENCE_RANK.get(self.decision.evidence_grade, len(_EVIDENCE_RANK))


def effective_decisions(decisions: Sequence[Decision]) -> list[Decision]:
    """Judgement order with corrections applied, using canonical classifier values."""
    restated = {d.restates_id for d in decisions if d.restates_id}
    return [
        normalize_decision(d)
        for d in sorted(
            (d for d in decisions if d.id is None or d.id not in restated),
            key=lambda d: (d.occurred_at, d.created_at is None, d.created_at or d.occurred_at),
        )
    ]


def _statements(decisions: Sequence[Decision]) -> list[_Statement]:
    return [_Statement(d) for d in effective_decisions(decisions)]


def _strongest(statements: Sequence[_Statement], field: str) -> _Statement | None:
    candidates = [s for s in statements if getattr(s.decision, field) in _JUDGEMENTS[field]]
    if not candidates:
        return None
    strength = min(s.strength for s in candidates)
    return next(s for s in reversed(candidates) if s.strength == strength)


def _admit_statement(
    history: Sequence[Decision], decision: Decision, actor: Principal | None, now: datetime
) -> None:
    if actor is None or decision.actor != actor.ref:
        raise ForbiddenError("a direct statement is made by the calling principal, as its actor")
    if not actor.is_verified_human():
        raise ForbiddenError(f"{actor.ref}: a direct statement needs a verified human")
    if len((decision.rationale or "").strip()) < RATIONALE_MIN_LENGTH:
        raise ValidationError(f"a rationale of at least {RATIONALE_MIN_LENGTH} characters")
    if all(getattr(decision, field) is None for field in _JUDGEMENTS):
        raise ValidationError("a direct statement selects validity, resolution or severity")
    if decision.occurred_at.tzinfo is None or decision.occurred_at.utcoffset() is None:
        raise ValidationError("a decision occurred_at must include a timezone")
    if decision.occurred_at > now + FUTURE_LIMIT:
        raise ValidationError(f"occurred_at {decision.occurred_at} is more than a day ahead")
    said = _statements(history)
    if decision.validity == Validity.FALSE_POSITIVE:
        proven = any(s.strength == 0 and s.decision.validity == Validity.CONFIRMED for s in said)
        if proven and any(
            s.human
            and s.decision.validity == Validity.FALSE_POSITIVE
            and s.decision.actor == actor.ref
            for s in said
        ):
            raise ForbiddenError(
                f"{actor.ref}: execution confirmed this finding; "
                "a second verified human must concur"
            )


class Disposition(Model):
    """A finding's merged judgement, ordered only by explicit E0-E3 evidence strength."""

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
    def fold(cls, finding_id: UUID, decisions: Sequence[Decision]) -> Disposition:
        said = _statements(decisions)
        fp, confirmed = Validity.FALSE_POSITIVE, Validity.CONFIRMED
        valid = [s for s in said if s.decision.validity in _JUDGEMENTS["validity"]]
        eligible = [
            s for s in valid if s.decision.validity != fp or s.human or s.decision.auto_accept_tier
        ]
        chosen = _strongest(eligible, "validity")
        validity = chosen.decision.validity if chosen else None
        overridden = blocked = False
        proof = _strongest([s for s in eligible if s.decision.validity != fp], "validity")
        if proof is not None and proof.strength == 0 and proof.decision.validity == confirmed:
            human_fp = [s for s in valid if s.human and s.decision.validity == fp]
            overridden = any(s.at <= proof.at for s in human_fp)
            later = [s for s in human_fp if s.at > proof.at and s.strength == 0]
            if len({s.decision.actor for s in later}) >= 2:
                validity, overridden = fp, False
            else:
                validity = confirmed
                blocked = bool(later)
        seen = {s.decision.validity for s in valid}
        conflict = {confirmed, fp} <= seen
        awaiting = (
            any(
                s.decision.validity == fp and not s.human and not s.decision.auto_accept_tier
                for s in valid
            )
            and validity != fp
            and not any(s.human for s in valid)
            and not conflict
        )
        strength = min((s.strength for s in said), default=len(_EVIDENCE_RANK))
        assurance = (
            DispositionAssurance.EXECUTION_PROVEN,
            DispositionAssurance.HUMAN_REVIEWED,
            DispositionAssurance.MACHINE_VERIFIED,
            DispositionAssurance.CLAIMED,
            DispositionAssurance.CLAIMED,
        )[strength]
        resolved = _strongest(said, "resolution")
        accepted = [
            s
            for s in said
            if s.human and s.decision.resolution == DispositionResolution.RISK_ACCEPTED
        ]
        if accepted and (resolved is None or accepted[-1].at >= resolved.at):
            resolved = accepted[-1]
        rated = _strongest(said, "severity")
        return cls(
            finding_id=finding_id,
            validity=validity,
            resolution=resolved.decision.resolution if resolved else None,
            assurance=assurance,
            conflict=conflict,
            fp_overridden=overridden,
            fp_reassertion_blocked=blocked,
            awaiting_signoff=awaiting,
            severity=rated.decision.severity if rated else None,
            last_decision_at=said[-1].at if said else None,
        )

    @classmethod
    def admit(
        cls, history: Sequence[Decision], decision: Decision, actor: Principal | None, now: datetime
    ) -> Disposition:
        if decision.assessment_id is None:
            _admit_statement(history, decision, actor, now)
        said = _statements(history)
        draft = _Statement(normalize_decision(decision))
        for field in ("validity", "severity", "resolution"):
            value = getattr(draft.decision, field)
            if field == "resolution" and value == DispositionResolution.RISK_ACCEPTED:
                continue
            current = _strongest(said, field)
            if (
                value is not None
                and current is not None
                and value != getattr(current.decision, field)
                and draft.strength > current.strength
            ):
                raise ValidationError(f"weaker or ungraded evidence cannot override {field}")
        return cls.fold(decision.finding_id, [*history, decision])

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
    effective_severity: Severity | None = None
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
        return (
            FindingState.HARDENING
            if self.finding.kind == FindingKind.WEAKNESS or d.validity == Validity.HARDENING
            else FindingState.OPEN
        )


class FindingClock(Model):
    """When a finding was first reported, first judged, first filed in a tracker and (when it
    stands resolved) last resolved: what SLA clocks start and stop on."""

    view: FindingView
    reported_at: datetime | None = None
    decided_at: datetime | None = None
    filed_at: datetime | None = None
    resolved_at: datetime | None = None


class FindingFix(Model):
    """A finding a standing decision says was fixed on a commit, with the commit it was last
    reported on before that and the fixing decision's rationale."""

    view: FindingView
    reported_ref_id: UUID
    fixed_ref_id: UUID
    rationale: str | None = None


class ReviewCase(Model):
    """One thing for a person: a fold state on a finding, or a pending review item."""

    kind: ReviewCaseKind
    finding_id: UUID
    repository_id: UUID
    since: datetime
    disposition: Disposition | None = None
    review_item: ReviewItem | None = None


class ReviewItemCase(Model):
    review_item: ReviewItem
    finding: FindingView
    history: tuple[Decision, ...] = ()
    external_refs: tuple[FindingExternalRef, ...] = ()
    evidence_artifact_ids: tuple[UUID, ...] = ()


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


class TriageRecordResult(Model):
    assessment_id: UUID
    artifact_id: UUID
    decisions: list[Decision]


class FindingSeriesPoint(Model):
    bucket: datetime
    open_by_severity: Mapping[ScannerSeverity, int]
    new: int
    resolved: int
    accepted: int
    hardening: int
    false_positives: int
    regressions: int
    decisions: int = 0  # recorded within the bucket
    mttr_days: float | None = None
    risk_index: float | None
    accepted_risk_index: float | None = 0.0
