from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import NewType
from uuid import UUID

from pydantic import Field

from traust_core.v1 import contracts
from traust_core.v1.errors import ForbiddenError, ValidationError
from traust_core.v1.models import candidate_formats
from traust_core.v1.models.base import AppendOnly, Entity, Model
from traust_core.v1.models.common import CodeSpan
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.vocabulary import (
    ActorKind,
    DecisionReason,
    DispositionAssurance,
    DispositionResolution,
    EvidenceGrade,
    FindingKind,
    FindingOrigin,
    RestatementReason,
    ReviewItemStatus,
    ReviewReason,
    Severity,
    SourceChannel,
    Validity,
)

Label = NewType("Label", str)
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
class WeaknessLabels(Model): ...


class PrecedentReason(Model): ...


class IdentityMove(Model): ...


class IntakeResult(Model): ...


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


class ReviewFilter(Model):
    finding_id: UUID | None = None
    reason: ReviewReason | str | None = Field(default=None, union_mode="left_to_right")
    status: ReviewItemStatus | str = Field(default="pending", union_mode="left_to_right")


class FindingFilter(Model): ...


class FindingRollup(Model): ...


class RatingInputs(Model): ...


class RiskRating(Model): ...


class FindingCandidate(Model):
    """A reported finding before intake; severity and confidence are None when not reported."""

    label: Label
    repository_id: UUID
    title: str
    description: str = ""
    rule: str | None = None
    cwes: tuple[CweId, ...] = ()
    category: Category | None = None
    locations: tuple[CodeSpan, ...] = ()
    reported_severity: Severity | None = None
    confidence: Confidence | None = None
    origin: FindingOrigin

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
                    locations=(CodeSpan(path=f["path"], line=f["line"]),) if f["path"] else (),
                    reported_severity=Severity(f["severity"]) if f["severity"] else None,
                    confidence=Confidence(f["confidence"]) if f["confidence"] is not None else None,
                    origin=origin,
                )
            )
        return out


class Finding(Entity):
    """3b · one weakness or vulnerability in a repository, identified by fingerprint."""

    repository_id: UUID
    advisory_id: UUID | None = None
    advisory_match: str | None = None
    fingerprint_algo: str
    fingerprint: str
    kind: FindingKind | str | None = Field(default=None, union_mode="left_to_right")
    title: str


class Occurrence(AppendOnly):
    """A finding as one assessment reported it."""

    finding_id: UUID
    assessment_id: UUID
    severity: Severity
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


RESTATABLE = ("validity", "resolution", "evidence_grade", "severity", "fixed_repository_ref_id")


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


def _statements(decisions: Sequence[Decision]) -> list[_Statement]:
    restated = {d.restates_id for d in decisions if d.restates_id}
    return [
        _Statement(normalize_decision(d))
        for d in sorted(
            (d for d in decisions if d.id is None or d.id not in restated),
            key=lambda d: (d.occurred_at, d.created_at is None, d.created_at or d.occurred_at),
        )
    ]


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
    if len(decision.rationale or "") < RATIONALE_MIN_LENGTH:
        raise ValidationError(f"a rationale of at least {RATIONALE_MIN_LENGTH} characters")
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
    last_decision_at: datetime | None = None

    @classmethod
    def fold(cls, finding_id: UUID, decisions: Sequence[Decision]) -> Disposition:
        said = _statements(decisions)
        fp, confirmed = Validity.FALSE_POSITIVE, Validity.CONFIRMED
        valid = [s for s in said if s.decision.validity in (fp, confirmed, "not_affected")]
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
        return cls(
            finding_id=finding_id,
            validity=validity,
            resolution=resolved.decision.resolution if resolved else None,
            assurance=assurance,
            conflict=conflict,
            fp_overridden=overridden,
            fp_reassertion_blocked=blocked,
            awaiting_signoff=awaiting,
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
    effective_severity: Severity
    sla_due: datetime | None = None


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
