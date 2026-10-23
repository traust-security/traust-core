from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, NewType
from uuid import UUID

from traust_core.v1.errors import ConflictError, ForbiddenError, ValidationError
from traust_core.v1.models import candidate_formats
from traust_core.v1.models.base import AppendOnly, Entity, Model
from traust_core.v1.models.common import CodeSpan
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.integrity import canonical_json, sha256_hex
from traust_core.v1.models.vocabulary import (
    ActorKind,
    DispositionAssurance,
    DispositionResolution,
    EvidenceGrade,
    FindingOrigin,
    RestatementReason,
    ScannerSeverity,
    Severity,
    SourceType,
    Validity,
)

if TYPE_CHECKING:
    from traust_core.v1.models.assessment import Assessment

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


class PrecedentStrength(StrEnum):
    """What a precedent may save: a person's verdict earns fewer votes; a machine's annotates."""

    HUMAN = "human_countersigned"
    MACHINE = "machine_refuted_sound"


class PrecedentReason(Model):
    """Why a prior verdict applies: the same function in the same (vendor-normalized) file."""

    strength: PrecedentStrength
    path: str
    symbol: str


class IdentityMove(Model): ...


class IntakeResult(Model):
    """Each candidate's finding by its report label, and the findings this intake created."""

    findings: Mapping[Label, UUID]
    created: tuple[UUID, ...] = ()


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


class ReviewCase(Model): ...


class ReviewFilter(Model): ...


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


class FindingRollup(Model): ...


class RatingInputs(Model): ...


class RiskRating(Model): ...


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
                    locations=(CodeSpan(path=f["path"], line=f["line"], symbol=f["symbol"]),)
                    if f["path"]
                    else (),
                    reported_severity=ScannerSeverity(f["severity"] or ScannerSeverity.UNRATED),
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
