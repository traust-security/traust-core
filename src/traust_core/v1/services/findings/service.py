from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Callable, Collection, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any
from uuid import UUID

from traust_core.v1.errors import ConflictError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import (
    ANALYSIS_ARTIFACTS,
    CodeFactsArtifact,
    FindingClaimArtifact,
    FindingIntakeArtifact,
    ImpactAnalysisArtifact,
    IsolationReviewArtifact,
    ReportArtifact,
    VulnFindingsArtifact,
)
from traust_core.v1.models.assessment import (
    REBASELINED_KINDS,
    RECORDED_SCHEMAS,
    REPORTED_FINDINGS,
    AssessmentKind,
)
from traust_core.v1.models.common import (
    Page,
    PageRequest,
    RecordBudget,
    TimeBucket,
    TimeWindow,
)
from traust_core.v1.models.finding_claims import FindingClaim
from traust_core.v1.models.findings import (
    Decision,
    Finding,
    FindingCandidate,
    FindingClock,
    FindingDimension,
    FindingFilter,
    FindingFix,
    FindingRollup,
    FindingSeriesPoint,
    FindingState,
    FindingView,
    IdentityMove,
    IntakeResult,
    Label,
    Location,
    Occurrence,
    ReviewItem,
    SurfaceCoverage,
    VerifiedFixMtta,
    folded_resolutions,
    normalize_decision,
)
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.integrity import FingerprintInput
from traust_core.v1.models.inventory import default_line, ref_line
from traust_core.v1.models.vocabulary import (
    DecisionReason,
    DispositionResolution,
    ReviewItemStatus,
    ScannerSeverity,
    Severity,
    Validity,
)
from traust_core.v1.providers.comments import JIRA
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectStore
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    AssessmentLog,
    PublishSpec,
    PublishSpecs,
    stored_bytes,
)
from traust_core.v1.services.findings.claims import FindingClaims, retained_claim_artifact
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.facts import FindingFacts
from traust_core.v1.services.findings.identity import primary_cwe
from traust_core.v1.services.findings.intake import (
    CATEGORY,
    CWE_IDENTIFIER,
    REBASELINE_MAPPING,
    FindingIntake,
)
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.findings.rating import RatingPolicy
from traust_core.v1.services.findings.records import FindingRecords
from traust_core.v1.services.findings.review import FindingReview, request
from traust_core.v1.services.findings.views import FindingViewQuery
from traust_core.v1.services.portfolio import Inventory

_HELD_TIERS = frozenset({"path_cwe", "path_set"})
_HELD_DOCUMENTS = {
    ReportArtifact.schema: ReportArtifact,
    VulnFindingsArtifact.schema: VulnFindingsArtifact,
}


class FindingService:
    def lock_findings(self, finding_ids: Collection[UUID]) -> None:
        """Lock the findings' rows in one order until the transaction ends, so two requests
        scheduling any of them run one after the other."""
        with self._uow as uow:
            for finding_id in sorted(set(finding_ids), key=str):
                uow.findings.get_for_update(finding_id)

    def __init__(
        self,
        uow: TraustUnitOfWork,
        intake: FindingIntake,
        decisions: FindingDecisions,
        review: FindingReview,
        precedents: FindingPrecedents,
        rating: RatingPolicy,
        objects: ObjectStore,
    ) -> None:
        self._uow = uow
        self._inventory = Inventory(uow)
        self._log = AssessmentLog(uow)
        self.records = FindingRecords(uow)
        self._rating = rating
        self._views = FindingViewQuery(rating, objects)
        self._objects = objects
        types = dict.fromkeys(
            artifact.schema_type()
            for artifact in (
                *ANALYSIS_ARTIFACTS,
                CodeFactsArtifact,
                ImpactAnalysisArtifact,
                IsolationReviewArtifact,
                FindingClaimArtifact,
                FindingIntakeArtifact,
            )
        )
        self.artifacts = ArtifactPublisher(
            PublishSpecs(*(PublishSpec(artifact) for artifact in types)), objects, uow
        )
        self.intake = intake
        self.decisions = decisions
        self.review = review
        self.precedents = precedents
        self._claims = FindingClaims(uow, objects, self.artifacts, intake, decisions)

    def request_claim_correction(
        self,
        finding_id: UUID,
        assessment_id: UUID,
        report: ReportArtifact,
        label: Label,
        *,
        ticket: str,
        rationale: str,
        principal: Principal,
    ) -> ReviewItem:
        return self._claims.request(
            finding_id,
            assessment_id,
            report,
            label,
            ticket=ticket,
            rationale=rationale,
            principal=principal,
        )

    def correct_claim(
        self,
        review_item_id: UUID,
        *,
        ticket: str,
        rationale: str,
        principal: Principal,
        approvers: tuple[str, ...] = (),
    ) -> FindingView:
        with self._uow.write() as uow:
            finding_id = self._claims.correct(
                review_item_id,
                ticket=ticket,
                rationale=rationale,
                principal=principal,
                approvers=approvers,
            )
            view = self.get(finding_id)
            uow.commit()
            return view

    def claim(self, finding_id: UUID, as_of: datetime | None = None) -> FindingClaim | None:
        return self._claims.claim(finding_id, as_of)

    def get(self, finding_id: UUID) -> FindingView:
        with self._uow as uow:
            (view,) = self._views.views(uow, [uow.findings.get(finding_id)])
        return view

    def get_by_fingerprint(
        self, repository_id: UUID, fingerprint: str, fingerprint_algo: str | None = None
    ) -> FindingView:
        """Resolve an exact fingerprint, refusing ambiguity when its algorithm is omitted."""
        self._inventory.get_repository(repository_id)
        with self._uow as uow:
            found = uow.findings.find_by_fingerprint(repository_id, fingerprint_algo, fingerprint)
            if found is None:
                raise NotFoundError(
                    f"finding with fingerprint {fingerprint!r} for repository {repository_id}"
                )
            (view,) = self._views.views(uow, [found])
        return view

    def list_by_ids(
        self, finding_ids: Collection[UUID], *, read_budget: RecordBudget | None = None
    ) -> list[FindingView]:
        """These findings as they stand; NotFoundError names any that don't exist."""
        with self._uow as uow:
            found = uow.findings.list_by_ids(finding_ids, read_budget=read_budget)
            if missing := set(finding_ids) - {f.id for f in found}:
                raise NotFoundError(f"findings {', '.join(sorted(map(str, missing)))}")
            return self._views.views(uow, found, as_of=None, read_budget=read_budget)

    def list_by_cwe(self, cwe: str) -> list[FindingView]:
        """Every finding tagged with this CWE, in any repository (a fleet fix's targets)."""
        if not CWE_IDENTIFIER.fullmatch(cwe):
            raise ValidationError(f"{cwe!r} is not a CWE identifier (CWE-<n>)")
        with self._uow as uow:
            tagged = uow.cwes.find_by_identifier(cwe)
            ids = (
                {fc.finding_id for fc in uow.finding_cwes.list_for_cwe(tagged.id)}
                if tagged is not None
                else set()
            ) | set(uow.decisions.list_finding_ids_with_claims())
            return (
                [
                    view
                    for view in self._views.views(uow, uow.findings.list_by_ids(ids), as_of=None)
                    if cwe in view.cwes
                ]
                if ids
                else []
            )

    def hold_moves(
        self, repository_id: UUID, candidates: Sequence[FindingCandidate]
    ) -> list[IdentityMove]:
        """A re-audit's candidates that report a recorded finding under another identity by
        location (a title alone is too loose to hold one back), each with a pending
        `rebaseline_mapping` review on that finding; the recorder admits only the others, so
        a re-audit never opens a duplicate. Inside the caller's transaction."""
        held = [
            m
            for m in self.intake.moves(
                self.all(FindingFilter(repository_id=repository_id)), candidates
            )
            if m.matched_by in _HELD_TIERS
        ]
        with self._uow as uow:
            for move in held:
                request(uow, move.finding_id, REBASELINE_MAPPING)
        return held

    def settle_move(self, review_item_id: UUID) -> IntakeResult:
        """After a person answers a held move's `rebaseline_mapping` review, in one transaction
        (the caller's, when it answered the review in it): accepted, the recorded finding takes
        the newest re-audit's identity and every held occurrence (same id, so its decisions
        follow); rejected, each held candidate is admitted as the finding it is. Settling again
        admits nothing more."""
        with self._uow.write() as uow:
            item = uow.review_items.get(review_item_id)
            if item.reason != REBASELINE_MAPPING:
                raise ValidationError(f"review item {review_item_id} is not a rebaseline review")
            if (
                item.decision_id is not None
                and retained_claim_artifact(uow, uow.decisions.get(item.decision_id)) is not None
            ):
                raise ValidationError("retained claim corrections use correct_claim")
            if item.status == ReviewItemStatus.PENDING:
                raise ConflictError(f"review item {review_item_id} is still pending")
            held = self._held(item)
            accepted = item.status == ReviewItemStatus.ACCEPTED
            if held and accepted:
                self.intake.rebaseline([held[-1][2]], review_item_id)
            findings: dict[Label, UUID] = {}
            created: list[UUID] = []
            for assessment_id, candidate, _ in held:
                if accepted:
                    candidate = candidate.model_copy(update={"finding_id": item.finding_id})
                taken = self.intake.accept(assessment_id, [candidate])
                findings |= taken.findings
                created += taken.created
            uow.commit()
        return IntakeResult(findings=findings, created=tuple(dict.fromkeys(created)))

    def _held(self, item: ReviewItem) -> list[tuple[UUID, FindingCandidate, IdentityMove]]:
        """Every candidate still held under this review, oldest audit first. Holding opens the
        review before it records its audit, so only audits recorded since the review opened
        can hold under it; an audit that already reports the finding holds nothing."""
        repository_id = self.intake.get(item.finding_id).repository_id
        assert item.created_at is not None
        with self._uow as uow:
            reported = {o.assessment_id for o in uow.occurrences.list_for_finding(item.finding_id)}
        refs = [r.id for r in self._inventory.list_refs(repository_id) if r.id]
        audits = [
            a
            for a in self._log.list_of(None, refs)
            if a.kind in REBASELINED_KINDS
            and a.created_at is not None
            and a.created_at >= item.created_at
            and a.id not in reported
        ]
        if not audits:
            return []
        schemas = {RECORDED_SCHEMAS[AssessmentKind(a.kind)] for a in audits}
        previous = self.all(FindingFilter(repository_id=repository_id))
        held = []
        for assessment, artifact in sorted(
            self._log.documents(audits, schemas),
            key=lambda pair: (pair[0].created_at, pair[0].occurred_at),
        ):
            doc = _HELD_DOCUMENTS[artifact.kind].parse(stored_bytes(self._objects, artifact))
            candidates = REPORTED_FINDINGS[AssessmentKind(assessment.kind)](doc, repository_id)
            by_label = {c.label: c for c in candidates}
            assert assessment.id is not None
            held += [
                (assessment.id, by_label[m.label], m)
                for m in self.intake.moves(previous, candidates)
                if m.finding_id == item.finding_id and m.matched_by in _HELD_TIERS
            ]
        return held

    def moves(
        self, repository_id: UUID, candidates: Sequence[FindingCandidate]
    ) -> list[IdentityMove]:
        """The rebaseline proposals for a re-audit of the repository, each with a pending
        `rebaseline_mapping` review a person accepts before `intake.rebaseline` moves it."""
        moves = self.intake.moves(self.all(FindingFilter(repository_id=repository_id)), candidates)
        for move in moves:
            self.review.request_signoff(move.finding_id, REBASELINE_MAPPING)
        return moves

    def occurrences(
        self,
        *,
        assessment_id: UUID | None = None,
        finding_ids: Collection[UUID] | None = None,
        read_budget: RecordBudget | None = None,
    ) -> list[Occurrence]:
        """What one assessment reported, or every report of these findings (exactly one)."""
        if (assessment_id is None) == (finding_ids is None):
            raise ValidationError("occurrences of an assessment or of findings, exactly one")
        with self._uow as uow:
            if assessment_id is not None:
                return uow.occurrences.list_for_assessment(assessment_id, read_budget=read_budget)
            assert finding_ids is not None
            return uow.occurrences.list_for_findings(finding_ids, read_budget=read_budget)

    def locations(
        self, occurrence_ids: Collection[UUID], *, read_budget: RecordBudget | None = None
    ) -> list[Location]:
        """Where these occurrences were reported, by occurrence, path and line."""
        with self._uow as uow:
            return uow.locations.list_for_occurrences(occurrence_ids, read_budget=read_budget)

    def rule_hits(self) -> list[Occurrence]:
        """Every occurrence a scanner rule reported."""
        with self._uow as uow:
            return uow.occurrences.list_with_rule()

    def list(self, filter: FindingFilter, page: PageRequest) -> Page[FindingView]:
        """A repository's findings newest first, narrowed by their folded disposition."""
        after = page.position()
        kept = self.all(filter)
        if after is not None:
            kept = [v for v in kept if _newest_first(v) > _newest_first_key(*after)]
        return Page.of(kept, page.limit, key=_cursor)

    def all(self, filter: FindingFilter) -> list[FindingView]:
        """Every finding `list` pages through, newest first."""
        with self._uow as uow:
            views = self._views.views(
                uow, uow.findings.list_for_repository(filter.repository_id), filter.as_of
            )
        return sorted((v for v in views if filter.keeps(v)), key=_newest_first)

    def all_in(
        self, repository_ids: Collection[UUID], as_of: datetime | None = None
    ) -> dict[UUID, list[FindingView]]:
        """Every repository's findings newest first, keyed by repository id: the batched `all`
        for a scope. The folded-disposition narrows are `list`'s; callers filter with the view's
        own rules."""
        by_repo: defaultdict[UUID, list[Finding]] = defaultdict(list)
        grouped: defaultdict[UUID, list[FindingView]] = defaultdict(list)
        with self._uow as uow:
            for finding in uow.findings.list_for_repositories(repository_ids):
                by_repo[finding.repository_id].append(finding)
            batch: list[list[Finding]] = []
            size = 0
            for findings in by_repo.values():
                if batch and size + len(findings) > _FACTS_BATCH:
                    self._fold_batch(uow, batch, grouped, as_of)
                    batch, size = [], 0
                batch.append(findings)
                size += len(findings)
            if batch:
                self._fold_batch(uow, batch, grouped, as_of)
        for views in grouped.values():
            views.sort(key=_newest_first)
        return grouped

    def _fold_batch(
        self,
        uow: TraustUnitOfWork,
        batch: Sequence[Sequence[Finding]],
        grouped: defaultdict[UUID, list[FindingView]],
        as_of: datetime | None,
    ) -> None:
        # one facts load per bounded batch of whole repositories: a whole scope's ids at once
        # would exceed the bind limit, and a repository's refs must be read once, not once per
        # batch that happens to hold one of its findings
        findings = [f for repo_findings in batch for f in repo_findings]
        for view in self._views.views(uow, findings, as_of):
            grouped[view.finding.repository_id].append(view)

    def on_ref(self, repository_ref_id: UUID) -> list[FindingView]:
        """Findings reported on this named line, with resolution folded on that line."""
        with self._uow as uow:
            ref = self._inventory.get_ref(repository_ref_id)
            refs = self._inventory.list_refs(ref.repository_id)
            line = ref_line(ref, refs)
            findings = uow.findings.list_for_repository(ref.repository_id)
            if not findings:
                return []
            facts = FindingFacts.load(uow, findings, None, repository_ref_id, objects=self._objects)
            kept = [f for f in findings if not facts.off_line(f.id, line)]
            return self._views.views(uow, kept, facts=facts)

    def review_surfaces(
        self, repository_id: UUID, as_of: datetime | None = None
    ) -> dict[str, SurfaceCoverage]:
        """The latest audit's review-surface coverage, with the scans that followed it merged in.

        A scan's `finding` adds its findings (or replaces any other status); a `negative`
        replaces `negative` / `not_applicable` / `not_assessed`, and replaces `finding` only once
        every finding on the surface is closed; a scan's other statuses change nothing. Only
        scans dated on or after the audit count. A label a report entry can't be matched to a
        finding stays as a label and counts as open.
        """
        with self._uow as uow:
            repo = self._inventory.get_repository(repository_id)
            refs = [r.id for r in self._inventory.list_refs(repository_id) if r.id]
            runs = [
                a for a in self._log.list_of(None, refs) if as_of is None or a.occurred_at <= as_of
            ]
            at = {a.id: a.occurred_at for a in runs if a.id}
            docs = [
                d
                for _, d in sorted(
                    self._log.documents(runs, (_AUDIT, *_SCANS)),
                    key=lambda held: (held[0].occurred_at, held[1].created_at),
                )
            ]
            views = {
                v.finding.id: v
                for v in self._views.views(
                    uow, uow.findings.list_for_repository(repository_id), as_of
                )
            }
        audits = [d for d in docs if d.kind == _AUDIT]
        if not audits:
            return {}
        audit = audits[-1]
        since = at[audit.assessment_id]  # type: ignore[index]
        labels: dict[str, UUID] = {}
        merged: dict[str, SurfaceCoverage] = {}
        for doc in [audit, *(d for d in docs if d.kind in _SCANS and at[d.assessment_id] >= since)]:  # type: ignore[index]
            body = json.loads(stored_bytes(self._objects, doc))
            labels.update(self._labels(repo.id, repo.url, body))  # type: ignore[arg-type]
            for surface, entry in (body.get("review_surface_coverage") or {}).items():
                said = _coverage(entry, labels)
                merged[surface] = (
                    said if doc is audit else _merge(merged.get(surface), said, labels, views)
                )
        return merged

    def list_by_validity(self, validity: Validity) -> list[FindingView]:
        """Every finding whose folded disposition is `validity`, across repositories."""
        with self._uow as uow:
            ids = uow.decisions.list_finding_ids_with_validity(validity)
            views = self._views.views(uow, uow.findings.list_by_ids(ids), as_of=None) if ids else []
        return [v for v in views if v.disposition and v.disposition.validity == validity]

    def fixes(self, validity: Validity) -> list[FindingFix]:
        """Resolved findings of this folded validity whose standing resolving decision names the
        commit it was fixed on, and that a report saw on an earlier commit."""
        with self._uow as uow:
            return self._fixes(uow, self._with_validity(uow, validity), validity)

    def fixes_by_fingerprint(self, validity: Validity, batch: int) -> Iterator[FindingFix]:
        """`fixes` in (fingerprint, finding id) order, folded `batch` findings at a time so a
        bounded reader stops early."""
        if batch < 1:
            raise ValidationError("fix batch size must be positive")
        with self._uow as uow:
            found = sorted(
                self._with_validity(uow, validity), key=lambda f: (f.fingerprint, str(f.id))
            )
        for start in range(0, len(found), batch):
            with self._uow as uow:
                fixes = self._fixes(uow, found[start : start + batch], validity)
            yield from fixes

    @staticmethod
    def _with_validity(uow: TraustUnitOfWork, validity: Validity) -> list[Finding]:
        ids = uow.decisions.list_finding_ids_with_validity(validity)
        return uow.findings.list_by_ids(ids) if ids else []

    def _fixes(
        self, uow: TraustUnitOfWork, found: Sequence[Finding], validity: Validity
    ) -> list[FindingFix]:
        facts = FindingFacts.load(uow, found, until=None, objects=self._objects)
        fixed: list[tuple[FindingView, Occurrence, Decision]] = []
        for view in self._views.views(uow, found, None, facts=facts):
            finding_id = view.finding.id
            assert finding_id is not None
            if view.state() != FindingState.RESOLVED or view.disposition.validity != validity:  # type: ignore[union-attr]
                continue
            fixing = [
                d
                for d in _standing(facts.decided_by(finding_id, None))
                if d.resolution == _RESOLVED and d.fixed_repository_ref_id
            ]
            if not fixing:
                continue
            fix = max(fixing, key=lambda d: d.occurred_at)
            earlier = [
                o
                for o in facts.reported_by(finding_id, None)
                if facts.at[o.assessment_id] <= fix.occurred_at
                and facts.assessments[o.assessment_id].repository_ref_id
                not in (None, fix.fixed_repository_ref_id)
            ]
            if earlier:
                fixed.append((view, earlier[-1], fix))
        places: defaultdict[UUID, list[Location]] = defaultdict(list)
        reported_ids = [o.id for _, o, _ in fixed if o.id is not None]
        for location in uow.locations.list_for_occurrences(reported_ids) if reported_ids else ():
            places[location.occurrence_id].append(location)
        return [
            FindingFix(
                view=view,
                reported_ref_id=facts.assessments[reported.assessment_id].repository_ref_id,  # type: ignore[arg-type]
                reported_locations=tuple(places[reported.id]) if reported.id else (),
                fixed_ref_id=fix.fixed_repository_ref_id,  # type: ignore[arg-type]
                rationale=fix.rationale,
            )
            for view, reported, fix in fixed
        ]

    def history(self, finding_id: UUID) -> list[Decision]:
        return self.decisions.list_for_finding(finding_id)

    def baseline(self, repository_id: UUID, as_of: datetime) -> list[FindingView]:
        """The repository's findings as they stood at `as_of`: reported by then, judged by then."""
        with self._uow as uow:
            return self._views.views(uow, uow.findings.list_for_repository(repository_id), as_of)

    def open_count(self, repository_id: UUID, severities: Sequence[Severity]) -> int:
        counts = self.open_by_severity(repository_id)
        return sum(counts[s] for s in set(severities))

    def open_by_severity(self, repository_id: UUID) -> Counter[Severity]:
        """The repository's open exposure (hardening debt left out) per effective severity on
        its default line; unrated findings count nowhere. Until a default branch is observed,
        every line is the default."""
        with self._uow as uow:
            findings = uow.findings.list_for_repository(repository_id)
            facts = FindingFacts.load(uow, findings, until=None, objects=self._objects)
            line = default_line(self._inventory.list_refs(repository_id))
        views = (
            self._views.view(facts, f, None, {})
            for f in findings
            if not (line and facts.off_line(f.id, line))  # type: ignore[arg-type]
        )
        return Counter(
            v.effective_severity
            for v in views
            if v and v.state() == FindingState.OPEN and v.effective_severity
        )

    def summary(self, filter: FindingFilter, group_by: FindingDimension) -> list[FindingRollup]:
        """The filter's reported findings as they stood at `as_of`, counted by state per group,
        largest first. A finding counts in its primary CWE's group, and in each of its labels'."""
        with self._uow as uow:
            findings = uow.findings.list_for_repository(filter.repository_id)
            facts = FindingFacts.load(uow, findings, until=filter.as_of, objects=self._objects)
        groups: defaultdict[str | None, list[FindingView]] = defaultdict(list)
        for finding in findings:
            if not facts.reported_by(finding.id, filter.as_of):  # type: ignore[arg-type]
                continue  # never reported: no severity, and no baseline holds it either
            view = self._views.view(facts, finding, filter.as_of, {})
            if view is not None and filter.keeps(view):
                for key in _keys(view, group_by, facts, filter.as_of):
                    groups[key].append(view)
        return sorted(
            (finding_rollup(key, views) for key, views in groups.items()),
            key=lambda r: (-r.findings, r.key is None, r.key or ""),
        )

    def verified_fix_mtta(self, filter: FindingFilter) -> list[VerifiedFixMtta]:
        """First report to the first standing, evidence-backed resolved decision on the line the
        disposition folds; human-only closures never qualify, even if a later report repeats it."""
        with self._uow as uow:
            findings = uow.findings.list_for_repository(filter.repository_id)
            facts = FindingFacts.load(uow, findings, until=filter.as_of, objects=self._objects)
        groups: defaultdict[ScannerSeverity, list[float]] = defaultdict(list)
        for finding in findings:
            assert finding.id is not None
            reported = facts.reported_by(finding.id, filter.as_of)
            view = self._views.view(facts, finding, filter.as_of, {})
            if not reported or view is None or not filter.keeps(view):
                continue
            fixed = [
                decision.occurred_at
                for decision in folded_resolutions(
                    facts.decided_by(finding.id, filter.as_of), facts.lines
                )
                if decision.resolution == _RESOLVED
                and decision.assessment_id is not None
                and facts.assessments[decision.assessment_id].kind in {"validation", "verification"}
            ]
            if not fixed:
                continue
            first = facts.at[reported[0].assessment_id]
            days = max((min(fixed) - first).total_seconds() / 86400, 0.0)
            severity = ScannerSeverity(view.effective_severity or ScannerSeverity.UNRATED)
            groups[severity].append(days)
        return sorted(
            (
                VerifiedFixMtta(
                    severity=severity,
                    findings=len(days),
                    mtta_days=round(sum(days) / len(days), 1),
                )
                for severity, days in groups.items()
            ),
            key=lambda row: (-row.mtta_days, row.severity),
        )

    def timeline(self, filter: FindingFilter, bucket: TimeBucket) -> list[FindingSeriesPoint]:
        """The filter's findings replayed bucket by bucket, from the first report to `as_of` (else
        to the last report or decision). Open, accepted, hardening and the risk index stand at each
        bucket's end; new, resolved, false positives and regressions happened within it."""
        with self._uow as uow:
            findings = uow.findings.list_for_repository(filter.repository_id)
            facts = FindingFacts.load(uow, findings, until=filter.as_of, objects=self._objects)
        return _series(self, facts, findings, filter.keeps, bucket, filter.as_of)

    def timelines(
        self, repository_ids: Collection[UUID], bucket: TimeBucket, as_of: datetime | None = None
    ) -> dict[UUID, list[FindingSeriesPoint]]:
        """Each repository's series, keyed by repository id: the batched `timeline` for a scope.
        Every finding counts; the folded-disposition narrows are `timeline`'s."""
        by_repo: defaultdict[UUID, list[Finding]] = defaultdict(list)
        series: dict[UUID, list[FindingSeriesPoint]] = {}
        with self._uow as uow:
            for finding in uow.findings.list_for_repositories(repository_ids):
                by_repo[finding.repository_id].append(finding)
            batch: list[tuple[UUID, list[Finding]]] = []
            size = 0
            for repository_id, findings in by_repo.items():
                if batch and size + len(findings) > _FACTS_BATCH:
                    self._replay_batch(uow, batch, series, bucket, as_of)
                    batch, size = [], 0
                batch.append((repository_id, findings))
                size += len(findings)
            if batch:
                self._replay_batch(uow, batch, series, bucket, as_of)
        return series

    def _replay_batch(
        self,
        uow: TraustUnitOfWork,
        batch: Sequence[tuple[UUID, list[Finding]]],
        series: dict[UUID, list[FindingSeriesPoint]],
        bucket: TimeBucket,
        as_of: datetime | None,
    ) -> None:
        # one facts load per bounded batch of whole repositories: a whole scope's ids at once
        # would exceed the bind limit, and one repository's facts must not span batches
        facts = FindingFacts.load(
            uow, [f for _, findings in batch for f in findings], until=as_of, objects=self._objects
        )
        for repository_id, findings in batch:
            series[repository_id] = _series(self, facts, findings, _keeps_all, bucket, as_of)

    def _labels(self, repository_id: UUID, url: str, body: dict[str, Any]) -> dict[str, UUID]:
        """A report's own labels (`findings[].id`, `regressions[].id`) to the findings they are."""
        out: dict[str, UUID] = {}
        for entry in [*(body.get("findings") or ()), *(body.get("regressions") or ())]:
            label = entry.get("id")
            if not isinstance(label, str):
                continue
            try:
                found = self.intake.match(repository_id, FingerprintInput.from_report(entry, url))
            except ValidationError:
                continue  # no usable location: the label stays unresolved (counted as open)
            if found is not None:
                out[label] = found
        return out

    def clocks(self, filter: FindingFilter) -> list[FindingClock]:
        """Each finding `all` lists, with the times its SLA clock reads, as of `as_of`; filed
        means first linked to a Jira issue."""
        with self._uow as uow:
            findings = uow.findings.list_for_repository(filter.repository_id)
            facts = FindingFacts.load(uow, findings, until=filter.as_of, objects=self._objects)
            views = [
                view
                for view in self._views.views(uow, findings, filter.as_of, facts=facts)
                if filter.keeps(view)
            ]
            ids = [v.finding.id for v in views if v.finding.id]
            filed: dict[UUID, datetime] = {}
            for ref in uow.finding_external_refs.list_for_findings(ids, JIRA) if ids else ():
                at = ref.created_at
                if at and (filter.as_of is None or at <= filter.as_of):
                    filed[ref.finding_id] = min(at, filed.get(ref.finding_id, at))
        views.sort(key=_newest_first)
        return [self._clock(facts, v, filter.as_of, filed) for v in views]

    def _clock(
        self,
        facts: FindingFacts,
        view: FindingView,
        as_of: datetime | None,
        filed: Mapping[UUID, datetime],
    ) -> FindingClock:
        finding_id = view.finding.id
        assert finding_id is not None
        reported = facts.reported_by(finding_id, as_of)
        decided = facts.decided_by(finding_id, as_of)
        resolving = [d.occurred_at for d in _standing(decided) if d.resolution == _RESOLVED]
        return FindingClock(
            view=view,
            reported_at=facts.at[reported[0].assessment_id] if reported else None,
            decided_at=min((d.occurred_at for d in decided), default=None),
            filed_at=filed.get(finding_id),
            resolved_at=max(resolving, default=None)
            if view.state() == FindingState.RESOLVED
            else None,
        )


_AUDIT = "report"
_SCANS = ("vuln-findings", "verification")
_REPLACED_BY_NEGATIVE = frozenset({"negative", "not_applicable", "not_assessed"})


def _newest_first(view: FindingView) -> tuple[float, str]:
    f = view.finding
    return _newest_first_key(f.created_at, f.id)  # type: ignore[arg-type]


def _cursor(view: FindingView) -> tuple[datetime, UUID]:
    f = view.finding
    assert f.created_at is not None and f.id is not None
    return f.created_at, f.id


def _newest_first_key(created_at: datetime, finding_id: UUID) -> tuple[float, str]:
    return (-created_at.timestamp(), str(finding_id))


def _coverage(entry: dict[str, Any], labels: dict[str, UUID]) -> SurfaceCoverage:
    named = tuple(entry.get("finding_ids") or ())
    return SurfaceCoverage(
        status=entry["status"],
        labels=named,
        finding_ids=tuple(labels[n] for n in named if n in labels),
        notes=(entry["note"],) if entry.get("note") else (),
    )


def _merge(
    current: SurfaceCoverage | None,
    scan: SurfaceCoverage,
    labels: dict[str, UUID],
    views: dict[UUID | None, FindingView],
) -> SurfaceCoverage:
    if scan.status == "finding":
        if current is not None and current.status == "finding":
            return current.model_copy(
                update={
                    "labels": tuple(dict.fromkeys((*current.labels, *scan.labels))),
                    "finding_ids": tuple(dict.fromkeys((*current.finding_ids, *scan.finding_ids))),
                }
            )
        return scan
    if scan.status == "negative":
        if current is None or current.status in _REPLACED_BY_NEGATIVE:
            return scan
        still_open = any(n not in labels for n in current.labels) or any(
            views[i].is_open() for i in current.finding_ids if i in views
        )
        return current if still_open else scan
    return current or scan


_TICK = timedelta(microseconds=1)
_FACTS_BATCH = 1_000


def _keeps_all(view: FindingView) -> bool:
    return True


def _series(
    service: FindingService,
    facts: FindingFacts,
    findings: Sequence[Finding],
    keeps: Callable[[FindingView], bool],
    bucket: TimeBucket,
    as_of: datetime | None,
) -> list[FindingSeriesPoint]:
    first = {
        f.id: facts.at[seen[0].assessment_id]
        for f in findings
        if f.id and (seen := facts.reported_by(f.id, as_of))
    }
    if not first:
        return []
    replay = _Replay(service, facts, findings, keeps, first)
    end = as_of or max(_end_times(facts, findings))
    points = []
    window = bucket.window_of(min(first.values()))
    while window.start <= end:
        points.append(replay.point(window, min(window.end - _TICK, end)))
        window = bucket.window_of(window.end)
    return points


def _end_times(facts: FindingFacts, findings: Sequence[Finding]) -> list[datetime]:
    """When the findings' history ends: their reports' and decisions' assessments, and the
    decisions themselves."""
    out = [d.occurred_at for f in findings if f.id for d in facts.decisions.get(f.id, ())]
    for f in findings:
        if f.id is None:
            continue
        for occurrence in facts.reported.get(f.id, ()):
            out.append(facts.at[occurrence.assessment_id])
        for decision in facts.decisions.get(f.id, ()):
            if decision.assessment_id and (at := facts.at.get(decision.assessment_id)):
                out.append(at)
    return out


def _keys(
    view: FindingView, by: FindingDimension, facts: FindingFacts, as_of: datetime | None
) -> list[str | None]:
    """The groups a view counts in; origin is the assessor of the finding's first report."""
    d = view.disposition
    match by:
        case FindingDimension.SEVERITY:
            return [view.effective_severity]
        case FindingDimension.CWE:
            return [primary_cwe(FingerprintInput(cwes=view.cwes)) if view.cwes else None]
        case FindingDimension.CATEGORY:
            return [view.label(CATEGORY)]
        case FindingDimension.LABEL:
            return [f"{fl.taxonomy}:{fl.label}" for fl in view.labels] or [None]
        case FindingDimension.ORIGIN:
            seen = facts.reported_by(view.finding.id, as_of)  # type: ignore[arg-type]
            return [facts.assessors[seen[0].assessment_id] if seen else None]
        case FindingDimension.VALIDITY:
            return [d.validity if d else None]
        case FindingDimension.RESOLUTION:
            return [d.resolution if d else None]
        case FindingDimension.REPOSITORY:
            return [str(view.finding.repository_id)]
    raise ValidationError(f"no such finding dimension: {by}")


def _by_severity(counts: Counter[Severity | None]) -> dict[ScannerSeverity, int]:
    by_severity = {ScannerSeverity(s): counts[s] for s in Severity}
    if counts[None]:
        by_severity[ScannerSeverity.UNRATED] = counts[None]
    return by_severity


def finding_rollup(key: str | None, views: Sequence[FindingView]) -> FindingRollup:
    states = Counter(v.state() for v in views)
    opened = Counter(v.effective_severity for v in views if v.state() is FindingState.OPEN)
    return FindingRollup(
        key=key,
        findings=len(views),
        open=states[FindingState.OPEN],
        hardening=states[FindingState.HARDENING],
        accepted=states[FindingState.ACCEPTED],
        resolved=states[FindingState.RESOLVED],
        false_positives=states[FindingState.FALSE_POSITIVE],
        open_by_severity=_by_severity(opened),
    )


@dataclass
class _Replay:
    """The views at successive bucket ends: only a finding with a report or decision since the
    last bucket is re-folded, and the standing counts move with it."""

    service: FindingService
    facts: FindingFacts
    findings: Sequence[Finding]
    keeps: Callable[[FindingView], bool]
    first: Mapping[UUID, datetime]
    views: dict[UUID, FindingView] = field(default_factory=dict)
    standing: dict[UUID, tuple[FindingState, Severity | None, float | None]] = field(
        default_factory=dict
    )
    states: Counter[FindingState] = field(default_factory=Counter)
    opened: Counter[Severity | None] = field(default_factory=Counter)
    last: datetime | None = None

    def __post_init__(self) -> None:
        self._by_id = {f.id: f for f in self.findings if f.id is not None}
        facts = self.facts
        # only these findings' events: the facts may be shared with other repositories
        self._events = sorted(
            [
                (facts.at[o.assessment_id], o.finding_id)
                for f in self.findings
                if f.id
                for o in facts.reported.get(f.id, ())
            ]
            + [
                (d.occurred_at, d.finding_id)
                for f in self.findings
                if f.id
                for d in facts.decisions.get(f.id, ())
            ],
            key=lambda e: e[0],
        )
        self._next = 0

    def point(self, window: TimeWindow, cut: datetime) -> FindingSeriesPoint:
        since = self.last or window.start - _TICK
        new = resolved = false_positives = regressions = decisions = 0
        fixes: list[int] = []
        for finding_id in self._moved(cut):
            view = self.service._views.view(self.facts, self._by_id[finding_id], cut, {})
            if view is None:
                continue
            was = self.views.get(finding_id)
            self.views[finding_id] = view
            self._unstand(finding_id)
            if not self.keeps(view):
                continue
            state = view.state()
            self._stand(finding_id, view, state)
            moved = was is None or was.state() is not state
            new += self.first[finding_id] >= window.start
            decided = self.facts.decided_by(finding_id, cut)
            decisions += sum(d.occurred_at > since for d in decided)
            standing = _standing(decided)
            if state is FindingState.RESOLVED and moved:
                resolved += 1
                fixed = [d.occurred_at for d in standing if d.resolution == _RESOLVED]
                if fixed:
                    days = (_day(max(fixed)) - _day(self.first[finding_id])).days
                    fixes.append(max(days, 0))
            elif state is FindingState.FALSE_POSITIVE and moved:
                false_positives += 1
            regressions += sum(d.occurred_at > since and d.reason == _REGRESSION for d in standing)
        self.last = cut
        return FindingSeriesPoint(
            bucket=window.start,
            open_by_severity=_by_severity(self.opened),
            new=new,
            resolved=resolved,
            accepted=self.states[FindingState.ACCEPTED],
            hardening=self.states[FindingState.HARDENING],
            false_positives=false_positives,
            regressions=regressions,
            decisions=decisions,
            mttr_days=round(sum(fixes) / len(fixes), 1) if fixes else None,
            risk_index=self._weight(FindingState.OPEN),
            accepted_risk_index=self._weight(FindingState.ACCEPTED),
        )

    def _weight(self, state: FindingState) -> float | None:
        weights = [w for s, _, w in self.standing.values() if s is state]
        return None if any(w is None for w in weights) else round(sum(weights), 1)  # type: ignore[arg-type]

    def _moved(self, cut: datetime) -> list[UUID]:
        """The findings with a report or decision up to `cut` not yet replayed, in event order."""
        start = self._next
        while self._next < len(self._events) and self._events[self._next][0] <= cut:
            self._next += 1
        return list(dict.fromkeys(fid for _, fid in self._events[start : self._next]))

    def _stand(self, finding_id: UUID, view: FindingView, state: FindingState) -> None:
        severity = view.effective_severity
        weight: float | None = 0.0
        if state is FindingState.OPEN:
            self.opened[severity] += 1
        if state in (FindingState.OPEN, FindingState.ACCEPTED):
            weight = self.service._rating.risk_weight(view.occurrence, severity)
        self.states[state] += 1
        self.standing[finding_id] = (state, severity, weight)

    def _unstand(self, finding_id: UUID) -> None:
        if (was := self.standing.pop(finding_id, None)) is not None:
            state, severity, _ = was
            self.states[state] -= 1
            if state is FindingState.OPEN:
                self.opened[severity] -= 1


_RESOLVED = DispositionResolution.RESOLVED
_REGRESSION = DecisionReason.REGRESSION


def _standing(decisions: Sequence[Decision]) -> list[Decision]:
    """The decisions no later restatement replaced."""
    replaced = {d.restates_id for d in decisions if d.restates_id}
    return [normalize_decision(d) for d in decisions if d.id not in replaced]


def _day(at: datetime) -> date:
    return at.astimezone(UTC).date()
