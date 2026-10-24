from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any
from uuid import UUID

from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.common import (
    Page,
    PageRequest,
    TimeBucket,
    TimeWindow,
)
from traust_core.v1.models.findings import (
    Decision,
    Finding,
    FindingClock,
    FindingDimension,
    FindingFilter,
    FindingRollup,
    FindingSeriesPoint,
    FindingState,
    FindingView,
    Location,
    Occurrence,
    SurfaceCoverage,
)
from traust_core.v1.models.integrity import FingerprintInput
from traust_core.v1.models.vocabulary import DispositionResolution, Severity, Validity
from traust_core.v1.providers.comments import JIRA
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectStore
from traust_core.v1.services.artifact_publishing import AssessmentLog, stored_bytes
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.facts import FindingFacts
from traust_core.v1.services.findings.identity import primary_cwe
from traust_core.v1.services.findings.intake import CATEGORY, CWE_IDENTIFIER, FindingIntake
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.findings.rating import RatingPolicy
from traust_core.v1.services.findings.records import FindingRecords
from traust_core.v1.services.findings.review import FindingReview
from traust_core.v1.services.portfolio import Inventory


class FindingService:
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
        self._objects = objects
        self.intake = intake
        self.decisions = decisions
        self.review = review
        self.precedents = precedents

    def get(self, finding_id: UUID) -> FindingView:
        with self._uow as uow:
            (view,) = self._views(uow, [uow.findings.get(finding_id)], as_of=None)
        return view

    def list_by_ids(self, finding_ids: Collection[UUID]) -> list[FindingView]:
        """These findings as they stand; NotFoundError names any that don't exist."""
        with self._uow as uow:
            found = uow.findings.list_by_ids(finding_ids)
            if missing := set(finding_ids) - {f.id for f in found}:
                raise NotFoundError(f"findings {', '.join(sorted(map(str, missing)))}")
            return self._views(uow, found, as_of=None)

    def list_by_cwe(self, cwe: str) -> list[FindingView]:
        """Every finding tagged with this CWE, in any repository (a fleet fix's targets)."""
        if not CWE_IDENTIFIER.fullmatch(cwe):
            raise ValidationError(f"{cwe!r} is not a CWE identifier (CWE-<n>)")
        with self._uow as uow:
            tagged = uow.cwes.find_by_identifier(cwe)
            if tagged is None:
                return []
            ids = [fc.finding_id for fc in uow.finding_cwes.list_for_cwe(tagged.id)]  # type: ignore[arg-type]
            return self._views(uow, uow.findings.list_by_ids(ids), as_of=None) if ids else []

    def occurrences(
        self, *, assessment_id: UUID | None = None, finding_ids: Collection[UUID] | None = None
    ) -> list[Occurrence]:
        """What one assessment reported, or every report of these findings (exactly one)."""
        if (assessment_id is None) == (finding_ids is None):
            raise ValidationError("occurrences of an assessment or of findings, exactly one")
        with self._uow as uow:
            if assessment_id is not None:
                return uow.occurrences.list_for_assessment(assessment_id)
            assert finding_ids is not None
            return uow.occurrences.list_for_findings(finding_ids)

    def locations(self, occurrence_ids: Collection[UUID]) -> list[Location]:
        """Where these occurrences were reported, by occurrence, path and line."""
        with self._uow as uow:
            return uow.locations.list_for_occurrences(occurrence_ids)

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
            views = self._views(
                uow, uow.findings.list_for_repository(filter.repository_id), filter.as_of
            )
        return sorted((v for v in views if filter.keeps(v)), key=_newest_first)

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
                for v in self._views(uow, uow.findings.list_for_repository(repository_id), as_of)
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
            views = self._views(uow, uow.findings.list_by_ids(ids), as_of=None) if ids else []
        return [v for v in views if v.disposition and v.disposition.validity == validity]

    def history(self, finding_id: UUID) -> list[Decision]:
        """Every decision on the finding, restated ones included, in judgement order."""
        with self._uow as uow:
            uow.findings.get(finding_id)
            return uow.decisions.list_for_finding(finding_id)

    def baseline(self, repository_id: UUID, as_of: datetime) -> list[FindingView]:
        """The repository's findings as they stood at `as_of`: reported by then, judged by then."""
        with self._uow as uow:
            return self._views(uow, uow.findings.list_for_repository(repository_id), as_of)

    def open_count(self, repository_id: UUID, severities: Sequence[Severity]) -> int:
        with self._uow as uow:
            return uow.open_counts.open_count(repository_id, severities)

    def summary(self, filter: FindingFilter, group_by: FindingDimension) -> list[FindingRollup]:
        """The filter's reported findings as they stood at `as_of`, counted by state per group,
        largest first. A finding counts in its primary CWE's group, and in each of its labels'."""
        with self._uow as uow:
            findings = uow.findings.list_for_repository(filter.repository_id)
            facts = FindingFacts.load(uow, findings, until=filter.as_of)
        groups: defaultdict[str | None, list[FindingView]] = defaultdict(list)
        for finding in findings:
            if not facts.reported_by(finding.id, filter.as_of):  # type: ignore[arg-type]
                continue  # never reported: no severity, and no baseline holds it either
            view = self._view(facts, finding, filter.as_of, {})
            if view is not None and filter.keeps(view):
                for key in _keys(view, group_by, facts, filter.as_of):
                    groups[key].append(view)
        return sorted(
            (_rollup(key, views) for key, views in groups.items()),
            key=lambda r: (-r.findings, r.key is None, r.key or ""),
        )

    def timeline(self, filter: FindingFilter, bucket: TimeBucket) -> list[FindingSeriesPoint]:
        """The filter's findings replayed bucket by bucket, from the first report to `as_of` (else
        to the last report or decision). Open, accepted, hardening and the risk index stand at each
        bucket's end; new, resolved, false positives and regressions happened within it."""
        with self._uow as uow:
            findings = uow.findings.list_for_repository(filter.repository_id)
            facts = FindingFacts.load(uow, findings, until=filter.as_of)
        first = {
            f.id: facts.at[seen[0].assessment_id]
            for f in findings
            if f.id and (seen := facts.reported_by(f.id, filter.as_of))
        }
        if not first:
            return []
        end = filter.as_of or max(
            [*facts.at.values(), *(d.occurred_at for ds in facts.decisions.values() for d in ds)]
        )
        replay = _Replay(self, facts, findings, filter, first)
        points = []
        window = bucket.window_of(min(first.values()))
        while window.start <= end:
            points.append(replay.point(window, min(window.end - _TICK, end)))
            window = bucket.window_of(window.end)
        return points

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
            facts = FindingFacts.load(uow, findings, until=filter.as_of)
            views = [v for v in self._views(uow, findings, filter.as_of, facts) if filter.keeps(v)]
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
        resolving = [d.occurred_at for d in decided if d.resolution == _RESOLVED]
        return FindingClock(
            view=view,
            reported_at=facts.at[reported[0].assessment_id] if reported else None,
            decided_at=min((d.occurred_at for d in decided), default=None),
            filed_at=filed.get(finding_id),
            resolved_at=max(resolving, default=None)
            if view.state() == FindingState.RESOLVED
            else None,
        )

    def _views(
        self,
        uow: TraustUnitOfWork,
        findings: Sequence[Finding],
        as_of: datetime | None,
        facts: FindingFacts | None = None,
    ) -> list[FindingView]:
        """One query per table for the set; a finding not yet reported at `as_of` is left out."""
        facts = facts or FindingFacts.load(uow, findings, until=as_of)
        latest_ids = [
            seen[-1].id
            for f in findings
            if f.id and (seen := facts.reported_by(f.id, as_of)) and seen[-1].id
        ]
        places: defaultdict[UUID, list[Location]] = defaultdict(list)
        for loc in uow.locations.list_for_occurrences(latest_ids) if latest_ids else ():
            places[loc.occurrence_id].append(loc)
        return [v for f in findings if (v := self._view(facts, f, as_of, places)) is not None]

    def _view(
        self,
        facts: FindingFacts,
        finding: Finding,
        as_of: datetime | None,
        places: Mapping[UUID, Sequence[Location]],
    ) -> FindingView | None:
        assert finding.id is not None
        reported = facts.reported_by(finding.id, as_of)
        if as_of is not None and not reported:
            return None
        latest = reported[-1] if reported else None
        disposition = facts.disposition(finding.id, as_of)
        severity = self._rating.effective_severity(latest, disposition)
        due = None
        if latest is not None and (disposition is None or disposition.is_open()):
            opened = facts.at[reported[0].assessment_id]
            due = self._rating.sla_due(severity, opened, latest.cvss_score)
        return FindingView(
            finding=finding,
            occurrence=latest,
            disposition=disposition,
            effective_severity=severity,
            sla_due=due,
            locations=tuple(places.get(latest.id, ())) if latest and latest.id else (),
            cwes=tuple(sorted(facts.cwes.get(finding.id, ()))),
            labels=tuple(facts.labels.get(finding.id, ())),
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
_RESOLVED = DispositionResolution.RESOLVED


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


def _by_severity(counts: Counter[Severity]) -> dict[Severity, int]:
    return {s: counts[s] for s in Severity}


def _rollup(key: str | None, views: Sequence[FindingView]) -> FindingRollup:
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
    filter: FindingFilter
    first: Mapping[UUID, datetime]
    views: dict[UUID, FindingView] = field(default_factory=dict)
    standing: dict[UUID, tuple[FindingState, Severity, float]] = field(default_factory=dict)
    states: Counter[FindingState] = field(default_factory=Counter)
    opened: Counter[Severity] = field(default_factory=Counter)
    last: datetime | None = None

    def __post_init__(self) -> None:
        self._by_id = {f.id: f for f in self.findings if f.id is not None}
        facts = self.facts
        self._events = sorted(
            [
                (facts.at[o.assessment_id], o.finding_id)
                for os in facts.reported.values()
                for o in os
            ]
            + [(d.occurred_at, d.finding_id) for ds in facts.decisions.values() for d in ds],
            key=lambda e: e[0],
        )
        self._next = 0

    def point(self, window: TimeWindow, cut: datetime) -> FindingSeriesPoint:
        since = self.last or window.start - _TICK
        new = resolved = false_positives = regressions = 0
        fixes: list[int] = []
        for finding_id in self._moved(cut):
            view = self.service._view(self.facts, self._by_id[finding_id], cut, {})
            if view is None:
                continue
            was = self.views.get(finding_id)
            self.views[finding_id] = view
            self._unstand(finding_id)
            if not self.filter.keeps(view):
                continue
            state = view.state()
            self._stand(finding_id, view, state)
            moved = was is None or was.state() is not state
            new += self.first[finding_id] >= window.start
            standing = _standing(self.facts.decided_by(finding_id, cut))
            if state is FindingState.RESOLVED and moved:
                resolved += 1
                fixed = [d.occurred_at for d in standing if d.resolution == _RESOLVED]
                if fixed:
                    days = (_day(max(fixed)) - _day(self.first[finding_id])).days
                    fixes.append(max(days, 0))
            elif state is FindingState.FALSE_POSITIVE and moved:
                false_positives += 1
            regressions += sum(
                d.occurred_at > since and d.resolution == _REGRESSION for d in standing
            )
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
            mttr_days=round(sum(fixes) / len(fixes), 1) if fixes else None,
            risk_index=round(sum(w for _, _, w in self.standing.values()), 1),
        )

    def _moved(self, cut: datetime) -> list[UUID]:
        """The findings with a report or decision up to `cut` not yet replayed, in event order."""
        start = self._next
        while self._next < len(self._events) and self._events[self._next][0] <= cut:
            self._next += 1
        return list(dict.fromkeys(fid for _, fid in self._events[start : self._next]))

    def _stand(self, finding_id: UUID, view: FindingView, state: FindingState) -> None:
        severity = view.effective_severity
        weight = 0.0
        if state is FindingState.OPEN:
            self.opened[severity] += 1
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
_REGRESSION = DispositionResolution.REGRESSION_INTRODUCED


def _standing(decisions: Sequence[Decision]) -> list[Decision]:
    """The decisions no later restatement replaced."""
    replaced = {d.restates_id for d in decisions if d.restates_id}
    return [d for d in decisions if d.id not in replaced]


def _day(at: datetime) -> date:
    return at.astimezone(UTC).date()
