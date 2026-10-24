from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta
from typing import Any
from uuid import UUID

from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.assessment import Artifact
from traust_core.v1.models.common import (
    Page,
    PageRequest,
    TimeBucket,
    TimeWindow,
    decode_cursor,
    encode_cursor,
)
from traust_core.v1.models.findings import (
    Decision,
    Finding,
    FindingDimension,
    FindingFilter,
    FindingRollup,
    FindingSeriesPoint,
    FindingState,
    FindingView,
    Location,
    SurfaceCoverage,
)
from traust_core.v1.models.integrity import FingerprintInput
from traust_core.v1.models.vocabulary import DispositionResolution, Severity, Validity
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey, ObjectStore
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.facts import FindingFacts
from traust_core.v1.services.findings.identity import primary_cwe
from traust_core.v1.services.findings.intake import CATEGORY, FindingIntake
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.findings.rating import RatingPolicy
from traust_core.v1.services.findings.review import FindingReview


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

    def list(self, filter: FindingFilter, page: PageRequest) -> Page[FindingView]:
        """A repository's findings newest first, narrowed by their folded disposition."""
        if page.limit <= 0:
            raise ValidationError("page limit must be positive")
        after = decode_cursor(page.cursor)
        with self._uow as uow:
            views = self._views(
                uow, uow.findings.list_for_repository(filter.repository_id), filter.as_of
            )
        kept = sorted((v for v in views if filter.keeps(v)), key=_newest_first)
        if after is not None:
            kept = [v for v in kept if _newest_first(v) > _newest_first_key(*after)]
        items = kept[: page.limit]
        cursor = None
        if len(kept) > page.limit:
            last = items[-1].finding
            assert last.created_at is not None and last.id is not None
            cursor = encode_cursor(last.created_at, last.id)
        return Page(items=tuple(items), next=cursor)

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
            repo = uow.repositories.get(repository_id)
            refs = [r.id for r in uow.repository_refs.list_for(repository_id) if r.id]
            at = {
                a.id: a.occurred_at
                for a in uow.assessments.list_for_refs(refs)
                if a.id and (as_of is None or a.occurred_at <= as_of)
            }
            docs = sorted(
                uow.artifacts.list_for_assessments(at, (_AUDIT, *_SCANS)),
                key=lambda d: (at[d.assessment_id], d.created_at),  # type: ignore[index]
            )
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
            body = self._document(doc)
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
        """The filter's findings as they stood at `as_of`, counted by state per group, largest
        first. A finding counts in its primary CWE's group, and in every label's group it has."""
        with self._uow as uow:
            findings = uow.findings.list_for_repository(filter.repository_id)
            facts = FindingFacts.load(uow, findings, until=filter.as_of)
        groups: defaultdict[str | None, list[FindingView]] = defaultdict(list)
        for finding in findings:
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

    def _document(self, artifact: Artifact) -> dict[str, Any]:
        ref = self._objects.stat(ObjectKey.parse(artifact.uri))
        return json.loads(self._objects.get(replace(ref, sha256=artifact.digest)))

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

    def _views(
        self, uow: TraustUnitOfWork, findings: Sequence[Finding], as_of: datetime | None
    ) -> list[FindingView]:
        """One query per table for the set; a finding not yet reported at `as_of` is left out."""
        facts = FindingFacts.load(uow, findings, until=as_of)
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
    """The views at successive bucket ends; a finding is re-folded only when something moved."""

    service: FindingService
    facts: FindingFacts
    findings: Sequence[Finding]
    filter: FindingFilter
    first: Mapping[UUID, datetime]
    views: dict[UUID, FindingView] = field(default_factory=dict)
    last: datetime | None = None

    def point(self, window: TimeWindow, cut: datetime) -> FindingSeriesPoint:
        states: Counter[FindingState] = Counter()
        opened: Counter[Severity] = Counter()
        new = resolved = false_positives = regressions = 0
        risk = 0.0
        fixes: list[int] = []
        for finding in self.findings:
            assert finding.id is not None
            was = self.views.get(finding.id)
            said = self.facts.changed(finding.id, self.last or window.start - _TICK, cut)
            view = self.service._view(self.facts, finding, cut, {}) if said is not None else was
            if view is None:
                continue
            self.views[finding.id] = view
            if not self.filter.keeps(view):
                continue
            state = view.state()
            states[state] += 1
            moved = was is None or was.state() is not state
            new += self.first[finding.id] >= window.start
            standing = _standing(self.facts.decided_by(finding.id, cut))
            if state is FindingState.OPEN:
                opened[view.effective_severity] += 1
                risk += self.service._rating.risk_weight(view.occurrence, view.effective_severity)
            elif state is FindingState.RESOLVED and moved:
                resolved += 1
                fixed = [d.occurred_at for d in standing if d.resolution == _RESOLVED]
                if fixed:
                    days = (_day(max(fixed)) - _day(self.first[finding.id])).days
                    fixes.append(max(days, 0))
            elif state is FindingState.FALSE_POSITIVE and moved:
                false_positives += 1
            if said:
                regressions += sum(d in said and d.resolution == _REGRESSION for d in standing)
        self.last = cut
        return FindingSeriesPoint(
            bucket=window.start,
            open_by_severity=_by_severity(opened),
            new=new,
            resolved=resolved,
            accepted=states[FindingState.ACCEPTED],
            hardening=states[FindingState.HARDENING],
            false_positives=false_positives,
            regressions=regressions,
            mttr_days=round(sum(fixes) / len(fixes), 1) if fixes else None,
            risk_index=round(risk, 1),
        )


_RESOLVED = DispositionResolution.RESOLVED
_REGRESSION = DispositionResolution.REGRESSION_INTRODUCED


def _standing(decisions: Sequence[Decision]) -> list[Decision]:
    """The decisions no later restatement replaced."""
    replaced = {d.restates_id for d in decisions if d.restates_id}
    return [d for d in decisions if d.id not in replaced]


def _day(at: datetime) -> date:
    return at.astimezone(UTC).date()
