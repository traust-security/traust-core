from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime
from typing import Any
from uuid import UUID

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.assessment import Artifact
from traust_core.v1.models.common import (
    Page,
    PageRequest,
    TimeBucket,
    decode_cursor,
    encode_cursor,
)
from traust_core.v1.models.findings import (
    Decision,
    Disposition,
    Finding,
    FindingDimension,
    FindingFilter,
    FindingLabel,
    FindingRollup,
    FindingSeriesPoint,
    FindingView,
    Location,
    Occurrence,
    SurfaceCoverage,
)
from traust_core.v1.models.integrity import FingerprintInput
from traust_core.v1.models.vocabulary import Severity
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey, ObjectStore
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.intake import FindingIntake
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

    def history(self, finding_id: UUID) -> list[Decision]:
        return self.decisions.list_for_finding(finding_id)

    def baseline(self, repository_id: UUID, as_of: datetime) -> list[FindingView]:
        """The repository's findings as they stood at `as_of`: reported by then, judged by then."""
        with self._uow as uow:
            return self._views(uow, uow.findings.list_for_repository(repository_id), as_of)

    def open_count(self, repository_id: UUID, severities: Sequence[Severity]) -> int:
        with self._uow as uow:
            return uow.open_counts.open_count(repository_id, severities)

    def summary(self, filter: FindingFilter, group_by: FindingDimension) -> list[FindingRollup]:
        raise NotImplementedError("stub: replaces findings_summary, pattern_exposure, dashboards")

    def timeline(self, filter: FindingFilter, bucket: TimeBucket) -> list[FindingSeriesPoint]:
        raise NotImplementedError("stub: replaces build_cumulative.py, build_trends buckets")

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
        ids = [f.id for f in findings if f.id is not None]
        decisions: defaultdict[UUID, list[Decision]] = defaultdict(list)
        for d in uow.decisions.list_for_findings(ids, until=as_of):
            decisions[d.finding_id].append(d)
        occurrences = uow.occurrences.list_for_findings(ids)
        assessments = uow.assessments.list_by_ids(
            {o.assessment_id for o in occurrences}
            | {d.assessment_id for ds in decisions.values() for d in ds if d.assessment_id}
        )
        at = {a.id: a.occurred_at for a in assessments}
        seen: defaultdict[UUID, list[Occurrence]] = defaultdict(list)
        for o in sorted(occurrences, key=lambda o: at[o.assessment_id]):
            if as_of is None or at[o.assessment_id] <= as_of:
                seen[o.finding_id].append(o)
        latest_ids = [ocs[-1].id for ocs in seen.values() if ocs[-1].id]
        places: defaultdict[UUID, list[Location]] = defaultdict(list)
        for loc in uow.locations.list_for_occurrences(latest_ids) if latest_ids else ():
            places[loc.occurrence_id].append(loc)
        links = uow.finding_cwes.list_for_findings(ids) if ids else []
        names = {c.id: c.identifier for c in uow.cwes.list_by_ids({fc.cwe_id for fc in links})}
        cwes: defaultdict[UUID, list[str]] = defaultdict(list)
        for fc in links:
            cwes[fc.finding_id].append(names[fc.cwe_id])
        tags: defaultdict[UUID, list[FindingLabel]] = defaultdict(list)
        for fl in uow.finding_labels.list_for_findings(ids) if ids else ():
            tags[fl.finding_id].append(fl)
        views = []
        for finding in findings:
            assert finding.id is not None
            reported, said = seen[finding.id], decisions[finding.id]
            if as_of is not None and not reported:
                continue
            latest = reported[-1] if reported else None
            disposition = Disposition.fold(finding.id, said) if said else None
            severity = self._rating.effective_severity(latest, disposition)
            due = None
            if latest is not None and (disposition is None or disposition.is_open()):
                opened = at[reported[0].assessment_id]
                due = self._rating.sla_due(severity, opened, latest.cvss_score)
            views.append(
                FindingView(
                    finding=finding,
                    occurrence=latest,
                    disposition=disposition,
                    effective_severity=severity,
                    sla_due=due,
                    locations=tuple(places[latest.id]) if latest and latest.id else (),
                    cwes=tuple(sorted(cwes[finding.id])),
                    labels=tuple(tags[finding.id]),
                )
            )
        return views


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
