from __future__ import annotations

import json
from collections.abc import Collection, Sequence
from dataclasses import replace
from datetime import datetime
from typing import Any
from uuid import UUID

from traust_core.v1.errors import NotFoundError, ValidationError
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
    FindingDimension,
    FindingFilter,
    FindingRollup,
    FindingSeriesPoint,
    FindingView,
    SurfaceCoverage,
)
from traust_core.v1.models.integrity import FingerprintInput
from traust_core.v1.models.vocabulary import Severity, Validity
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey, ObjectStore
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.intake import FindingIntake
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.findings.review import FindingReview
from traust_core.v1.services.findings.views import FindingViewQuery


class FindingService:
    def __init__(
        self,
        uow: TraustUnitOfWork,
        intake: FindingIntake,
        decisions: FindingDecisions,
        review: FindingReview,
        precedents: FindingPrecedents,
        views: FindingViewQuery,
        objects: ObjectStore,
    ) -> None:
        self._uow = uow
        self._views = views
        self._objects = objects
        self.intake = intake
        self.decisions = decisions
        self.review = review
        self.precedents = precedents

    def get(self, finding_id: UUID) -> FindingView:
        with self._uow as uow:
            (view,) = self._views.views(uow, [uow.findings.get(finding_id)])
        return view

    def list_by_ids(self, finding_ids: Collection[UUID]) -> list[FindingView]:
        """These findings as they stand; NotFoundError names any that don't exist."""
        with self._uow as uow:
            found = uow.findings.list_by_ids(finding_ids)
            if missing := set(finding_ids) - {f.id for f in found}:
                raise NotFoundError(f"findings {', '.join(sorted(map(str, missing)))}")
            return self._views.views(uow, found, as_of=None)

    def list(self, filter: FindingFilter, page: PageRequest) -> Page[FindingView]:
        """A repository's findings newest first, narrowed by their folded disposition."""
        if page.limit <= 0:
            raise ValidationError("page limit must be positive")
        after = decode_cursor(page.cursor)
        with self._uow as uow:
            views = self._views.views(
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
            views = self._views.views(uow, uow.findings.list_by_ids(ids), as_of=None) if ids else []
        return [v for v in views if v.disposition and v.disposition.validity == validity]

    def history(self, finding_id: UUID) -> list[Decision]:
        return self.decisions.list_for_finding(finding_id)

    def baseline(self, repository_id: UUID, as_of: datetime) -> list[FindingView]:
        """The repository's findings as they stood at `as_of`: reported by then, judged by then."""
        with self._uow as uow:
            return self._views.views(uow, uow.findings.list_for_repository(repository_id), as_of)

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
