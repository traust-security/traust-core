"""DashboardFacts: the seam dashboards read through. The SQL lives in the
repositories layer (traust.findings.dashboard_facts); this protocol is the
contract between them — dashboards never see storage."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.dashboard import Subject


class DashboardFacts(Protocol):
    """Aggregates over a subject, filtered to repositories, grouped and
    ordered, capped. Rows are positional: the group values, then the
    measure values."""

    def aggregate(
        self,
        subject: Subject,
        repository_ids: frozenset[UUID] | None,
        columns: list[str],
        aggregates: list[str],
        predicates: list[tuple[str, tuple[str, ...]]],
        order: list[str],
        limit: int,
    ) -> list[tuple[object, ...]]: ...
