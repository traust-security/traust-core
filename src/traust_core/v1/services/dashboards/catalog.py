"""The catalog: which dimensions and measures each subject serves, and the SQL
each maps to. Identifiers come only from here — a request names an enum member,
never a column."""

from __future__ import annotations

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.dashboard import Dimension, Measure, Subject

# The findings subject's facts, one column each; group keys are text on the wire
# (a repository id is its uuid string, a boolean is true/false, null is a state).
_COLUMNS: dict[Dimension, str] = {
    Dimension.REPOSITORY: "repository_id",
    Dimension.STATE: "state",
    Dimension.SEVERITY: "severity",
    Dimension.CATEGORY: "category",
    Dimension.DECIDED: "decided",
    Dimension.REASON: "reason",
    Dimension.STATUS: "status",
}

_AGE_DAYS = {
    "postgresql": "extract(epoch from (current_timestamp - min(created_at))) / 86400",
    "sqlite": "(julianday(current_timestamp) - julianday(min(created_at)))",
}


def _aggregates(dialect: str) -> dict[Measure, str]:
    return {
        Measure.FINDINGS: "count(*)",
        Measure.REPOSITORIES: "count(distinct repository_id)",
        Measure.OLDEST_OPEN_AGE: _AGE_DAYS.get(dialect, _AGE_DAYS["postgresql"]),
        Measure.REVIEW_ITEMS: "count(*)",
    }


# What this build serves; the query schema states the intent, the catalog the
# present. Subjects and vocabulary beyond these refuse until their facts land.
_SERVED_MEASURES = frozenset({Measure.FINDINGS, Measure.REPOSITORIES, Measure.OLDEST_OPEN_AGE})
_FINDING_DIMENSIONS = frozenset(_COLUMNS) - {Dimension.REASON, Dimension.STATUS}
SERVED: dict[Subject, tuple[frozenset[Dimension], frozenset[Measure]]] = {
    Subject.FINDINGS: (_FINDING_DIMENSIONS, _SERVED_MEASURES),
    # a review item with its finding's current answer: the countersign queue's counts
    Subject.REVIEW_ITEMS: (
        frozenset(
            {
                Dimension.REPOSITORY,
                Dimension.REASON,
                Dimension.STATUS,
                Dimension.STATE,
                Dimension.SEVERITY,
            }
        ),
        frozenset({Measure.REVIEW_ITEMS}),
    ),
}

# The subjects that exist in the facts layer; work_items waits on a stamped status.
_FACTS: frozenset[Subject] = frozenset({Subject.FINDINGS, Subject.REVIEW_ITEMS})


def require(
    subject: Subject,
    dimensions: tuple[Dimension, ...],
    measures: tuple[Measure, ...],
    where: dict[Dimension, tuple[str, ...]],
) -> None:
    """Refuse what this build does not serve, before any SQL is built."""
    served_dims, served_measures = SERVED.get(subject, (frozenset(), frozenset()))
    if subject not in _FACTS:
        raise ValidationError(f"the {subject} subject is not yet served")
    unknown = [d for d in dimensions if d not in served_dims]
    if unknown:
        raise ValidationError(
            f"the {subject} subject does not group by {', '.join(map(str, unknown))}"
        )
    unknown = [m for m in measures if m not in served_measures]
    if unknown:
        raise ValidationError(
            f"the {subject} subject does not measure {', '.join(map(str, unknown))}"
        )
    unknown = [d for d in where if d not in served_dims]
    if unknown:
        raise ValidationError(
            f"the {subject} subject does not filter by {', '.join(map(str, unknown))}"
        )


def columns(dimensions: tuple[Dimension, ...]) -> list[str]:
    return [_COLUMNS[dimension] for dimension in dimensions]


def aggregates(measures: tuple[Measure, ...], dialect: str) -> list[str]:
    served = _aggregates(dialect)
    return [served[measure] for measure in measures]


def order_key(by: Measure | Dimension, desc: bool, dialect: str) -> str:
    expression = _aggregates(dialect).get(by) or _COLUMNS.get(by)
    assert expression is not None, by  # require() refused the rest
    return f"{expression} desc" if desc else expression
