"""The catalog: which dimensions and measures each subject serves, and the SQL
each maps to. Identifiers come only from here — a request names an enum member,
never a column."""

from __future__ import annotations

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.dashboard import Dimension, Measure, Subject


# The findings subject's facts, one column each; group keys are text on the wire
# (a repository id is its uuid string, a boolean is true/false, null is a state).
# `decided` renders and filters as canonical text on every engine: PostgreSQL's
# boolean::text is true/false, SQLite's integers are not.
def _columns(dialect: str) -> dict[Dimension, str]:
    decided = (
        "decided::text"
        if dialect == "postgresql"
        else "CASE WHEN decided THEN 'true' ELSE 'false' END"
    )
    return {
        Dimension.REPOSITORY: "repository_id",
        # The shipped product's slug, present only when the facts carry the estate
        # join (the service asks for it exactly when a query groups or filters by
        # product); a repository can ship in several products, so the join fans a
        # finding out per product and the count measures go distinct in that mode.
        Dimension.PRODUCT: "product",
        Dimension.STATE: "state",
        Dimension.SEVERITY: "severity",
        Dimension.CATEGORY: "category",
        Dimension.DECIDED: decided,
        Dimension.REASON: "reason",
        Dimension.STATUS: "status",
    }


# the oldest open finding's age: closed findings never set it
_OPEN_SINCE = "CASE WHEN state = 'open' THEN created_at END"
_AGE_DAYS = {
    "postgresql": f"extract(epoch from (current_timestamp - min({_OPEN_SINCE}))) / 86400",
    "sqlite": f"(julianday(current_timestamp) - julianday(min({_OPEN_SINCE})))",
}


def _aggregates(dialect: str, products: bool = False) -> dict[Measure, str]:
    # Under the estate join a finding has a row per product that ships its
    # repository: count(*) would double-count a shared repository's findings,
    # so the counts go distinct (identical without the join, one row per finding).
    counted = "count(distinct id)" if products else "count(*)"
    return {
        Measure.FINDINGS: counted,
        Measure.REPOSITORIES: "count(distinct repository_id)",
        Measure.OLDEST_OPEN_AGE: _AGE_DAYS.get(dialect, _AGE_DAYS["postgresql"]),
        Measure.REVIEW_ITEMS: counted,
    }


# What this build serves; the query schema states the intent, the catalog the
# present. Subjects and vocabulary beyond these refuse until their facts land.
_SERVED_MEASURES = frozenset({Measure.FINDINGS, Measure.REPOSITORIES, Measure.OLDEST_OPEN_AGE})
_FINDING_DIMENSIONS = frozenset(
    {
        Dimension.REPOSITORY,
        Dimension.PRODUCT,
        Dimension.STATE,
        Dimension.SEVERITY,
        Dimension.CATEGORY,
        Dimension.DECIDED,
    }
)
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
    order: tuple[Measure | Dimension, ...] = (),
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
    unordered = [key for key in order if not (key in served_measures or key in dimensions)]
    if unordered:
        raise ValidationError(
            f"the {subject} subject cannot order by {', '.join(map(str, unordered))}: order by a "
            "served measure or a dimension the query groups by"
        )


def columns(dimensions: tuple[Dimension, ...], dialect: str) -> list[str]:
    served = _columns(dialect)
    return [served[dimension] for dimension in dimensions]


def aggregates(measures: tuple[Measure, ...], dialect: str, *, products: bool = False) -> list[str]:
    served = _aggregates(dialect, products)
    return [served[measure] for measure in measures]


def order_key(by: Measure | Dimension, desc: bool, dialect: str, *, products: bool = False) -> str:
    expression = _aggregates(dialect, products).get(by) or _columns(dialect).get(by)
    assert expression is not None, by  # require() refused the rest
    return f"{expression} desc" if desc else expression
