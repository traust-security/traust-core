from __future__ import annotations

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.findings.test_intake import Target, audit, candidate, intake, rows
from tests.v1.services.findings.test_intake import engine as engine
from tests.v1.services.findings.test_intake import target as target
from traust_core.v1.errors import RepositoryError, ValidationError
from traust_core.v1.models.common import CodeSpan
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy


def snapshot(engine: Engine) -> dict[str, tuple[tuple[object, ...], ...]]:
    with SqlTraustUnitOfWork(engine) as uow:
        return {
            name: tuple(
                tuple(row)
                for row in uow.connection.execute(
                    sa.select(getattr(uow, name).table).order_by(getattr(uow, name).table.c.id)
                )
            )
            for name in (
                "assessments",
                "findings",
                "occurrences",
                "locations",
                "cwes",
                "finding_cwes",
                "finding_labels",
            )
        }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("reported_severity", "urgent"),
        ("reported_severity", "info"),
        ("reported_severity", None),
        ("category", 42),
        ("category", {"label": "injection"}),
        ("origin", "unknown-origin"),
        ("origin", "vuln_scan"),
        ("title", None),
        ("rule", []),
        ("cwes", (42,)),
        ("cwes", ("CWE89",)),
        ("confidence", "not-a-number"),
        ("locations", None),
        ("locations", (None,)),
        ("locations", ()),
        ("unexpected", "unsupported"),
    ],
)
def test_mutated_candidate_batch_is_refused_without_partial_rows(
    engine: Engine, target: Target, field: str, value: object
) -> None:
    run = audit(engine, target)
    invalid = candidate(target, label="BAD-002").model_copy(update={field: value})
    before = snapshot(engine)
    with pytest.raises(ValidationError):
        intake(engine).accept(run, [candidate(target, label="GOOD-001"), invalid])
    assert snapshot(engine) == before


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("path", 42),
        ("path", ""),
        ("line", "not-a-line"),
        ("line", 0),
        ("line", -1),
        ("symbol", ""),
        ("symbol", []),
        ("unexpected", "unsupported"),
    ],
)
def test_nested_mutated_locations_are_refused_without_partial_rows(
    engine: Engine, target: Target, field: str, value: object
) -> None:
    run = audit(engine, target)
    span = CodeSpan(path="bad.go", line=7, symbol="Handle").model_copy(update={field: value})
    invalid = candidate(target, label="BAD-002").model_copy(update={"locations": (span,)})
    before = snapshot(engine)
    with pytest.raises(ValidationError):
        intake(engine).accept(run, [candidate(target, label="GOOD-001"), invalid])
    assert snapshot(engine) == before


def test_valid_mutated_candidate_remains_unrated_and_exactly_replayable(
    engine: Engine, target: Target
) -> None:
    run = audit(engine, target)
    reported = candidate(target).model_copy(
        update={
            "reported_severity": "unrated",
            "origin": None,
            "category": "team-specific-label",
            "locations": (CodeSpan(path="handler.go", line=41, symbol="Handle"),),
        }
    )
    service = intake(engine)
    first = service.accept(run, [reported])
    before = snapshot(engine)
    again = service.accept(run, [reported])
    assert again.findings == first.findings
    assert again.created == ()
    assert snapshot(engine) == before
    got = rows(engine, first.created[0])
    assert got["occurrences"][0].severity == "unrated"
    assert got["occurrences"][0].assessment_id == run
    assert got["labels"] == [("category", "team-specific-label")]
    with SqlTraustUnitOfWork(engine) as uow:
        [location] = uow.locations.list_for_occurrence(got["occurrences"][0].id)
    assert (location.path, location.line_start, location.symbol) == ("handler.go", 41, "Handle")


def test_caught_invalid_intake_marks_the_shared_transaction_rollback_only(
    engine: Engine, target: Target
) -> None:
    run = audit(engine, target)
    before = snapshot(engine)
    unit = SqlTraustUnitOfWork(engine)
    service = FindingIntake(unit, IdentityPolicy(), TaxonomyPolicy())
    with unit:
        Seed(unit).assessment(target.ref)
        invalid = candidate(target).model_copy(update={"origin": "unknown-origin"})
        with pytest.raises(ValidationError):
            service.accept(run, [invalid])
        with pytest.raises(RepositoryError, match="rollback-only"):
            unit.commit()
    assert snapshot(engine) == before
