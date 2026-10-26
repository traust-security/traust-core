"""The isolation-review gate past its schema, ported from traust's validate_isolation_review.py
cross-reference: each `gaps[].interface_id` names an `interfaces[].id`. Through
`AssessmentService.check_audit` and `record` as `Context.services()` reaches them."""

from __future__ import annotations

import copy
import json
from typing import Any
from uuid import UUID

import pytest

from tests.v1.services import test_assessment_record as recording
from tests.v1.services.test_assessment_record import ISOLATION, REPORT, record
from traust_core.v1.context import Context
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import IsolationReviewArtifact
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.isolation_review import GapInterfaces
from traust_core.v1.services.lint import LintContext

engine, context, ref = recording.engine, recording.context, recording.ref

BASE = json.loads(ISOLATION.payload)


def review(interfaces: tuple[str, ...], gaps: tuple[str, ...]) -> IsolationReviewArtifact:
    doc = copy.deepcopy(BASE)
    template, gap = doc["interfaces"][0], doc["gaps"][0]
    doc["interfaces"] = [{**template, "id": i} for i in interfaces]
    doc["gaps"] = [{**gap, "interface_id": g} for g in gaps]
    return IsolationReviewArtifact.from_document(doc)


@pytest.mark.parametrize(
    ("interfaces", "gaps", "flagged"),
    [
        (("IF-1",), ("IF-1",), {}),
        (("IF-1", "IF-2"), (), {}),
        (("IF-1", "IF-2"), ("IF-2", "IF-1", "IF-2"), {}),
        (("IF-1",), ("IF-2",), {"gaps[0]": "IF-2"}),
        (
            ("IF-1", "IF-2"),
            ("IF-1", "IF-9", "IF-2", "IF-10"),
            {"gaps[1]": "IF-9", "gaps[3]": "IF-10"},
        ),
        ((), ("IF-1",), {"gaps[0]": "IF-1"}),
        ((), (), {}),
    ],
    ids=["named", "no-gaps", "repeats", "dangling", "two-dangling", "no-interfaces", "empty"],
)
def test_each_gap_names_a_listed_interface(
    context: Context, interfaces: tuple[str, ...], gaps: tuple[str, ...], flagged: dict[str, str]
) -> None:
    report = context.services().assessment.check_audit(review(interfaces, gaps))
    assert {v.item: v.rule for v in report.violations} == dict.fromkeys(
        flagged, "isolation-review.gap-interfaces"
    )
    for v in report.violations:
        assert f"interface_id '{flagged[v.item]}' does not match any interfaces[].id" == v.message
    assert report.passed is not flagged


def test_the_recorded_fixture_passes(context: Context) -> None:
    assert context.services().assessment.check_audit(ISOLATION).passed


def test_the_rule_checks_isolation_reviews_only() -> None:
    with pytest.raises(ValidationError, match="checks isolation reviews, not ReportArtifact"):
        GapInterfaces().check(REPORT, LintContext())


def test_record_refuses_a_review_failing_its_gate(context: Context, ref: UUID) -> None:
    with pytest.raises(ValidationError, match=r"gaps\[0\]: interface_id 'IF-7'"):
        record(
            context, review(("IF-1",), ("IF-7",)), ref, AssessmentKind.ISOLATION_REVIEW_CANONICAL
        )
    with SqlTraustUnitOfWork(context.database) as uow:
        assert uow.assessments.list_for_ref(ref) == []


def test_record_takes_a_review_passing_its_gate(context: Context, ref: UUID) -> None:
    doc: Any = review(("IF-1", "IF-2"), ("IF-2",))
    assert record(context, doc, ref, AssessmentKind.ISOLATION_REVIEW_CANONICAL).id is not None
