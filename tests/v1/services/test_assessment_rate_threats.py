"""`AssessmentService.rate_threats` through `Context.services()`: each threat's OWASP risk_rating
rebuilt from its factors, as traust's `reporting rate-threats` did with contracts' `risk_rating`
(expected ratings are that function's output for the OWASP worked example)."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from tests.v1.services import test_assessment_record as recording
from tests.v1.services.test_assessment_record import fixture
from traust_core.v1.context import Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.artifacts import ThreatModelArtifact
from traust_core.v1.models.findings import (
    BUSINESS_IMPACT_FACTORS,
    LIKELIHOOD_FACTORS,
    TECHNICAL_IMPACT_FACTORS,
    RatingInputs,
)
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.assessment import AssessmentService

engine, context = recording.engine, recording.context

L = dict(zip(LIKELIHOOD_FACTORS, [5, 2, 7, 1, 3, 6, 9, 2], strict=True))
T = dict(zip(TECHNICAL_IMPACT_FACTORS, [9, 7, 5, 8], strict=True))
B = dict(zip(BUSINESS_IMPACT_FACTORS, [1, 2, 1, 5], strict=True))
TECHNICAL = {
    "method": "owasp-risk-rating",
    "likelihood": {"factors": L, "score": 4.375, "level": "medium"},
    "impact": {"basis": "technical", "technical": T, "score": 7.25, "level": "high"},
    "severity": "high",
}
BUSINESS = {
    "method": "owasp-risk-rating",
    "likelihood": {"factors": L, "score": 4.375, "level": "medium"},
    "impact": {
        "basis": "business",
        "technical": T,
        "score": 2.25,
        "level": "low",
        "business": B,
    },
    "severity": "low",
    "rationale": {"motive": "an insider gains little"},
}
MODEL = json.loads(fixture("assessments/widget-threat-model.json"))


def draft(rating: Any) -> dict[str, Any]:
    """The widget model with T2's rating replaced; T1 states none."""
    model = copy.deepcopy(MODEL)
    model["threats"][1]["risk_rating"] = rating
    return model


def factors_only(likelihood: Any = L, technical: Any = T, **impact: Any) -> dict[str, Any]:
    return {"likelihood": {"factors": likelihood}, "impact": {"technical": technical, **impact}}


@pytest.mark.parametrize(
    ("stated", "rebuilt", "changed"),
    [
        (factors_only(), TECHNICAL, ("T2",)),
        (
            {**factors_only(business=B), "rationale": BUSINESS["rationale"]},
            BUSINESS,
            ("T2",),
        ),
        ({**TECHNICAL, "severity": "critical"}, TECHNICAL, ("T2",)),
        (
            {**TECHNICAL, "likelihood": {"factors": L, "score": 9, "level": "high"}},
            TECHNICAL,
            ("T2",),
        ),
        (TECHNICAL, TECHNICAL, ()),
        (BUSINESS, BUSINESS, ()),
    ],
    ids=["draft", "business-preferred", "wrong-severity", "wrong-score", "rated", "rated-biz"],
)
def test_each_rating_is_rebuilt_from_its_factors(
    context: Context, stated: Any, rebuilt: Any, changed: tuple[str, ...]
) -> None:
    model = draft(stated)
    before = copy.deepcopy(model)
    got = context.services().assessment.rate_threats(model)
    assert got.model["threats"][1]["risk_rating"] == rebuilt
    assert (got.changed, got.failed) == (changed, {})
    assert "risk_rating" not in got.model["threats"][0]
    assert model == before
    ThreatModelArtifact.from_document(json.loads(json.dumps(got.model)))


@pytest.mark.parametrize(
    ("stated", "reason"),
    [
        (factors_only({**L, "motive": 10}), "0 to 9"),
        (factors_only({**L, "motive": True}), "likelihood.motive: Input should be a valid integer"),
        (factors_only({**L, "motive": 2.0}), "likelihood.motive: Input should be a valid integer"),
        (factors_only({k: v for k, v in L.items() if k != "awareness"}), "['awareness']"),
        (factors_only(technical={**T, "extra": 1}), "unknown factors ['extra']"),
        (factors_only(basis="business"), "needs its factor set"),
        ({"likelihood": {}, "impact": {}}, "missing factors"),
    ],
    ids=["out-of-range", "bool", "float", "missing", "unknown", "basis-without-set", "empty"],
)
def test_unratable_factors_are_named_and_left_as_stated(
    context: Context, stated: Any, reason: str
) -> None:
    got = context.services().assessment.rate_threats(draft(stated))
    assert got.changed == ()
    assert list(got.failed) == ["T2"]
    assert reason in got.failed["T2"]
    assert not got.failed["T2"].startswith("Value error")
    assert got.model["threats"][1]["risk_rating"] == stated


def test_a_model_with_no_ratings_is_unchanged(context: Context) -> None:
    model = {**MODEL, "threats": [MODEL["threats"][0]]}
    got = context.services().assessment.rate_threats(model)
    assert (got.model, got.changed, got.failed) == (model, (), {})


def test_rating_threats_needs_the_rating_policy(context: Context) -> None:
    service = AssessmentService(SqlTraustUnitOfWork(context.database))
    with pytest.raises(ConfigError, match="needs the rating policy"):
        service.rate_threats(MODEL)


def test_a_rating_needs_factors_or_a_severity() -> None:
    with pytest.raises(ValueError, match="factor scores or a severity"):
        RatingInputs(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
