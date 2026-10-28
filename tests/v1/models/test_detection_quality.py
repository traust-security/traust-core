"""Precedent-card parsing (the reject gate) and predicates.

Scenarios ported from traust tests/test_compile_precedent_cards.py (traust b48ff14).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.code_facts import ConfigTriple, RouteGuardRow
from traust_core.v1.models.detection_quality import CardDeck, Predicate, fact_fields

PILOT = Path(__file__).parents[2] / "fixtures/detection_quality/precedent-cards.yaml"


def route_card(**over: Any) -> dict[str, Any]:
    return {
        "id": "pc-test-route",
        "source_findings": [{"finding_id": "REPO-abc1234-001", "repo": "repo"}],
        "weakness_shape": "A route lacks the guard its siblings carry.",
        "enumerator": "route-guards",
        "predicate": {
            "all": [
                {"field": "judgement_required", "op": "truthy"},
                {"field": "guards", "op": "empty"},
                {"field": "scope_guards", "op": "empty"},
            ]
        },
        "judge_question": "Is the route reachable unauthenticated?",
        "expected_fp_sources": ["healthz endpoints"],
        "severity_hint": "high",
    } | over


def config_card(**over: Any) -> dict[str, Any]:
    return {
        "id": "pc-test-dsn",
        "source_findings": [{"id": "REPO-abc1234-002"}],
        "weakness_shape": "A DSN default composes to plaintext.",
        "enumerator": "config-matrix",
        "predicate": {
            "all": [
                {"field": "class", "op": "eq", "value": "dsn"},
                {"field": "judgement_required", "op": "truthy"},
                {
                    "field": "effective_default",
                    "op": "matches",
                    "value": "sslmode=disable|^postgres://",
                },
            ]
        },
        "judge_question": "Does the default reach a production path?",
        "expected_fp_sources": ["dev compose files"],
    } | over


def reasons(card: dict[str, Any]) -> str:
    deck = CardDeck.parse({"cards": [card]})
    assert not deck.cards
    return " ".join(deck.rejected[0].reasons)


def test_valid_cards_parse_with_their_provenance() -> None:
    deck = CardDeck.parse({"cards": [route_card(), config_card()]})
    assert not deck.rejected
    assert [c.source_findings[0].finding_id for c in deck.cards] == [
        "REPO-abc1234-001",
        "REPO-abc1234-002",
    ]
    assert deck.cards[1].severity_hint == "medium"


def test_a_prose_checklist_is_rejected_with_every_reason() -> None:
    card = route_card(checklist=["look at all the routes"])
    del card["predicate"]
    found = reasons(card)
    assert "no_predicate" in found and "prose_checklist_fields" in found


@pytest.mark.parametrize(
    ("over", "reason"),
    [
        ({"enumerator": "manual-review"}, "unknown_enumerator"),
        (
            {"predicate": {"field": "is_actually_dangerous", "op": "truthy"}},
            "is_actually_dangerous",
        ),
        ({"predicate": {"field": "guards", "op": "looks_suspicious"}}, "unknown op"),
        ({"predicate": {"field": "guards", "op": "eq"}}, "requires a `value`"),
        ({"predicate": {"field": "guards", "op": "empty", "value": 1}}, "takes no `value`"),
        ({"predicate": {"field": "guards", "op": "empty", "why": "x"}}, "unknown leaf keys"),
        ({"predicate": {"all": []}}, "must be a non-empty list"),
        ({"predicate": {"all": [{"field": "guards", "op": "empty"}], "not": {}}}, "exactly one"),
        ({"predicate": {"not": "guards"}}, "non-empty mapping"),
        ({"predicate": {"field": "pattern", "op": "matches", "value": "(unclosed"}}, "bad regex"),
        ({"severity_hint": "catastrophic"}, "severity_hint"),
        ({"source_findings": [{"repo": "no id"}]}, "source_findings"),
        ({"weakness_shape": 3}, "weakness_shape"),
    ],
)
def test_a_card_that_is_not_a_recipe_is_rejected(over: dict[str, Any], reason: str) -> None:
    assert reason in reasons(route_card(**over))


def test_missing_required_fields_are_all_named() -> None:
    card = route_card()
    del card["judge_question"], card["source_findings"]
    found = reasons(card)
    assert "`judge_question`" in found and "`source_findings`" in found


def test_probe_run_fields_need_the_execution_acknowledgement() -> None:
    card = route_card(
        enumerator="sanitizer-probes",
        predicate={"field": "outcome", "op": "eq", "value": "survived"},
    )
    assert "'outcome'" in reasons(card)
    card["enumerator_options"] = {"run": True}
    assert CardDeck.parse({"cards": [card]}).cards[0].enumerator_options.run


def test_a_symbol_card_names_its_query() -> None:
    card = route_card(
        enumerator="symbol-index", predicate={"field": "name", "op": "matches", "value": "Handler$"}
    )
    assert "symbol_index_query_missing" in reasons(card)
    card["enumerator_options"] = {"query": {"mode": "defs", "name": "Handler"}}
    assert CardDeck.parse({"cards": [card]}).cards
    card["predicate"] = {"field": "is_def", "op": "truthy"}
    assert "'is_def'" in reasons(card)  # a references field, on a definitions query
    card["enumerator_options"] = {"query": {"mode": "refs", "name": "Handler"}}
    assert CardDeck.parse({"cards": [card]}).cards


def test_a_card_file_without_a_cards_list_is_refused() -> None:
    with pytest.raises(ValidationError, match="cards"):
        CardDeck.parse({"card": []})
    assert CardDeck.parse({"cards": ["x"]}).rejected[0].reasons == ("card must be a mapping",)


def test_the_pilot_has_four_recipes_and_its_one_pinned_reject() -> None:
    deck = CardDeck.parse(yaml.safe_load(PILOT.read_text()))
    assert len(deck.cards) == 4 and not deck.unexpected
    [reject] = deck.rejected
    assert reject.id == "pc-REJECT-oauth-callback-prose" and reject.expect_reject
    found = " ".join(reject.reasons)
    for reason in ("unknown_enumerator", "no_predicate", "prose_checklist_fields"):
        assert reason in found


def test_field_paths_follow_the_fact_models_serialised_names() -> None:
    config = fact_fields(ConfigTriple)
    assert {"class", "source.system", "sink.status", "sink.sites"} <= config
    assert "config_class" not in config and "source" not in config
    routes = fact_fields(RouteGuardRow)
    assert {"handler.expr", "handler.resolved.path", "registration.line", "guards"} <= routes


ROW: dict[str, Any] = {
    "guards": [],
    "judgement_required": True,
    "pattern": "/API/cleanup",
    "registration": {"line": 11},
    "tags": ["a"],
}


@pytest.mark.parametrize(
    ("predicate", "expected"),
    [
        ({"not": {"field": "guards", "op": "not_empty"}}, True),
        ({"field": "scope_guards", "op": "empty"}, True),  # missing reads as None
        ({"field": "scope_guards", "op": "truthy"}, False),
        ({"field": "judgement_required", "op": "falsy"}, False),
        ({"field": "pattern", "op": "matches", "value": "/api/"}, True),  # case-insensitive
        ({"field": "pattern", "op": "contains", "value": "clean"}, True),
        ({"field": "tags", "op": "contains", "value": "a"}, True),
        ({"field": "tags", "op": "not_contains", "value": "a"}, False),
        ({"field": "pattern", "op": "in", "value": ["/API/cleanup"]}, True),
        ({"field": "pattern", "op": "not_in", "value": ["/x"]}, True),
        ({"field": "pattern", "op": "ne", "value": "/x"}, True),
        ({"field": "registration.line", "op": "gte", "value": 11}, True),
        ({"field": "registration.line", "op": "lte", "value": 10}, False),
        ({"field": "pattern", "op": "gte", "value": 1}, False),  # not a number
        ({"field": "registration.path.deeper", "op": "empty"}, True),
        ({"any": [{"field": "guards", "op": "truthy"}, {"field": "tags", "op": "truthy"}]}, True),
        ({"all": [{"field": "guards", "op": "truthy"}, {"field": "tags", "op": "truthy"}]}, False),
    ],
)
def test_predicates_read_rows_as_the_legacy_compiler_did(
    predicate: dict[str, Any], expected: bool
) -> None:
    assert Predicate.model_validate(predicate).matches(ROW) is expected


def test_mining_clusters_weaknesses_apart_and_only_weakness_rules_cover_them() -> None:
    from uuid import uuid4

    from traust_core.v1.models.detection_quality import RuleMining, RulePack, RuleRef, TruePositive

    def tp(kind: str | None) -> TruePositive:
        return TruePositive(
            finding_id=uuid4(),
            repository_id=uuid4(),
            cwe="CWE-693",
            severity="medium",
            language="python",
            title="t",
            kind=kind,  # type: ignore[arg-type]
        )

    corpus = [tp("weakness"), tp("weakness"), tp("vulnerability"), tp(None)]
    vuln_rule = RuleRef(id="traust-python-x", languages=("python",), cwes=("CWE-693",))
    mining = RuleMining.of(corpus, RulePack(name="p", version="1", rules=(vuln_rule,)), [])
    assert [(c.kind, c.count, c.covered_by) for c in mining.covered] == [
        ("vulnerability", 2, ("traust-python-x",))
    ]
    assert [(c.kind, c.count) for c in mining.uncovered] == [("weakness", 2)]
    weak_rule = vuln_rule.model_copy(update={"id": "traust-python-y", "kind": "weakness"})
    mining = RuleMining.of(corpus, RulePack(name="p", version="1", rules=(weak_rule,)), [])
    assert [(c.kind, c.covered_by) for c in mining.covered] == [("weakness", ("traust-python-y",))]
