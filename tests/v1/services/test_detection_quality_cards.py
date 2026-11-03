"""Precedent cards swept over a checkout's code facts, on SQLite and Postgres.

Scenarios ported from traust tests/test_compile_precedent_cards.py (traust b48ff14).
"""

from __future__ import annotations

from collections.abc import Collection, Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from sqlalchemy.engine import Engine

from tests.v1.conftest import CLOCK, SQL_BACKENDS, contract_db
from tests.v1.models.test_detection_quality import PILOT, config_card, route_card
from tests.v1.services.findings.test_reads import service as finding_service
from tests.v1.services.test_code_facts import Fixed
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.code_facts import (
    CodeFactKind,
    CodeFactsInput,
    ConfigFact,
    ConfigSink,
    ConfigSource,
    ConfigTriple,
    RouteGuardFact,
    RouteGuardRow,
    RouteHandler,
    SanitizerFact,
    SymbolFact,
    SymbolReference,
)
from traust_core.v1.models.common import CodeSpan, ToolRequest
from traust_core.v1.models.detection_quality import CardDeck, CardFactInput, CardStatus, CardSweep
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.symbols import SymbolIndex
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpecs
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.code_facts import CodeFactsService
from traust_core.v1.services.detection_quality import DetectionQualityService


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def route(pattern: str, line: int, *, guards: tuple[str, ...] = (), **kw: Any) -> RouteGuardRow:
    span = CodeSpan(path="server/routes.go", line=line)
    return RouteGuardRow(
        family="go-http",
        method="HandleFunc",
        pattern=pattern,
        handler=RouteHandler(expr=f"{pattern}Handler", path="server/routes.go", line=line),
        registration=span,
        guards=guards,
        judgement_required=not guards and not kw.get("scope_guards"),
        **kw,
    )


def triple(key: str, default: str, path: str, config_class: str = "dsn") -> ConfigTriple:
    return ConfigTriple(
        key=key,
        effective_default=default,
        source=ConfigSource(system="helm", path=path, line=42),
        sink=ConfigSink(status="unresolved"),
        config_class=config_class,  # type: ignore[arg-type]
        judgement_required=config_class == "dsn",
    )


ROUTES = RouteGuardFact(
    routes=(
        route("/api/admin", 10, guards=("requireAuth",)),
        route("/api/cleanup", 11, asymmetry=True),
        route("/api/data", 5, scope_guards=("authMiddleware",)),
    )
)
CONFIG = ConfigFact(
    triples=(
        triple("database.sslmode", "sslmode=disable", "chart/values.yaml"),
        triple("database.url", "postgresql://db/app?sslmode=verify-full", "chart/values.yaml"),
        triple("log.level", "info", "chart/values.yaml", "other"),
        triple("TEST_DB_URL", "postgres://localhost/test", "tests/docker-compose.yaml"),
    )
)


class Counting(Fixed):
    def __init__(self, kind: CodeFactKind, *facts: Any) -> None:
        super().__init__(kind, *facts)
        self.calls = 0

    def enumerate(self, request: ToolRequest) -> Any:
        self.calls += 1
        return super().enumerate(request)


def quality(
    engine: Engine, *enumerators: Fixed, symbols: SymbolIndex | None = None
) -> DetectionQualityService:
    uow = SqlTraustUnitOfWork(engine)
    publisher = ArtifactPublisher(PublishSpecs(), InMemoryObjectStore(), uow)
    code_facts = CodeFactsService(
        AssessmentService(uow), publisher, list(enumerators), symbols=symbols
    )
    return DetectionQualityService(uow, finding_service(engine), publisher, code_facts=code_facts)


def sweep(engine: Engine, tmp_path: Path, *cards: dict[str, Any]) -> CardSweep:
    service = quality(
        engine,
        Fixed(CodeFactKind.ROUTE_GUARD, ROUTES),
        Fixed(CodeFactKind.CONFIG, CONFIG),
        Fixed(
            CodeFactKind.SANITIZER,
            SanitizerFact(function="clean", path="a.py", line=1, arg="v", is_method=False),
        ),
        Fixed(
            CodeFactKind.SYMBOL,
            SymbolFact(
                name="Handler", location=CodeSpan(path="h.go", line=3), kind="func", language="Go"
            ),
            SymbolFact(
                name="Other", location=CodeSpan(path="h.go", line=9), kind="func", language="Go"
            ),
        ),
    )
    deck = CardDeck.parse({"cards": list(cards)})
    assert not deck.rejected
    return service.sweep_cards(deck.cards, ToolRequest(workspace=tmp_path / "fixture-repo"))


def test_matched_rows_become_candidates_in_the_sweep_shape(engine: Engine, tmp_path: Path) -> None:
    found = sweep(engine, tmp_path, route_card(), config_card())
    assert {(c.id, c.status, c.rows_enumerated, c.matched) for c in found.cards} == {
        ("pc-test-route", CardStatus.COMPILED, 3, 1),
        ("pc-test-dsn", CardStatus.COMPILED, 4, 2),
    }
    by_card = {c.card_id: c for c in found.candidates if not c.test_path}
    hit = by_card["pc-test-route"]
    assert (hit.repo, hit.file, hit.line, hit.location) == (
        "fixture-repo",
        "server/routes.go",
        11,
        "server/routes.go:11",
    )
    assert hit.url == f"dir:{tmp_path / 'fixture-repo'}"
    assert "/api/cleanup" in hit.excerpt and "ASYMMETRY" in hit.excerpt
    assert (hit.rule_id, hit.origin, hit.severity_hint) == (
        "pc-test-route",
        "semantic-sweep",
        "high",
    )
    assert hit.source_finding_provenance == ("REPO-abc1234-001",)
    assert hit.judge_question and hit.expected_fp_sources == ("healthz endpoints",)
    assert "class=dsn" in by_card["pc-test-dsn"].excerpt
    [test_hit] = [c for c in found.candidates if c.test_path]
    assert test_hit.file == "tests/docker-compose.yaml"


def test_a_symbol_card_sweeps_its_named_definitions(engine: Engine, tmp_path: Path) -> None:
    card = route_card(
        id="pc-sym",
        enumerator="symbol-index",
        enumerator_options={"query": {"mode": "defs", "name": "Handler"}},
        predicate={"field": "kind", "op": "eq", "value": "func"},
    )
    found = sweep(engine, tmp_path, card)
    assert found.cards[0].rows_enumerated == 1
    assert found.candidates[0].excerpt == "func Handler (Go)"


def test_cards_core_cannot_enumerate_are_reported_not_run(engine: Engine, tmp_path: Path) -> None:
    probe = route_card(
        id="pc-probe",
        enumerator="sanitizer-probes",
        enumerator_options={"run": True},
        predicate={"field": "outcome", "op": "eq", "value": "survived"},
    )
    discovery = route_card(
        id="pc-discovery",
        enumerator="sanitizer-probes",
        predicate={"field": "function", "op": "eq", "value": "clean"},
    )
    found = {c.id: c for c in sweep(engine, tmp_path, probe, discovery).cards}
    assert found["pc-probe"].status is CardStatus.NOT_RUN
    assert "NEED(tools package: sanitizer probe runner)" in (found["pc-probe"].reason or "")
    assert (found["pc-discovery"].status, found["pc-discovery"].matched) == (CardStatus.COMPILED, 1)


def test_cards_sharing_an_enumerator_run_it_once(engine: Engine, tmp_path: Path) -> None:
    config = Counting(CodeFactKind.CONFIG, CONFIG)
    service = quality(engine, config)
    deck = CardDeck.parse({"cards": [config_card(), config_card(id="pc-again")]})
    found = service.sweep_cards(deck.cards, ToolRequest(workspace=tmp_path))
    assert config.calls == 1 and [c.matched for c in found.cards] == [2, 2]


def test_no_cards_sweep_nothing(engine: Engine, tmp_path: Path) -> None:
    found = quality(engine).sweep_cards((), ToolRequest(workspace=tmp_path))
    assert found.cards == () and found.candidates == ()


def test_the_pilot_sweeps_its_recipes(engine: Engine, tmp_path: Path) -> None:
    deck = CardDeck.parse(yaml.safe_load(PILOT.read_text()))
    service = quality(
        engine,
        Fixed(CodeFactKind.ROUTE_GUARD, ROUTES),
        Fixed(CodeFactKind.CONFIG, CONFIG),
    )
    found = {
        c.id: c for c in service.sweep_cards(deck.cards, ToolRequest(workspace=tmp_path)).cards
    }
    assert found["pc-unguarded-route-class"].matched == 1
    assert found["pc-dsn-plaintext-default"].matched == 2
    assert found["pc-sanitizer-bypass-survivor"].status is CardStatus.NOT_RUN


def test_sweeping_needs_the_code_facts_service(engine: Engine, tmp_path: Path) -> None:
    uow = SqlTraustUnitOfWork(engine)
    publisher = ArtifactPublisher(PublishSpecs(), InMemoryObjectStore(), uow)
    service = DetectionQualityService(uow, finding_service(engine), publisher)
    with pytest.raises(ConfigError, match="code-facts"):
        service.sweep_cards((), ToolRequest(workspace=tmp_path))


class CountingSymbols(SymbolIndex):
    calls = 0

    def references(
        self,
        root: Path,
        names: Collection[str],
        *,
        definitions: Collection[SymbolFact] | None = None,
    ) -> list[SymbolReference]:
        self.calls += 1
        return super().references(root, names, definitions=definitions)


def symbol_card(mode: str, **overrides: Any) -> dict[str, Any]:
    return route_card(
        enumerator="symbol-index",
        enumerator_options={"query": {"mode": mode, "name": "Handler"}},
        **overrides,
    )


def test_symbol_defs_and_refs_have_separate_caches_and_actual_reference_rows(
    engine: Engine, tmp_path: Path
) -> None:
    (tmp_path / "h.go").write_text("package api\nfunc Handler() {}\nfunc Caller() { Handler() }\n")
    definitions = Counting(
        CodeFactKind.SYMBOL,
        SymbolFact(
            name="Handler", location=CodeSpan(path="h.go", line=2), kind="func", language="Go"
        ),
    )
    symbols = CountingSymbols(ProcessRunner(()), CLOCK)
    service = quality(engine, definitions, symbols=symbols)
    deck = CardDeck.parse(
        {
            "cards": [
                symbol_card(
                    "defs",
                    id="pc-defs",
                    predicate={"field": "kind", "op": "eq", "value": "func"},
                ),
                symbol_card("refs", id="pc-refs", predicate={"field": "is_def", "op": "falsy"}),
                symbol_card(
                    "refs", id="pc-refs-again", predicate={"field": "is_def", "op": "falsy"}
                ),
            ]
        }
    )
    assert not deck.rejected
    found = service.sweep_cards(deck.cards, ToolRequest(workspace=tmp_path))
    assert definitions.calls == 1 and symbols.calls == 1
    assert [(run.id, run.rows_enumerated, run.matched) for run in found.cards] == [
        ("pc-defs", 1, 1),
        ("pc-refs", 2, 1),
        ("pc-refs-again", 2, 1),
    ]
    refs = [candidate for candidate in found.candidates if candidate.card_id.startswith("pc-refs")]
    assert [(row.file, row.line, row.excerpt) for row in refs] == [
        ("h.go", 3, "func Caller() { Handler() }"),
        ("h.go", 3, "func Caller() { Handler() }"),
    ]


def test_offline_arrays_use_existing_predicates_and_never_invoke_checkout_tools(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("offline input must never invoke checkout tools")

    monkeypatch.setattr(CodeFactsService, "enumerate", forbidden)
    monkeypatch.setattr(CodeFactsService, "route_guards", forbidden)
    monkeypatch.setattr(CodeFactsService, "symbol_references", forbidden)
    deck = CardDeck.parse(
        {
            "cards": [
                route_card(),
                config_card(),
                symbol_card("refs", id="pc-refs", predicate={"field": "is_def", "op": "falsy"}),
                route_card(
                    id="pc-probe",
                    enumerator="sanitizer-probes",
                    enumerator_options={"run": True},
                    predicate={"field": "survived", "op": "gte", "value": 1},
                ),
            ]
        }
    )
    artifacts = (
        CardFactInput(enumerator="route-guards", facts=CodeFactsInput(routes=ROUTES.routes)),
        CardFactInput(enumerator="config-matrix", facts=CodeFactsInput(triples=CONFIG.triples)),
        CardFactInput(
            enumerator="symbol-index",
            facts=CodeFactsInput(
                refs=(SymbolReference(path="call.go", line=8, is_def=False, text="Handler()"),)
            ),
        ),
        CardFactInput(
            enumerator="sanitizer-probes",
            facts=CodeFactsInput.model_validate(
                {
                    "probes": [
                        {
                            "function": "clean",
                            "path": "a.py",
                            "line": 2,
                            "arg": "v",
                            "is_method": False,
                            "outcome": "survived",
                            "survived": 1,
                        }
                    ]
                }
            ),
        ),
    )
    found = quality(engine).sweep_cards(
        deck.cards, ToolRequest(workspace=tmp_path / "absent"), artifacts=artifacts
    )
    assert all(run.status is CardStatus.COMPILED for run in found.cards)
    assert [run.matched for run in found.cards] == [1, 2, 1, 1]
    assert found.candidates[-1].excerpt == "clean(v) outcome=survived survived=1"
    assert found.candidates[-2].file == "call.go"


def test_offline_card_specific_facts_override_generic_including_empty_arrays(
    engine: Engine,
) -> None:
    deck = CardDeck.parse({"cards": [config_card(), config_card(id="pc-empty")]})
    found = quality(engine).sweep_cards(
        deck.cards,
        artifacts=(
            CardFactInput(enumerator="config-matrix", facts=CodeFactsInput(triples=CONFIG.triples)),
            CardFactInput(
                enumerator="config-matrix",
                card_id="pc-empty",
                facts=CodeFactsInput(triples=()),
            ),
        ),
    )
    assert [(run.rows_enumerated, run.matched) for run in found.cards] == [(4, 2), (0, 0)]
    assert all(run.status is CardStatus.COMPILED for run in found.cards)
    assert found.repo == "artifact-input"


def test_missing_offline_arrays_are_not_run_and_do_not_fall_back_to_checkout(
    engine: Engine, tmp_path: Path
) -> None:
    deck = CardDeck.parse({"cards": [route_card(), config_card()]})
    found = quality(engine).sweep_cards(
        deck.cards,
        ToolRequest(workspace=tmp_path / "absent"),
        artifacts=(CardFactInput(enumerator="route-guards", facts=CodeFactsInput(routes=())),),
    )
    assert found.cards[0].status is CardStatus.COMPILED
    assert found.cards[1].status is CardStatus.NOT_RUN and found.cards[1].reason
    assert found.candidates == ()


def test_missing_offline_probe_evidence_does_not_execute_a_sanitizer(engine: Engine) -> None:
    card = route_card(
        id="pc-probe",
        enumerator="sanitizer-probes",
        enumerator_options={"run": True},
        predicate={"field": "survived", "op": "gte", "value": 1},
    )
    deck = CardDeck.parse({"cards": [card]})
    found = quality(engine).sweep_cards(
        deck.cards,
        artifacts=(
            CardFactInput(enumerator="sanitizer-probes", facts=CodeFactsInput(candidates=())),
        ),
    )
    assert found.cards[0].status is CardStatus.NOT_RUN
    assert found.cards[0].reason and found.candidates == ()


def test_duplicate_offline_bindings_are_refused(engine: Engine) -> None:
    deck = CardDeck.parse({"cards": [route_card()]})
    provided = CardFactInput(enumerator="route-guards", facts=CodeFactsInput(routes=()))
    with pytest.raises(ValidationError, match="duplicate"):
        quality(engine).sweep_cards(deck.cards, artifacts=(provided, provided))


def test_offline_symbol_modes_select_their_own_typed_array(engine: Engine) -> None:
    deck = CardDeck.parse(
        {
            "cards": [
                symbol_card(
                    "defs", id="pc-defs", predicate={"field": "kind", "op": "eq", "value": "func"}
                ),
                symbol_card("refs", id="pc-refs", predicate={"field": "is_def", "op": "falsy"}),
            ]
        }
    )
    facts = CodeFactsInput.model_validate(
        {
            "defs": [
                {"name": "Handler", "path": "h.go", "line": 2, "kind": "func", "language": "Go"}
            ],
            "refs": [
                {"path": "h.go", "line": 2, "is_def": True, "text": "func Handler() {}"},
                {"path": "h.go", "line": 3, "is_def": False, "text": "Handler()"},
            ],
        }
    )
    found = quality(engine).sweep_cards(
        deck.cards, artifacts=(CardFactInput(enumerator="symbol-index", facts=facts),)
    )
    assert [(run.rows_enumerated, run.matched) for run in found.cards] == [(1, 1), (2, 1)]
    assert [(row.line, row.excerpt) for row in found.candidates] == [
        (2, "func Handler (Go)"),
        (3, "Handler()"),
    ]


def test_offline_sanitizer_modes_do_not_share_discovery_and_probe_rows(engine: Engine) -> None:
    candidate = {"function": "clean", "path": "a.py", "line": 2, "arg": "v", "is_method": False}
    deck = CardDeck.parse(
        {
            "cards": [
                route_card(
                    id="pc-discovery",
                    enumerator="sanitizer-probes",
                    predicate={"field": "function", "op": "eq", "value": "clean"},
                ),
                route_card(
                    id="pc-probe",
                    enumerator="sanitizer-probes",
                    enumerator_options={"run": True},
                    predicate={"field": "survived", "op": "gte", "value": 1},
                ),
            ]
        }
    )
    facts = CodeFactsInput.model_validate(
        {
            "candidates": [candidate],
            "probes": [{**candidate, "outcome": "neutralized", "survived": 0, "errors": 0}],
        }
    )
    found = quality(engine).sweep_cards(
        deck.cards, artifacts=(CardFactInput(enumerator="sanitizer-probes", facts=facts),)
    )
    assert [(run.rows_enumerated, run.matched) for run in found.cards] == [(1, 1), (1, 0)]
    assert found.candidates[0].excerpt == "clean(v) outcome=discovered survived=n/a"


def test_offline_probe_transcripts_remain_filterable_by_the_existing_predicate(
    engine: Engine,
) -> None:
    deck = CardDeck.parse(
        {
            "cards": [
                route_card(
                    id="pc-transcript",
                    enumerator="sanitizer-probes",
                    enumerator_options={"run": True},
                    predicate={"field": "transcript", "op": "not_empty"},
                )
            ]
        }
    )
    assert not deck.rejected
    facts = CodeFactsInput.model_validate(
        {
            "probes": [
                {
                    "function": "clean",
                    "path": "a.py",
                    "line": 2,
                    "arg": "v",
                    "is_method": False,
                    "outcome": "survived",
                    "transcript": [{"class": "ssti", "payload": "{{7*7}}", "outcome": "survived"}],
                }
            ]
        }
    )
    found = quality(engine).sweep_cards(
        deck.cards, artifacts=(CardFactInput(enumerator="sanitizer-probes", facts=facts),)
    )
    assert found.cards[0].matched == 1
