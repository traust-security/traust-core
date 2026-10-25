"""Precedent cards swept over a checkout's code facts, on SQLite and Postgres.

Scenarios ported from traust tests/test_compile_precedent_cards.py (traust b48ff14).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.models.test_detection_quality import PILOT, config_card, route_card
from tests.v1.services.findings.test_reads import service as finding_service
from tests.v1.services.test_code_facts import Fixed
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.code_facts import (
    CodeFactKind,
    ConfigFact,
    ConfigSink,
    ConfigSource,
    ConfigTriple,
    RouteGuardFact,
    RouteGuardRow,
    RouteHandler,
    SanitizerFact,
    SymbolFact,
)
from traust_core.v1.models.common import CodeSpan, ToolRequest
from traust_core.v1.models.detection_quality import CardDeck, CardStatus, CardSweep
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


def quality(engine: Engine, *enumerators: Fixed) -> DetectionQualityService:
    uow = SqlTraustUnitOfWork(engine)
    publisher = ArtifactPublisher(PublishSpecs(), InMemoryObjectStore(), uow)
    code_facts = CodeFactsService(AssessmentService(uow), publisher, list(enumerators))
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
    refs = route_card(
        id="pc-refs",
        enumerator="symbol-index",
        enumerator_options={"query": {"mode": "refs", "name": "Handler"}},
        predicate={"field": "is_def", "op": "falsy"},
    )
    discovery = route_card(
        id="pc-discovery",
        enumerator="sanitizer-probes",
        predicate={"field": "function", "op": "eq", "value": "clean"},
    )
    found = {c.id: c for c in sweep(engine, tmp_path, probe, refs, discovery).cards}
    assert found["pc-probe"].status is CardStatus.NOT_RUN
    assert "NEED(tools package: sanitizer probe runner)" in (found["pc-probe"].reason or "")
    assert "NEED(core: symbol references fact)" in (found["pc-refs"].reason or "")
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
