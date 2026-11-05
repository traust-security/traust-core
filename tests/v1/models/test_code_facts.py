from __future__ import annotations

import pytest
from pydantic import ValidationError

from traust_core.v1.models.code_facts import (
    CodeFactKind,
    CodeFactsInput,
    ConfigTriple,
    SanitizerOutcome,
    SanitizerRunFact,
    SymbolMode,
    SymbolReference,
)


def test_offline_definitions_accept_the_original_flat_symbol_output() -> None:
    facts = CodeFactsInput.model_validate(
        {
            "query": "Handler",
            "defs": [
                {"name": "Handler", "path": "h.go", "line": 3, "kind": "func", "language": "Go"}
            ],
        }
    )
    assert facts.defs is not None
    assert facts.defs[0].location.path == "h.go"
    assert facts.defs[0].location.line == 3
    assert facts.rows(CodeFactKind.SYMBOL) == facts.defs
    assert facts.rows(CodeFactKind.SYMBOL, symbol_mode=SymbolMode.REFS) is None


def test_offline_references_retain_definition_markers_and_source_text() -> None:
    facts = CodeFactsInput.model_validate(
        {"refs": [{"path": "call.go", "line": 9, "is_def": False, "text": "Handler()"}]}
    )
    rows = facts.rows(CodeFactKind.SYMBOL, symbol_mode=SymbolMode.REFS)
    assert rows == (SymbolReference(path="call.go", line=9, is_def=False, text="Handler()"),)


def test_offline_config_uses_the_emitted_class_alias() -> None:
    facts = CodeFactsInput.model_validate(
        {
            "triples": [
                {
                    "key": "database.url",
                    "effective_default": "sslmode=disable",
                    "source": {"system": "helm", "path": "values.yaml", "line": 1},
                    "sink": {"status": "unresolved"},
                    "class": "dsn",
                    "judgement_required": True,
                }
            ]
        }
    )
    rows = facts.rows(CodeFactKind.CONFIG)
    assert rows is not None and isinstance(rows[0], ConfigTriple)
    assert rows[0].model_dump(mode="json", by_alias=True)["class"] == "dsn"


def test_offline_sanitizer_execution_facts_are_distinct_from_discovery() -> None:
    candidate = {"function": "clean", "path": "a.py", "line": 2, "arg": "v", "is_method": False}
    facts = CodeFactsInput.model_validate(
        {
            "candidates": [candidate],
            "probes": [
                {
                    **candidate,
                    "outcome": "survived",
                    "survived": 1,
                    "errors": 0,
                    "transcript": [{"class": "ssti", "payload": "{{7*7}}", "outcome": "survived"}],
                }
            ],
        }
    )
    rows = facts.rows(CodeFactKind.SANITIZER, run=True)
    assert rows is not None and isinstance(rows[0], SanitizerRunFact)
    assert rows[0].outcome is SanitizerOutcome.SURVIVED
    assert rows[0].transcript[0].payload_class == "ssti"
    assert facts.rows(CodeFactKind.SANITIZER) == facts.candidates


def test_a_measured_empty_array_is_not_an_unmeasured_enumerator() -> None:
    facts = CodeFactsInput(routes=())
    assert facts.rows(CodeFactKind.ROUTE_GUARD) == ()
    assert facts.rows(CodeFactKind.CONFIG) is None


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"refs": None},
        {"refs": [{}]},
        {"refs": [{"path": "h.go", "line": 0, "is_def": False, "text": "Handler()"}]},
        {"routes": {}},
        {"defs": [{"name": "Handler", "path": "h.go"}]},
        {"probes": [{"outcome": "survived"}]},
    ],
)
def test_malformed_offline_facts_are_not_silently_empty(document: object) -> None:
    with pytest.raises(ValidationError):
        CodeFactsInput.model_validate(document)
