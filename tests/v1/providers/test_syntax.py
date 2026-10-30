"""Grammar readiness: each route matrix's tree-sitter grammar loads, or names its coverage gap."""

from __future__ import annotations

from pathlib import Path

import pytest

from traust_core.v1.context import Config, Context
from traust_core.v1.providers import syntax


def test_every_shipped_grammar_loads() -> None:
    readiness = syntax.grammar_readiness()
    assert sorted(readiness) == ["JS/TS", "Java", "Ruby", "Rust"]
    assert all(r.ready and r.detail == "" for r in readiness.values())


@pytest.mark.parametrize(
    ("loader", "language", "package"),
    [
        ("js_parsers", "JS/TS", "tree-sitter-javascript"),
        ("java_parser", "Java", "tree-sitter-java"),
        ("rust_parser", "Rust", "tree-sitter-rust"),
        ("ruby_parser", "Ruby", "tree-sitter-ruby"),
    ],
)
def test_a_grammar_that_wont_load_names_its_gap(
    monkeypatch: pytest.MonkeyPatch, loader: str, language: str, package: str
) -> None:
    monkeypatch.setattr(syntax, loader, lambda: None)
    readiness = syntax.grammar_readiness()
    assert not readiness[language].ready
    assert readiness[language].detail == syntax.grammar_missing(language, package)
    assert all(r.ready for name, r in readiness.items() if name != language)


def test_the_code_facts_service_reports_grammar_readiness(tmp_path: Path) -> None:
    readiness = Context(Config(home=tmp_path)).services().code_facts.grammar_readiness()
    assert readiness == syntax.grammar_readiness()
