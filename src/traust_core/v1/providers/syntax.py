"""Shared helpers for the tree-sitter enumerators (Express, Java, Rust, Ruby). The grammars
are core dependencies, loaded here and only when asked; a host where one won't import gets a
named coverage gap instead of a failure."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from traust_core.v1.providers.base import Readiness
from traust_core.v1.providers.tree import TreeFile

Node = Any


def grammar_missing(language: str, package: str) -> str:
    """The coverage-gap wording for a grammar that won't import (a broken install, or a host with
    no prebuilt wheel for it)."""
    return (
        f"the {language} grammar ({package}, a traust-core dependency) won't import on this host "
        "(reinstall traust-core; a platform without a prebuilt wheel needs a C compiler)"
    )


def walk(node: Node) -> Iterator[Node]:
    """Every node under `node`, depth first in source order."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


@dataclass
class Parsed:
    file: TreeFile
    root: Node
    data: bytes

    def text(self, node: Node | None) -> str:
        return self.data[node.start_byte : node.end_byte].decode("utf-8", "replace") if node else ""

    def line(self, node: Node) -> int:
        return node.start_point[0] + 1


def js_parsers() -> dict[str, Node] | None:
    """A parser per JS/TS grammar, or None when the grammars won't import on this host."""
    try:
        import tree_sitter
        import tree_sitter_javascript
        import tree_sitter_typescript
    except ImportError:
        return None
    languages = {
        "javascript": tree_sitter_javascript.language(),
        "typescript": tree_sitter_typescript.language_typescript(),
        "tsx": tree_sitter_typescript.language_tsx(),
    }
    return {k: tree_sitter.Parser(tree_sitter.Language(v)) for k, v in languages.items()}


def java_parser() -> Node | None:
    """The Java parser, or None when its grammar won't import on this host."""
    try:
        import tree_sitter
        import tree_sitter_java
    except ImportError:
        return None
    return tree_sitter.Parser(tree_sitter.Language(tree_sitter_java.language()))


def rust_parser() -> Node | None:
    """The Rust parser, or None when its grammar won't import on this host."""
    try:
        import tree_sitter
        import tree_sitter_rust
    except ImportError:
        return None
    return tree_sitter.Parser(tree_sitter.Language(tree_sitter_rust.language()))


def ruby_parser() -> Node | None:
    """The Ruby parser, or None when its grammar won't import on this host."""
    try:
        import tree_sitter
        import tree_sitter_ruby
    except ImportError:
        return None
    return tree_sitter.Parser(tree_sitter.Language(tree_sitter_ruby.language()))


def grammar_readiness() -> dict[str, Readiness]:
    """Each route matrix's grammar by language: ready when it loads, else the coverage-gap
    wording its enumerator reports."""
    grammars: tuple[tuple[str, str, Callable[[], object]], ...] = (
        ("JS/TS", "tree-sitter-javascript", js_parsers),
        ("Java", "tree-sitter-java", java_parser),
        ("Rust", "tree-sitter-rust", rust_parser),
        ("Ruby", "tree-sitter-ruby", ruby_parser),
    )
    return {
        language: Readiness(ready=True)
        if load() is not None
        else Readiness(ready=False, detail=grammar_missing(language, package))
        for language, package, load in grammars
    }
