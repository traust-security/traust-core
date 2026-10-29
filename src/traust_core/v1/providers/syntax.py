"""Shared helpers for the tree-sitter enumerators (Express, Java, Rust, Ruby). The grammars
are core dependencies, loaded here and only when asked; a host where one won't import gets a
named coverage gap instead of a failure."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

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
