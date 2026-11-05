from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from traust_core.v1.models.findings import Location


@dataclass(frozen=True, slots=True)
class CodeFindingPolicy:
    """Positive source evidence only: no CWE-name, title or configuration inference."""

    extensions: frozenset[str] = frozenset(
        (
            "go",
            "py",
            "ts",
            "tsx",
            "mts",
            "cts",
            "js",
            "jsx",
            "mjs",
            "cjs",
            "java",
            "kt",
            "kts",
            "scala",
            "groovy",
            "c",
            "cc",
            "cpp",
            "cxx",
            "h",
            "hh",
            "hpp",
            "rs",
            "rb",
            "php",
            "cs",
            "swift",
            "m",
            "mm",
            "sh",
            "bash",
            "zsh",
            "pl",
            "pm",
            "lua",
            "ex",
            "exs",
            "erl",
            "hs",
            "clj",
            "cljs",
        )
    )
    languages: frozenset[str] = frozenset(
        (
            "go",
            "golang",
            "python",
            "py",
            "typescript",
            "ts",
            "tsx",
            "javascript",
            "js",
            "jsx",
            "java",
            "kotlin",
            "scala",
            "groovy",
            "c",
            "cpp",
            "c++",
            "rust",
            "ruby",
            "php",
            "csharp",
            "c#",
            "swift",
            "objc",
            "objective-c",
            "sh",
            "bash",
            "shell",
            "zsh",
            "perl",
            "lua",
            "elixir",
            "erlang",
            "haskell",
            "clojure",
        )
    )

    def includes(self, locations: Sequence[Location]) -> bool:
        return any(
            (
                location.path.rsplit(".", 1)[-1].lower() in self.extensions
                and "." in location.path.rsplit("/", 1)[-1]
            )
            or (location.language or "").strip().lower() in self.languages
            for location in locations
        )
