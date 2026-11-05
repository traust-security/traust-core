from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

import pydantic

from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.language_coverage import ReachabilityReview
from traust_core.v1.models.vocabulary import ImpactTier
from traust_core.v1.providers.analysis import ImpactAnalyzer
from traust_core.v1.providers.syft import LANGUAGE_MANIFESTS, dependency_ecosystem

NO_DEPENDENCIES_REASONS = {
    "Shell": "shell scripts have no package-dependency graph; sourced commands need manual review",
    "YAML": "configuration data is examined by its owning configuration or IaC lane",
    "Markdown": "documentation has no package-dependency graph",
    "Dockerfile": "container dependencies are measured through image SBOMs",
    "HCL": "IaC dependencies and configuration are owned by cloud-config-audit",
    "Terraform": "IaC dependencies and configuration are owned by cloud-config-audit",
    "Go Template": "templates have no independent package-dependency graph",
    "Jsonnet": "configuration generation is owned by its configuration review lane",
    "Starlark": "build configuration is owned by its build review lane",
    "Makefile": "build recipes have no independent package-dependency graph",
    "HTML": "markup has no independent package-dependency graph",
    "CSS": "stylesheets have no independent package-dependency graph",
    "SCSS": "stylesheets have no independent package-dependency graph",
    "Text": "plain text has no package-dependency graph",
    "Gherkin": "test specifications have no independent package-dependency graph",
    "PLpgSQL": "database procedures have no independent package-dependency graph",
    "Jinja": "templates have no independent package-dependency graph",
    "Mustache": "templates have no independent package-dependency graph",
    "Smarty": "templates have no independent package-dependency graph",
    "Open Policy Agent": "Rego policy is reviewed as policy, not a package-dependency graph",
    "JSON": "configuration data has no independent package-dependency graph",
}
_ALIASES = {
    "bash": "Shell",
    "bourne shell": "Shell",
    "bourne again shell": "Shell",
    "jsx": "JavaScript",
    "javascript jsx": "JavaScript",
    "tsx": "TypeScript",
    "typescript jsx": "TypeScript",
    "csharp": "C#",
    "fsharp": "F#",
    "visual basic .net": "Visual Basic",
    "rego": "Open Policy Agent",
    "jinja2": "Jinja",
}
_CANONICAL = {
    name.casefold(): name for name in (*LANGUAGE_MANIFESTS, *NO_DEPENDENCIES_REASONS)
} | _ALIASES


class LanguageCoverageCatalog:
    """Dependency readers and the symbol-tier analyzers actually wired into exposure."""

    def __init__(self, analyzers: Sequence[ImpactAnalyzer]) -> None:
        self._analyzers = tuple(a for a in analyzers if a.tier == ImpactTier.GOVULNCHECK)

    def canonical_language(self, name: str) -> str:
        return _CANONICAL.get(name.casefold(), name)

    def dependency_ecosystem(self, language: str) -> str | None:
        ecosystem = dependency_ecosystem(self.canonical_language(language))
        return ecosystem.value if ecosystem is not None else None

    def reachability_engines(self, language: str) -> tuple[str, ...]:
        ecosystem = self.dependency_ecosystem(language)
        return tuple(sorted({a.name for a in self._analyzers if ecosystem in a.ecosystems}))

    def no_dependencies_reason(self, language: str) -> str | None:
        return NO_DEPENDENCIES_REASONS.get(self.canonical_language(language))


class ReachabilityReviewFile:
    """The human-maintained reachability-watch reference; reading never marks it reviewed."""

    def __init__(self, path: Path | None, documents: Callable[[str], list[object]]) -> None:
        self._path = path
        self._documents = documents

    def read(self) -> ReachabilityReview | None:
        if self._path is None:
            return None
        try:
            text = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except (OSError, UnicodeError) as e:
            raise ConfigError(f"reachability review {self._path}: {e}") from e
        try:
            documents = self._documents(text)
            if len(documents) != 1:
                raise ValidationError("expected one reachability review document")
            return ReachabilityReview.model_validate(documents[0])
        except (ValidationError, pydantic.ValidationError) as e:
            raise ConfigError(f"reachability review {self._path}: {e}") from e
