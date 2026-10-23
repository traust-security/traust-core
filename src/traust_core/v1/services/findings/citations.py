from __future__ import annotations

import re
from collections.abc import Iterator

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import ArtifactDocument, TriageArtifact
from traust_core.v1.providers.sources import WorkspaceFiles
from traust_core.v1.services.lint import LintAction, LintContext, LintRuleId, Violation

# file:line (pkg/rbac/scope.go:37, handler.py:112-118); the extension keeps out ratios and times.
CITATION = re.compile(
    r"(?<![\w/])([\w.\-]+(?:/[\w.\-]+)*\.[A-Za-z]{1,6}[a-z0-9]?):(\d{1,6})(?:-\d{1,6})?"
)
_NOT_CITATIONS = ("http://", "https://", "none found", "n/a")
_DISMISSALS = {"false_positive", "hardening"}


class VerdictCitations:
    """Every file:line a verdict cites must exist in the checkout and be in range.

    A dismissal resting on evidence that isn't there is the worst triage failure (a real
    vulnerability dropped on invented grounds), so a broken dismissal asks for a fresh vote;
    any other broken verdict asks for review.
    """

    id = LintRuleId("triage.verdict-citations")

    def check(self, subject: ArtifactDocument, context: LintContext) -> list[Violation]:
        if not isinstance(subject, TriageArtifact):
            raise ValidationError(
                f"{self.id} checks triage artifacts, not {type(subject).__name__}"
            )
        if context.files is None:
            raise ValidationError(f"{self.id} needs the target checkout (LintContext.files)")
        return [
            Violation(
                rule=self.id,
                item=f.id,
                message=f"{origin}: {defect}",
                action=LintAction.RE_VOTE if f.verdict in _DISMISSALS else LintAction.REVIEW,
            )
            for f in subject.findings
            if f.verdict != "duplicate"
            for path, line, origin in citations(f.first_links, f.rationale)
            if (defect := _defect(context.files, path, line))
        ]


def citations(links: tuple[str, ...], rationale: str | None) -> list[tuple[str, int, str]]:
    """(path, line, where) cited by a verdict, first occurrence of each path:line only."""

    def found() -> Iterator[tuple[str, int, str]]:
        for link in links:
            if not any(t in link.lower() for t in _NOT_CITATIONS) and (m := CITATION.search(link)):
                yield m[1], int(m[2]), "first_links"
        for m in CITATION.finditer(rationale or ""):
            yield m[1], int(m[2]), "rationale"

    seen: set[tuple[str, int]] = set()
    return [c for c in found() if c[:2] not in seen and not seen.add(c[:2])]


def _defect(files: WorkspaceFiles, path: str, line: int) -> str | None:
    matches = files.matches(path)
    if not matches:
        return f"{path}:{line}: file not found under the checkout"
    counts = [n for n in map(files.line_count, matches) if n is not None]
    if not counts:
        return f"{path}:{line}: unreadable"
    if line > max(counts):
        exact = files.resolve(path) is not None
        where = "" if exact else f" (best suffix match of {len(matches)})"
        return f"{path}:{line}: line out of range ({max(counts)}-line file{where})"
    return None
