from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import Any

from traust_core.v1.errors import DocumentError, Issue, ValidationError
from traust_core.v1.models.artifacts import (
    ArtifactDocument,
    CloudConfigAuditArtifact,
    ReportArtifact,
    TriageArtifact,
)
from traust_core.v1.providers.sources import WorkspaceFiles
from traust_core.v1.rendering import HtmlRenderer, MarkdownRenderer
from traust_core.v1.services.insight import SarifExport, TriageView
from traust_core.v1.services.lint import Lint, LintContext, LintReport


class RenderFormat(StrEnum):
    MARKDOWN = "md"
    HTML = "html"


class ReportingService:
    """Report documents a caller holds: contract issues, lint, renders and SARIF; nothing stored."""

    def __init__(self, lints: Sequence[Lint], sarif_tool_uri: str | None) -> None:
        self._lints = lints
        self._sarif_tool_uri = sarif_tool_uri

    def validate(self, payload: bytes, artifact: type[ArtifactDocument]) -> tuple[Issue, ...]:
        """The payload's issues against the artifact's contract schema; none means it conforms."""
        # NEED(reporting: cross-validation): the legacy validator's content checks past the schema
        # (counts vs findings, canonical ids, metadata.repository, --strict) have no core home yet.
        try:
            artifact.parse(payload)
        except DocumentError as e:
            return tuple(e.issues)
        return ()

    def lint(self, document: ArtifactDocument, files: WorkspaceFiles | None = None) -> LintReport:
        """Every core Lint rule registered for the document's type; citation rules need `files`."""
        context = LintContext(files=files)
        return LintReport(
            violations=tuple(
                v for lint in self._lints for v in lint.run(document, context).violations
            )
        )

    def render(self, document: ArtifactDocument, format: RenderFormat) -> str:
        # NEED(reporting: report views): security reports and threat models have no
        # document -> Report view yet (legacy render.render_report / render_threat_model).
        if not isinstance(document, TriageArtifact):
            raise ValidationError(f"no report view renders {document.name} documents yet")
        renderer = MarkdownRenderer() if format is RenderFormat.MARKDOWN else HtmlRenderer()
        return renderer.render(TriageView().report(document)).decode()

    def sarif(self, document: ReportArtifact | CloudConfigAuditArtifact) -> dict[str, Any]:
        return SarifExport().report(document, self._sarif_tool_uri)
