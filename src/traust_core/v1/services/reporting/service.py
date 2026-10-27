from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC
from enum import StrEnum
from pathlib import Path
from typing import Any

from traust_core.v1.errors import DocumentError, Issue, ValidationError
from traust_core.v1.models.artifacts import (
    ArtifactDocument,
    CloudConfigAuditArtifact,
    ReportArtifact,
    TriageArtifact,
)
from traust_core.v1.providers.clock import Clock, SystemClock
from traust_core.v1.providers.report_files import ReportFiles
from traust_core.v1.providers.sources import WorkspaceFiles
from traust_core.v1.rendering import HtmlRenderer, MarkdownRenderer
from traust_core.v1.services.artifact_publishing import RedactionPolicy
from traust_core.v1.services.insight import SarifExport, TriageView
from traust_core.v1.services.lint import Lint, LintContext, LintReport
from traust_core.v1.services.reporting.checks import (
    CheckContext,
    ReportValidation,
    detect_schema,
    validate_report,
)


class RenderFormat(StrEnum):
    MARKDOWN = "md"
    HTML = "html"


class ReportingService:
    """Report documents a caller holds: contract issues, content checks, lint, renders and
    SARIF; nothing stored."""

    def __init__(
        self,
        lints: Sequence[Lint],
        sarif_tool_uri: str | None,
        *,
        files: ReportFiles | None = None,
        redaction: RedactionPolicy | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._lints = lints
        self._sarif_tool_uri = sarif_tool_uri
        self._files = files or ReportFiles()
        self._redaction = redaction or RedactionPolicy()
        self._clock = clock or SystemClock()

    def validate(self, payload: bytes, artifact: type[ArtifactDocument]) -> tuple[Issue, ...]:
        """The payload's issues against the artifact's contract schema; none means it conforms."""
        try:
            artifact.parse(payload)
        except DocumentError as e:
            return tuple(e.issues)
        return ()

    def validate_reports(
        self, path: Path, *, strict: bool = False, schema: str | None = None
    ) -> list[ReportValidation]:
        """Every report file at `path` (a file, or the .json files under a directory) against its
        contract schema and its family's content checks. The schema comes from each file name
        unless `schema` names one; `strict` adds the audit-report warnings."""
        context = CheckContext(
            today=self._clock.now().astimezone(UTC).date(),
            redaction=self._redaction,
            files=self._files,
        )
        results = []
        for file in self._files.collect(path):
            try:
                text = self._files.read(file)
            except (OSError, UnicodeDecodeError) as e:
                results.append(ReportValidation(str(file), [f"Cannot read file: {e}"]))
                continue
            name = schema or detect_schema(file, text, self._files)
            results.append(validate_report(str(file), text, name, context, strict=strict))
        return results

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
