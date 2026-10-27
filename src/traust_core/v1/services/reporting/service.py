from __future__ import annotations

import json
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
    ThreatModelArtifact,
    TriageArtifact,
)
from traust_core.v1.models.assessment import AttackCatalog
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
from traust_core.v1.services.reporting.report_markdown import render_report
from traust_core.v1.services.reporting.threat_model import (
    lint_threat_model,
    lost_sections,
    render_threat_model,
    shape_only_attack_ids,
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
        attack_catalog: AttackCatalog | None = None,
    ) -> None:
        self._lints = lints
        self._sarif_tool_uri = sarif_tool_uri
        self._files = files or ReportFiles()
        self._redaction = redaction or RedactionPolicy()
        self._clock = clock or SystemClock()
        self._attack_catalog = attack_catalog

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

    def lint_threat_models(
        self, paths: Sequence[Path], *, strict: bool = False
    ) -> list[ReportValidation]:
        """Each THREAT_MODEL.md at `paths` (files, or found under directories) against the prose
        contract; ATT&CK ids are checked against the registered catalog, else by shape only."""
        attack_ids = shape_only_attack_ids
        if (catalog := self._attack_catalog) is not None:
            attack_ids = catalog.invalid
        results = []
        for file in self._files.threat_models(paths):
            try:
                text = self._files.read(file)
            except (OSError, UnicodeDecodeError) as e:
                raise ValidationError(f"cannot read threat model {file}: {e}") from e
            errors, warnings = lint_threat_model(text, strict=strict, attack_ids=attack_ids)
            results.append(ReportValidation(str(file), errors, warnings))
        return results

    def lost_sections(self, existing: str, rendered: str) -> list[str]:
        """The sections an existing threat-model Markdown fills that `rendered` drops or empties."""
        return lost_sections(existing, rendered)

    def render(self, document: ArtifactDocument, format: RenderFormat) -> str:
        """Triage as Markdown or HTML; security reports and threat models as Markdown."""
        if isinstance(document, TriageArtifact):
            renderer = MarkdownRenderer() if format is RenderFormat.MARKDOWN else HtmlRenderer()
            return renderer.render(TriageView().report(document)).decode()
        view = {ReportArtifact: render_report, ThreatModelArtifact: render_threat_model}.get(
            document.schema_type()
        )
        if view is None:
            raise ValidationError(f"no report view renders {document.name} documents yet")
        if format is not RenderFormat.MARKDOWN:
            raise ValidationError(f"{document.name} documents render as Markdown only")
        return view(json.loads(document.payload))

    def sarif(self, document: ReportArtifact | CloudConfigAuditArtifact) -> dict[str, Any]:
        return SarifExport().report(document, self._sarif_tool_uri)

    def sarif_reports(self, root: Path) -> list[Path]:
        """The reports under `root` a SARIF sweep exports: one per baseline, the disposition-aware
        findings-current over its raw audit."""
        return self._files.sarif_reports(root)
