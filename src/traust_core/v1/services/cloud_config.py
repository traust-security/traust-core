from __future__ import annotations

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import (
    ArtifactDocument,
    CloudConfigAuditArtifact,
    SchemaView,
)
from traust_core.v1.services.lint import LintAction, LintContext, LintRuleId, Violation


class CloudConfigCitations:
    """The cloud-config report gate beyond its schema: every judgement over the facts says why.

    OSS Checkov rates nothing, so any severity over an unrated fact needs the rubric row applied.
    """

    id = LintRuleId("cloud-config.citations")

    def check(self, subject: ArtifactDocument, context: LintContext) -> list[Violation]:
        if not isinstance(subject, CloudConfigAuditArtifact):
            raise ValidationError(
                f"{self.id} checks cloud-config audits, not {type(subject).__name__}"
            )
        return [
            Violation(rule=self.id, item=f.id, message=message, action=LintAction.REVIEW)
            for f in subject.findings
            for message in _defects(f)
        ]


def _defects(finding: SchemaView) -> list[str]:
    explained = bool((finding.rationale or "").strip())
    scanner = finding.scanner_severity or "unrated"
    defects = []
    if finding.status in ("suppressed", "needs_review") and not explained:
        defects.append(f"status '{finding.status}' without rationale")
    if scanner == "unrated" and not explained:
        defects.append(
            "severity assigned over an unrated fact without rationale "
            "(cite the SKILL.md rubric row)"
        )
    elif scanner != finding.severity and not explained:
        defects.append("severity changed from scanner's without rationale")
    if not any(loc.file_path for loc in finding.locations):
        defects.append("no location with a file_path, so the finding can't be tracked")
    return defects
