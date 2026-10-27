from __future__ import annotations

from collections import Counter

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import ArtifactDocument, FuzzReportArtifact
from traust_core.v1.services.lint import LintAction, LintContext, LintRuleId, Violation


class FuzzHarnessReferences:
    """The fuzz-report gate beyond its schema: harness and crasher names are unique and each
    crasher names a harness the target ran."""

    id = LintRuleId("fuzz-report.harness-references")

    def check(self, subject: ArtifactDocument, context: LintContext) -> list[Violation]:
        if not isinstance(subject, FuzzReportArtifact):
            raise ValidationError(f"{self.id} checks fuzz reports, not {type(subject).__name__}")
        harnesses = Counter(h.name for h in subject.target.harnesses)
        found = [
            (f"target.harnesses[{n}]", f"harness name {h.name!r} is not unique")
            for n, h in enumerate(subject.target.harnesses)
            if harnesses[h.name] > 1
        ]
        crashers = Counter(c.id for c in subject.crashers)
        for n, c in enumerate(subject.crashers):
            if crashers[c.id] > 1:
                found.append((f"crashers[{n}]", f"crasher id {c.id!r} is not unique"))
            if c.harness not in harnesses:
                found.append(
                    (f"crashers[{n}]", f"harness {c.harness!r} does not match any target harness")
                )
        return [
            Violation(rule=self.id, item=item, message=message, action=LintAction.REVIEW)
            for item, message in found
        ]
