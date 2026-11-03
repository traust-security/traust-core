from __future__ import annotations

from collections import Counter

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import (
    ArtifactDocument,
    FuzzCampaignArtifact,
    FuzzReportArtifact,
)
from traust_core.v1.services.lint import LintAction, LintContext, LintRuleId, Violation


class FuzzHarnessReferences:
    """Harness, crasher and pattern names are unique; each crasher names a target harness."""

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
        patterns = Counter(p.name for p in subject.patterns)
        found.extend(
            (f"patterns[{n}]", f"pattern {p.name!r} is not unique")
            for n, p in enumerate(subject.patterns)
            if patterns[p.name] > 1
        )
        return [
            Violation(rule=self.id, item=item, message=message, action=LintAction.REVIEW)
            for item, message in found
        ]


class FuzzCampaignReferences:
    """Keep supplied aggregate facts coherent without promoting them to execution evidence."""

    id = LintRuleId("fuzz-campaign.references")

    def check(self, subject: ArtifactDocument, context: LintContext) -> list[Violation]:
        if not isinstance(subject, FuzzCampaignArtifact):
            raise ValidationError(f"{self.id} checks fuzz campaigns, not {type(subject).__name__}")
        found: list[tuple[str, str]] = []
        for collection, keys in (
            ("batches", [b.batch for b in subject.batches]),
            ("bugs", [b.num for b in subject.bugs]),
            ("patterns", [p.name for p in subject.patterns]),
        ):
            duplicates = {key for key, count in Counter(keys).items() if count > 1}
            found.extend(
                (f"{collection}[{n}]", f"duplicate {collection} key {key!r}")
                for n, key in enumerate(keys)
                if key in duplicates
            )
        found.extend(
            (f"patterns[{n}]", "vulnerable count exceeds tested count")
            for n, p in enumerate(subject.patterns)
            if p.vulnerable > p.tested
        )
        return [
            Violation(rule=self.id, item=item, message=message, action=LintAction.REVIEW)
            for item, message in found
        ]
