from __future__ import annotations

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import ArtifactDocument, IsolationReviewArtifact
from traust_core.v1.services.lint import LintAction, LintContext, LintRuleId, Violation


class GapInterfaces:
    """The isolation-review gate beyond its schema: each gap names an interface the review lists."""

    id = LintRuleId("isolation-review.gap-interfaces")

    def check(self, subject: ArtifactDocument, context: LintContext) -> list[Violation]:
        if not isinstance(subject, IsolationReviewArtifact):
            raise ValidationError(
                f"{self.id} checks isolation reviews, not {type(subject).__name__}"
            )
        listed = {i.id for i in subject.interfaces}
        return [
            Violation(
                rule=self.id,
                item=f"gaps[{n}]",
                message=f"interface_id {g.interface_id!r} does not match any interfaces[].id",
                action=LintAction.REVIEW,
            )
            for n, g in enumerate(subject.gaps)
            if g.interface_id not in listed
        ]
