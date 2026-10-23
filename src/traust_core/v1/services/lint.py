from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import NewType, Protocol

import pydantic

from traust_core.v1.models.artifacts import ArtifactDocument
from traust_core.v1.models.base import Model
from traust_core.v1.providers.sources import WorkspaceFiles

LintRuleId = NewType("LintRuleId", str)


class LintAction(StrEnum):
    """What a violation asks of the skill; a lint routes, it never concludes."""

    RE_VOTE = "re_vote"
    REVIEW = "review"


class LintContext(Model):
    model_config = pydantic.ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    files: WorkspaceFiles | None = None


class Violation(Model):
    rule: LintRuleId
    item: str
    message: str
    action: LintAction


class LintReport(Model):
    violations: tuple[Violation, ...] = ()

    @property
    def passed(self) -> bool:
        return not self.violations


class LintRule(Protocol):
    id: LintRuleId

    def check(self, subject: ArtifactDocument, context: LintContext) -> list[Violation]: ...


class Lint:
    def __init__(self, rules: Mapping[type[ArtifactDocument], Sequence[LintRule]]) -> None:
        self._rules = rules

    def run(self, subject: ArtifactDocument, context: LintContext) -> LintReport:
        rules = self._rules.get(type(subject), ())
        return LintReport(violations=tuple(v for r in rules for v in r.check(subject, context)))
