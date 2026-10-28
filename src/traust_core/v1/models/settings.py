"""Tier 2 settings: versioned scope-ref documents, one kind per contracts settings-kind value."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

import pydantic

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import (
    AdrRegistryArtifact,
    ArtifactDocument,
    BenchmarkTargetArtifact,
    BudgetArtifact,
    ComplianceMappingArtifact,
    ExecutionBoundariesArtifact,
    FeedAccessArtifact,
    OrgParametersArtifact,
    ProductDefinitionsMapArtifact,
    RemediationTargetArtifact,
    RulePackAllowlistArtifact,
    SlaPolicyArtifact,
)
from traust_core.v1.models.base import Model
from traust_core.v1.models.compliance import ComplianceMapping
from traust_core.v1.models.detection_quality import CanaryKind
from traust_core.v1.models.vocabulary import SettingKind

SETTING_ARTIFACTS: Mapping[SettingKind, type[ArtifactDocument]] = {
    SettingKind(a.schema): a
    for a in (
        BudgetArtifact,
        SlaPolicyArtifact,
        RulePackAllowlistArtifact,
        FeedAccessArtifact,
        ExecutionBoundariesArtifact,
        RemediationTargetArtifact,
        ProductDefinitionsMapArtifact,
        OrgParametersArtifact,
        AdrRegistryArtifact,
        ComplianceMappingArtifact,
        BenchmarkTargetArtifact,
    )
}
REVISION = "revision"


class SettingSource(StrEnum):
    DEFAULT = "default"
    CHANGED = "changed"
    NOT_SET = "not_set"


class SettingVersion(Model):
    """One version of a kind: the shipped default (version 1 of a kind that has one) or a
    stored document, with who set it, why and when."""

    kind: SettingKind
    version: int = pydantic.Field(ge=1)
    default: bool
    digest: str
    artifact_id: UUID | None = None
    set_by: str | None = None
    reason: str | None = None
    set_at: datetime | None = None


class Setting(Model):
    """A kind's effective document (its revision block removed) and the version it is."""

    version: SettingVersion
    document: dict[str, Any]


class SettingSummary(Model):
    kind: SettingKind
    source: SettingSource
    version: SettingVersion | None = None
    summary: str = ""


class SettingChange(Model):
    """What a set or reset did: the version now in force and the diff it applied; `changed`
    false when the document already was the effective one."""

    version: SettingVersion
    changed: bool
    diff: str = ""


class SettingDiff(Model):
    kind: SettingKind
    from_version: int
    to_version: int
    diff: str


def without_revision(document: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in document.items() if k != REVISION}


def summary(document: Mapping[str, Any]) -> str:
    """One line a person can read: each top-level field, collections by their size."""

    def part(value: Any) -> str:
        if isinstance(value, Mapping):
            return f"{len(value)} entries"
        if isinstance(value, list):
            return f"{len(value)} items"
        return str(value)

    return "; ".join(f"{k}: {part(v)}" for k, v in without_revision(document).items())


def _answer_key(doc: ArtifactDocument) -> None:
    ids = [t.id for t in doc.targets]
    if dupes := sorted({i for i in ids if ids.count(i) > 1}):
        raise ValidationError(f"benchmark answer key: duplicate target ids {dupes}")
    if held := [t.id for t in doc.targets if t.provenance == CanaryKind.SEEDED and t.held_out]:
        raise ValidationError(
            f"benchmark answer key: seeded targets {held} are held out; their author has "
            "read the answer key, so they are development split only"
        )


def _lanes(doc: ArtifactDocument) -> None:
    lanes = [lane.lane for lane in doc.lanes]
    if dupes := sorted({lane for lane in lanes if lanes.count(lane) > 1}):
        raise ValidationError(f"budget: more than one budget per lane: {dupes}")


def _compliance_mapping(doc: ArtifactDocument) -> None:
    assert isinstance(doc, ComplianceMappingArtifact)
    ComplianceMapping.of(doc)


# Rules beyond the schema, checked on every write of the kind (CLI, REST and domain doors).
SETTING_CHECKS: Mapping[SettingKind, Callable[[ArtifactDocument], None]] = {
    SettingKind("benchmark-target"): _answer_key,
    SettingKind("budget"): _lanes,
    SettingKind("compliance-mapping"): _compliance_mapping,
}
