from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, NewType
from uuid import UUID

from pydantic import Field

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import AppendOnly, Model
from traust_core.v1.models.findings import FindingView, Label, SkillInput
from traust_core.v1.models.vocabulary import (
    ChainSeverity,
    IsolationPosture,
    PeachBoundaryType,
    TenancyProfile,
    ThreatActor,
    ThreatImpact,
    ThreatLikelihood,
    ThreatStatus,
)

ToolName = NewType("ToolName", str)


class AssessmentKind(StrEnum):
    SECURE_CODE = "secure-code"
    CONTAINER = "container"
    RPM = "rpm"
    CLOUD_CONFIG = "cloud-config"
    VULN_SCAN = "vuln-scan"
    THREAT_MODEL = "threat-model"
    ISOLATION_REVIEW = "isolation-review"
    PRIV_PROFILE = "priv-profile"
    PQC_READINESS = "pqc-readiness"
    FUZZ = "fuzz"
    REPO_STATE = "repo-state"
    TRIAGE = "triage"
    SCANNER = "scanner"  # third-party scanner output (SARIF, Dependabot, govulncheck)
    TOOL_SCAN = "tool_scan"
    IMPACT = "impact"
    COMPLIANCE = "compliance"
    BENCHMARK_AUDIT = "benchmark_audit"  # an audit of a recall-benchmark target's pinned ref
    REMEDIATION = "remediation"
    VERIFICATION = "verification"  # a remediation re-checked on a patched commit
    FLEET_FIX = "fleet_fix"  # one fleet-fix spec applied to a repository's commit


class GapSignal(StrEnum):
    STRUCTURED = "structured"  # metadata.additional.coverage_gaps: the recording convention
    STEPS = "steps"  # a deterministic pre-scan recorded as "skipped: ..."
    TEXT = "text"  # a known emitter phrasing in negative_results; lowest confidence


@dataclass(frozen=True, slots=True)
class ReportGap:
    tool: str
    system: str
    signal: GapSignal
    count: int | None = None
    quote: str | None = None


# Each regex is a known emitter phrasing, not a guess: unrecognised prose never makes a gap.
# A None system is the regex's captured framework or language.
_GAP_PHRASES: tuple[tuple[re.Pattern[str], str, str | None], ...] = (
    (
        re.compile(r"toml/ini/properties config file — no v1 expander"),
        "config-matrix",
        "toml-ini-properties",
    ),
    (re.compile(r"\b(express|fastapi|flask|spring)\b[^.]*UNENUMERATED"), "route-guards", None),
    (re.compile(r"defaults resolve only at render time"), "config-matrix", "helm-render-gated"),
    (re.compile(r"CRD-shaped config"), "config-matrix", "crd-operator-config"),
    (
        re.compile(r"opengrep\b[^.]{0,80}\b(?:has\s+)?(?:0|~?no)\s+(\w+)\s+rules", re.I),
        "opengrep",
        None,
    ),
    (
        re.compile(r"sanitizer[- ]probes?[^.]{0,60}Python-only", re.I),
        "sanitizer-probes",
        "non-python",
    ),
)
_LANGUAGE_ALIASES = {
    "js": "javascript",
    "ts": "javascript",
    "typescript": "javascript",
    "golang": "go",
    "py": "python",
}


def report_gaps(report: Mapping[str, Any]) -> Iterator[ReportGap]:
    """What an audit report says it could not examine, at each signal tier."""
    additional = (report.get("metadata") or {}).get("additional") or {}
    for g in additional.get("coverage_gaps") or ():
        yield ReportGap(
            str(g.get("tool") or "unknown"),
            str(g.get("system") or "unknown"),
            GapSignal.STRUCTURED,
            g.get("count") if isinstance(g.get("count"), int) else None,
        )
    for step, state in (additional.get("deterministic_steps") or {}).items():
        if isinstance(state, str) and state.startswith("skipped"):
            yield ReportGap(str(step), "pre-scan-skipped", GapSignal.STEPS, quote=state[:160])
    for entry in report.get("negative_results") or ():
        text = " ".join(str(entry.get(k) or "") for k in ("area", "result", "files"))
        for pattern, tool, system in _GAP_PHRASES:
            if m := pattern.search(text):
                captured = (m.group(1) if m.groups() else None) or "unknown"
                name = system or _LANGUAGE_ALIASES.get(captured.lower(), captured.lower())
                yield ReportGap(tool, name, GapSignal.TEXT, quote=m.group(0)[:160])


class CoverageGap(Model):
    """A tool and the system it could not examine, across the audits that said so."""

    tool: str
    system: str
    repositories: int
    items: int | None = None  # summed counts, None when no report recorded one
    signals: dict[GapSignal, int]
    example_repository_ids: tuple[UUID, ...] = ()


class AttackTechnique(Model): ...


class Permission(Model): ...


class IsolationCheck(Model): ...


class PopulationRow(Model):
    """One repository's assessments of one kind as of a moment: the newest on its default line,
    and how many ran on the default line and on other branches (re-audits)."""

    repository_id: UUID
    kind: str
    latest: Assessment | None = None
    default_line: int = 0
    branches: int = 0


class AssessmentFilter(Model):
    repository_ref_id: UUID | None = None
    kind: AssessmentKind | None = None
    status: str | None = None


class ThreatFilter(Model): ...


class Coverage(Model):
    examined: int
    total: int
    gaps: tuple[CoverageGap, ...] = ()

    def ratio(self) -> float:
        """Share of the audits in scope whose report was examined; 0.0 when none were in scope."""
        return self.examined / self.total if self.total else 0.0


# NEED(contracts): the assessment-status enum, once it lands, owns these values.
ASSESSMENT_COMPLETED = "completed"
ASSESSMENT_DEGRADED = "degraded"


class Assessment(AppendOnly):
    """3a · what was examined: a ref (and image), by an assessor, with what outcome."""

    repository_ref_id: UUID
    image_id: UUID | None = None
    baseline_assessment_id: UUID | None = None
    run_order_id: UUID | None = None
    kind: str
    status: str
    assessor: str
    assessor_version: str
    occurred_at: datetime


class Artifact(AppendOnly):
    """A document an assessment produced (or imported); bytes live at uri."""

    assessment_id: UUID | None = None
    digest: str
    kind: str
    uri: str


# Artifact-lane content: read from the assessment's artifacts, never tables.
class Threat(Model):
    assessment_id: UUID
    label: Label
    title: str
    status: ThreatStatus
    actor: ThreatActor
    likelihood: ThreatLikelihood
    impact: ThreatImpact
    boundary: PeachBoundaryType | None = None
    techniques: tuple[AttackTechnique, ...] = ()


class AttackChain(Model):
    assessment_id: UUID
    threat_ids: tuple[UUID, ...]
    severity: ChainSeverity


class PrivilegeProfile(Model):
    assessment_id: UUID
    permissions: tuple[Permission, ...] = ()
    tenancy: TenancyProfile


class IsolationResult(Model):
    assessment_id: UUID
    posture: IsolationPosture
    checks: tuple[IsolationCheck, ...] = ()


class Freshness(Model):
    repository_ref_id: UUID | None = None
    last_assessed_at: datetime | None = None
    churn_ratio: float | None = None

    def age_days(self, now: datetime) -> int | None:
        if self.last_assessed_at is None:
            return None
        return (now.date() - self.last_assessed_at.date()).days


class Population(Model):
    as_of: datetime
    rows: tuple[PopulationRow, ...] = ()
    never_assessed_repository_ids: tuple[UUID, ...] = ()


class DiffRequest(Model):
    """Diff mode: scope the review to `checkout`'s changes since a baseline audit. The baseline
    is the latest completed secure-code audit of the default branch unless one is named;
    `since` overrides the commit the diff starts from."""

    checkout: Path
    baseline_assessment_id: UUID | None = None
    since: str | None = Field(default=None, pattern=r"^[0-9a-f]{7,40}$")


class DiffResolution(StrEnum):
    AUTO = "auto"
    OVERRIDE = "override"


class DiffFile(Model):
    path: str
    added: int
    deleted: int
    sensitive: bool
    hunks: str | None = None  # None: the scope's byte budget ran out first (listed in omitted)
    truncated: bool = False


class DiffCaller(Model):
    symbol: str
    defined_in: str
    path: str
    line: int
    context: str


class DiffCluster(Model):
    name: str
    files: tuple[DiffFile, ...]
    callers: tuple[DiffCaller, ...] = ()
    baseline: tuple[FindingView, ...] = ()


class DiffScope(Model):
    anchor: str
    resolution: DiffResolution
    baseline_assessment_id: UUID | None
    changed_lines: int
    sensitive_lines: int
    deps_manifests_changed: bool
    first_party_files: int
    changed_ratio: float
    clusters: tuple[DiffCluster, ...]
    callers_note: str | None = None
    omitted: tuple[str, ...] = ()


class DiffRefused(ValidationError):
    """The diff can't stand in for the baseline audit; run a full audit instead. A scan must
    never widen past this to the whole repository, or narrow past it."""

    recommend = "full-audit"

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class AssessmentSkillInput(SkillInput):
    kind: AssessmentKind
    threat_model: tuple[Artifact, ...] = ()
    diff: DiffScope | None = None
