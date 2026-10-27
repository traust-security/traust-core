from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, NewType, Self
from uuid import UUID, uuid5

from pydantic import Field, computed_field

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import ReportArtifact
from traust_core.v1.models.base import AppendOnly, Dto, Model
from traust_core.v1.models.findings import FindingCandidate, FindingView, Label, SkillInput
from traust_core.v1.models.vocabulary import (
    AssessmentKind,
    ChainSeverity,
    EntryPointKind,
    InterfaceComplexity,
    IsolationDimension,
    IsolationPosture,
    RiskRatingBand,
    TenancyProfile,
    ThreatActor,
    ThreatImpact,
    ThreatLikelihood,
    ThreatStatus,
)

ToolName = NewType("ToolName", str)


# The contracts schema of the document each kind records through `AssessmentService.record`;
# the other kinds are recorded by their owner's door.
RECORDED_SCHEMAS: dict[AssessmentKind, str] = {
    AssessmentKind.SECURE_CODE_CANONICAL: "report",
    AssessmentKind.CONTAINER: "report",
    AssessmentKind.RPM: "report",
    AssessmentKind.BENCHMARK_AUDIT: "report",
    AssessmentKind.CLOUD_CONFIG_CANONICAL: "cloud-config-audit",
    AssessmentKind.VULN_SCAN_CANONICAL: "vuln-findings",
    AssessmentKind.THREAT_MODEL_CANONICAL: "threat-model",
    AssessmentKind.ISOLATION_REVIEW_CANONICAL: "isolation-review",
    AssessmentKind.PRIV_PROFILE_CANONICAL: "operator-priv-profile",
    AssessmentKind.REPO_STATE_CANONICAL: "repo-state",
    AssessmentKind.TOOL_SCAN: "code-facts",
    AssessmentKind.FUZZ: "fuzz-report",
}
# Kinds whose recorded document's findings (a fuzz report's crashers) are findings of the
# assessment, and how the document states them. Benchmark runs are scored, never taken in;
# secure-code reports are not taken in at record (not decided here).
REPORTED_FINDINGS: dict[AssessmentKind, Callable[[Any, UUID], list[FindingCandidate]]] = {
    AssessmentKind.CONTAINER: lambda doc, r: FindingCandidate.of_report(doc.findings, r),
    AssessmentKind.RPM: lambda doc, r: FindingCandidate.of_report(doc.findings, r),
    AssessmentKind.VULN_SCAN_CANONICAL: lambda doc, r: FindingCandidate.of_scan(doc.findings, r),
    AssessmentKind.FUZZ: lambda doc, r: FindingCandidate.of_fuzz(doc.crashers, r),
}


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


class ThreatModelEntryPoint(Dto):
    """A threat model's section-3 entry point, as far as a coverage check reads it."""

    entry_point: str
    kind: EntryPointKind | None = None


class CoverageGap(Model):
    """A tool and the system it could not examine, across the audits that said so."""

    tool: str
    system: str
    repositories: int
    items: int | None = None  # summed counts, None when no report recorded one
    signals: dict[GapSignal, int]
    example_repository_ids: tuple[UUID, ...] = ()


class AttackTechnique(Model):
    id: str  # a MITRE ATT&CK technique id (T1078, T1078.001)


_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


class CatalogTechnique(Dto):
    name: str
    tactics: tuple[str, ...] = ()
    deprecated: bool = False
    revoked: bool = False
    revoked_by: str | None = None


class AttackCatalog(Model):
    """One pinned ATT&CK release's techniques and the pack's vocabulary-to-technique maps."""

    attack_version: str
    mapping_version: str
    attribution: str
    techniques: Mapping[str, CatalogTechnique]
    capability_map: Mapping[str, tuple[str, ...]] = Field(default_factory=dict)
    category_map: Mapping[str, tuple[str, ...]] = Field(default_factory=dict)

    def invalid(self, ids: Iterable[str]) -> tuple[str, ...]:
        """Why each id can't be cited: malformed, unknown, revoked or deprecated in the release."""
        return tuple(e for e in (self._why(i) for i in ids) if e)

    def _why(self, technique_id: str) -> str | None:
        if not _TECHNIQUE_ID.match(technique_id):
            return f"{technique_id}: malformed technique ID"
        entry = self.techniques.get(technique_id)
        if entry is None:
            return f"{technique_id}: not in pinned ATT&CK table"
        if entry.revoked:
            return f"{technique_id}: revoked" + (
                f" -> use {entry.revoked_by}" if entry.revoked_by else ""
            )
        if entry.deprecated:
            return f"{technique_id}: deprecated in pinned ATT&CK release"
        return None


class Permission(Model):
    """One RBAC grant: an API group, resource and verb, cluster-wide or namespaced."""

    api_group: str = ""
    resource: str
    verb: str
    cluster_scoped: bool = False


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


class ThreatFilter(Model):
    repository_ids: tuple[UUID, ...]
    statuses: tuple[ThreatStatus, ...] = ()  # any when empty
    technique: str | None = None
    as_of: datetime | None = None  # the models held then; now when None


class ThreatRatings(Model):
    """A threat model with each OWASP risk_rating's derived values rebuilt from its factors;
    `failed` names the threats whose factors can't be rated, with why."""

    model: dict[str, Any]
    changed: tuple[Label, ...] = ()
    failed: dict[Label, str] = Field(default_factory=dict)


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
    kind: AssessmentKind | str = Field(union_mode="left_to_right")
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
class ThreatMitigation(Model):
    text: str
    closes_class: str  # yes | partial | no
    effort: str | None
    blocked_external: bool | None = None


class TenantBoundary(Model):
    """One tenant-facing interface as a multi-tenant threat model states it (its section 10)."""

    assessment_id: UUID
    repository_id: UUID
    boundary_id: Label  # IF-n, never renumbered or reused
    interface: str
    kind: str
    exposure: str
    complexity: InterfaceComplexity | None = None
    dimensions: dict[IsolationDimension, str] = Field(default_factory=dict)  # results as stated
    threat_ids: tuple[Label, ...] = ()
    isolation_review_ref: str | None = None

    @property
    def id(self) -> UUID:
        """Stable per (assessment, boundary id), as a threat's is per label."""
        return uuid5(self.assessment_id, self.boundary_id)

    @classmethod
    def of(
        cls, assessment: Assessment, repository_id: UUID, model: Mapping[str, Any]
    ) -> list[TenantBoundary]:
        assert assessment.id is not None
        return [
            cls(
                assessment_id=assessment.id,
                repository_id=repository_id,
                boundary_id=Label(b["boundary_id"]),
                interface=b["interface"],
                kind=b["kind"],
                exposure=b["exposure"],
                complexity=b.get("complexity"),
                dimensions={d: b[d] for d in IsolationDimension if d in b},
                threat_ids=tuple(Label(t) for t in b.get("threat_ids") or ()),
                isolation_review_ref=b.get("isolation_review_ref") or None,
            )
            for b in model.get("tenant_boundaries") or ()
        ]


class Threat(Model):
    """One threat as a threat model states it."""

    assessment_id: UUID
    repository_id: UUID | None = None  # set when read through AssessmentService.threats
    label: Label
    title: str
    status: ThreatStatus
    actor: ThreatActor  # the weakest position: what scoring reads
    actors: tuple[ThreatActor, ...] = ()  # every position, weakest first
    severity: RiskRatingBand | None = None  # OWASP risk rating; None until re-rated
    likelihood: ThreatLikelihood | None = None  # legacy labels, valid until re-rated
    impact: ThreatImpact | None = None
    surface: str | None = None
    asset: str | None = None
    controls: str | None = None
    evidence: tuple[str, ...] = ()  # empty: modelled but not evidenced, not "unmitigated"
    techniques: tuple[AttackTechnique, ...] = ()
    isolation_dimensions: tuple[IsolationDimension, ...] = ()  # the dimensions it stresses
    boundary_ids: tuple[str, ...] = ()  # the tenant boundaries naming it
    isolation_review_ref: str | None = None  # the first naming boundary's full review
    mitigations: tuple[ThreatMitigation, ...] = ()
    linddun: bool = False  # a privacy-overlay row

    @property
    def id(self) -> UUID:
        """Stable per (assessment, label): a model never renumbers or reuses a threat id."""
        return uuid5(self.assessment_id, self.label)

    @classmethod
    def of(
        cls, assessment: Assessment, repository_id: UUID, model: Mapping[str, Any]
    ) -> list[Threat]:
        """Every threat a threat-model document states, joined to its boundaries and mitigations."""
        assert assessment.id is not None
        boundaries: dict[str, list[str]] = {}
        reviews: dict[str, str] = {}
        for b in TenantBoundary.of(assessment, repository_id, model):
            for label in b.threat_ids:
                boundaries.setdefault(label, []).append(b.boundary_id)
                if b.isolation_review_ref:
                    reviews.setdefault(label, b.isolation_review_ref)
        mitigations: dict[str, list[ThreatMitigation]] = {}
        for m in model.get("mitigations") or ():
            mitigation = ThreatMitigation(
                text=m["mitigation"],
                closes_class=m["closes_class"],
                effort=m["effort"],
                blocked_external=(
                    m["blocked_external"] if isinstance(m.get("blocked_external"), bool) else None
                ),
            )
            for label in m["threat_ids"]:
                mitigations.setdefault(label, []).append(mitigation)
        return [
            cls(
                assessment_id=assessment.id,
                repository_id=repository_id,
                label=Label(t["id"]),
                title=t["threat"],
                status=t["status"],
                actor=t["actor"][0],
                actors=tuple(t["actor"]),
                severity=(t.get("risk_rating") or {}).get("severity"),
                likelihood=t.get("likelihood"),
                impact=t.get("impact"),
                surface=t.get("surface"),
                asset=t.get("asset"),
                controls=t.get("controls"),
                evidence=tuple(t.get("evidence") or ()),
                techniques=tuple(AttackTechnique(id=r) for r in t.get("attack_refs") or ()),
                isolation_dimensions=tuple(t.get("isolation_dimensions") or ()),
                boundary_ids=tuple(boundaries.get(t["id"], ())),
                isolation_review_ref=reviews.get(t["id"]),
                mitigations=tuple(mitigations.get(t["id"], ())),
                linddun=t["threat"].lower().startswith("linddun:"),
            )
            for t in model["threats"]
        ]


class AttackScenario(Model):
    """A threat model's narrative of one threat's attack as it unfolds (its section 9)."""

    assessment_id: UUID
    repository_id: UUID
    label: Label
    threat: str | None = None
    steps: tuple[str, ...]


class AttackChain(Model):
    assessment_id: UUID
    threat_ids: tuple[UUID, ...]
    severity: ChainSeverity


class PrivilegeProfile(Model):
    """A repository's declared privileges (static tiers), as its priv-profile states them."""

    assessment_id: UUID
    repository_id: UUID
    permissions: tuple[Permission, ...] = ()  # the distinct grants its RBAC rules expand to
    # NEED(contracts): the priv-profile schema carries no tenancy; None until producers write it.
    tenancy: TenancyProfile | None = None
    workloads: int
    privileged_workloads: int | None = None  # privileged or host namespace: the headline
    rbac_rules: int
    wildcard_rules: int | None = None
    scc_requests: tuple[str, ...] = ()
    flags: dict[str, int] = Field(default_factory=dict)  # a pattern is present only if it matched
    containers: int | None = None  # None when the profile lists no workloads
    privileged_containers: int | None = None
    run_as_non_root_containers: int | None = None  # a container unset inherits its pod's
    namespaces: tuple[str, ...] = ()
    install_modes: tuple[str, ...] = ()  # the supported ones
    kubebuilder_markers: int | None = None
    surplus: int | None = None  # shipped, no marker asking for it; None when not derivable

    @computed_field  # type: ignore[prop-decorator]
    @property
    def distinct_rule_triples(self) -> int:
        return len({(p.api_group, p.resource, p.verb) for p in self.permissions})

    @computed_field  # type: ignore[prop-decorator]
    @property
    def distinct_cluster_triples(self) -> int:
        return len(
            {(p.api_group, p.resource, p.verb) for p in self.permissions if p.cluster_scoped}
        )

    @classmethod
    def of(cls, assessment: Assessment, repository_id: UUID, profile: Mapping[str, Any]) -> Self:
        assert assessment.id is not None
        summary = profile["summary"]
        tier2 = profile.get("tier2_required_vs_granted") or {}
        posture = {}
        if "workloads" in profile:
            contexts = [
                (c.get("securityContext") or {}, w.get("pod_securityContext") or {})
                for w in profile["workloads"]
                for c in w.get("containers") or ()
            ]
            posture = {
                "containers": len(contexts),
                "privileged_containers": sum(bool(c.get("privileged")) for c, _ in contexts),
                "run_as_non_root_containers": sum(
                    bool(
                        pod.get("runAsNonRoot")
                        if c.get("runAsNonRoot") is None
                        else c["runAsNonRoot"]
                    )
                    for c, pod in contexts
                ),
            }
        grants = {
            Permission(
                api_group=group,
                resource=resource,
                verb=verb,
                cluster_scoped=rule.get("scope") == "cluster",
            ): None
            for rule in profile.get("rbac_rules") or ()
            for group in rule.get("apiGroups") or [""]
            for resource in rule.get("resources") or ()
            for verb in rule.get("verbs") or ()
        }
        return cls(
            assessment_id=assessment.id,
            repository_id=repository_id,
            permissions=tuple(grants),
            workloads=summary["workloads"],
            privileged_workloads=summary.get("privileged_or_host_workloads"),
            rbac_rules=summary["rbac_rules"],
            wildcard_rules=summary.get("wildcard_rules"),
            scc_requests=tuple(summary.get("scc_requests") or ()),
            flags={k: len(v) for k, v in (profile.get("rbac_flags") or {}).items() if v},
            namespaces=tuple(profile.get("namespaces") or ()),
            install_modes=tuple(k for k, v in (profile.get("install_modes") or {}).items() if v),
            kubebuilder_markers=tier2.get("kubebuilder_markers"),
            surplus=tier2.get("shipped_not_declared_count"),
            **posture,
        )


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


# Earlier reports kept the reviewed line count in metadata.additional under one of these keys.
_LEGACY_LINES_REVIEWED = ("lines_reviewed", "loc_reviewed", "lines_of_code")


def _line_count(value: object) -> int | None:
    if isinstance(value, str):
        value = int(value) if value.strip().isdigit() else None
    if isinstance(value, bool) or not isinstance(value, int | float) or value <= 0:
        return None
    return int(value)


class AuditScope(Model):
    """What a code audit says it covered: the lines it reviewed and the lanes it left to others
    (`metadata.additional.companion_lanes`, e.g. `cloud-config-audit` for IaC in the tree)."""

    lines_reviewed: int | None = None
    companion_lanes: tuple[str, ...] = ()

    @classmethod
    def of_report(cls, doc: ReportArtifact) -> AuditScope:
        additional = doc.metadata.additional
        counts = [doc.metadata.loc_reviewed]
        if additional is not None:
            counts += [getattr(additional, key, None) for key in _LEGACY_LINES_REVIEWED]
        return cls(
            lines_reviewed=next((n for c in counts if (n := _line_count(c))), None),
            companion_lanes=additional.companion_lanes if additional is not None else (),
        )


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
    threat_model_document: dict[str, Any] | None = None  # the latest threat model's JSON
    # the diff's named audit, else the default line's newest completed code audit
    baseline_assessment_id: UUID | None = None
    diff: DiffScope | None = None
