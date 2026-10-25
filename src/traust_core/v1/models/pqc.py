from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import Field

from traust_core.v1.models.base import Model
from traust_core.v1.models.findings import SkillInput
from traust_core.v1.models.vocabulary import (
    PqcBlastRadius,
    PqcClassification,
    PqcDominantProvenance,
    PqcPathClass,
    PqcReadinessBucket,
    PqcRemediationCategory,
    RemediationEffort,
    Severity,
)


class PqcStamps(Model):
    """What a Layer-1 scan was produced by; a scan stamped otherwise is stale for the pack."""

    adapter_version: str
    pqc_scan_commit: str
    rules_sha256: str
    binary_sha256: str | None = None

    def same_pack(self, other: PqcStamps) -> bool:
        return (self.adapter_version, self.rules_sha256) == (
            other.adapter_version,
            other.rules_sha256,
        )


class PqcScanFinding(Model):
    """One raw rule hit from the pinned scanner (or a material check), before post-processing."""

    rule_id: str = Field(min_length=1)
    file: str
    line: int | None = None
    detail: str = ""
    match: str = ""
    finding_id: str | None = None
    severity: str | None = None
    risk: str | None = None
    confidence: float | None = None


class PqcScan(Model):
    """One scanner run over a checkout: its hits, its coverage and the pack it ran."""

    findings: tuple[PqcScanFinding, ...] = ()
    scanned_files: int | None = None
    skipped_files: int | None = None
    rules_in_pack: int
    stamps: PqcStamps
    cbom: bytes | None = None  # CycloneDX, as the scanner wrote it


class PqcClock(Model):
    status_now: str | None = None
    deprecated_after: int | None = None
    disallowed_after: int | None = None


class Ir8547(Model):
    """A rule's NIST IR 8547 mapping: quantum class, usage and the transition clock."""

    qclass: str
    usage: str = "unknown"
    clock: PqcClock | None = None
    matched_prefix: str = ""
    qclass_resolved: str | None = None


class PqcFact(Model):
    """One Layer-1 fact of a pqc-facts document; raw signal, never a verdict."""

    fact_id: str = Field(pattern=r"^F[0-9]{4,}$")
    rule_id: str = Field(min_length=1)
    file: str
    line: int | None = None
    detail: str = ""
    match: str | None = None
    provider: str | None = None
    pqc_capable: bool | None = None
    fips_mode: bool | None = None
    capability_hint: str | None = None
    finding_id: str | None = None
    severity: str | None = None
    risk: str | None = None
    confidence: float | None = None
    ir8547: Ir8547
    provenance_hint: str
    path_class: PqcPathClass


class PqcRoute(StrEnum):
    """How much Layer-2 work a commit needs (l2_prepass tiers, worst first); never a score."""

    FULL = "full"
    LIGHT = "light"
    SKIP = "skip"
    UNSCORED = "unscored"
    UNREFRESHED = "unrefreshed"


class PqcFilter(Model):
    repository_ref_ids: tuple[UUID, ...] | None = None
    product_id: UUID | None = None
    buckets: tuple[PqcReadinessBucket, ...] = ()
    categories: tuple[PqcRemediationCategory, ...] = ()
    patchable: bool | None = None


class PqcDimension(StrEnum):
    BUCKET = "bucket"
    PROVENANCE = "provenance"


class PqcRollup(Model):
    """One group of commits' latest readiness: how many, how ready, and what is left to do."""

    key: str
    repositories: int
    mean_overall: float
    clock_2030: int
    hndl_priority: int
    blocked: int
    remediations: dict[PqcRemediationCategory, int] = Field(default_factory=dict)


class PqcRemediation(Model):
    """One actionable item of a readiness report (`remediations[]`), owner-facing."""

    id: str
    category: PqcRemediationCategory
    action: str
    target: str | None = None
    details: str | None = None
    locations: tuple[str, ...] = ()
    blocked_on: str | None = None
    remediation_effort: RemediationEffort | None = None
    blast_radius: PqcBlastRadius | None = None
    deadline: int | None = None
    recipe: str | None = None


class PqcBlocker(Model):
    """A remediation of a commit's latest readiness, in the findings vocabulary /patch reads."""

    repository_ref_id: UUID
    assessment_id: UUID
    remediation: PqcRemediation
    severity: Severity
    classification: PqcClassification

    @property
    def patchable(self) -> bool:
        return bool(self.remediation.locations)


class PqcClockItem(Model):
    """A primitive on the NIST IR 8547 transition clock (`clock_items[]`)."""

    primitive: str
    deprecated_after: int | None = None
    disallowed_after: int | None = None
    remediation_effort: RemediationEffort | None = None


class PqcReadiness(Model):
    """A commit's recorded readiness: the report's scorecard and its remediations."""

    assessment_id: UUID
    repository_ref_id: UUID
    assessed_at: datetime
    bucket: PqcReadinessBucket | None = None
    overall: float
    has_2030_clock_items: bool
    hndl_priority: bool
    runtime_verification_required: bool
    dominant: PqcDominantProvenance
    who_sets_tls: str | None = None
    pqca: float | None = None
    fips_interaction: str | None = None
    clock_items: tuple[PqcClockItem, ...] = ()
    remediations: tuple[PqcRemediation, ...] = ()

    def is_blocked(self) -> bool:
        """A remediation anchored in this repository: something /patch can work on."""
        return any(r.locations for r in self.remediations)


class PqcSiteKind(StrEnum):
    """A first-party fact the roll-up lists by location: a classical-only group pin blocking
    hybrid TLS, or a Go toolchain below the PQC key-exchange default."""

    GROUP_PIN = "group-pin"
    TOOLCHAIN = "toolchain"


class PqcSite(Model):
    repository_ref_id: UUID
    kind: PqcSiteKind
    fact: PqcFact


class PqcPrescan(Model):
    """Layer 1 for one commit: its facts, the templated report when the scan found nothing, and
    the scan's CBOM (derived output for the caller to write; never stored)."""

    assessment_id: UUID
    facts: tuple[PqcFact, ...]
    scanned: bool
    readiness: PqcReadiness | None = None
    cbom: bytes | None = None


class PqcReadinessInput(SkillInput):
    """What Layer 2 scores from: the commit's facts, the route, and its prior readiness."""

    facts: tuple[PqcFact, ...]
    no_crypto_detected_assertion: str | None = None
    route: PqcRoute
    prior: PqcReadiness | None = None
