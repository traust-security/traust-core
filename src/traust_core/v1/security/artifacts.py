from __future__ import annotations

from traust_core.v1 import contracts
from traust_core.v1.artifacts.artifact import Artifact
from traust_core.v1.domain.analysis_results import ResultKind


class SecurityAuditArtifact(
    Artifact,
    name="security-audit",
    schema="report",
    kind=ResultKind.SECURITY_AUDIT,
    role="baseline",
): ...


class FindingsCurrentArtifact(
    Artifact,
    name="findings-current",
    schema="report",
    kind=ResultKind.FINDINGS_CURRENT,
    role="cumulative",
): ...


class FindingsLayerArtifact(
    Artifact, name="findings-layer", schema="layer", kind=ResultKind.FINDINGS_LAYER
): ...


class TriageArtifact(Artifact, name="triage", schema="triage", kind=ResultKind.TRIAGE): ...


class ThreatModelArtifact(
    Artifact, name="threat-model", schema="threat-model", kind=ResultKind.THREAT_MODEL
): ...


class ValidationArtifact(
    Artifact, name="validation", schema="validation", kind=ResultKind.VALIDATION
): ...


class VerificationArtifact(
    Artifact,
    name="remediation-verification",
    schema="verification",
    kind=ResultKind.REMEDIATION_VERIFICATION,
): ...


class CloudConfigAuditArtifact(
    Artifact,
    name="cloud-config-audit",
    schema="cloud-config-audit",
    kind=ResultKind.CLOUD_CONFIG_AUDIT,
): ...


class PrivProfileArtifact(
    Artifact, name="priv-profile", schema="operator-priv-profile", kind=ResultKind.PRIV_PROFILE
): ...


ANALYSIS_ARTIFACTS: tuple[type[Artifact], ...] = (
    SecurityAuditArtifact,
    FindingsCurrentArtifact,
    FindingsLayerArtifact,
    TriageArtifact,
    ThreatModelArtifact,
    ValidationArtifact,
    VerificationArtifact,
    CloudConfigAuditArtifact,
    PrivProfileArtifact,
)
ARTIFACT_FOR_KIND = {a.kind: a for a in ANALYSIS_ARTIFACTS if a.kind is not None}

Verdict = contracts.enum("verdict")
Severity = contracts.enum("severity")
