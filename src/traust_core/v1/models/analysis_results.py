from __future__ import annotations

from enum import StrEnum


class ResultKind(StrEnum):
    SECURITY_AUDIT = "security-audit.json"
    SECURITY_AUDIT_MD = "security-audit.md"
    CLOUD_CONFIG_AUDIT = "cloud-config-audit.json"
    CONTAINER_AUDIT = "container-audit.json"
    FINDINGS_LAYER = "findings-layer.json"
    FINDINGS_CURRENT = "findings-current.json"
    TRIAGE = "triage.json"
    TRIAGE_MD = "triage.md"
    THREAT_MODEL = "threat-model.json"
    THREAT_MODEL_MD = "threat-model.md"
    PRIV_PROFILE = "priv-profile.json"
    VALIDATION = "validation.json"
    REMEDIATION_VERIFICATION = "remediation-verification.json"
    REMEDIATION_PATCH = "remediation-patch.diff"
    REPO_STATE = "repo-state.json"
