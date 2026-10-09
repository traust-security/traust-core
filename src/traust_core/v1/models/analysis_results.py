from __future__ import annotations

from enum import StrEnum

from traust_core.v1.models.base import Model


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


class Subject(Model):
    tree: str
    product: str | None = None
    repo_dir: str
    base: str

    @property
    def key(self) -> str:
        return "/".join(p for p in (self.tree, self.product, self.repo_dir, self.base) if p)
