"""Repository observation: forge measurements and what they are measured against.

Keyed by repository_id, matching the inventory tables.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from enum import StrEnum
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import AwareDatetime, field_serializer

from traust_core.v1.models.artifacts import RepoStateArtifact
from traust_core.v1.models.base import Model
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import ComparisonStatus

# The rescan router and diff-mode scoping share these: if they disagreed on what is first-party
# or sensitive, a diff the router sent to diff-scan could be refused, or widened, by the scan.
SENSITIVE_RX = re.compile(
    r"auth|login|token|secret|cred|crypt|tls|ssl|cert|session|passw|"
    r"rbac|scc|privile|sanitiz|escap|deserial|unmarshal|jwt|oauth|"
    r"saml|acl",
    re.I,
)

DEPS_MANIFESTS = frozenset(
    {
        "go.mod",
        "go.sum",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "poetry.lock",
        "pom.xml",
        "Cargo.toml",
        "Cargo.lock",
        "Gemfile",
        "Gemfile.lock",
    }
)

CHURN_FULL_LINES = 8000

_EXCLUDE_DIR_PARTS = frozenset({"vendor", "node_modules", "third_party", "dist"})


def is_first_party(path: str) -> bool:
    parts = path.split("/")
    if any(p in _EXCLUDE_DIR_PARTS or "_generated" in p for p in parts):
        return False
    return not (parts[-1].endswith(".pb.go") or parts[-1].lower().endswith(".md"))


def is_deps_manifest(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return name in DEPS_MANIFESTS or (name.startswith("requirements") and name.endswith(".txt"))


class Designation(StrEnum):
    """Adopter-configured exposure hint; customer-reach derives from component -> product."""

    EXTERNAL = "external"
    INTERNAL_TOOLING = "internal-tooling"


class ObservationTarget(Model):
    """What the observation measures: a repository, its latest audit, its pinned commit."""

    repository_id: UUID
    repo_url: str | None
    has_audit: bool = True
    audit_date: str | None = None
    pinned_sha: str | None = None
    # NEED(artifacts): from the assessment's artifact document once that lane lands.
    lines_reviewed: int | None = None
    designation: Designation | None = None
    repository_ref_id: UUID | None = None
    audit_assessment_id: UUID | None = None


class SeenHead(Model):
    """The default-branch head an earlier observation recorded, and the push it followed."""

    branch: str | None
    pushed_at: str | None
    head: str


class ForgeFacts(Model):
    repository_id: UUID
    repo: HttpsRepoUrl | None
    repo_url: str | None
    audited_sha: str | None
    audit_date: str | None
    has_audit: bool
    status: ComparisonStatus
    observed_at: AwareDatetime
    pushed_at: str | None = None
    archived: bool | None = None
    default_branch: str | None = None
    head: str | None = None
    visibility: str | None = None
    fork: bool | None = None
    parent: str | None = None
    ahead_by: int | None = None
    changed_lines: int | None = None
    sensitive_changed: bool | None = None
    sensitive_lines: int | None = None
    deps_only: bool | None = None
    compare_truncated: bool | None = None
    error: str | None = None

    @field_serializer("repo", when_used="json")
    def serialize_repo(self, repo: HttpsRepoUrl | None) -> str | None:
        return str(repo) if repo else None

    def document(self, fork_of: HttpsRepoUrl | None) -> RepoStateArtifact:
        doc: dict[str, object] = {
            "observed_at": self.observed_at.isoformat(),
            "status": self.status.value,
        }
        if self.pushed_at:
            doc["pushed_at"] = self.pushed_at
        if self.ahead_by is not None:
            doc["comparison"] = {
                "ahead_by": self.ahead_by,
                "truncated": bool(self.compare_truncated),
                "changed_lines": self.changed_lines,
                "sensitive_changed": self.sensitive_changed,
                "sensitive_lines": self.sensitive_lines,
                "deps_only": self.deps_only,
            }
        if fork_of is not None:
            doc["fork_of"] = str(fork_of)
        return RepoStateArtifact.from_document(doc)

    @classmethod
    def from_document(
        cls,
        target: ObservationTarget,
        repo: HttpsRepoUrl | None,
        doc: RepoStateArtifact,
        **facts: object,
    ) -> ForgeFacts:
        """An observation read back: the document's measurements plus the inventory's facts."""
        stored = json.loads(doc.payload)
        compared = stored.get("comparison") or {}
        fork_of = stored.get("fork_of")
        return cls(
            repository_id=target.repository_id,
            repo=repo,
            repo_url=target.repo_url,
            audited_sha=target.pinned_sha,
            audit_date=target.audit_date,
            has_audit=target.has_audit,
            status=ComparisonStatus(stored["status"]),
            observed_at=datetime.fromisoformat(stored["observed_at"]),
            pushed_at=stored.get("pushed_at"),
            fork=fork_of is not None,
            parent=urlsplit(fork_of).path.strip("/") if fork_of else None,
            ahead_by=compared.get("ahead_by"),
            compare_truncated=compared.get("truncated"),
            changed_lines=compared.get("changed_lines"),
            sensitive_changed=compared.get("sensitive_changed"),
            sensitive_lines=compared.get("sensitive_lines"),
            deps_only=compared.get("deps_only"),
            **facts,
        )


class ChangeMetrics(Model):
    changed_lines: int
    sensitive_changed: bool
    sensitive_lines: int
    deps_only: bool
    first_party_files: int
    iac_files: int
    threat_model_files: int


class DesignationRecord(Model):
    match: str
    designation: Designation
