"""Forge measurement: observe a repository, classify what changed.

Pure machinery behind PortfolioService.record_forge_facts - no persistence here.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from datetime import date, datetime
from typing import TypeVar

from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.observation import (
    ChangeMetrics,
    ComparisonStatus,
    ForgeFacts,
    ObservationTarget,
    SeenHead,
)
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.providers.base import Result
from traust_core.v1.providers.sources import (
    ChangedFile,
    Comparison,
    Quota,
    RepoInfo,
    SourceError,
    SourceProvider,
)

T = TypeVar("T")


SENSITIVE_RX = re.compile(
    r"auth|login|token|secret|cred|crypt|tls|ssl|cert|session|passw|"
    r"rbac|scc|privile|sanitiz|escap|deserial|unmarshal|jwt|oauth|"
    r"saml|acl",
    re.I,
)

DEPS_MANIFESTS = {
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

TM_SURFACE_RX = re.compile(
    r"(^|/)(cmd|api|apis|handler|handlers|route|routes|controller|"
    r"controllers|webhook|webhooks|middleware|admission|server|"
    r"endpoints?)(/|$)"
    r"|(^|/)main\.(go|py|rs|java|ts|js)$"
    r"|(^|/)(openapi|swagger)[^/]*\.(ya?ml|json)$"
    r"|\.proto$",
    re.I,
)

BAN_STREAK_THRESHOLD = 50

IAC_RX = re.compile(
    r"\.tf$|\.tfvars$|\.tf\.json$"
    r"|(^|/)(cloudformation|cfn)/[^ ]*\.(ya?ml|json)$"
    r"|\.bicep$|(^|/)azuredeploy[^/]*\.json$"
)


_EXCLUDE_DIR_PARTS = {"vendor", "node_modules", "third_party", "dist"}


class BanBreaker:
    def __init__(self, threshold: int = BAN_STREAK_THRESHOLD) -> None:
        self.threshold, self.streak, self.tripped = threshold, 0, False

    def record(self, ok: bool) -> None:
        self.streak = 0 if ok else self.streak + 1
        if self.streak >= self.threshold:
            self.tripped = True


def change_metrics(files: Sequence[ChangedFile]) -> ChangeMetrics:
    changed, sensitive_lines, first_party, iac, threat = 0, 0, 0, 0, 0
    sensitive, deps_only = False, bool(files)
    for file in files:
        path = file.filename
        parts, name = path.split("/"), path.rsplit("/", 1)[-1]
        if not (
            name in DEPS_MANIFESTS or (name.startswith("requirements") and name.endswith(".txt"))
        ):
            deps_only = False
        if (
            any(p in _EXCLUDE_DIR_PARTS or "_generated" in p for p in parts)
            or name.endswith(".pb.go")
            or name.lower().endswith(".md")
        ):
            continue
        changed += file.changes
        first_party += 1
        if SENSITIVE_RX.search(path):
            sensitive = True
            sensitive_lines += file.changes
        iac += bool(IAC_RX.search(path))
        threat += bool(TM_SURFACE_RX.search(path))
    return ChangeMetrics(
        changed_lines=changed,
        sensitive_changed=sensitive,
        sensitive_lines=sensitive_lines,
        deps_only=deps_only,
        first_party_files=first_party,
        iac_files=iac,
        threat_model_files=threat,
    )


def observation_url(raw: str | None, hosts: Mapping[str, str]) -> HttpsRepoUrl | None:
    if raw is None:
        return None
    try:
        typed = HttpsRepoUrl.parse(raw, hosts)
    except ValueError:
        return None
    if hosts[typed.host] == "github":
        return HttpsRepoUrl(typed.host, "/".join(typed.path.split("/")[:2]).lower())
    return typed


T = TypeVar("T")


def _fetch(fetch: Callable[[], Result[T]], expected: type[T]) -> T:
    try:
        data = fetch().data
        if not isinstance(data, expected):
            raise TypeError("unexpected forge result type")
        return data
    except SourceError:
        raise
    except OSError as exc:
        raise SourceError(str(exc), ComparisonStatus.UNREACHABLE) from exc
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise SourceError(
            f"malformed forge response ({type(exc).__name__})", ComparisonStatus.ERROR
        ) from exc


def observe_forge_facts(
    target: ObservationTarget,
    sources: SourceProvider | None,
    now: datetime,
    *,
    hosts: Mapping[str, str],
    network: bool = True,
    breaker: BanBreaker | None = None,
    quota_deferred: bool | None = None,
    seen: SeenHead | None = None,
) -> ForgeFacts:
    """`seen` spares the head lookup when the forge reports no push since it."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValidationError("observation time must include a timezone")
    repo = observation_url(target.repo_url, hosts)
    status = ComparisonStatus.OK
    if target.repo_url is None:
        status = ComparisonStatus.NO_REPO_URL
    elif repo is None:
        status = ComparisonStatus.UNSUPPORTED_HOST
    elif not target.has_audit:
        status = ComparisonStatus.NEVER_AUDITED
    elif not network:
        status = ComparisonStatus.NETWORK_SKIPPED
    facts = ForgeFacts(
        repository_id=target.repository_id,
        repo=repo,
        repo_url=target.repo_url,
        audited_sha=target.pinned_sha,
        audit_date=target.audit_date,
        has_audit=target.has_audit,
        status=status,
        observed_at=now,
    )
    if status != ComparisonStatus.OK:
        return facts
    if sources is None or repo is None:
        raise ConfigError("repository observation requires a source provider")
    github = hosts[repo.host] == "github"
    breaker = breaker if breaker is not None else BanBreaker()
    if github and breaker.tripped:
        return facts.model_copy(
            update={
                "status": ComparisonStatus.BAN_SUSPECTED,
                "error": "skipped: consecutive-error streak suggests a GitHub secondary ban",
            }
        )
    try:
        info = _fetch(lambda: sources.info(repo), RepoInfo)
        if info.repo != repo:
            raise SourceError(
                "forge response identifies a different repository", ComparisonStatus.ERROR
            )
        branch = info.default_branch
        head = None
        if seen is not None and (seen.branch, seen.pushed_at) == (branch, info.pushed_at):
            head = seen.head
        elif branch:
            head = str(_fetch(lambda: sources.head(repo, branch), GitSha))
    except SourceError as exc:
        if github:
            breaker.record(False)
        return facts.model_copy(update={"status": exc.observation_status, "error": str(exc)})
    if github:
        breaker.record(True)
    facts = facts.model_copy(
        update={
            key: getattr(info, key)
            for key in ("pushed_at", "archived", "default_branch", "visibility", "fork", "parent")
        }
        | {"head": head}
    )
    pushed, audited = parse_audit_date(info.pushed_at), parse_audit_date(target.audit_date)
    if not (pushed and audited and pushed >= audited):
        return facts
    if not target.pinned_sha:
        return facts.model_copy(update={"status": ComparisonStatus.NO_PINNED_SHA})
    try:
        deferred = quota_deferred
        if deferred is None:
            quota = _fetch(lambda: sources.quota(repo), Quota) if github else Quota(remaining=None)
            deferred = quota.remaining is not None and quota.remaining <= 0
        if deferred:
            return facts.model_copy(update={"status": ComparisonStatus.QUOTA_DEFERRED})
        compared = _fetch(
            lambda: sources.compare(repo, target.pinned_sha, info.default_branch or "HEAD"),
            Comparison,
        )
    except SourceError as exc:
        return facts.model_copy(update={"status": exc.observation_status, "error": str(exc)})
    metrics = change_metrics(compared.files)
    return facts.model_copy(
        update=dict(
            ahead_by=compared.ahead_by,
            compare_truncated=compared.truncated,
            changed_lines=metrics.changed_lines,
            sensitive_changed=metrics.sensitive_changed,
            sensitive_lines=metrics.sensitive_lines,
            deps_only=metrics.deps_only,
        )
    )


def parse_audit_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None
