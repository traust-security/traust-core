from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import TypeVar
from uuid import UUID

from traust_core.v1.errors import ConfigError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import Severity
from traust_core.v1.models.portfolio import (
    ChangeMetrics,
    CodeLine,
    ComparisonStatus,
    Designation,
    ExposureClass,
    ForgeFacts,
    ObservationTarget,
    Repository,
    RepoState,
    RiskTier,
)
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.providers.base import Result
from traust_core.v1.providers.clock import Clock, SystemClock
from traust_core.v1.providers.sources import (
    ChangedFile,
    Comparison,
    Quota,
    RepoInfo,
    SourceError,
    SourceProvider,
)
from traust_core.v1.repositories.designations import DesignationRepository
from traust_core.v1.repositories.findings import FindingUnitOfWork
from traust_core.v1.repositories.portfolio import PortfolioUnitOfWork
from traust_core.v1.services.assessment import AssessmentService, parse_audit_date

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

_EXCLUDE_DIR_PARTS = {"vendor", "node_modules", "third_party", "dist"}

DORMANT_DAYS = 365

P0_MIN_LIVE = 5

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


class PortfolioPolicy:
    def __init__(self, *, p0_min_live: int = P0_MIN_LIVE, dormant_days: int = DORMANT_DAYS) -> None:
        if p0_min_live < 1 or dormant_days < 0:
            raise ValidationError("portfolio policy thresholds must be positive")
        self.p0_min_live, self.dormant_days = p0_min_live, dormant_days

    def exposure_class(
        self, designation: Designation | None, public: bool | None, public_upstream: bool | None
    ) -> ExposureClass:
        if public:
            return (
                ExposureClass.PUBLIC_INTERNAL
                if designation == Designation.INTERNAL_TOOLING
                else ExposureClass.PUBLIC_EXTERNAL
            )
        if designation == Designation.EXTERNAL:
            return (
                ExposureClass.PUBLIC_EXTERNAL if public_upstream else ExposureClass.PRIVATE_EXTERNAL
            )
        return ExposureClass.PUBLIC_INTERNAL if public_upstream else ExposureClass.PRIVATE_INTERNAL

    def risk_tier(self, open_critical_high: int, archived: bool, dormant: bool) -> RiskTier:
        if open_critical_high >= self.p0_min_live:
            return RiskTier.P0
        if open_critical_high >= 1:
            return RiskTier.P1
        return RiskTier.P3 if archived or dormant else RiskTier.P2


class PortfolioService:
    def __init__(
        self,
        uow: PortfolioUnitOfWork,
        policy: PortfolioPolicy,
        *,
        assessment: AssessmentService | None = None,
        findings: FindingUnitOfWork | None = None,
        sources: SourceProvider | None = None,
        designations: DesignationRepository | None = None,
        clock: Clock | None = None,
        hosts: Mapping[str, str] | None = None,
    ) -> None:
        self._uow, self._policy = uow, policy
        self._assessment, self._findings, self._sources = assessment, findings, sources
        self._designations = designations
        self._clock = clock or SystemClock()
        self._hosts = dict(hosts or {"github.com": "github", "gitlab.com": "gitlab"})

    def _target(
        self, *, repo_url: str | None = None, repo_key: str | None = None
    ) -> ObservationTarget:
        if self._assessment is None:
            raise ConfigError("repository observation requires AssessmentService")
        return self._assessment.observation_target(repo_url=repo_url, repo_key=repo_key)

    def record_forge_facts(
        self,
        *,
        repo_url: str | None = None,
        repo_key: str | None = None,
        network: bool = True,
        breaker: BanBreaker | None = None,
        quota_deferred: bool | None = None,
    ) -> ForgeFacts:
        target = self._target(repo_url=repo_url, repo_key=repo_key)
        facts = observe_forge_facts(
            target,
            self._sources,
            self._clock.now(),
            hosts=self._hosts,
            network=network,
            breaker=breaker,
            quota_deferred=quota_deferred,
        )
        with self._uow as uow:
            uow.portfolio.save_forge_facts(facts)
            uow.commit()
        return facts

    def repo_state(self, *, repo_url: str | None = None, repo_key: str | None = None) -> RepoState:
        target = self._target(repo_url=repo_url, repo_key=repo_key)
        typed = observation_url(target.repo_url, self._hosts)
        identity = observation_identity(target.repo_key, typed)
        with self._uow as uow:
            facts = uow.portfolio.forge_facts(identity)
        if facts is None:
            raise NotFoundError(f"no forge observation for {target.repo_key}; observe it first")
        if (facts.audited_sha, facts.audit_date, facts.has_audit) != (
            target.pinned_sha,
            target.audit_date,
            target.has_audit,
        ):
            raise NotFoundError(f"audit baseline changed for {target.repo_key}; observe it again")
        if self._findings is None or self._assessment is None:
            raise ConfigError("repo_state requires findings and assessment services")
        with self._findings as uow:
            live = max(
                (
                    uow.findings.open_count(key, (Severity.CRITICAL, Severity.HIGH))
                    for key in (target.repo_key, *target.sibling_repo_keys)
                ),
                default=0,
            )
        now = self._clock.now()
        fresh = self._assessment.freshness(
            baseline=target, changed_lines=facts.changed_lines, as_of=now
        )
        designation = target.designation
        if self._designations:
            designation = next(
                (
                    row.designation
                    for row in self._designations.entries()
                    if target.repo_url
                    and (
                        target.repo_url == row.match
                        or (row.match.endswith("/") and target.repo_url.startswith(row.match))
                    )
                ),
                None,
            )
        pushed = parse_audit_date(facts.pushed_at)
        audited = parse_audit_date(target.audit_date) if target.has_audit else None
        dormant = bool(pushed and (now.date() - pushed).days > self._policy.dormant_days)
        return RepoState(
            repo_key=target.repo_key,
            repo=facts.repo,
            source_url=target.repo_url,
            status=facts.status,
            risk_tier=self._policy.risk_tier(live, bool(facts.archived), dormant),
            exposure=self._policy.exposure_class(
                designation,
                (facts.visibility or "").lower() == "public",
                bool(facts.fork and facts.parent),
            ),
            audit_age_days=fresh.audit_age_days,
            churn_ratio=fresh.churn_ratio,
            changed_lines=facts.changed_lines,
            sensitive_changed=facts.sensitive_changed,
            sensitive_lines=facts.sensitive_lines,
            deps_only=facts.deps_only,
            ahead_by=facts.ahead_by,
            compare_truncated=facts.compare_truncated,
            push_changed=pushed >= audited if pushed and audited else None,
            observed_at=facts.observed_at,
            error=facts.error,
        )

    def register_repository(self, url: HttpsRepoUrl, product: str) -> Repository:
        raise NotImplementedError("stub: replaces corpus_intake.py, inventory.py")

    def register_code_line(self, repository_id: UUID, ref: str) -> CodeLine:
        raise NotImplementedError("stub: replaces product_repo (product, repo, ref) rows")

    def set_owner(self, repository_id: UUID, team: str) -> None:
        raise NotImplementedError("stub: replaces fetch_forge_owners.py")

    def designation(self, repository_id: UUID) -> Designation | None:
        raise NotImplementedError("stub: replaces build_rescan_worklist.lookup_designation")

    def record_liveness(
        self, repository_id: UUID, archived: bool, pushed_at: datetime | None
    ) -> None:
        raise NotImplementedError("stub: replaces check_repo_liveness.py")

    def exposure(self, repository_id: UUID) -> ExposureClass:
        raise NotImplementedError("stub: replaces build_rescan_worklist.exposure_class")

    def risk_tier(self, repository_id: UUID, open_critical_high: int) -> RiskTier:
        raise NotImplementedError("stub: replaces build_rescan_worklist.risk_tier")

    def by_org(self, org: str) -> list[Repository]:
        raise NotImplementedError("stub: replaces build_org_index.py")


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


def observation_identity(repo_key: str, repo: HttpsRepoUrl | None) -> str:
    return f"url:{repo}" if repo else f"key:{repo_key}"


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
) -> ForgeFacts:
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
        identity=observation_identity(target.repo_key, repo),
        repo_key=target.repo_key,
        repo=repo,
        source_url=target.repo_url,
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
