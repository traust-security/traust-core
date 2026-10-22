from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from uuid import UUID

from traust_core.v1.errors import ConfigError, NotFoundError, ValidationError
from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.inventory import (
    DEFAULT_FORGE_HOSTS,
    Component,
    ComponentFilter,
    ExposureClass,
    ForgeHost,
    Liveness,
    OrgName,
    Ownership,
    OwnershipSource,
    Product,
    ProductSlug,
    RefName,
    Release,
    ReleaseChange,
    Repository,
    RepositoryFilter,
    RepositoryRef,
    RepoState,
    RiskTier,
    SyncReport,
    VersionLabel,
)
from traust_core.v1.models.observation import (
    Designation,
    DesignationRecord,
    ForgeFacts,
    ObservationTarget,
    ObservedRepoState,
)
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import RefKind, Severity
from traust_core.v1.providers.clock import Clock, SystemClock
from traust_core.v1.providers.sources import SourceProvider
from traust_core.v1.repositories.traust.inventory import InventoryUnitOfWork
from traust_core.v1.services.assessment import AssessmentService, parse_audit_date
from traust_core.v1.services.findings.service import FindingService
from traust_core.v1.services.observation import BanBreaker, observe_forge_facts

DORMANT_DAYS = 365

P0_MIN_LIVE = 5


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
        uow: InventoryUnitOfWork,
        policy: PortfolioPolicy,
        *,
        assessment: AssessmentService | None = None,
        sources: SourceProvider | None = None,
        clock: Clock | None = None,
        hosts: Mapping[str, str] | None = None,
    ) -> None:
        self._uow, self._policy = uow, policy
        # NEED(assessments): facts become a repo-state assessment (RepoStateArtifact) and
        # public/upstream/archived on the repository; until then they last one session.
        self._facts: dict[UUID, ForgeFacts] = {}
        self._assessment, self._sources = assessment, sources
        self._clock = clock or SystemClock()
        self._hosts = dict(hosts or DEFAULT_FORGE_HOSTS)

    def _target(
        self, *, repository_id: UUID | None = None, repo_url: str | None = None
    ) -> ObservationTarget:
        if self._assessment is None:
            raise ConfigError("repository observation requires AssessmentService")
        return self._assessment.observation_target(repository_id=repository_id, repo_url=repo_url)

    def record_forge_facts(
        self,
        *,
        repository_id: UUID | None = None,
        repo_url: str | None = None,
        network: bool = True,
        breaker: BanBreaker | None = None,
        quota_deferred: bool | None = None,
    ) -> ForgeFacts:
        target = self._target(repository_id=repository_id, repo_url=repo_url)
        facts = observe_forge_facts(
            target,
            self._sources,
            self._clock.now(),
            hosts=self._hosts,
            network=network,
            breaker=breaker,
            quota_deferred=quota_deferred,
        )
        previous = self._facts.get(facts.repository_id)
        if previous is None or previous.observed_at <= facts.observed_at:
            self._facts[facts.repository_id] = facts  # never move time backwards
        return facts

    def forge_facts(self, repository_id: UUID) -> ForgeFacts | None:
        return self._facts.get(repository_id)

    def register_product(self, slug: ProductSlug, name: str) -> Product:
        raise NotImplementedError("stub: replaces registry/products.py, inventory.py")

    def register_repository(self, url: HttpsRepoUrl, public: bool) -> Repository:
        raise NotImplementedError("stub: replaces corpus_intake.py, add-inputs")

    def register_ref(
        self, repository_id: UUID, sha: GitSha, name: RefName | None, kind: RefKind | None
    ) -> RepositoryRef:
        raise NotImplementedError("stub: replaces product_repo (product, repo, ref) rows")

    def record_release(self, product_id: UUID, version: VersionLabel) -> Release:
        raise NotImplementedError("stub: replaces product_repo_version, build_release_events")

    def add_component(self, release_id: UUID, repository_ref_id: UUID) -> Component:
        raise NotImplementedError("stub: replaces product_repo upserts")

    def release_changes(self, release_id: UUID, previous_id: UUID) -> ReleaseChange:
        raise NotImplementedError("stub: replaces build_release_events.diff_container")

    def assign_owner(self, repository_id: UUID, team: str, at: datetime) -> Ownership:
        raise NotImplementedError("stub: replaces repo_owner, subject_ownership")

    def exposure_class(self, repository_id: UUID, liveness: Liveness) -> ExposureClass:
        raise NotImplementedError("stub: replaces build_rescan_worklist.exposure_class")

    def is_dormant(self, liveness: Liveness, now: datetime, after: timedelta) -> bool:
        raise NotImplementedError("stub: replaces check_repo_liveness.classify")

    def risk_tier(self, repository_id: UUID, open_critical_high: int, now: datetime) -> RiskTier:
        raise NotImplementedError("stub: replaces build_rescan_worklist.risk_tier")

    def get_repository(self, repository_id: UUID) -> Repository:
        raise NotImplementedError("stub: portfolio read")

    def find_repository(self, url: HttpsRepoUrl) -> Repository | None:
        raise NotImplementedError("stub: replaces canon_repo / normalize_repo lookups")

    def list_repositories(self, filter: RepositoryFilter, page: PageRequest) -> Page[Repository]:
        raise NotImplementedError("stub: replaces build_org_index.py, repo-graph")

    def get_product(self, product_id: UUID) -> Product:
        raise NotImplementedError("stub: portfolio read")

    def find_product(self, slug: ProductSlug) -> Product | None:
        raise NotImplementedError("stub: replaces registry/products.resolve_product")

    def list_components(self, filter: ComponentFilter, page: PageRequest) -> Page[Component]:
        raise NotImplementedError("stub: replaces corpus/resolver ownership cuts")


class PortfolioSync:
    def __init__(self, portfolio: PortfolioService, sources: SourceProvider) -> None:
        self._portfolio = portfolio
        self._sources = sources

    def liveness(self, repository_id: UUID) -> Liveness:
        raise NotImplementedError("stub: replaces check_repo_liveness.gh_repo_info")

    def import_org(self, org: OrgName, host: ForgeHost) -> SyncReport:
        raise NotImplementedError("stub: replaces corpus_intake.py org import")

    def import_owners(self, source: OwnershipSource) -> SyncReport:
        raise NotImplementedError("stub: replaces fetch_forge_owners.py")


class RepoStateQuery:
    """Composite read across portfolio, assessments and findings (traust#58)."""

    def __init__(
        self,
        portfolio: PortfolioService,
        assessments: AssessmentService,
        findings: FindingService,
        policy: PortfolioPolicy,
        *,
        designations: Sequence[DesignationRecord] = (),
        clock: Clock | None = None,
        hosts: Mapping[str, str] | None = None,
    ) -> None:
        self._portfolio = portfolio
        self._assessments = assessments
        self._findings = findings
        self._policy = policy
        self._designations = tuple(designations)
        self._clock = clock or SystemClock()
        self._hosts = dict(hosts or DEFAULT_FORGE_HOSTS)

    def observed(
        self, *, repository_id: UUID | None = None, repo_url: str | None = None
    ) -> ObservedRepoState:
        """The routing state derived from one repository's latest observation."""
        target = self._assessments.observation_target(
            repository_id=repository_id, repo_url=repo_url
        )
        facts = self._portfolio.forge_facts(target.repository_id)
        if facts is None:
            raise NotFoundError(f"no forge observation for {target.repo_url}; observe it first")
        if (facts.audited_sha, facts.audit_date, facts.has_audit) != (
            target.pinned_sha,
            target.audit_date,
            target.has_audit,
        ):
            raise NotFoundError(f"audit baseline changed for {target.repo_url}; observe it again")
        live = self._findings.open_count(target.repository_id, (Severity.CRITICAL, Severity.HIGH))
        now = self._clock.now()
        fresh = self._assessments.freshness(
            baseline=target, changed_lines=facts.changed_lines, as_of=now
        )
        designation = target.designation
        if self._designations:
            designation = next(
                (
                    row.designation
                    for row in self._designations
                    if target.repo_url
                    and (
                        target.repo_url == row.match
                        or (row.match.endswith("/") and target.repo_url.startswith(row.match))
                    )
                ),
                target.designation,
            )
        pushed = parse_audit_date(facts.pushed_at)
        audited = parse_audit_date(target.audit_date) if target.has_audit else None
        dormant = bool(pushed and (now.date() - pushed).days > self._policy.dormant_days)
        return ObservedRepoState(
            repository_id=target.repository_id,
            repo=facts.repo,
            status=facts.status,
            risk_tier=self._policy.risk_tier(live, bool(facts.archived), dormant),
            exposure=self._policy.exposure_class(
                designation,
                (facts.visibility or "").lower() == "public",
                bool(facts.fork and facts.parent),
            ),
            audit_age_days=fresh.age_days(now),
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

    def repo_state(self, repository_id: UUID) -> RepoState:
        raise NotImplementedError("stub: replaces traust#58 observe_repo")

    def list(self, filter: RepositoryFilter, page: PageRequest) -> Page[RepoState]:
        raise NotImplementedError("stub: replaces build_rescan_worklist, build_crown_jewel_tiers")
