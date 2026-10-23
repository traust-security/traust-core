from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date, datetime
from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.errors import ConfigError, NotFoundError, ValidationError
from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.inventory import (
    DEFAULT_FORGE_HOSTS,
    Component,
    ComponentFilter,
    ExposureClass,
    ForgeHost,
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
    Team,
    VersionLabel,
)
from traust_core.v1.models.observation import (
    Designation,
    DesignationRecord,
    ForgeFacts,
    ObservationTarget,
)
from traust_core.v1.models.values import (
    GitSha,
    HttpsRepoUrl,
    require_aware_datetime,
    require_nonblank,
    require_uuid,
)
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

    def is_dormant(self, pushed: date | None, today: date) -> bool:
        """No push for longer than `dormant_days`; an unknown push date is not dormant."""
        return pushed is not None and (today - pushed).days > self.dormant_days

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
        require_nonblank(slug, "product.slug")
        require_nonblank(name, "product.name")
        with self._uow as uow:
            product = uow.products.get_or_add(Product(slug=slug, name=name))
            uow.commit()
            return product

    def register_repository(self, url: HttpsRepoUrl, public: bool) -> Repository:
        if not isinstance(url, HttpsRepoUrl):
            raise ValidationError("repository.url must be an HttpsRepoUrl")
        if not isinstance(public, bool):
            raise ValidationError("repository.public must be a boolean")
        require_nonblank(url.host, "repository.url.host")
        require_nonblank(url.path, "repository.url.path")
        try:
            url = HttpsRepoUrl.parse(str(url), (url.host,))
        except (TypeError, ValueError) as exc:
            raise ValidationError("repository.url is invalid") from exc
        with self._uow as uow:
            repository = uow.repositories.get_or_add(Repository(url=str(url), public=public))
            uow.commit()
            return repository

    def register_ref(
        self, repository_id: UUID, sha: GitSha, name: RefName | None, kind: RefKind | None
    ) -> RepositoryRef:
        require_uuid(repository_id, "repository_ref.repository_id")
        if not isinstance(sha, GitSha):
            raise ValidationError("repository_ref.sha must be a GitSha")
        require_nonblank(sha.value, "repository_ref.sha")
        GitSha.parse(sha.value)
        if (name is None) != (kind is None):
            raise ValidationError("repository ref name and kind must both be set or both be absent")
        if name is not None:
            require_nonblank(name, "repository_ref.name")
            if not isinstance(kind, RefKind):
                raise ValidationError("repository_ref.kind must be a RefKind")
            contracts.validate_enum("ref_kind", kind)
        with self._uow as uow:
            ref = uow.repository_refs.get_or_add(
                RepositoryRef(repository_id=repository_id, sha=str(sha), name=name, kind=kind)
            )
            uow.commit()
            return ref

    def get_ref(self, repository_ref_id: UUID) -> RepositoryRef:
        with self._uow as uow:
            return uow.repository_refs.get(repository_ref_id)

    def record_release(self, product_id: UUID, version: VersionLabel) -> Release:
        require_uuid(product_id, "release.product_id")
        require_nonblank(version, "release.version")
        with self._uow as uow:
            release = uow.releases.get_or_add(Release(product_id=product_id, version=version))
            uow.commit()
            return release

    def add_component(self, release_id: UUID, repository_ref_id: UUID) -> Component:
        require_uuid(release_id, "component.release_id")
        require_uuid(repository_ref_id, "component.repository_ref_id")
        with self._uow as uow:
            component = uow.components.get_or_add(
                Component(release_id=release_id, repository_ref_id=repository_ref_id)
            )
            uow.commit()
            return component

    def release_changes(self, release_id: UUID, previous_id: UUID) -> ReleaseChange:
        raise NotImplementedError("stub: replaces build_release_events.diff_container")

    def assign_owner(self, repository_id: UUID, team: str, at: datetime) -> Ownership:
        require_uuid(repository_id, "ownership.repository_id")
        require_nonblank(team, "team.name")
        require_aware_datetime(at, "ownership.valid_from")
        with self._uow as uow:
            owner = uow.teams.get_or_add(Team(name=team))
            ownership = uow.ownerships.get_or_add(
                Ownership(repository_id=repository_id, team_id=owner.id, valid_from=at)
            )
            uow.commit()
            return ownership

    def get_repository(self, repository_id: UUID) -> Repository:
        with self._uow as uow:
            return uow.repositories.get(repository_id)

    def find_repository(self, url: HttpsRepoUrl) -> Repository | None:
        with self._uow as uow:
            return uow.repositories.find_by_url(str(url))

    def list_repositories(self, filter: RepositoryFilter, page: PageRequest) -> Page[Repository]:
        after = page.position()
        with self._uow as uow:
            rows = uow.repositories.search(limit=page.limit + 1, after=after)
        return Page.of(rows, page.limit, lambda r: (r.created_at, r.id))

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

    def repo_state(
        self, *, repository_id: UUID | None = None, repo_url: str | None = None
    ) -> RepoState:
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
        dormant = self._policy.is_dormant(pushed, now.date())
        return RepoState(
            repository_id=target.repository_id,
            repo=facts.repo,
            status=facts.status,
            risk_tier=self._policy.risk_tier(live, bool(facts.archived), dormant),
            open_critical_high=live,
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

    def list(self, filter: RepositoryFilter, page: PageRequest) -> Page[RepoState]:
        raise NotImplementedError("stub: replaces build_rescan_worklist, build_crown_jewel_tiers")
