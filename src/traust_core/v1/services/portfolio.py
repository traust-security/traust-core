from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import defaultdict
from collections.abc import Collection, Iterable, Mapping, Sequence
from datetime import date, datetime
from time import perf_counter
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit
from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.errors import ConfigError, ConflictError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import (
    CorpusRegistryArtifact,
    ProductDefinitionsMapArtifact,
    RepoLivenessArtifact,
    RepoStateArtifact,
)
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    Assessment,
    AssessmentFilter,
    AssessmentKind,
    AuditScope,
)
from traust_core.v1.models.common import (
    Cursor,
    Page,
    PageRequest,
    Provenance,
    RecordBudget,
    every_item,
)
from traust_core.v1.models.corpus import CorpusRegistry, CorpusSubject
from traust_core.v1.models.findings import SubjectRef
from traust_core.v1.models.inventory import (
    DEFAULT_FORGE_HOSTS,
    Component,
    ComponentFilter,
    ExposureClass,
    InventoryExportRow,
    Liveness,
    OrgName,
    Ownership,
    OwnershipSource,
    Product,
    RecordedRelease,
    RefName,
    Release,
    ReleaseBump,
    ReleaseChange,
    ReleaseCommit,
    RepoLiveness,
    Repository,
    RepositoryFilter,
    RepositoryRef,
    RepoState,
    RiskTier,
    SyncReport,
    Team,
    TeamName,
    VersionLabel,
)
from traust_core.v1.models.observation import (
    ForgeFacts,
    ObservationTarget,
    SeenHead,
)
from traust_core.v1.models.operations import AssetName, OrderFilter, OrderState
from traust_core.v1.models.product_definitions import (
    ProductDefinitions,
    ProductDefinitionsSnapshot,
    ProductMappings,
    ProductMatchTier,
    ProductResolution,
    ProductSourceStatus,
    drop_rate_warning,
)
from traust_core.v1.models.values import (
    GitSha,
    HttpsRepoUrl,
    ProductSlug,
    RepoPath,
    require_aware_datetime,
    require_nonblank,
    require_uuid,
)
from traust_core.v1.models.vocabulary import (
    ComparisonStatus,
    LivenessStatus,
    OwnershipClass,
    RefKind,
    Severity,
)
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.clock import Clock, SystemClock
from traust_core.v1.providers.product_definitions import ProductDefinitionsCache
from traust_core.v1.providers.sources import OwnerHint, RepoInfo, SourceError, SourceProvider
from traust_core.v1.providers.tools import ToolProvider
from traust_core.v1.repositories.traust.inventory import InventoryUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, Imported, PublishResult
from traust_core.v1.services.observation import (
    OBSERVED,
    BanBreaker,
    observation_url,
    observe_forge_facts,
    parse_audit_date,
)

if TYPE_CHECKING:
    from traust_core.v1.services.assessment import AssessmentService
    from traust_core.v1.services.findings.service import FindingService
    from traust_core.v1.services.operations import OpsService

log = logging.getLogger(__name__)

DORMANT_DAYS = 365
_RELEASE_VERSION = re.compile(r"v?(\d+)\.(\d+)(?:\.(\d+))?")

P0_MIN_LIVE = 5


class PortfolioPolicy:
    def __init__(self, *, p0_min_live: int = P0_MIN_LIVE, dormant_days: int = DORMANT_DAYS) -> None:
        if p0_min_live < 1 or dormant_days < 0:
            raise ValidationError("portfolio policy thresholds must be positive")
        self.p0_min_live, self.dormant_days = p0_min_live, dormant_days

    def exposure_class(
        self, ships_in_product: bool, public: bool, has_upstream: bool
    ) -> ExposureClass:
        if public or has_upstream:
            return (
                ExposureClass.PUBLIC_EXTERNAL if ships_in_product else ExposureClass.PUBLIC_INTERNAL
            )
        return (
            ExposureClass.PRIVATE_EXTERNAL if ships_in_product else ExposureClass.PRIVATE_INTERNAL
        )

    def is_dormant(self, pushed: date | None, today: date) -> bool:
        """No push for longer than `dormant_days`; an unknown push date is not dormant."""
        return pushed is not None and (today - pushed).days > self.dormant_days

    def risk_tier(self, open_critical_high: int, archived: bool, dormant: bool) -> RiskTier:
        if open_critical_high >= self.p0_min_live:
            return RiskTier.P0
        if open_critical_high >= 1:
            return RiskTier.P1
        return RiskTier.P3 if archived or dormant else RiskTier.P2


class Inventory:
    """Repository and ref reads on the caller's unit of work: the one door every service resolves
    a repository or commit through (needs only the uow, so findings and assessment can use it)."""

    def __init__(self, uow: InventoryUnitOfWork, hosts: Mapping[str, str] | None = None) -> None:
        self._uow = uow
        self._hosts = dict(hosts or DEFAULT_FORGE_HOSTS)

    @property
    def hosts(self) -> Mapping[str, str]:
        """The forge hosts and kinds its URL lookups resolve by."""
        return dict(self._hosts)

    def get_repository(self, repository_id: UUID) -> Repository:
        with self._uow as uow:
            return uow.repositories.get(repository_id)

    def get_ref(self, repository_ref_id: UUID) -> RepositoryRef:
        with self._uow as uow:
            return uow.repository_refs.get(repository_ref_id)

    def default_line(self, repository_id: UUID) -> RepositoryRef | None:
        """The latest ref named the repository's default line (import or observation) —
        the onboarding step that gives a run something to work on; None for a registered row
        alone. Earlier flags stay: each was the forge's answer when it was recorded; the
        naming time (default_named_at), not the row's age, orders them."""
        with self._uow as uow:
            return uow.repository_refs.default(repository_id)

    def lock_ref(self, repository_ref_id: UUID) -> RepositoryRef:
        """The commit, locked for the caller's transaction."""
        with self._uow as uow:
            return uow.repository_refs.get_for_update(repository_ref_id)

    def resolve(self, repository_ref_id: UUID) -> tuple[RepositoryRef, Repository]:
        """The commit and the repository it belongs to; NotFoundError names whichever is missing."""
        with self._uow as uow:
            ref = uow.repository_refs.get(repository_ref_id)
            return ref, uow.repositories.get(ref.repository_id)

    def subject(self, repository_ref_id: UUID, assessment_id: UUID | None = None) -> SubjectRef:
        """What a skill works on: the commit, its repository, and the assessment when given."""
        ref, repository = self.resolve(repository_ref_id)
        assert repository.id is not None
        return SubjectRef(
            repository_id=repository.id,
            repository_url=repository.url,
            repository_ref_id=repository_ref_id,
            sha=ref.sha,
            assessment_id=assessment_id,
        )

    def find_repository(self, url: HttpsRepoUrl | str) -> Repository | None:
        """The repository registered at this URL; on GitHub in any case of owner/repo."""
        with self._uow as uow:
            return _registered_repository(uow, str(url), self._hosts)

    def list_refs(
        self,
        repository_id: UUID,
        sha: str | None = None,
        *,
        read_budget: RecordBudget | None = None,
    ) -> list[RepositoryRef]:
        """The repository's refs, or only those of one commit."""
        with self._uow as uow:
            refs = uow.repository_refs.list_for(repository_id, read_budget=read_budget)
        return [r for r in refs if sha is None or r.sha == sha]

    def list_refs_of(
        self, repository_ids: Collection[UUID], *, read_budget: RecordBudget | None = None
    ) -> list[RepositoryRef]:
        """Every recorded ref of the repositories, read in bounded batches."""
        with self._uow as uow:
            return uow.repository_refs.list_for_repositories(
                repository_ids, read_budget=read_budget
            )

    def list_refs_by_ids(self, repository_ref_ids: Collection[UUID]) -> list[RepositoryRef]:
        with self._uow as uow:
            return uow.repository_refs.list_by_ids(repository_ref_ids)

    def list_repositories(self, repository_ids: Collection[UUID]) -> list[Repository]:
        with self._uow as uow:
            return uow.repositories.list_by_ids(repository_ids)

    def find_ref(self, repository_id: UUID, sha: str, name: str | None = None) -> RepositoryRef:
        """The registered ref of a commit: by name when given, else the one ref of that commit;
        never guessed into existence."""
        with self._uow as uow:
            if name:
                ref = uow.repository_refs.find(repository_id, name, sha)
                if ref is None:
                    raise NotFoundError(f"{name}@{sha} is not a registered ref: register it first")
                return ref
            refs = [r for r in uow.repository_refs.list_for(repository_id) if r.sha == sha]
        if len(refs) != 1:
            raise ValidationError(
                f"commit {sha} has {len(refs)} registered refs: name the patched ref (patched_ref)"
            )
        return refs[0]

    def private_mirror(self, repository_id: UUID) -> Repository | None:
        with self._uow as uow:
            return uow.repositories.find_private_mirror(repository_id)

    def get_component(self, component_id: UUID) -> Component:
        with self._uow as uow:
            return uow.components.get(component_id)


class ProductLookup:
    """Ownership candidates from a product-definitions snapshot a caller holds; no store is
    opened."""

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def resolve_products(
        self,
        snapshot: ProductDefinitionsSnapshot,
        mappings: ProductMappings,
        packages: Iterable[str] = (),
        repo_urls: Iterable[str] = (),
        product_ids: Iterable[str] = (),
        *,
        read_budget: RecordBudget | None = None,
    ) -> ProductResolution:
        """Ownership context from the product-definitions registry: candidate contacts and
        lifecycle per package, repo URL or product id; a candidate generator, never an owner."""
        if snapshot.document is None:
            return ProductResolution(
                source_status=snapshot.status,
                source=snapshot.source,
                results=(),
                warnings=(
                    "product-definitions cache unavailable — this source is "
                    "optional; continue with the other ownership sources when "
                    "the feed cache is unreachable.",
                ),
            )
        definitions = ProductDefinitions(
            snapshot.document, self._clock.now().date(), read_budget=read_budget
        )
        results = definitions.resolve(mappings, packages, repo_urls, product_ids)
        warnings = []
        if drop := drop_rate_warning(results):
            warnings.append(drop)
        if snapshot.status is ProductSourceStatus.STALE:
            warnings.append(
                f"cache is {snapshot.source.age_hours}h old (threshold "
                f"{snapshot.source.max_age_hours}h) — refresh with "
                f"traust feeds fetch-products"
            )
        return ProductResolution(
            source_status=snapshot.status,
            source=snapshot.source,
            results=results,
            **({"warnings": tuple(warnings)} if warnings else {}),
        )


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
        publisher: ArtifactPublisher | None = None,
        tools: ProviderRegistry[ToolProvider[Any]] | None = None,
        product_definitions: ProductDefinitionsCache | None = None,
        ops: OpsService | None = None,
    ) -> None:
        self._uow, self._policy = uow, policy
        self._tools = tools
        self._ops = ops
        self._hosts = dict(hosts or DEFAULT_FORGE_HOSTS)
        self.inventory = Inventory(uow, self._hosts)
        self._publisher = publisher
        self._product_definitions = product_definitions
        self._assessment, self._sources = assessment, sources
        self._clock = clock or SystemClock()

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
        """Observe one repository at the forge and keep what it answered: public, archived and
        its fork's upstream (brought into the inventory) on the repository, and a repo-state
        assessment of the default-branch head when its status or measurements changed."""
        started = perf_counter()
        target = self._target(repository_id=repository_id, repo_url=repo_url)
        facts = observe_forge_facts(
            target,
            self._sources,
            self._clock.now(),
            hosts=self._hosts,
            network=network,
            breaker=breaker,
            quota_deferred=quota_deferred,
            seen=self._seen_head(target.repository_id),
            tools=self._tools,
        )
        if facts.availability_queried:
            unknown = facts.liveness_status == LivenessStatus.UNKNOWN
            self.record_liveness(
                Liveness(
                    repository_id=target.repository_id,
                    url=self.get_repository(target.repository_id).url,
                    status=facts.liveness_status,
                    observed_at=facts.observed_at,
                    canonical_url=facts.canonical_url,
                    archived=facts.archived,
                    pushed_at=facts.pushed_at,
                    unobserved=facts.status if unknown and facts.status not in OBSERVED else None,
                    reason=(facts.error or "forge did not report repository availability")
                    if unknown
                    else facts.error
                    if facts.liveness_status == LivenessStatus.MISSING
                    else None,
                )
            )
        if facts.head is not None:
            self._keep(target, facts, started)
        return facts

    def _keep(self, target: ObservationTarget, facts: ForgeFacts, started: float) -> None:
        assert facts.repo is not None and facts.head is not None and self._assessment is not None
        fork_of = _fork_parent_url(facts.repo.host, facts.fork, facts.parent, self._hosts)
        observed = facts.status in (*OBSERVED, ComparisonStatus.NO_PINNED_SHA)
        with self._uow.write() as uow:
            repository = uow.repositories.get_for_update(facts.repository_id)
            upstream = self._upstream(uow, fork_of) if fork_of else None
            seen_public = _is_public(facts.visibility)
            current = repository.model_copy(
                update=dict(
                    public=repository.public if seen_public is None else seen_public,
                    archived=repository.archived if facts.archived is None else facts.archived,
                    # fork=None means the forge did not say — keep the recorded lineage;
                    # a reported fork repoints it, a reported non-fork clears it
                    upstream_id=upstream.id
                    if upstream
                    else repository.upstream_id
                    if facts.fork is None
                    else None,
                )
            )
            metadata_changed = current != repository
            if metadata_changed:
                uow.repositories.update(current)
            if observed:
                named = _named_at(self._clock.now())
                ref = uow.repository_refs.get_or_add(
                    RepositoryRef(
                        repository_id=facts.repository_id,
                        name=facts.default_branch,
                        kind=RefKind.BRANCH,
                        is_default=True,
                        default_named_at=named,
                        sha=facts.head,
                    )
                )
                if not ref.is_default or ref.default_named_at != named:
                    ref = uow.repository_refs.update(
                        ref.model_copy(update={"is_default": True, "default_named_at": named})
                    )
            uow.commit()
        if metadata_changed:
            self._log_metadata_change(current, started)
        # Availability is recorded separately; a failed comparison is never a repo-state document.
        if not observed:
            return
        assert ref.id is not None
        doc = facts.document(fork_of)
        previous = self._latest_observation(facts.repository_id)
        if previous is not None:
            previous_ref, previous_assessment, previous_doc = previous
            if (
                previous_ref.id == ref.id
                and _measured(previous_doc) == _measured(doc)
                and previous_assessment.baseline_assessment_id == target.audit_assessment_id
            ):
                return
        published = self._require_publisher().publish_artifact(doc)
        assessment = self._assessment.record_observation(
            doc,
            published.artifact_id,
            ref.id,
            baseline_assessment_id=target.audit_assessment_id,
            assessor=self._sources.name if self._sources else "forge",
            assessor_version=contracts.version(),
            occurred_at=facts.observed_at,
        )
        assert assessment.id is not None
        committed = (
            facts.repository_id,
            ref.id,
            assessment.id,
            facts.status,
            facts.secret_hits,
            (perf_counter() - started) * 1000,
        )
        self._uow.after_commit(
            lambda: log.info(
                "portfolio observation repository=%s ref=%s assessment=%s "
                "status=%s secret_hits=%s duration_ms=%.1f",
                *committed,
            )
        )

    def _log_metadata_change(self, repository: Repository, started: float) -> None:
        committed = (
            repository.id,
            repository.public,
            repository.archived,
            (perf_counter() - started) * 1000,
        )
        self._uow.after_commit(
            lambda: log.info(
                "portfolio repository metadata updated id=%s public=%s "
                "archived=%s duration_ms=%.1f",
                *committed,
            )
        )

    def forge_facts(self, repository_id: UUID) -> ForgeFacts | None:
        """The latest observation of the default-branch head; NotFoundError when it was measured
        against an audit that has since been replaced."""
        target = self._target(repository_id=repository_id)
        observed = self._latest_observation(target.repository_id)
        if observed is None:
            return None
        ref, assessment, doc = observed
        if assessment.baseline_assessment_id != target.audit_assessment_id:
            raise NotFoundError(f"audit baseline changed for {target.repo_url}; observe it again")
        with self._uow as uow:
            repository = uow.repositories.get(target.repository_id)
            upstream = (
                uow.repositories.get(repository.upstream_id)
                if repository.upstream_id is not None
                else None
            )
        return ForgeFacts.from_document(
            target,
            observation_url(target.repo_url, self._hosts),
            doc,
            archived=repository.archived,
            default_branch=ref.name,
            head=ref.sha,
            visibility="public" if repository.public else "private",
            # the document cannot tell an unreported fork status from an explicit non-fork
            # (both omit fork_of): the inventory's recorded lineage is what answers
            fork=repository.upstream_id is not None,
            parent=urlsplit(upstream.url).path.strip("/") if upstream else None,
        )

    def liveness(self, filter: RepositoryFilter, page: PageRequest) -> Page[Liveness]:
        """Availability history from its owner; unqueried repositories remain unknown."""
        listed = self.list_repositories(filter, page)
        return Page(items=tuple(self._liveness_of(listed.items)), next=listed.next)

    def liveness_in(self, repository_ids: Collection[UUID]) -> dict[UUID, Liveness]:
        """Liveness for selected repository IDs, without enumerating unrelated inventory."""
        if not repository_ids:
            return {}
        return {
            row.repository_id: row
            for row in self._liveness_of(self.inventory.list_repositories(repository_ids))
        }

    def _liveness_of(self, repositories: Sequence[Repository]) -> list[Liveness]:
        if self._assessment is None:
            raise ConfigError("liveness reads observations through AssessmentService")
        if not repositories:
            return []
        ids = [repository.id for repository in repositories if repository.id]
        now = self._clock.now()
        snapshot = self._require_publisher().latest(RepoLivenessArtifact)
        recorded = RepoLiveness.of(snapshot).repositories if snapshot is not None else {}
        unaudited = set(
            self._assessment.population(
                now,
                AssessmentFilter(kind=AssessmentKind.SECURE_CODE, status=ASSESSMENT_COMPLETED),
                ids,
            ).never_assessed_repository_ids
        )
        completed = self._completed_orders(ids, now)
        rows = []
        for repository in repositories:
            assert repository.id is not None
            row = recorded.get(repository.id) or self._unqueried_liveness(repository, unaudited)
            row = self._fold_completed(row, completed.get(repository.id, ()), now)
            rows.append(
                row.model_copy(
                    update={
                        "dormant": self._policy.is_dormant(
                            parse_audit_date(row.pushed_at), now.date()
                        )
                        if row.pushed_at is not None
                        else None
                    }
                )
            )
        return rows

    def liveness_reference(self) -> RepoLiveness:
        """The complete reference snapshot, excluding repositories never queried."""
        rows = every_item(lambda page: self.liveness(RepositoryFilter(), page))
        return RepoLiveness(
            generated=self._clock.now(),
            repositories={row.repository_id: row for row in rows if row.observed_at is not None},
        )

    def record_liveness(self, row: Liveness) -> PublishResult:
        """Record explicit availability evidence, carrying the start of an unchanged status."""
        require_uuid(row.repository_id, "liveness.repository_id")
        repository = self.get_repository(row.repository_id)
        if row.url != repository.url:
            raise ValidationError("liveness URL must match the registered repository")
        now = self._clock.now()
        if row.observed_at is None or row.observed_at > now:
            raise ValidationError("liveness needs an observation time no later than Core's clock")
        if row.canonical_url is not None:
            HttpsRepoUrl.parse(row.canonical_url, self._hosts)
        if row.status == LivenessStatus.MOVED and (
            row.canonical_url is None or row.canonical_url == row.url
        ):
            raise ValidationError("moved liveness needs a distinct canonical repository URL")
        publisher = self._require_publisher()
        while True:
            latest = publisher.latest_imported(RepoLivenessArtifact)
            recorded = {} if latest is None else dict(RepoLiveness.of(latest.document).repositories)
            previous = recorded.get(row.repository_id)
            if (
                previous is not None
                and previous.observed_at is not None
                and previous.observed_at > row.observed_at
            ):
                raise ValidationError(
                    "liveness observation predates the repository's recorded history"
                )
            previous = self._fold_completed(
                previous or Liveness(repository_id=row.repository_id, url=repository.url),
                self._completed_orders((row.repository_id,), row.observed_at).get(
                    row.repository_id, ()
                ),
                row.observed_at,
            )
            saved = row.model_copy(
                update={
                    "status_since": previous.status_since
                    if previous.status == row.status and previous.status_since is not None
                    else row.observed_at,
                    "dormant": None,
                }
            )
            if recorded.get(row.repository_id) == saved:
                assert latest is not None
                return PublishResult(
                    artifact=RepoLivenessArtifact.name, artifact_id=latest.artifact_id, written=()
                )
            recorded[row.repository_id] = saved
            snapshot = RepoLiveness(generated=self._clock.now(), repositories=recorded)
            try:
                return publisher.publish_successor(
                    snapshot.to_artifact(), None if latest is None else latest.artifact_id
                )
            except ConflictError:
                continue

    def _completed_orders(self, repository_ids: Sequence[UUID], now: datetime) -> dict[UUID, list]:
        """The finished degraded/failed/refused repo_state orders of several repositories,
        one indexed query for the whole page instead of one per repository — a liveness
        page render used to run (and manifest-parse) per repository."""
        ops = self._ops
        if ops is None or not repository_ids:
            return {}
        filter = OrderFilter(
            repository_ids=tuple(repository_ids),
            asset=AssetName("repo_state"),
            states=(OrderState.DEGRADED, OrderState.FAILED, OrderState.REFUSED),
        )
        grouped: dict[UUID, list] = {}
        for order in every_item(lambda page: ops.list(filter, page)):
            if order.finished_at is not None and order.finished_at <= now:
                grouped.setdefault(order.repository_id, []).append(order)
        return grouped

    def _fold_completed(self, row: Liveness, orders: Sequence, now: datetime) -> Liveness:
        failures = set(ComparisonStatus) - OBSERVED - {ComparisonStatus.NO_PINNED_SHA}
        orders = sorted(
            (
                order
                for order in orders
                if row.observed_at is None
                or (
                    order.finished_at > row.observed_at
                    and (order.started_at is None or order.started_at > row.observed_at)
                )
            ),
            key=lambda order: (order.finished_at, str(order.id)),
        )
        for order in orders:
            assert order.id is not None
            assert self._ops is not None  # the fold only runs with an ops service
            manifest = self._ops.manifest(order.id)
            statuses = sorted(
                (status for status in failures if manifest.degraded.get(status.value, 0) > 0),
                key=lambda status: status.value,
            )
            if not statuses:
                continue
            row = Liveness(
                repository_id=row.repository_id,
                url=row.url,
                observed_at=order.finished_at,
                status_since=row.status_since
                if row.status == LivenessStatus.UNKNOWN and row.status_since is not None
                else order.finished_at,
                unobserved=statuses[0] if len(statuses) == 1 else ComparisonStatus.ERROR,
                reason="completed repo_state observation: "
                + ", ".join(status.value for status in statuses),
            )
        return row

    def _unqueried_liveness(self, repository: Repository, unaudited: Collection[UUID]) -> Liveness:
        assert repository.id is not None
        row = Liveness(repository_id=repository.id, url=repository.url)
        if observation_url(repository.url, self._hosts) is None:
            status, reason = ComparisonStatus.UNSUPPORTED_HOST, "no forge observes this host"
        elif repository.id in unaudited:
            status = ComparisonStatus.NEVER_AUDITED
            reason = "no audit and no forge observation yet; observe it"
        else:
            status, reason = ComparisonStatus.NETWORK_SKIPPED, "no forge observation; observe it"
        return row.model_copy(update={"unobserved": status, "reason": reason})

    def _seen_head(self, repository_id: UUID) -> SeenHead | None:
        observed = self._latest_observation(repository_id)
        if observed is None:
            return None
        ref, _, doc = observed
        pushed_at = json.loads(doc.payload).get("pushed_at")
        return SeenHead(branch=ref.name, pushed_at=pushed_at, head=ref.sha)

    def default_ref(
        self, repository_id: UUID, as_of: datetime | None = None
    ) -> RepositoryRef | None:
        """The head from the latest completed default-branch observation."""
        return self.default_refs([repository_id], as_of).get(repository_id)

    def default_refs(
        self, repository_ids: Collection[UUID], as_of: datetime | None = None
    ) -> dict[UUID, RepositoryRef]:
        """`default_ref` for many repositories at once; one never observed is absent."""
        if self._assessment is None:
            raise ConfigError("default-branch head requires AssessmentService")
        latest = self._assessment.latest_on_default_lines(
            repository_ids, AssessmentKind.REPO_STATE, as_of
        )
        refs = self.inventory.list_refs_by_ids({a.repository_ref_id for a in latest.values()})
        by_id = {r.id: r for r in refs}
        return {repository_id: by_id[a.repository_ref_id] for repository_id, a in latest.items()}

    def current_default_ref(self, repository_id: UUID) -> RepositoryRef | None:
        """The default branch's current head: the latest default-line observation's, unless a
        default line was named more recently (the data model's default-branch cohort) — the
        naming time, not the row's creation: a line is immutable once recorded, so an
        imported head re-flags a row older than the last observation. Both times are the
        service's clock (the observation's occurred_at), not the database's."""
        imported = self.inventory.default_line(repository_id)
        observed = self._latest_default_assessment(repository_id)
        if observed is None:
            return imported
        assert imported is not None
        named = imported.default_named_at or imported.created_at  # legacy rows: creation time
        assert named and observed.occurred_at
        if named > observed.occurred_at:
            return imported
        return self.inventory.get_ref(observed.repository_ref_id)

    def _latest_default_assessment(self, repository_id: UUID) -> Assessment | None:
        """The repository's latest completed default-branch repo-state assessment."""
        if self._assessment is None:
            raise ConfigError("default-branch head requires AssessmentService")
        return self._assessment.latest_on_default_line(repository_id, AssessmentKind.REPO_STATE)

    def fork_answer(self, repository_id: UUID) -> bool | None:
        """Whether the forge last called the repository a fork, from its latest repo-state
        document; None when no document says (or this portfolio reads no observations)."""
        if self._assessment is None or self._publisher is None:
            return None
        observed = self._latest_observation(repository_id)
        return None if observed is None else json.loads(observed[2].payload).get("fork")

    def _latest_observation(
        self, repository_id: UUID
    ) -> tuple[RepositoryRef, Assessment, RepoStateArtifact] | None:
        """The observed default-branch head and its latest repo-state document."""
        assessment = self._latest_default_assessment(repository_id)
        if assessment is None:
            return None
        ref = self.inventory.get_ref(assessment.repository_ref_id)
        assert assessment.id is not None
        doc = self._require_publisher().latest_for_assessment(assessment.id, RepoStateArtifact)
        if doc is None:
            raise NotFoundError(f"repo-state assessment {assessment.id} has no document")
        return ref, assessment, doc

    def register_product(self, slug: ProductSlug, name: str) -> Product:
        """Idempotent on slug: an existing product returns unchanged; renames use update_product."""
        if not isinstance(slug, ProductSlug):
            raise ValidationError("product.slug must be a ProductSlug")
        require_nonblank(name, "product.name")
        with self._uow as uow:
            product = uow.products.get_or_add(Product(slug=str(slug), name=name))
            uow.commit()
            return product

    def register_repository(self, url: HttpsRepoUrl, public: bool) -> Repository:
        started = perf_counter()
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
        with self._uow.write() as uow:
            # a GitHub repository registered in another case of owner/repo is this one
            uow.repositories.lock_url(str(url))
            known = _registered_repository(uow, str(url), self._hosts)
            if known is not None:
                repository, created = known, False
            else:
                repository, created = uow.repositories.get_or_add_with_status(
                    Repository(url=str(url), public=public)
                )
            uow.commit()
        if created:
            committed = (
                repository.id,
                repository.public,
                hashlib.sha256(repository.url.encode()).hexdigest()[:16],
                (perf_counter() - started) * 1000,
            )
            self._uow.after_commit(
                lambda: log.info(
                    "portfolio repository registered id=%s public=%s url_hash=%s duration_ms=%.1f",
                    *committed,
                )
            )
        return repository

    def record_repo_info(
        self, repository_id: UUID, public: bool | None, parent_url: HttpsRepoUrl | None
    ) -> Repository:
        """What an import learned from the forge: the visibility it reports (None: it didn't
        say) and a fork's parent, brought into the inventory (private, until its own import
        says otherwise) when absent."""
        require_uuid(repository_id, "repository.id")
        if parent_url is not None and not isinstance(parent_url, HttpsRepoUrl):
            raise ValidationError("repository.parent_url must be an HttpsRepoUrl")
        with self._uow.write() as uow:
            repository = uow.repositories.get_for_update(repository_id)
            update: dict[str, object] = {}
            if public is not None and public != repository.public:
                update["public"] = public
            if parent_url is not None:
                upstream = self._upstream(uow, parent_url)
                if upstream.id != repository.upstream_id:
                    update["upstream_id"] = upstream.id
            if update:
                repository = uow.repositories.update(repository.model_copy(update=update))
                uow.commit()
        return repository

    def _upstream(self, uow: InventoryUnitOfWork, parent_url: HttpsRepoUrl) -> Repository:
        """A fork's parent row: the one registered (any case on GitHub), else a new private row."""
        uow.repositories.lock_url(str(parent_url))
        found = _registered_repository(uow, str(parent_url), self._hosts)
        return found or uow.repositories.get_or_add(Repository(url=str(parent_url), public=False))

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

    def mark_default_branch(
        self, repository_id: UUID, sha: GitSha, branch: RefName
    ) -> RepositoryRef:
        """The default branch's commit, recorded as the repository's default line — the
        subject a run works on, before any observation runs. The line is added when absent
        and flagged when already imported: a named line is immutable once recorded, so the
        default flag is what a new answer moves."""
        with self._uow as uow:
            named = _named_at(self._clock.now())
            ref = uow.repository_refs.get_or_add(
                RepositoryRef(
                    repository_id=repository_id,
                    name=branch,
                    kind=RefKind.BRANCH,
                    is_default=True,
                    default_named_at=named,
                    sha=str(sha),
                )
            )
            if not ref.is_default or ref.default_named_at != named:
                ref = uow.repository_refs.update(
                    ref.model_copy(update={"is_default": True, "default_named_at": named})
                )
            uow.commit()
            return ref

    def record_manifest_sbom(
        self, repository_ref_id: UUID, sbom_id: UUID, scan_id: UUID | None = None
    ) -> RepositoryRef:
        """The SBOM read from the commit's source tree (manifests, lockfiles), and the manifest
        scan whose coverage is current: none for an SBOM given as a document, which clears it."""
        with self._uow as uow:
            ref = uow.repository_refs.get(repository_ref_id)
            wanted = {"manifest_sbom_id": sbom_id, "manifest_sbom_assessment_id": scan_id}
            changed = any(getattr(ref, k) != v for k, v in wanted.items())
            if changed:
                ref = uow.repository_refs.update(ref.model_copy(update=wanted))
                uow.commit()
        if changed:
            self._uow.after_commit(
                lambda: log.info("manifest sbom %s linked to ref %s", sbom_id, repository_ref_id)
            )
        return ref

    def list_products_shipping(self, repository_ref_id: UUID) -> list[Product]:
        """Products with a release that includes this commit."""
        with self._uow as uow:
            releases = {
                c.release_id: uow.releases.get(c.release_id)
                for c in uow.components.list_for_ref(repository_ref_id)
            }
            products = {r.product_id: uow.products.get(r.product_id) for r in releases.values()}
        return sorted(products.values(), key=lambda p: p.slug)

    def list_products_of(self, repository_id: UUID) -> list[Product]:
        """Products with a release that includes any commit of this repository, by slug."""
        with self._uow as uow:
            uow.repositories.get(repository_id)
            refs = [r.id for r in uow.repository_refs.list_for(repository_id) if r.id]
            releases = {c.release_id for c in uow.components.list_for_refs(refs)}
            products = {r.product_id for r in uow.releases.list_by_ids(releases)}
            return sorted(uow.products.list_by_ids(products), key=lambda p: p.slug)

    def inventory_export(self, *, max_records: int = 10_000) -> tuple[InventoryExportRow, ...]:
        """Registered repositories with current owners, shipping products and cached contacts."""
        if self._product_definitions is None:
            raise ConfigError("inventory export requires ProductDefinitionsCache")
        budget = RecordBudget(
            max_records,
            "inventory export",
            hint="use PortfolioService.inventory_export(max_records=...) for a larger workload",
        )
        with self._uow as uow:
            repositories = uow.repositories.list_all(read_budget=budget)
            if not repositories:
                return ()
            repository_ids = {r.id for r in repositories if r.id is not None}
            ownerships = uow.ownerships.current_for_repositories(repository_ids, read_budget=budget)
            teams = {
                t.id: t.name
                for t in uow.teams.list_by_ids({o.team_id for o in ownerships}, read_budget=budget)
            }
            refs = {
                r.id: r.repository_id
                for r in uow.repository_refs.list_for_repositories(
                    repository_ids, read_budget=budget
                )
                if r.id is not None
            }
            components = uow.components.list_for_refs(refs, read_budget=budget)
            releases = {
                r.id: r.product_id
                for r in uow.releases.list_by_ids(
                    {c.release_id for c in components}, read_budget=budget
                )
            }
            products = {
                p.id: p.slug
                for p in uow.products.list_by_ids(set(releases.values()), read_budget=budget)
            }
        owners: defaultdict[UUID, set[str]] = defaultdict(set)
        shipping: defaultdict[UUID, set[str]] = defaultdict(set)
        for ownership in ownerships:
            owners[ownership.repository_id].add(teams[ownership.team_id])
        for component in components:
            shipping[refs[component.repository_ref_id]].add(
                products[releases[component.release_id]]
            )
        mappings = self.product_mappings(read_budget=budget)
        resolution = self.resolve_products(
            self._product_definitions.read(),
            mappings,
            repo_urls=[r.url for r in repositories],
            read_budget=budget,
        )
        contacts = {
            match.query.value: tuple(
                f"{c.kerberos_id} ({c.field}; embargo_cleared={c.embargo_cleared})"
                for c in match.contacts
            )
            for match in resolution.results
            if resolution.source_status is not ProductSourceStatus.UNAVAILABLE
            and match.query is not None
            and match.match_tier is not ProductMatchTier.NONE
        }
        rows = []
        for repository in repositories:
            assert repository.id is not None
            parts = urlsplit(repository.url)
            organization, _, name = parts.path.strip("/").rpartition("/")
            rows.append(
                InventoryExportRow(
                    repository=f"{organization}/{name}" if organization else name,
                    url=repository.url,
                    host=parts.hostname or None,
                    organization=organization or None,
                    repo_name=name or None,
                    owner_teams=tuple(sorted(owners[repository.id])),
                    products=tuple(sorted(shipping[repository.id])),
                    accountable_contacts=contacts.get(repository.url),
                )
            )
        return tuple(rows)

    def repositories_shipping(self, repository_ids: Collection[UUID]) -> set[UUID]:
        """Repositories with any commit included in a product release."""
        with self._uow as uow:
            refs = {
                ref.id: ref.repository_id
                for ref in uow.repository_refs.list_for_repositories(repository_ids)
                if ref.id is not None
            }
            return {
                refs[component.repository_ref_id]
                for component in uow.components.list_for_refs(refs)
            }

    def list_product_refs(self, product_id: UUID) -> list[RepositoryRef]:
        """Every commit any release of the product ships, once each."""
        with self._uow as uow:
            uow.products.get(product_id)
            ref_ids = {
                c.repository_ref_id
                for r in uow.releases.list_for_product(product_id)
                if r.id is not None
                for c in uow.components.list_for_release(r.id)
            }
            return sorted((uow.repository_refs.get(i) for i in ref_ids), key=lambda r: str(r.id))

    def list_refs_by_manifest(self, sbom_ids: Collection[UUID]) -> list[RepositoryRef]:
        with self._uow as uow:
            return uow.repository_refs.list_for_manifest_sboms(sbom_ids)

    def update_product(self, product_id: UUID, name: str) -> Product:
        require_uuid(product_id, "product.id")
        require_nonblank(name, "product.name")
        with self._uow as uow:
            product = uow.products.get(product_id).model_copy(update={"name": name})
            product = uow.products.update(product)
            uow.commit()
            return product

    def set_corpus_ownership(
        self, product_id: UUID, ownership: OwnershipClass, business_unit: str
    ) -> CorpusRegistryArtifact:
        """Publish a new corpus registry when this product's ownership or business unit changes.

        Single writer expected (operator CLI); a concurrent publish raises ConflictError.
        """
        require_uuid(product_id, "product.id")
        _require_ownership(ownership, business_unit)
        latest = self._require_publisher().latest_imported(CorpusRegistryArtifact)
        with self._uow as uow:
            product = uow.products.get(product_id)
        return self._publish_ownership(product, latest, ownership, business_unit)

    def register_corpus_product(
        self, slug: ProductSlug, label: str, ownership: OwnershipClass, business_unit: str
    ) -> tuple[Product, CorpusSubject]:
        """Register a product with its corpus ownership. The same fields again is a no-op;
        different fields for a registered slug raise ConflictError (changes go by update)."""
        _require_ownership(ownership, business_unit)
        latest = self._require_publisher().latest_imported(CorpusRegistryArtifact)
        product = self.register_product(slug, label)
        stored = _subject_of(latest, product)
        given = (label, str(ownership), business_unit)
        have = (product.name, *(None if v is None else str(v) for v in _owned(stored)))
        if have[0] != label or (stored is not None and have != given):
            raise ConflictError(
                f"{str(slug)!r} is already registered as (label, ownership, business_unit) "
                f"{have}, not {given}; change it with update"
            )
        if stored is not None:
            return product, stored
        doc = self._publish_ownership(product, latest, ownership, business_unit)
        return product, _registered(doc, product)

    def update_corpus_product(
        self,
        slug: ProductSlug,
        label: str | None = None,
        ownership: OwnershipClass | None = None,
        business_unit: str | None = None,
    ) -> tuple[Product, CorpusSubject | None]:
        """Change only the fields given; ownership and business unit merge with the stored ones
        inside the registry's compare-and-set, so a concurrent edit raises ConflictError."""
        if label is not None:
            require_nonblank(label, "product.name")
        latest = self._require_publisher().latest_imported(CorpusRegistryArtifact)
        product = self.find_product(slug)
        if product is None:
            raise NotFoundError(f"no product named {str(slug)!r}")
        stored = _subject_of(latest, product)
        merged: tuple[OwnershipClass, str] | None = None
        if ownership is not None or business_unit is not None:
            was_owned, was_unit = _owned(stored)
            owned = was_owned if ownership is None else ownership
            unit = was_unit if business_unit is None else business_unit
            if owned is None or unit is None:
                raise ValidationError(f"{str(slug)!r} has no ownership yet: give both fields")
            _require_ownership(owned, unit)
            merged = (owned, unit)
        if label is not None and label != product.name:
            product = self.update_product(product.id, label)
        if merged is None:
            return product, stored
        doc = self._publish_ownership(product, latest, *merged)
        return product, _registered(doc, product)

    def _publish_ownership(
        self,
        product: Product,
        latest: Imported[CorpusRegistryArtifact] | None,
        ownership: OwnershipClass,
        business_unit: str,
    ) -> CorpusRegistryArtifact:
        current = CorpusRegistry() if latest is None else CorpusRegistry.of(latest.document)
        owned = {"tree": product.slug, "ownership": ownership, "business_unit": business_unit}
        stored = current.subject(str(product.id))
        subject = (
            CorpusSubject(subject_id=str(product.id), **owned)
            if stored is None
            else stored.model_copy(update=owned)
        )
        if latest is not None and subject == stored:
            return latest.document
        # Stamp `updated` so A->B->A gets fresh bytes; digest dedup would return the old A row.
        registry = current.with_subject(subject).model_copy(
            update={"updated": self._clock.now().isoformat()}
        )
        doc = registry.to_artifact()
        self._require_publisher().publish_successor(
            doc, None if latest is None else latest.artifact_id
        )
        return doc

    def corpus_registry(self, as_of: datetime | None = None) -> CorpusRegistryArtifact | None:
        """The corpus registry now, or as it stood at `as_of`."""
        return self._require_publisher().latest(CorpusRegistryArtifact, as_of)

    def record_product_map(
        self, doc: ProductDefinitionsMapArtifact, provenance: Provenance
    ) -> PublishResult:
        """Record the next version of the reviewed package/repo -> product pairs; product lookups
        use the newest."""
        result, created = self._require_publisher().publish_artifact_with_status(doc)
        if created:
            log.info("product map recorded as %s by run %s", result.artifact_id, provenance.run_id)
        return result

    def product_mappings(self, *, read_budget: RecordBudget | None = None) -> ProductMappings:
        """The newest recorded product map's pairs; none recorded is none."""
        doc = self._require_publisher().latest(ProductDefinitionsMapArtifact)
        if doc is None:
            return ProductMappings()
        if read_budget is not None:
            read_budget.consume(1)
        mappings = json.loads(doc.payload)["mappings"]
        if read_budget is not None:
            read_budget.consume(
                len(mappings.get("packages") or {}) + len(mappings.get("repos") or {})
            )
        return ProductMappings(
            packages=mappings.get("packages") or {}, repos=mappings.get("repos") or {}
        )

    def _require_publisher(self) -> ArtifactPublisher:
        if self._publisher is None:
            raise ConfigError(
                "the corpus registry, the product map and repository observation require an "
                "ArtifactPublisher"
            )
        return self._publisher

    def record_release(self, product_id: UUID, version: VersionLabel) -> Release:
        require_uuid(product_id, "release.product_id")
        require_nonblank(version, "release.version")
        with self._uow as uow:
            release = uow.releases.get_or_add(Release(product_id=product_id, version=version))
            uow.commit()
            return release

    def find_release(self, product_id: UUID, version: VersionLabel) -> Release | None:
        require_uuid(product_id, "release.product_id")
        require_nonblank(version, "release.version")
        with self._uow as uow:
            return uow.releases.find(product_id, version)

    def import_release(
        self, product_id: UUID, version: VersionLabel, commits: Sequence[ReleaseCommit]
    ) -> Release:
        """The product's release at `version` with a component per commit, in one transaction.
        Re-importing the same commits changes nothing; different commits are a ConflictError
        (a release's contents don't change), and an unregistered repository a NotFoundError."""
        require_uuid(product_id, "release.product_id")
        require_nonblank(version, "release.version")
        if not commits:
            raise ValidationError(f"release {version}: no commits to import")
        with self._uow as uow:
            uow.products.get(product_id)
            repositories = {c.url: uow.repositories.find_by_url(str(c.url)) for c in commits}
            if missing := sorted(str(u) for u, r in repositories.items() if r is None):
                raise NotFoundError(f"release {version}: unregistered repositories {missing}")
            refs = {
                uow.repository_refs.get_or_add(
                    RepositoryRef(
                        repository_id=repositories[c.url].id,  # type: ignore[union-attr]
                        sha=str(c.sha),
                        name=c.branch,
                        kind=None if c.branch is None else RefKind.BRANCH,
                    )
                ).id
                for c in commits
            }
            known = uow.releases.find(product_id, version)
            held = (
                set()
                if known is None
                else {c.repository_ref_id for c in uow.components.list_for_release(known.id)}  # type: ignore[arg-type]
            )
            if known is not None and held != refs:
                raise ConflictError(
                    f"release {version} of product {product_id} already ships {len(held)} "
                    f"commits; the import names {len(refs)}, not the same set"
                )
            release = known or uow.releases.add(Release(product_id=product_id, version=version))
            for ref_id in refs - held:
                uow.components.add(Component(release_id=release.id, repository_ref_id=ref_id))  # type: ignore[arg-type]
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

    def release_changes(self, release_id: UUID, previous_id: UUID | None = None) -> ReleaseChange:
        """A release against an earlier one of the same product (by default the highest version
        recorded before it): its version bump and the commits each ships that the other doesn't."""
        if release_id == previous_id:
            raise ValidationError(f"release {release_id} compared with itself")
        with self._uow as uow:
            release = uow.releases.get(release_id)
            previous = (
                _high_water(release, uow.releases.list_for_product(release.product_id))
                if previous_id is None
                else uow.releases.get(previous_id)
            )
            if previous is None:
                raise NotFoundError(
                    f"release {release.version} is its product's first recorded release: "
                    "nothing to compare"
                )
            if release.product_id != previous.product_id:
                raise ValidationError(
                    f"releases {release_id} and {previous_id} belong to different products"
                )
            return _change(release, previous, _shipped(uow, release), _shipped(uow, previous))

    def release_feed_after(self, after: tuple[datetime, UUID] | None, limit: int) -> list[Release]:
        """Releases recorded after a feed position, oldest first (the ops feed's half)."""
        with self._uow as uow:
            return uow.releases.feed_after(after, limit)

    def recorded_release(self, release_id: UUID) -> RecordedRelease:
        """A release with the repositories it ships and its change against the highest version
        recorded before it; a product's first release has no change."""
        with self._uow as uow:
            release = uow.releases.get(release_id)
            previous = _high_water(release, uow.releases.list_for_product(release.product_id))
            shipped = _shipped(uow, release)
            refs = uow.repository_refs.list_by_ids(shipped)
            return RecordedRelease(
                release=release,
                repository_ids=tuple(sorted({r.repository_id for r in refs}, key=str)),
                change=None
                if previous is None
                else _change(release, previous, shipped, _shipped(uow, previous)),
            )

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

    def set_owners(
        self, repository_id: UUID, teams: Collection[TeamName], at: datetime | None = None
    ) -> SyncReport:
        """Mirror the teams a source now reports for one repository: new teams' rows open and the
        rest close, at `at` (core's clock; a sync of many repositories passes one instant)."""
        at = self._clock.now() if at is None else at
        require_uuid(repository_id, "ownership.repository_id")
        require_aware_datetime(at, "ownership.valid_from")
        for team in teams:
            require_nonblank(team, "team.name")
        with self._uow as uow:
            uow.repositories.get(repository_id)
            current = {o.team_id: o for o in uow.ownerships.current(repository_id)}
            wanted = dict.fromkeys(uow.teams.get_or_add(Team(name=t)).id for t in teams)
            closing = [o for t, o in current.items() if t not in wanted]
            if early := [o for o in closing if o.valid_from >= at]:
                raise ConflictError(
                    f"repository {repository_id}: ownership opened at {early[0].valid_from} "
                    f"cannot close at {at}"
                )
            added = [
                uow.ownerships.add(Ownership(repository_id=repository_id, team_id=t, valid_from=at))
                for t in wanted
                if t not in current
            ]
            removed = [
                uow.ownerships.update(o.model_copy(update={"valid_to": at})) for o in closing
            ]
            uow.commit()
        return SyncReport(
            added=tuple(o.id for o in added if o.id),
            unchanged=tuple(o.id for t, o in current.items() if t in wanted and o.id),
            removed=tuple(o.id for o in removed if o.id),
        )

    def resolve_products(
        self,
        snapshot: ProductDefinitionsSnapshot,
        mappings: ProductMappings,
        packages: Iterable[str] = (),
        repo_urls: Iterable[str] = (),
        product_ids: Iterable[str] = (),
        *,
        read_budget: RecordBudget | None = None,
    ) -> ProductResolution:
        return ProductLookup(self._clock).resolve_products(
            snapshot, mappings, packages, repo_urls, product_ids, read_budget=read_budget
        )

    def get_repository(self, repository_id: UUID) -> Repository:
        return self.inventory.get_repository(repository_id)

    def find_repository(self, url: HttpsRepoUrl) -> Repository | None:
        return self.inventory.find_repository(url)

    def list_repositories(self, filter: RepositoryFilter, page: PageRequest) -> Page[Repository]:
        if filter.url is not None:
            found = self.find_repository(filter.url)
            return Page(items=(found,) if found else ())
        after = page.position()
        with self._uow as uow:
            rows = uow.repositories.search(limit=page.limit + 1, after=after)
        return Page.of(rows, page.limit, lambda r: (r.created_at, r.id))

    def list_owned_repositories(self, team_id: UUID, as_of: datetime | None = None) -> list[UUID]:
        """The repositories the team owns now, or at `as_of`."""
        require_uuid(team_id, "team.id")
        with self._uow as uow:
            uow.teams.get(team_id)
            rows = uow.ownerships.list_for_team(team_id)
        return sorted(
            {
                o.repository_id
                for o in rows
                if (as_of is None or o.valid_from <= as_of)
                and (o.valid_to is None or (as_of is not None and o.valid_to > as_of))
            },
            key=str,
        )

    def list_owners(self, repository_id: UUID, as_of: datetime | None = None) -> list[Team]:
        """The teams owning the repository now, or at `as_of`, by name."""
        require_uuid(repository_id, "repository.id")
        with self._uow as uow:
            uow.repositories.get(repository_id)
            rows = (
                uow.ownerships.current(repository_id)
                if as_of is None
                else uow.ownerships.as_of(repository_id, as_of)
            )
            teams = [uow.teams.get(t) for t in dict.fromkeys(o.team_id for o in rows)]
        return sorted(teams, key=lambda t: t.name)

    def get_product(self, product_id: UUID) -> Product:
        require_uuid(product_id, "product.id")
        with self._uow as uow:
            return uow.products.get(product_id)

    def find_product(self, slug: ProductSlug) -> Product | None:
        if not isinstance(slug, ProductSlug):
            raise ValidationError("product.slug must be a ProductSlug")
        with self._uow as uow:
            return uow.products.find_by_slug(str(slug))

    def list_products(self, page: PageRequest) -> Page[Product]:
        """Products by slug."""
        if page.limit <= 0:
            raise ValidationError("page limit must be positive")
        with self._uow as uow:
            rows = uow.products.list_after(page.cursor, page.limit + 1)
        items = tuple(rows[: page.limit])
        return Page(items=items, next=Cursor(items[-1].slug) if len(rows) > page.limit else None)

    def list_components(self, filter: ComponentFilter, page: PageRequest) -> Page[Component]:
        after = page.position()
        with self._uow as uow:
            rows = uow.components.search(limit=page.limit + 1, after=after)
        return Page.of(rows, page.limit, lambda r: (r.created_at, r.id))


def _named_at(at: datetime) -> datetime:
    """The naming time truncated to the store's millisecond precision, so the value
    written equals the value read back (contracts' timestamp TEXT format)."""
    return at.replace(microsecond=at.microsecond // 1000 * 1000)


def _bump(version: str, previous: str) -> ReleaseBump:
    new, old = _release_version(version), _release_version(previous)
    if new is None or old is None:
        return ReleaseBump.UNKNOWN
    if new == old:
        return ReleaseBump.NONE
    if new < old:
        return ReleaseBump.BACKFILL
    return (
        ReleaseBump.MAJOR
        if new[0] != old[0]
        else ReleaseBump.MINOR
        if new[1] != old[1]
        else ReleaseBump.PATCH
    )


def _high_water(release: Release, releases: Sequence[Release]) -> Release | None:
    """The highest version recorded before `release` (a version label outranks a non-version);
    None for the product's first release."""
    earlier = [
        r
        for r in releases
        if r.id != release.id and r.created_at <= release.created_at  # type: ignore[operator]
    ]
    return max(
        earlier,
        key=lambda r: (_release_version(r.version) or (-1, -1, -1), r.created_at),
        default=None,
    )


def _shipped(uow: InventoryUnitOfWork, release: Release) -> set[UUID]:
    return {c.repository_ref_id for c in uow.components.list_for_release(release.id)}  # type: ignore[arg-type]


def _change(release: Release, previous: Release, now: set[UUID], then: set[UUID]) -> ReleaseChange:
    return ReleaseChange(
        release_id=release.id,  # type: ignore[arg-type]
        previous_id=previous.id,  # type: ignore[arg-type]
        version=release.version,
        previous_version=previous.version,
        bump=_bump(release.version, previous.version),
        added=tuple(sorted(now - then, key=str)),
        removed=tuple(sorted(then - now, key=str)),
    )


def _release_version(label: str) -> tuple[int, int, int] | None:
    """`4.19` and `v4.19.2` as (major, minor, patch); None for a label that is no version."""
    found = _RELEASE_VERSION.fullmatch(label.strip())
    return None if found is None else (int(found[1]), int(found[2]), int(found[3] or 0))


def _is_public(visibility: str | None) -> bool | None:
    """The forge's visibility word as the inventory's flag; None when the forge didn't say."""
    return None if visibility is None else visibility.lower() == "public"


def _fork_parent_url(
    host: str, fork: bool | None, parent: str | None, hosts: Mapping[str, str]
) -> HttpsRepoUrl | None:
    """A reported fork's parent as an observation URL; None when unreported or unusable."""
    return observation_url(f"https://{host}/{parent}", hosts) if fork and parent else None


def _require_ownership(ownership: object, business_unit: str) -> None:
    if not isinstance(ownership, OwnershipClass):
        raise ValidationError(f"corpus ownership must be one of {list(OwnershipClass)}")
    require_nonblank(business_unit, "corpus.business_unit")


def _subject_of(
    latest: Imported[CorpusRegistryArtifact] | None, product: Product
) -> CorpusSubject | None:
    return None if latest is None else CorpusRegistry.of(latest.document).subject(str(product.id))


def _owned(subject: CorpusSubject | None) -> tuple[OwnershipClass | None, str | None]:
    return (None, None) if subject is None else (subject.ownership, subject.business_unit)


def _registered_repository(
    uow: InventoryUnitOfWork, url: str, hosts: Mapping[str, str]
) -> Repository | None:
    """The row registered at this URL; on GitHub, whose owner/repo is case-insensitive, one
    registered in another case (a fork's lowercased parent, a differently typed import)."""
    if (found := uow.repositories.find_by_url(url)) is not None:
        return found
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:  # a malformed URL names no registered repository
        return None
    if hosts.get(host) == "github":
        return uow.repositories.find_by_url_casefold(url)
    return None


def _registered(doc: CorpusRegistryArtifact, product: Product) -> CorpusSubject:
    subject = CorpusRegistry.of(doc).subject(str(product.id))
    assert subject is not None
    return subject


def _why(e: SourceError | ValidationError) -> object:
    return e.observation_status if isinstance(e, SourceError) else e


class PortfolioSync:
    """Brings forge listings and the declared ownership source into the portfolio."""

    def __init__(
        self,
        portfolio: PortfolioService,
        sources: SourceProvider,
        *,
        clock: Clock | None = None,
        hosts: Mapping[str, str] | None = None,
    ) -> None:
        self._portfolio = portfolio
        self._sources = sources
        self._clock = clock or SystemClock()
        # the portfolio's hosts unless told otherwise: a fork on a custom host needs them to
        # resolve its parent
        self._hosts = dict(hosts or portfolio.inventory.hosts)

    def list_org(self, org: OrgName, host: str) -> list[RepoInfo]:
        return self._sources.list_org(org, host).data

    def import_org(self, org: OrgName, host: str) -> SyncReport:
        """Register every non-archived, non-fork repository of an organisation; registered ones
        stay as they are."""
        return sum(
            (self._register(i.repo, i.visibility) for i in self.list_org(org, host)), SyncReport()
        )

    def import_repository(self, url: HttpsRepoUrl) -> SyncReport:
        """Register one repository with the visibility its forge reports and its fork's
        upstream linked. A known repository with no upstream is asked again on import unless
        its latest observation recorded the forge's answer that it isn't a fork."""
        known = self._portfolio.find_repository(url)
        if known is not None and known.id is not None:
            if known.upstream_id is None and self._portfolio.fork_answer(known.id) is not False:
                # lineage not known yet: the forge may name a parent, or correct a parent
                # placeholder's visibility. A forge outage, or a host the forge provider
                # can't ask, still returns the known id.
                try:
                    info = self._sources.info(url).data
                except (SourceError, ValidationError) as e:
                    return SyncReport(
                        unchanged=(known.id,),
                        skipped=(f"{url}: forge facts not refreshed: {_why(e)}",),
                    )
                return SyncReport(unchanged=(known.id,), skipped=self._record_info(known.id, info))
            return SyncReport(unchanged=(known.id,))
        info = self._sources.info(url).data
        report = self._register(url, info.visibility)
        skipped = self._record_info((*report.added, *report.unchanged)[0], info)
        return report + SyncReport(skipped=skipped)

    def _record_info(self, repository_id: UUID, info: RepoInfo) -> tuple[str, ...]:
        """What an import learned from the forge: the visibility it reports (None: it didn't
        say), a fork's parent, and the default branch's line — the observation's default ref
        without needing a run, so an imported repository is a subject from the start. A head
        the forge couldn't give is skipped, and holds back the parent link that would settle
        a fork's import, so the next import asks again."""
        head, skipped = None, ()
        if info.default_branch is not None:
            try:
                head = self._sources.head(info.repo, info.default_branch).data
            except (SourceError, ValidationError) as e:
                skipped = (f"{info.repo}: default line not imported: {_why(e)}",)
        parent = (
            None
            if skipped
            else _fork_parent_url(info.repo.host, info.fork, info.parent, self._hosts)
        )
        self._portfolio.record_repo_info(repository_id, _is_public(info.visibility), parent)
        if head is not None:
            assert info.default_branch is not None
            self._portfolio.mark_default_branch(repository_id, head, RefName(info.default_branch))
        return skipped

    def import_branch(
        self, repository_id: UUID, url: HttpsRepoUrl, branch: RefName
    ) -> RepositoryRef:
        """Register the commit a branch points at now; on the branch the recorded default line
        names (the forge's answer at import or observation) the head just imported is the
        default line's latest commit."""
        head = self._sources.head(url, branch).data
        line = self._portfolio.inventory.default_line(repository_id)
        if line is not None and line.name == branch:
            return self._portfolio.mark_default_branch(repository_id, head, branch)
        return self._portfolio.register_ref(repository_id, head, branch, RefKind.BRANCH)

    def owner_hints(self, url: HttpsRepoUrl) -> list[OwnerHint]:
        """Forge handles that may own a repository (OWNERS approvers, top contributors); hints
        for a person to weigh, never stored as ownership."""
        return self._sources.owners(url).data

    def find_file(self, url: HttpsRepoUrl, path: RepoPath, sha: GitSha) -> str | None:
        """One file's text at a pinned commit, read at the forge; untrusted content, None when
        the commit has no such file."""
        return self._sources.file(url, path, sha).data

    def import_owners(self, source: OwnershipSource) -> SyncReport:
        """Mirror the declared ownership source onto every registered repository; assignments
        for repositories not in the inventory come back as `skipped`."""
        at = self._clock.now()
        named: dict[str, tuple[TeamName, ...]] = {}
        for assignment in source.assignments:
            named[str(assignment.repo)] = named.get(str(assignment.repo), ()) + assignment.teams
        report = SyncReport()
        for repository in every_item(
            lambda page: self._portfolio.list_repositories(RepositoryFilter(), page)
        ):
            assert repository.id is not None
            teams = named.pop(repository.url, None)
            if teams is None:
                org = OrgName(repository.url.removeprefix("https://").split("/")[1])
                teams = (source.org_teams[org],) if org in source.org_teams else ()
            report += self._portfolio.set_owners(repository.id, teams, at)
        return report + SyncReport(skipped=tuple(sorted(named)))

    def _register(self, url: HttpsRepoUrl, visibility: str | None) -> SyncReport:
        known = self._portfolio.find_repository(url)
        repository = known or self._portfolio.register_repository(url, bool(_is_public(visibility)))
        assert repository.id is not None
        return SyncReport(**{"unchanged" if known else "added": (repository.id,)})


class RepoStateQuery:
    """Composite read across portfolio, assessments and findings (traust#58)."""

    def __init__(
        self,
        portfolio: PortfolioService,
        assessments: AssessmentService,
        findings: FindingService,
        policy: PortfolioPolicy,
        *,
        clock: Clock | None = None,
        hosts: Mapping[str, str] | None = None,
    ) -> None:
        self._portfolio = portfolio
        self._assessments = assessments
        self._findings = findings
        self._policy = policy
        self._clock = clock or SystemClock()
        self._hosts = dict(hosts or DEFAULT_FORGE_HOSTS)

    def repo_state(
        self, *, repository_id: UUID | None = None, repo_url: str | None = None
    ) -> RepoState:
        """The routing state derived from one repository's latest observation."""
        target = self._assessments.observation_target(
            repository_id=repository_id, repo_url=repo_url
        )
        repository = self._portfolio.get_repository(target.repository_id)
        ships = target.repository_id in self._portfolio.repositories_shipping(
            [target.repository_id]
        )
        return self._state(target, self._observed(target), repository, ships)

    def list(self, filter: RepositoryFilter, page: PageRequest) -> Page[RepoState]:
        """Each listed repository's routing state; one without a usable observation comes back
        `network-skipped` with why in `error` (the router's "observe first")."""
        listed = self._portfolio.list_repositories(filter, page)
        states = []
        ships = self._portfolio.repositories_shipping([r.id for r in listed.items if r.id])
        for repository in listed.items:
            target = self._assessments.observation_target(repository_id=repository.id)
            try:
                facts = self._observed(target)
            except NotFoundError as e:
                facts = self._unobserved(target).model_copy(update={"error": str(e)})
            states.append(self._state(target, facts, repository, target.repository_id in ships))
        return Page(items=tuple(states), next=listed.next)

    def _unobserved(self, target: ObservationTarget) -> ForgeFacts:
        # Without a URL, a supported host or an audit, the state needs no forge answer.
        return observe_forge_facts(
            target, None, self._clock.now(), hosts=self._hosts, network=False
        )

    def _observed(self, target: ObservationTarget) -> ForgeFacts:
        facts = self._unobserved(target)
        if facts.status not in (ComparisonStatus.NETWORK_SKIPPED, ComparisonStatus.NEVER_AUDITED):
            return facts
        try:
            observed = self._portfolio.forge_facts(target.repository_id)
        except NotFoundError:
            if facts.status == ComparisonStatus.NEVER_AUDITED:
                return facts
            raise
        if facts.status == ComparisonStatus.NEVER_AUDITED:
            return observed if observed is not None and observed.status == facts.status else facts
        if observed is None:
            raise NotFoundError(f"no forge observation for {target.repo_url}; observe it first")
        return observed

    def _state(
        self, target: ObservationTarget, facts: ForgeFacts, repository: Repository, ships: bool
    ) -> RepoState:
        now = self._clock.now()
        live = self._findings.open_count(target.repository_id, (Severity.CRITICAL, Severity.HIGH))
        latest = self._assessments.latest_on_default_line
        cloud_config = latest(target.repository_id, AssessmentKind.CLOUD_CONFIG) is not None
        threat_model = latest(target.repository_id, AssessmentKind.THREAT_MODEL)
        scope = AuditScope()
        # The report is read only when a rule can use it: churn needs a comparison, the
        # companion backfill a repository with no cloud-config baseline.
        if target.audit_assessment_id and (facts.changed_lines is not None or not cloud_config):
            scope = self._assessments.audit_scope(target.audit_assessment_id)
            target = target.model_copy(update={"lines_reviewed": scope.lines_reviewed})
        fresh = self._assessments.freshness(
            baseline=target, changed_lines=facts.changed_lines, as_of=now
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
                ships,
                repository.public,
                repository.upstream_id is not None,
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
            first_party_files=facts.first_party_files,
            iac_files=facts.iac_files,
            threat_model_files=facts.threat_model_files,
            tree_first_party_files=facts.tree_first_party_files,
            secret_hits=facts.secret_hits,
            has_cloud_config_baseline=cloud_config,
            threat_model_age_days=(now.date() - threat_model.occurred_at.date()).days
            if threat_model
            else None,
            companion_lanes=scope.companion_lanes,
        )


def _measured(doc: RepoStateArtifact) -> dict[str, object]:
    """What a repo-state document says, apart from when it was said."""
    return {k: v for k, v in json.loads(doc.payload).items() if k != "observed_at"}
