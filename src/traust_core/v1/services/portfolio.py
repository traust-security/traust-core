from __future__ import annotations

import json
import re
from collections.abc import Collection, Mapping, Sequence
from datetime import date, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.errors import ConfigError, ConflictError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import CorpusRegistryArtifact, RepoStateArtifact
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    Assessment,
    AssessmentFilter,
    AssessmentKind,
    AuditScope,
)
from traust_core.v1.models.common import Cursor, Page, PageRequest, every_item
from traust_core.v1.models.corpus import CorpusRegistry, CorpusSubject
from traust_core.v1.models.findings import SubjectRef
from traust_core.v1.models.inventory import (
    DEFAULT_FORGE_HOSTS,
    Component,
    ComponentFilter,
    ExposureClass,
    Liveness,
    OrgName,
    Ownership,
    OwnershipSource,
    Product,
    RefName,
    Release,
    ReleaseBump,
    ReleaseChange,
    ReleaseCommit,
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
from traust_core.v1.models.values import (
    GitSha,
    HttpsRepoUrl,
    ProductSlug,
    RepoPath,
    require_aware_datetime,
    require_nonblank,
    require_uuid,
)
from traust_core.v1.models.vocabulary import ComparisonStatus, OwnershipClass, RefKind, Severity
from traust_core.v1.providers.clock import Clock, SystemClock
from traust_core.v1.providers.sources import OwnerHint, RepoInfo, SourceProvider
from traust_core.v1.repositories.traust.inventory import InventoryUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, Imported
from traust_core.v1.services.observation import (
    BanBreaker,
    observation_url,
    observe_forge_facts,
    parse_audit_date,
)

if TYPE_CHECKING:
    from traust_core.v1.services.assessment import AssessmentService
    from traust_core.v1.services.findings.service import FindingService

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

    def __init__(self, uow: InventoryUnitOfWork) -> None:
        self._uow = uow

    def get_repository(self, repository_id: UUID) -> Repository:
        with self._uow as uow:
            return uow.repositories.get(repository_id)

    def get_ref(self, repository_ref_id: UUID) -> RepositoryRef:
        with self._uow as uow:
            return uow.repository_refs.get(repository_ref_id)

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
        with self._uow as uow:
            return uow.repositories.find_by_url(str(url))

    def list_refs(self, repository_id: UUID) -> list[RepositoryRef]:
        with self._uow as uow:
            return uow.repository_refs.list_for(repository_id)

    def list_refs_of(self, repository_ids: Collection[UUID]) -> list[RepositoryRef]:
        """Every recorded ref of the repositories, read in bounded batches."""
        with self._uow as uow:
            return uow.repository_refs.list_for_repositories(repository_ids)

    def default_ref(self, repository_id: UUID) -> RepositoryRef | None:
        """The latest commit recorded on the repository's default branch."""
        with self._uow as uow:
            return uow.repository_refs.default(repository_id)

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
    ) -> None:
        self._uow, self._policy = uow, policy
        self.inventory = Inventory(uow)
        self._publisher = publisher
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
        """Observe one repository at the forge and keep what it answered: public, archived and
        its fork's upstream (brought into the inventory) on the repository, and a repo-state
        assessment of the default-branch head when its status or measurements changed."""
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
        )
        if facts.head is not None:
            self._keep(target, facts)
        return facts

    def _keep(self, target: ObservationTarget, facts: ForgeFacts) -> None:
        assert facts.repo is not None and facts.head is not None and self._assessment is not None
        fork_of = (
            observation_url(f"https://{facts.repo.host}/{facts.parent}", self._hosts)
            if facts.fork and facts.parent
            else None
        )
        with self._uow as uow:
            repository = uow.repositories.get(facts.repository_id)
            upstream = (
                uow.repositories.get_or_add(Repository(url=str(fork_of), public=False))
                if fork_of
                else None
            )
            current = repository.model_copy(
                update=dict(
                    public=repository.public
                    if facts.visibility is None
                    else facts.visibility.lower() == "public",
                    archived=repository.archived if facts.archived is None else facts.archived,
                    upstream_id=upstream.id if upstream else None,
                )
            )
            if current != repository:
                uow.repositories.update(current)
            uow.commit()
        # Failed and deferred observations belong to the order's outcome, not a document.
        if facts.status not in (ComparisonStatus.OK, ComparisonStatus.NO_PINNED_SHA):
            return
        with self._uow as uow:
            ref = uow.repository_refs.get_or_add(
                RepositoryRef(
                    repository_id=facts.repository_id,
                    name=facts.default_branch,
                    kind=RefKind.BRANCH,
                    is_default=True,
                    sha=facts.head,
                )
            )
            uow.commit()
        assert ref.id is not None
        doc = facts.document(fork_of)
        previous = self._observation(ref.id)
        if (
            previous is not None
            and _measured(previous[1]) == _measured(doc)
            and previous[0].baseline_assessment_id == target.audit_assessment_id
        ):
            return
        published = self._require_publisher().publish_artifact(doc)
        self._assessment.record_observation(
            doc,
            published.artifact_id,
            ref.id,
            baseline_assessment_id=target.audit_assessment_id,
            assessor=self._sources.name if self._sources else "forge",
            assessor_version=contracts.version(),
            occurred_at=facts.observed_at,
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
        return ForgeFacts.from_document(
            target,
            observation_url(target.repo_url, self._hosts),
            doc,
            archived=repository.archived,
            default_branch=ref.name,
            head=ref.sha,
            visibility="public" if repository.public else "private",
        )

    def liveness(self, filter: RepositoryFilter, page: PageRequest) -> Page[Liveness]:
        """Each listed repository's archived flag and default-branch push as last observed; one
        never observed comes back `unobserved`, saying why."""
        if self._assessment is None:
            raise ConfigError("liveness reads observations through AssessmentService")
        listed = self.list_repositories(filter, page)
        ids = [r.id for r in listed.items if r.id]
        now = self._clock.now()
        observations = self._assessment.population(
            now, AssessmentFilter(kind=AssessmentKind.REPO_STATE), ids
        ).rows
        latest = {r.latest.id: r for r in observations if r.latest}
        pushes = {
            latest[a.id].repository_id: (a.occurred_at, json.loads(doc.payload).get("pushed_at"))
            for a, doc in self._require_publisher().documents(
                (r.latest for r in latest.values() if r.latest), RepoStateArtifact
            )
        }
        unaudited = set(
            self._assessment.population(
                now,
                AssessmentFilter(kind=AssessmentKind.SECURE_CODE, status=ASSESSMENT_COMPLETED),
                ids,
            ).never_assessed_repository_ids
        )
        return Page(
            items=tuple(self._liveness(r, pushes, unaudited, now.date()) for r in listed.items),
            next=listed.next,
        )

    def _liveness(
        self,
        repository: Repository,
        pushes: Mapping[UUID, tuple[datetime, str | None]],
        unaudited: Collection[UUID],
        today: date,
    ) -> Liveness:
        assert repository.id is not None
        row = Liveness(repository_id=repository.id, url=repository.url)
        if repository.id in pushes:
            observed_at, pushed_at = pushes[repository.id]
            return row.model_copy(
                update=dict(
                    observed_at=observed_at,
                    archived=repository.archived,
                    pushed_at=pushed_at,
                    dormant=self._policy.is_dormant(parse_audit_date(pushed_at), today),
                )
            )
        if observation_url(repository.url, self._hosts) is None:
            status, reason = ComparisonStatus.UNSUPPORTED_HOST, "no forge observes this host"
        elif repository.id in unaudited:
            status = ComparisonStatus.NEVER_AUDITED
            reason = "observation measures audited repositories only; this one has no audit"
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

    def _latest_observation(
        self, repository_id: UUID
    ) -> tuple[RepositoryRef, Assessment, RepoStateArtifact] | None:
        """The observed default-branch head and its latest repo-state document."""
        with self._uow as uow:
            ref = uow.repository_refs.default(repository_id)
        observed = None if ref is None or ref.id is None else self._observation(ref.id)
        return None if ref is None or observed is None else (ref, *observed)

    def _observation(self, ref_id: UUID) -> tuple[Assessment, RepoStateArtifact] | None:
        assert self._assessment is not None
        latest = self._assessment.latest(ref_id, AssessmentKind.REPO_STATE)
        if latest is None or latest.id is None:
            return None
        publisher = self._require_publisher()
        rows = publisher.list_for_assessment(latest.id, kind=RepoStateArtifact.schema)
        if not rows or rows[0].id is None:
            raise NotFoundError(f"repo-state assessment {latest.id} has no document")
        return latest, publisher.read(rows[0].id, RepoStateArtifact)

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

    def record_manifest_sbom(self, repository_ref_id: UUID, sbom_id: UUID) -> RepositoryRef:
        """The SBOM read from the commit's source tree (manifests, lockfiles)."""
        with self._uow as uow:
            ref = uow.repository_refs.get(repository_ref_id)
            if ref.manifest_sbom_id != sbom_id:
                ref = uow.repository_refs.update(
                    ref.model_copy(update={"manifest_sbom_id": sbom_id})
                )
                uow.commit()
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

    def _require_publisher(self) -> ArtifactPublisher:
        if self._publisher is None:
            raise ConfigError(
                "the corpus registry and repository observation require an ArtifactPublisher"
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
            if release.product_id != previous.product_id:
                raise ValidationError(
                    f"releases {release_id} and {previous_id} belong to different products"
                )
            now, then = (
                {c.repository_ref_id for c in uow.components.list_for_release(r.id)}  # type: ignore[arg-type]
                for r in (release, previous)
            )
        return ReleaseChange(
            release_id=release_id,
            previous_id=previous.id,  # type: ignore[arg-type]
            version=release.version,
            previous_version=previous.version,
            bump=_bump(release.version, previous.version),
            added=tuple(sorted(now - then, key=str)),
            removed=tuple(sorted(then - now, key=str)),
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
        self, repository_id: UUID, teams: Collection[TeamName], at: datetime
    ) -> SyncReport:
        """Mirror the teams a source now reports for one repository: open rows for new teams,
        close the rest at `at`."""
        require_uuid(repository_id, "ownership.repository_id")
        require_aware_datetime(at, "ownership.valid_from")
        for team in teams:
            require_nonblank(team, "team.name")
        with self._uow as uow:
            uow.repositories.get(repository_id)
            current = {o.team_id: o for o in uow.ownerships.current(repository_id)}
            wanted = dict.fromkeys(uow.teams.get_or_add(Team(name=t)).id for t in teams)
            added = [
                uow.ownerships.add(Ownership(repository_id=repository_id, team_id=t, valid_from=at))
                for t in wanted
                if t not in current
            ]
            removed = [
                uow.ownerships.update(o.model_copy(update={"valid_to": at}))
                for t, o in current.items()
                if t not in wanted
            ]
            uow.commit()
        return SyncReport(
            added=tuple(o.id for o in added if o.id),
            unchanged=tuple(o.id for t, o in current.items() if t in wanted and o.id),
            removed=tuple(o.id for o in removed if o.id),
        )

    def get_repository(self, repository_id: UUID) -> Repository:
        return self.inventory.get_repository(repository_id)

    def find_repository(self, url: HttpsRepoUrl) -> Repository | None:
        return self.inventory.find_repository(url)

    def list_repositories(self, filter: RepositoryFilter, page: PageRequest) -> Page[Repository]:
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


def _high_water(release: Release, releases: Sequence[Release]) -> Release:
    """The highest version recorded before `release` (a version label outranks a non-version)."""
    earlier = [
        r
        for r in releases
        if r.id != release.id and r.created_at <= release.created_at  # type: ignore[operator]
    ]
    if not earlier:
        raise NotFoundError(
            f"release {release.version} is its product's first recorded release: nothing to compare"
        )
    return max(earlier, key=lambda r: (_release_version(r.version) or (-1, -1, -1), r.created_at))


def _release_version(label: str) -> tuple[int, int, int] | None:
    """`4.19` and `v4.19.2` as (major, minor, patch); None for a label that is no version."""
    found = _RELEASE_VERSION.fullmatch(label.strip())
    return None if found is None else (int(found[1]), int(found[2]), int(found[3] or 0))


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


def _registered(doc: CorpusRegistryArtifact, product: Product) -> CorpusSubject:
    subject = CorpusRegistry.of(doc).subject(str(product.id))
    assert subject is not None
    return subject


class PortfolioSync:
    """Brings forge listings and the declared ownership source into the portfolio."""

    def __init__(
        self, portfolio: PortfolioService, sources: SourceProvider, *, clock: Clock | None = None
    ) -> None:
        self._portfolio = portfolio
        self._sources = sources
        self._clock = clock or SystemClock()

    def list_org(self, org: OrgName, host: str) -> list[RepoInfo]:
        return self._sources.list_org(org, host).data

    def import_org(self, org: OrgName, host: str) -> SyncReport:
        """Register every non-archived, non-fork repository of an organisation; registered ones
        stay as they are."""
        return sum(
            (self._register(i.repo, i.visibility) for i in self.list_org(org, host)), SyncReport()
        )

    def import_repository(self, url: HttpsRepoUrl) -> SyncReport:
        """Register one repository with the visibility its forge reports."""
        known = self._portfolio.find_repository(url)
        if known is not None and known.id is not None:
            return SyncReport(unchanged=(known.id,))
        return self._register(url, self._sources.info(url).data.visibility)

    def import_branch(
        self, repository_id: UUID, url: HttpsRepoUrl, branch: RefName
    ) -> RepositoryRef:
        """Register the commit a branch points at now."""
        head = self._sources.head(url, branch).data
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
        repository = known or self._portfolio.register_repository(url, visibility == "public")
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
        if facts.status != ComparisonStatus.NETWORK_SKIPPED:
            return facts
        observed = self._portfolio.forge_facts(target.repository_id)
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
            has_cloud_config_baseline=cloud_config,
            threat_model_age_days=(now.date() - threat_model.occurred_at.date()).days
            if threat_model
            else None,
            companion_lanes=scope.companion_lanes,
        )


def _measured(doc: RepoStateArtifact) -> dict[str, object]:
    """What a repo-state document says, apart from when it was said."""
    return {k: v for k, v in json.loads(doc.payload).items() if k != "observed_at"}
