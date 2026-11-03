from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime
from urllib.parse import urlsplit
from uuid import UUID

from traust_core.v1.errors import TraustError, ValidationError
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    Assessment,
    AssessmentFilter,
    AssessmentKind,
    PrivilegeProfile,
    Threat,
    ThreatFilter,
)
from traust_core.v1.models.common import every_item
from traust_core.v1.models.corpus import CorpusRegistry
from traust_core.v1.models.findings import FindingFilter, FindingState
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.inventory import ExposureClass, Repository, default_line
from traust_core.v1.models.observation import ComparisonStatus, is_first_party
from traust_core.v1.models.portfolio_analytics import (
    DRAFT_NOTICE,
    AnalyticsSource,
    AssessmentArtifactLink,
    CrownJewelComponents,
    CrownJewelDraft,
    CrownJewelProposalRow,
    CrownJewelProposedTiers,
    CrownJewelSignal,
    IacCensus,
    IacClass,
    IacClassification,
    IacRepository,
    OrganizationAssessment,
    OrganizationIndex,
    OrganizationRepository,
    SourceOrganization,
)
from traust_core.v1.models.values import HttpsRepoUrl, require_aware_datetime
from traust_core.v1.models.vocabulary import OwnershipClass, ThreatStatus
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.sources import SourceProvider
from traust_core.v1.rendering import Link, Report, Section, Table
from traust_core.v1.services.artifact_publishing import ArtifactPublisher
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingService
from traust_core.v1.services.insight import _scope
from traust_core.v1.services.observation import observation_url, parse_audit_date
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

_WEIGHTS = dict(zip(CrownJewelSignal, (0.35, 0.25, 0.20, 0.20), strict=True))
_IMPACT = {"low": 1, "medium": 2, "high": 3, "critical": 4, "existential": 5}
_OPEN_THREATS = (ThreatStatus("unmitigated"), ThreatStatus("partially_mitigated"))
_IAC_PATTERNS = {
    IacClass.TERRAFORM: re.compile(r"\.tf$|\.tfvars$|\.tf\.json$"),
    IacClass.CLOUDFORMATION: re.compile(r"(^|/)(cloudformation|cfn)/[^ ]*\.(ya?ml|json)$"),
    IacClass.ARM_BICEP: re.compile(
        r"\.bicep$|(^|/)azuredeploy[^/]*\.json$|(^|/)arm(-templates)?/[^ ]*\.json$"
    ),
    IacClass.HELM_CHART: re.compile(r"(^|/)Chart\.yaml$"),
    IacClass.DOCKERFILE: re.compile(r"(^|/)(Dockerfile|Containerfile)([._-][^/]*)?$"),
}


def _number(value: int | float | None) -> str:
    return "unknown" if value is None else f"{value:g}"


def _report_link(label: str, uri: str) -> str | Link:
    scheme = urlsplit(uri).scheme.lower()
    if scheme in {"http", "https"} or not scheme:
        return Link(label=label, href=uri)
    return uri


def classify_iac_paths(paths: Sequence[str]) -> IacClassification:
    first_party = sorted({p for p in paths if is_first_party(p)})
    return IacClassification(
        **{
            kind.value: tuple(p for p in first_party if rx.search(p))
            for kind, rx in _IAC_PATTERNS.items()
        }
    )


def privilege_tier(profile: PrivilegeProfile) -> int:
    flags = profile.flags
    if (
        profile.privileged_workloads
        or profile.privileged_sccs
        or any(
            flags.get(k) for k in ("wildcard_resources", "escalate_bind_impersonate", "rbac_write")
        )
    ):
        return 3
    if (
        profile.scc_requests
        or profile.distinct_cluster_triples
        or any(
            flags.get(k) for k in ("wildcard_verbs", "secrets_access", "pods_exec", "nodes_access")
        )
    ):
        return 2
    return 1


def _impact(threat: Threat) -> float | None:
    if threat.impact_score is not None:
        return threat.impact_score / 9
    points = _IMPACT.get(threat.impact or "")
    return points / 5 if points is not None else None


def _lognorm(value: int, maximum: int) -> float:
    return math.log2(1 + value) / math.log2(1 + maximum) if maximum else 0.0


class PortfolioAnalyticsService:
    """Read-only portfolio proposals and navigation, composed from the existing fact owners."""

    def __init__(
        self,
        portfolio: PortfolioService,
        assessment: AssessmentService,
        findings: FindingService,
        artifacts: ArtifactPublisher,
        sources: SourceProvider,
        exposure: ExposureService,
        policy: PortfolioPolicy,
        clock: Clock,
        *,
        hosts: Mapping[str, str],
    ) -> None:
        self._portfolio = portfolio
        self._assessment = assessment
        self._findings = findings
        self._artifacts = artifacts
        self._sources = sources
        self._exposure = exposure
        self._policy = policy
        self._clock = clock
        self._hosts = hosts

    def _as_of(self, filter: ViewFilter) -> datetime:
        as_of = filter.as_of or self._clock.now()
        require_aware_datetime(as_of, "portfolio analytics as_of")
        return as_of

    def _latest(
        self, kind: AssessmentKind, repository_ids: Sequence[UUID], as_of: datetime
    ) -> dict[UUID, Assessment]:
        population = self._assessment.population(
            as_of, AssessmentFilter(kind=kind, status=ASSESSMENT_COMPLETED), repository_ids
        )
        return {row.repository_id: row.latest for row in population.rows if row.latest is not None}

    def _owners(self, repository_id: UUID, as_of: datetime) -> tuple[str, ...]:
        return tuple(t.name for t in self._portfolio.list_owners(repository_id, as_of))

    def _ownership_classes(
        self, repositories: Sequence[Repository], as_of: datetime
    ) -> dict[UUID, tuple[OwnershipClass, ...]]:
        document = self._portfolio.corpus_registry(as_of)
        if document is None:
            return {}
        registry = CorpusRegistry.of(document)
        classes: defaultdict[UUID, set[OwnershipClass]] = defaultdict(set)
        by_url = {r.url: r.id for r in repositories if r.id is not None}
        in_scope = set(by_url.values())
        for subject in registry.subjects:
            if subject.repo_url in by_url and not subject.is_branch_audit:
                classes[by_url[subject.repo_url]].add(subject.ownership)
        for product in every_item(self._portfolio.list_products):
            subject = registry.subject(str(product.id))
            if subject is None:
                continue
            for ref in self._portfolio.list_product_refs(product.id):
                if ref.repository_id in in_scope:
                    classes[ref.repository_id].add(subject.ownership)
        return {i: tuple(sorted(values)) for i, values in classes.items()}

    def _counts(self, repository_id: UUID, as_of: datetime) -> tuple[int, int]:
        views = self._findings.all(FindingFilter(repository_id=repository_id, as_of=as_of))
        opened = {v.finding.id: v for v in views if v.state() == FindingState.OPEN}
        if not opened:
            return 0, 0
        line = default_line(self._portfolio.inventory.list_refs(repository_id))
        assessments = {
            a.id
            for a in self._assessment.list_for_repository(repository_id)
            if a.repository_ref_id in line and a.occurred_at <= as_of
        }
        reported = {
            o.finding_id
            for o in self._findings.occurrences(finding_ids=tuple(opened))
            if o.assessment_id in assessments
        }
        counts = Counter(opened[i].effective_severity for i in reported)
        return counts["critical"], counts["high"]

    def crown_jewel_draft(self, filter: ViewFilter, tier1_size: int = 20) -> CrownJewelDraft:
        if not 1 <= tier1_size <= 100:
            raise ValidationError("crown-jewel tier1_size must be between 1 and 100")
        as_of = self._as_of(filter)
        _, _, repositories = _scope(self._portfolio, filter)
        ids = tuple(r.id for r in repositories if r.id is not None)
        ownership = self._ownership_classes(repositories, as_of)
        fanin: dict[UUID, int] = {}
        threats: dict[UUID, tuple[int, float | None]] = {}
        threat_gaps: set[UUID] = set()
        profiles: dict[UUID, int] = {}
        counts: dict[UUID, tuple[int, int]] = {}
        sources = []
        for signal in CrownJewelSignal:
            gap = None
            try:
                if signal == CrownJewelSignal.FANIN:
                    fanin = {
                        row.repository_id: len(row.consumer_repository_ids)
                        for row in self._exposure.internal_coupling(ids)
                    }
                    measured, owner = len(fanin), "ExposureService.internal_coupling"
                elif signal == CrownJewelSignal.THREAT:
                    latest = self._latest(AssessmentKind.THREAT_MODEL_CANONICAL, ids, as_of)
                    modeled = {
                        i
                        for i, a in latest.items()
                        if a.id is not None
                        and self._artifacts.list_for_assessment(a.id, kind="threat-model")
                    }
                    query = ThreatFilter(repository_ids=ids, as_of=as_of, statuses=_OPEN_THREATS)
                    held: defaultdict[UUID, list[Threat]] = defaultdict(list)
                    for threat in every_item(
                        lambda page, query=query: self._assessment.threats(query, page)
                    ):
                        if threat.repository_id in modeled:
                            held[threat.repository_id].append(threat)
                    for i in modeled:
                        fractions = [_impact(t) for t in held[i]]
                        known = [f for f in fractions if f is not None]
                        threats[i] = (
                            len(held[i]),
                            max(known, default=0.0 if not held[i] else None),
                        )
                        if len(known) != len(fractions):
                            threat_gaps.add(i)
                    measured = sum(impact is not None for _, impact in threats.values())
                    owner = "AssessmentService.threats"
                elif signal == CrownJewelSignal.PRIVILEGE:
                    profiles = {
                        p.repository_id: privilege_tier(p)
                        for p in self._assessment.privileges(AssessmentFilter(), ids, as_of)
                    }
                    measured, owner = len(profiles), "AssessmentService.privileges"
                else:
                    counts = {i: self._counts(i, as_of) for i in ids}
                    measured, owner = len(counts), "FindingService default-line open findings"
            except TraustError as exc:
                measured, owner = 0, signal.value
                gap = f"{type(exc).__name__}: {exc}"
            available = bool(measured)
            if available and measured < len(ids):
                gap = f"No measured input for {len(ids) - measured} repositories"
            if available and signal == CrownJewelSignal.FANIN:
                gap = (f"{gap}. " if gap else "") + (
                    "Recorded dependency reach only; unrecorded consumer manifests are unknown"
                )
            sources.append(
                AnalyticsSource(
                    signal=signal,
                    owner=owner,
                    measured_repositories=measured,
                    total_repositories=len(ids),
                    available=available,
                    gap=gap or ("No measured inputs; weight dropped" if not available else None),
                )
            )
        active = {s.signal: _WEIGHTS[s.signal] for s in sources if s.available}
        total_weight = sum(active.values())
        weights = {k: v / total_weight for k, v in active.items()}
        max_fanin = max(fanin.values(), default=0)
        max_load = max((2 * c + h for c, h in counts.values()), default=0)
        rows = []
        for repository in repositories:
            assert repository.id is not None
            i = repository.id
            c, h = counts.get(i, (0, 0))
            normalized = {
                CrownJewelSignal.FANIN: _lognorm(fanin.get(i, 0), max_fanin),
                CrownJewelSignal.THREAT: threats.get(i, (0, None))[1] or 0.0,
                CrownJewelSignal.PRIVILEGE: profiles.get(i, 0) / 3,
                CrownJewelSignal.FINDINGS: _lognorm(2 * c + h, max_load),
            }
            rows.append(
                CrownJewelProposalRow(
                    repository_id=i,
                    repository_url=repository.url,
                    owners=self._owners(i, as_of),
                    ownership_classes=ownership.get(i, ()),
                    rank=1,
                    score=round(100 * sum(weights[k] * normalized[k] for k in weights), 2),
                    components=CrownJewelComponents(
                        fanin=fanin.get(i),
                        open_threats=threats[i][0] if i in threats else None,
                        threat_impact=threats[i][1] if i in threats else None,
                        privilege_tier=profiles.get(i),
                        open_critical=c if i in counts else None,
                        open_high=h if i in counts else None,
                        normalized={k: round(normalized[k], 6) for k in weights},
                    ),
                    gaps=tuple(
                        k
                        for k, measured in (
                            (CrownJewelSignal.FANIN, fanin),
                            (CrownJewelSignal.THREAT, threats),
                            (CrownJewelSignal.PRIVILEGE, profiles),
                            (CrownJewelSignal.FINDINGS, counts),
                        )
                        if i not in measured or (k == CrownJewelSignal.THREAT and i in threat_gaps)
                    ),
                )
            )
        rows.sort(key=lambda row: (-row.score, row.repository_url, str(row.repository_id)))
        rows = [r.model_copy(update={"rank": n}) for n, r in enumerate(rows, 1)]
        scored = [r for r in rows if r.score > 0]
        return CrownJewelDraft(
            as_of=as_of,
            universe_repositories=len(rows),
            scored_repositories=len(scored),
            tier1_size=tier1_size,
            weights_effective=weights,
            sources=tuple(sources),
            repositories=tuple(rows),
            tiers=CrownJewelProposedTiers(
                tier1=tuple(scored[:tier1_size]),
                tier2=tuple(scored[tier1_size:100]),
                watch=tuple(scored[100:200]),
            ),
        )

    def iac_census(self, filter: ViewFilter) -> IacCensus:
        as_of = self._as_of(filter)
        _, _, repositories = _scope(self._portfolio, filter)
        ids = tuple(r.id for r in repositories if r.id is not None)
        audited = self._latest(AssessmentKind.SECURE_CODE_CANONICAL, ids, as_of)
        baselines = self._latest(AssessmentKind.CLOUD_CONFIG_CANONICAL, ids, as_of)
        ships = self._portfolio.repositories_shipping(ids)
        rows = []
        for repository in repositories:
            assert repository.id is not None
            audit = audited.get(repository.id)
            if audit is None:
                continue
            assert audit.id is not None
            url = observation_url(repository.url, self._hosts)
            host = urlsplit(repository.url).hostname
            classification, reason, sha = None, None, None
            truncated, archived, dormant = False, False, False
            status = ComparisonStatus.NETWORK_SKIPPED
            if url is None:
                reason = "Repository URL or forge host is unsupported; tree unobserved"
            else:
                try:
                    info = self._sources.info(url).data
                    head = info.head
                    if head is None:
                        if info.default_branch is None:
                            raise ValidationError(f"{url}: no default branch or head was observed")
                        head = self._sources.head(url, info.default_branch).data
                    sha = str(head)
                    tree = self._sources.tree(url, sha).data
                    classification = classify_iac_paths(tree.paths)
                    truncated = tree.truncated
                    archived = bool(info.archived)
                    dormant = self._policy.is_dormant(
                        parse_audit_date(info.pushed_at), as_of.date()
                    )
                    status = ComparisonStatus.OK
                    if truncated:
                        reason = "Forge tree truncated; classification is a lower bound"
                except TraustError as exc:
                    status = ComparisonStatus.ERROR
                    reason = f"{type(exc).__name__}: {exc}"
            critical, high = self._counts(repository.id, as_of)
            rows.append(
                IacRepository(
                    repository_id=repository.id,
                    repository_url=repository.url,
                    host=host,
                    assessment_id=audit.id,
                    observed_sha=sha,
                    status=status,
                    reason=reason,
                    truncated=truncated,
                    classification=classification,
                    owners=self._owners(repository.id, as_of),
                    exposure=self._policy.exposure_class(
                        repository.id in ships,
                        repository.public,
                        repository.upstream_id is not None,
                    ),
                    risk_tier=self._policy.risk_tier(critical + high, archived, dormant),
                    open_critical_high=critical + high,
                    has_cloud_config_baseline=repository.id in baselines,
                )
            )
        exposure_order = (
            ExposureClass.PUBLIC_EXTERNAL,
            ExposureClass.PRIVATE_EXTERNAL,
            ExposureClass.PUBLIC_INTERNAL,
            ExposureClass.PRIVATE_INTERNAL,
        )
        worklist = sorted(
            (
                r
                for r in rows
                if r.classification is not None
                and r.classification.lane_files()
                and not r.has_cloud_config_baseline
            ),
            key=lambda r: (
                exposure_order.index(r.exposure),
                r.risk_tier,
                -r.open_critical_high,
                r.repository_url,
            ),
        )
        return IacCensus(
            as_of=as_of,
            population=len(rows),
            observed=sum(r.classification is not None for r in rows),
            never_audited=tuple(i for i in ids if i not in audited),
            repositories=tuple(rows),
            worklist=tuple(worklist),
            unobserved_by_host=dict(
                sorted(
                    Counter(
                        r.host or "no-source-host" for r in rows if r.classification is None
                    ).items()
                )
            ),
            by_class={
                k: sum(bool(r.classification and r.classification.paths(k)) for r in rows)
                for k in IacClass
            },
        )

    def organization_index(self, filter: ViewFilter) -> OrganizationIndex:
        as_of = self._as_of(filter)
        _, _, repositories = _scope(self._portfolio, filter)
        organizations: defaultdict[tuple[str, str], list[OrganizationRepository]] = defaultdict(
            list
        )
        unlocated = []
        for repository in repositories:
            assert repository.id is not None
            assessments = []
            for assessment in self._assessment.list_for_repository(repository.id):
                if assessment.occurred_at > as_of:
                    continue
                assert assessment.id is not None
                artifacts = sorted(
                    self._artifacts.list_for_assessment(assessment.id),
                    key=lambda a: (a.kind, a.uri, str(a.id)),
                )
                assessments.append(
                    OrganizationAssessment(
                        assessment=assessment,
                        artifacts=tuple(
                            AssessmentArtifactLink(
                                artifact_id=a.id, kind=a.kind, uri=a.uri, digest=a.digest
                            )
                            for a in artifacts
                            if a.id is not None
                        ),
                    )
                )
            row = OrganizationRepository(
                repository_id=repository.id,
                repository_url=repository.url,
                owners=self._owners(repository.id, as_of),
                assessments=tuple(assessments),
            )
            parts = urlsplit(repository.url)
            try:
                url = HttpsRepoUrl.parse(repository.url, (parts.hostname or "",))
            except ValidationError:
                unlocated.append(row)
            else:
                namespace = url.path.rsplit("/", 1)[0]
                organizations[url.host, namespace].append(row)
        return OrganizationIndex(
            as_of=as_of,
            unlocated=tuple(unlocated),
            organizations=tuple(
                SourceOrganization(
                    host=host,
                    namespace=namespace,
                    url=f"https://{host}/{namespace}",
                    repositories=tuple(rows),
                )
                for (host, namespace), rows in sorted(organizations.items())
            ),
        )


class CrownJewelDraftView:
    name = ViewName.CROWN_JEWEL_DRAFT

    def __init__(self, analytics: PortfolioAnalyticsService) -> None:
        self._analytics = analytics

    def build(self, filter: ViewFilter) -> CrownJewelDraft:
        return self._analytics.crown_jewel_draft(filter, filter.crown_jewel_tier1_size)

    def report(self, model: CrownJewelDraft, generated_at: datetime) -> Report:
        sections = [
            Section(heading="Unsigned proposal", body=DRAFT_NOTICE),
            Section(
                heading="Sources and gaps",
                body=(
                    "Weights: fanin 0.35, threat 0.25, privilege 0.20, findings 0.20, renormalized "
                    "over available sources. Fan-in and 2\u00d7critical+high are "
                    "log2-normalized; threat "
                    "is maximum open impact (OWASP /9, legacy /5); privilege is tier /3. "
                    "A missing per-repository input contributes zero, not evidence of low risk. "
                    "Fan-in uses current manifest provenance; other inputs are bounded by as_of."
                ),
                table=Table(
                    columns=("source", "owner", "measured", "effective weight", "gap"),
                    rows=tuple(
                        (
                            s.signal.value,
                            s.owner,
                            f"{s.measured_repositories}/{s.total_repositories}",
                            f"{model.weights_effective.get(s.signal, 0):.6f}",
                            s.gap or "—",
                        )
                        for s in model.sources
                    ),
                ),
            ),
        ]
        for heading, rows in (
            ("Tier 1", model.tiers.tier1),
            ("Tier 2", model.tiers.tier2),
            ("Watch", model.tiers.watch),
        ):
            sections.append(
                Section(
                    heading=heading,
                    table=Table(
                        columns=(
                            "rank",
                            "repository",
                            "score",
                            "fan-in",
                            "open threats / impact (0\u20131)",
                            "privilege tier",
                            "open critical/high",
                            "owners",
                            "ownership",
                            "missing inputs",
                        ),
                        rows=tuple(
                            (
                                str(r.rank),
                                r.repository_url,
                                f"{r.score:.2f}",
                                _number(r.components.fanin),
                                f"{_number(r.components.open_threats)} / "
                                f"{_number(r.components.threat_impact)}",
                                _number(r.components.privilege_tier),
                                f"{_number(r.components.open_critical)}/{_number(r.components.open_high)}",
                                ", ".join(r.owners) or "unknown team",
                                ", ".join(r.ownership_classes) or "unknown — ownership gap",
                                ", ".join(r.gaps) or "—",
                            )
                            for r in rows
                        ),
                    ),
                )
            )
        sections.append(Section(heading="Dispatch boundary", body=DRAFT_NOTICE))
        return Report(
            title="Crown-jewel draft", generated_at=generated_at, sections=tuple(sections)
        )


class IacCensusView:
    name = ViewName.IAC_CENSUS

    def __init__(self, analytics: PortfolioAnalyticsService) -> None:
        self._analytics = analytics

    def build(self, filter: ViewFilter) -> IacCensus:
        return self._analytics.iac_census(filter)

    def report(self, model: IacCensus, generated_at: datetime) -> Report:
        return Report(
            title="Fleet IaC census",
            generated_at=generated_at,
            sections=(
                Section(
                    heading="Population",
                    body=(
                        f"{model.population} default-line code-audited repositories; "
                        f"{model.observed} trees observed. "
                        f"{len(model.never_audited)} registered repositories have no "
                        f"completed default-line code audit. {model.notice}\n\n"
                        f"{model.classification_basis}"
                    ),
                ),
                Section(
                    heading="Baseline worklist",
                    table=Table(
                        columns=(
                            "rank",
                            "repository",
                            "exposure",
                            "risk tier",
                            "open C/H",
                            "IaC files",
                        ),
                        rows=tuple(
                            (
                                str(n),
                                r.repository_url,
                                r.exposure.value,
                                r.risk_tier.value,
                                str(r.open_critical_high),
                                str(r.classification.lane_files()),
                            )
                            for n, r in enumerate(model.worklist, 1)
                            if r.classification is not None
                        ),
                    ),
                ),
                Section(
                    heading="Repository classification",
                    table=Table(
                        columns=("repository", "status", *tuple(k.value for k in IacClass), "gap"),
                        rows=tuple(
                            (
                                r.repository_url,
                                r.status.value,
                                *(
                                    str(len(r.classification.paths(k)))
                                    if r.classification is not None
                                    else "unknown"
                                    for k in IacClass
                                ),
                                r.reason or "—",
                            )
                            for r in model.repositories
                        ),
                    ),
                ),
                Section(
                    heading="Unobserved hosts",
                    table=Table(
                        columns=("host", "repositories"),
                        rows=tuple(
                            (host, str(count)) for host, count in model.unobserved_by_host.items()
                        ),
                    ),
                ),
            ),
        )


class OrganizationIndexView:
    name = ViewName.ORGANIZATION_INDEX

    def __init__(self, analytics: PortfolioAnalyticsService) -> None:
        self._analytics = analytics

    def build(self, filter: ViewFilter) -> OrganizationIndex:
        return self._analytics.organization_index(filter)

    def report(self, model: OrganizationIndex, generated_at: datetime) -> Report:
        sections = []
        groups = [(f"{o.host}/{o.namespace}", o.repositories) for o in model.organizations]
        if model.unlocated:
            groups.append(("Unlocated source organization", model.unlocated))
        for name, repositories in groups:
            rows: list[tuple[str | Link, ...]] = []
            for repository in repositories:
                repository_link = _report_link(repository.repository_url, repository.repository_url)
                if not repository.assessments:
                    rows.append((repository_link, "—", "unassessed", "—", "—"))
                for held in repository.assessments:
                    assessment = held.assessment
                    for artifact in held.artifacts:
                        rows.append(
                            (
                                repository_link,
                                str(assessment.id),
                                str(assessment.kind),
                                artifact.kind,
                                _report_link(artifact.kind, artifact.uri),
                            )
                        )
                    if not held.artifacts:
                        rows.append(
                            (
                                repository_link,
                                str(assessment.id),
                                str(assessment.kind),
                                "no artifacts",
                                "—",
                            )
                        )
            sections.append(
                Section(
                    heading=name,
                    table=Table(
                        columns=("repository", "assessment", "kind", "artifact", "link"),
                        rows=tuple(rows),
                    ),
                )
            )
        return Report(
            title="Source organization index", generated_at=generated_at, sections=tuple(sections)
        )
