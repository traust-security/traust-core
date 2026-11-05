from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from traust_core.v1.models.assessment import AssessmentFilter, AssessmentKind
from traust_core.v1.models.common import every_item
from traust_core.v1.models.input_segments import InputSegmentInventory
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.repository_graph import (
    GraphAttributes,
    GraphEdge,
    GraphNode,
    GraphNodeKind,
    GraphRelation,
    RepositoryGraph,
    RepositoryGraphStats,
    RepositoryHub,
)
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.input_segments import InputSegments
from traust_core.v1.rendering import Report, Section, Table
from traust_core.v1.rendering.repository_graph import RepositoryGraphRenderer
from traust_core.v1.services.insight import _scoped_findings, _severity_rank, _tally

if TYPE_CHECKING:
    from traust_core.v1.services.artifact_publishing import ArtifactPublisher
    from traust_core.v1.services.assessment import AssessmentService
    from traust_core.v1.services.findings import FindingService
    from traust_core.v1.services.portfolio import PortfolioService


def _repo(url: str) -> str:
    return f"repo:{url.removeprefix('https://')}"


class RepositoryGraphView:
    name = ViewName.REPOSITORY_GRAPH

    def __init__(
        self,
        portfolio: PortfolioService,
        assessment: AssessmentService,
        findings: FindingService,
        artifacts: ArtifactPublisher,
        clock: Clock,
        *,
        segments: InputSegments | None = None,
    ) -> None:
        self._portfolio, self._assessment = portfolio, assessment
        self._findings, self._artifacts, self._clock = findings, artifacts, clock
        self._segments = segments

    def build(self, filter: ViewFilter) -> RepositoryGraph:
        as_of = filter.as_of or self._clock.now()
        _, _, repositories, finding_views = _scoped_findings(
            self._findings, self._portfolio, filter
        )
        repositories = [r for r in repositories if r.created_at is None or r.created_at <= as_of]
        snapshot = self._segments.read() if self._segments else InputSegmentInventory(segments=())
        segment_names: dict[str, set[str]] = defaultdict(set)
        all_segments: dict[str, set[str]] = defaultdict(set)
        for segment in snapshot.segments:
            for url in segment.repository_urls:
                all_segments[url].add(segment.name)
            if segment.name not in filter.exclude_segments:
                for url in segment.repository_urls:
                    segment_names[url].add(segment.name)
        repositories = [r for r in repositories if not all_segments[r.url] or segment_names[r.url]]
        ids = {r.id for r in repositories if r.id is not None}
        urls = {r.id: r.url for r in repositories}
        nodes: dict[str, GraphNode] = {}
        edges: set[GraphEdge] = set()
        population = self._assessment.population(as_of, AssessmentFilter(), tuple(ids))
        coverage: dict[UUID, set[str]] = defaultdict(set)
        for row in population.rows:
            latest = row.latest
            if latest is None or latest.kind in (
                AssessmentKind.TOOL_SCAN,
                AssessmentKind.REPO_STATE_CANONICAL,
            ):
                continue
            for artifact in self._artifacts.list_for_assessment(latest.id):
                key = f"findings:{artifact.id}"
                nodes[key] = GraphNode(
                    id=key,
                    type=GraphNodeKind.FINDINGS,
                    label=f"{row.kind} · {latest.occurred_at.date()}",
                    attrs=GraphAttributes(
                        url=artifact.uri,
                        repository_id=row.repository_id,
                        artifact_id=artifact.id,
                        assessment_kind=str(latest.kind),
                        assessed_at=latest.occurred_at,
                    ),
                )
                coverage[row.repository_id].add(artifact.uri)
                edges.add(
                    GraphEdge(
                        source=_repo(urls[row.repository_id]),
                        target=key,
                        rel=GraphRelation.HAS_FINDINGS,
                    )
                )
        for repository in repositories:
            assert repository.id is not None
            tally = _tally(finding_views[repository.id])
            severities = [
                v.effective_severity
                for v in finding_views[repository.id]
                if v.state().value == "open"
            ]
            worst = min(severities, key=_severity_rank, default=None)
            key = _repo(repository.url)
            nodes[key] = GraphNode(
                id=key,
                type=GraphNodeKind.REPOSITORY,
                label=repository.url.removeprefix("https://"),
                attrs=GraphAttributes(
                    url=repository.url,
                    repository_id=repository.id,
                    segments=tuple(sorted(segment_names[repository.url])),
                    findings="assessed" if coverage[repository.id] else "none",
                    max_severity=None if worst is None else str(worst),
                    open_findings=tally.open.total,
                    resolved_findings=tally.resolved,
                    false_positives=tally.false_positive,
                    tp_total=tally.tracked,
                    findings_dirs=tuple(sorted(coverage[repository.id])),
                ),
            )
            if repository.upstream_id in ids:
                edges.add(
                    GraphEdge(
                        source=key,
                        target=_repo(urls[repository.upstream_id]),
                        rel=GraphRelation.FORK_OF,
                    )
                )
            for team in self._portfolio.list_owners(repository.id, as_of):
                team_key = f"owner-team:{team.id}"
                nodes[team_key] = GraphNode(id=team_key, type=GraphNodeKind.TEAM, label=team.name)
                edges.add(GraphEdge(source=team_key, target=key, rel=GraphRelation.OWNED_BY))
        refs = {
            r.id: r
            for r in self._portfolio.inventory.list_refs_of(tuple(ids))
            if r.created_at is None or r.created_at <= as_of
        }
        for ref in refs.values():
            key = f"ref:{ref.id}"
            nodes[key] = GraphNode(
                id=key,
                type=GraphNodeKind.REF,
                label=f"{urls[ref.repository_id].removeprefix('https://')}@"
                f"{ref.name or ref.sha[:12]}",
                attrs=GraphAttributes(
                    repository_id=ref.repository_id, branch=ref.name, sha=ref.sha
                ),
            )
            edges.add(
                GraphEdge(
                    source=_repo(urls[ref.repository_id]), target=key, rel=GraphRelation.HAS_REF
                )
            )
        products = list(every_item(self._portfolio.list_products))
        for product in products:
            if product.created_at is not None and product.created_at > as_of:
                continue
            product_key = f"product:{product.id}"
            for release in self._portfolio.list_releases(product.id):
                if release.created_at is not None and release.created_at > as_of:
                    continue
                shipped = [r for r in self._portfolio.list_release_refs(release.id) if r.id in refs]
                if not shipped:
                    continue
                nodes[product_key] = GraphNode(
                    id=product_key, type=GraphNodeKind.PRODUCT, label=product.name
                )
                release_key = f"release:{release.id}"
                nodes[release_key] = GraphNode(
                    id=release_key,
                    type=GraphNodeKind.RELEASE,
                    label=f"{product.slug} {release.version}",
                )
                edges.add(
                    GraphEdge(source=product_key, target=release_key, rel=GraphRelation.CONTAINS)
                )
                for ref in shipped:
                    edges.add(
                        GraphEdge(
                            source=release_key,
                            target=_repo(urls[ref.repository_id]),
                            rel=GraphRelation.SHIPS,
                        )
                    )
                    edges.add(
                        GraphEdge(
                            source=release_key, target=f"ref:{ref.id}", rel=GraphRelation.SHIPS_REF
                        )
                    )
        self._hierarchy(
            snapshot, nodes, edges, filter, scoped=bool(filter.product_ids or filter.team_ids)
        )
        ordered_nodes = tuple(sorted(nodes.values(), key=lambda n: n.id))
        ordered_edges = tuple(sorted(edges, key=lambda e: (e.source, e.target, e.rel)))
        return RepositoryGraph(
            as_of=as_of,
            nodes=ordered_nodes,
            edges=ordered_edges,
            stats=_stats(ordered_nodes, ordered_edges),
            sources=(
                "PortfolioService: products, releases, commits, upstreams and temporal ownership",
                "AssessmentService.population: latest default-line assessments at the stated time",
                "FindingService: disposition-aware distinct findings at the stated time",
                *(
                    ("InputSegments: declared inventory hierarchy (current source snapshot)",)
                    if self._segments
                    else ()
                ),
            ),
        )

    def _hierarchy(
        self,
        snapshot: InputSegmentInventory,
        nodes: dict[str, GraphNode],
        edges: set[GraphEdge],
        filter: ViewFilter,
        *,
        scoped: bool,
    ) -> None:
        for row in snapshot.hierarchy:
            if row.segment in filter.exclude_segments:
                continue
            repository_key = _repo(row.repository_url)
            if scoped and repository_key not in nodes:
                continue
            if repository_key not in nodes:
                nodes[repository_key] = GraphNode(
                    id=repository_key,
                    type=GraphNodeKind.REPOSITORY,
                    label=row.repository_url.removeprefix("https://"),
                    attrs=GraphAttributes(
                        url=row.repository_url, findings="none", segments=(row.segment,)
                    ),
                )
            elif row.segment not in nodes[repository_key].attrs.segments:
                node = nodes[repository_key]
                nodes[repository_key] = node.model_copy(
                    update={
                        "attrs": node.attrs.model_copy(
                            update={"segments": tuple(sorted((*node.attrs.segments, row.segment)))}
                        )
                    }
                )
            parent = f"segment:{row.segment}"
            nodes[parent] = GraphNode(
                id=parent,
                type=GraphNodeKind.SEGMENT,
                label=row.segment_label,
                attrs=GraphAttributes(segment=row.segment),
            )
            for kind, value in (
                (GraphNodeKind.PRODUCT, row.product),
                (GraphNodeKind.PRODUCT_VERSION, row.version),
                (GraphNodeKind.RELEASE, row.release),
                (GraphNodeKind.CATEGORY, row.category),
            ):
                if value is None:
                    continue
                key = f"inventory-{kind}:{parent}/{value}"
                nodes[key] = GraphNode(
                    id=key, type=kind, label=value, attrs=GraphAttributes(segment=row.segment)
                )
                edges.add(GraphEdge(source=parent, target=key, rel=GraphRelation.CONTAINS))
                parent = key
            attrs = GraphAttributes(
                source=row.source,
                branch=row.branch,
                sub_service=row.sub_service,
                resource_type=row.resource_type,
            )
            edges.add(
                GraphEdge(
                    source=parent, target=repository_key, rel=GraphRelation.SHIPS, attrs=attrs
                )
            )
            if row.branch:
                key = f"ref:{row.repository_url.removeprefix('https://')}@{row.branch}"
                nodes[key] = GraphNode(
                    id=key,
                    type=GraphNodeKind.REF,
                    label=f"{row.repository_url.removeprefix('https://')}@{row.branch}",
                    attrs=GraphAttributes(branch=row.branch, segment=row.segment),
                )
                edges.add(GraphEdge(source=repository_key, target=key, rel=GraphRelation.HAS_REF))
                edges.add(
                    GraphEdge(source=parent, target=key, rel=GraphRelation.SHIPS_REF, attrs=attrs)
                )

    def report(self, model: RepositoryGraph, generated_at: datetime) -> Report:
        stats = model.stats
        coverage = "unmeasured" if stats.coverage_percent is None else f"{stats.coverage_percent}%"
        return Report(
            title="Repo Graph",
            generated_at=generated_at,
            sources=model.sources,
            sections=(
                Section(
                    heading="Population and coverage",
                    body=(
                        f"{stats.repositories} distinct repositories; "
                        f"{stats.repositories_with_findings} with recorded assessment artifacts; "
                        f"{stats.repos_without_findings} without assessment coverage. "
                        f"Coverage: {coverage}. "
                        f"{stats.nodes} nodes and {stats.edges} distinct directed relationships. "
                        "Inventory-only repositories remain visible as unassessed; "
                        "tool scans and repo-state "
                        "observations alone do not establish assessment coverage."
                    ),
                ),
                Section(
                    heading="Node types",
                    table=Table(
                        columns=("type", "nodes"),
                        rows=tuple(
                            (str(kind), str(count))
                            for kind, count in sorted(stats.node_types.items())
                        ),
                    ),
                ),
                Section(
                    heading="Relationships",
                    table=Table(
                        columns=("relation", "edges"),
                        rows=tuple(
                            (str(kind), str(count))
                            for kind, count in sorted(stats.edge_relations.items())
                        ),
                    ),
                ),
                Section(
                    heading="Top-20 hub repositories (highest degree)",
                    table=Table(
                        columns=("repository", "degree", "in", "out"),
                        rows=tuple(
                            (r.repository_url, str(r.degree), str(r.in_degree), str(r.out_degree))
                            for r in stats.top_hubs
                        ),
                    ),
                ),
            ),
        )

    def render_html(self, model: RepositoryGraph, report: Report) -> bytes:
        return RepositoryGraphRenderer().render(model, report)

    def graphviz(self, model: RepositoryGraph) -> str:
        return RepositoryGraphRenderer().graphviz(model)

    def gexf(self, model: RepositoryGraph) -> str:
        return RepositoryGraphRenderer().gexf(model)


def _stats(nodes: tuple[GraphNode, ...], edges: tuple[GraphEdge, ...]) -> RepositoryGraphStats:
    # Branch refs are additive: they must not inflate the repository-hub ranking.
    degree_edges = [
        e for e in edges if e.rel not in (GraphRelation.HAS_REF, GraphRelation.SHIPS_REF)
    ]
    incoming = Counter(e.target for e in degree_edges)
    outgoing = Counter(e.source for e in degree_edges)
    repositories = [n for n in nodes if n.type is GraphNodeKind.REPOSITORY]
    covered = sum(n.attrs.findings == "assessed" for n in repositories)
    hubs = [
        RepositoryHub(
            repository_id=n.attrs.repository_id,
            repository_url=n.attrs.url,
            degree=incoming[n.id] + outgoing[n.id],
            in_degree=incoming[n.id],
            out_degree=outgoing[n.id],
        )
        for n in repositories
        if n.attrs.url is not None
    ]
    return RepositoryGraphStats(
        nodes=len(nodes),
        edges=len(edges),
        node_types=dict(Counter(n.type for n in nodes)),
        edge_relations=dict(Counter(e.rel for e in edges)),
        repositories=len(repositories),
        repositories_with_findings=covered,
        repos_without_findings=len(repositories) - covered,
        coverage_percent=round(100 * covered / len(repositories), 2) if repositories else None,
        top_hubs=tuple(sorted(hubs, key=lambda r: (-r.degree, r.repository_url))[:20]),
    )
