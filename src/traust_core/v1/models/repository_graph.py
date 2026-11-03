from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import ConfigDict, Field

from traust_core.v1.models.base import Model
from traust_core.v1.models.insight import ViewModel


class GraphNodeKind(StrEnum):
    SEGMENT = "segment"
    PRODUCT = "product"
    RELEASE = "release"
    PRODUCT_VERSION = "product-version"
    CATEGORY = "category"
    REPOSITORY = "repo"
    REF = "repo-ref"
    TEAM = "owner-team"
    FINDINGS = "findings"


class GraphRelation(StrEnum):
    CONTAINS = "contains"
    SHIPS = "ships"
    OWNED_BY = "owned-by"
    HAS_FINDINGS = "has-findings"
    HAS_REF = "has_ref"
    SHIPS_REF = "ships_ref"
    FORK_OF = "fork-of"


class GraphAttributes(Model):
    url: str | None = None
    repository_id: UUID | None = None
    artifact_id: UUID | None = None
    branch: str | None = None
    sha: str | None = None
    segment: str | None = None
    segments: tuple[str, ...] = ()
    category: str | None = None
    assessment_kind: str | None = None
    assessed_at: datetime | None = None
    findings: str | None = None
    max_severity: str | None = None
    open_findings: int | None = None
    resolved_findings: int | None = None
    false_positives: int | None = None
    tp_total: int | None = None
    findings_dirs: tuple[str, ...] = ()
    source: str | None = None
    sub_service: str | None = None
    resource_type: str | None = None


class GraphNode(Model):
    id: str
    type: GraphNodeKind
    label: str
    attrs: GraphAttributes = GraphAttributes()


class GraphEdge(Model):
    model_config = ConfigDict(
        frozen=True, extra="forbid", populate_by_name=True, serialize_by_alias=True
    )

    source: str = Field(alias="from")
    target: str = Field(alias="to")
    rel: GraphRelation
    attrs: GraphAttributes = GraphAttributes()


class RepositoryHub(Model):
    repository_id: UUID | None = None
    repository_url: str
    degree: int
    in_degree: int
    out_degree: int


class RepositoryGraphStats(Model):
    nodes: int
    edges: int
    node_types: Mapping[GraphNodeKind, int]
    edge_relations: Mapping[GraphRelation, int]
    repositories: int
    repositories_with_findings: int
    repos_without_findings: int
    coverage_percent: float | None
    top_hubs: tuple[RepositoryHub, ...] = ()


class RepositoryGraph(ViewModel):
    as_of: datetime
    nodes: tuple[GraphNode, ...] = ()
    edges: tuple[GraphEdge, ...] = ()
    stats: RepositoryGraphStats
    sources: tuple[str, ...] = ()
