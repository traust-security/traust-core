from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from html.parser import HTMLParser
from xml.etree import ElementTree

from traust_core.v1.models.repository_graph import (
    GraphAttributes,
    GraphEdge,
    GraphNode,
    GraphNodeKind,
    GraphRelation,
    RepositoryGraph,
    RepositoryGraphStats,
)
from traust_core.v1.rendering import Report
from traust_core.v1.rendering.repository_graph import RepositoryGraphRenderer


class Page(HTMLParser):
    def __init__(self, html: str) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.scripts: list[tuple[dict[str, str | None], str]] = []
        self.current: dict[str, str | None] | None = None
        self.feed(html)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))
        if tag == "script":
            self.current = dict(attrs)
            self.scripts.append((self.current, ""))

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self.current = None

    def handle_data(self, data: str) -> None:
        if self.current is not None:
            attrs, text = self.scripts[-1]
            self.scripts[-1] = attrs, text + data


def model() -> RepositoryGraph:
    hostile = '</script><img src="https://untrusted.example/exfil" onerror="alert(1)">'
    return RepositoryGraph(
        as_of=datetime(2026, 11, 1, tzinfo=UTC),
        nodes=(
            GraphNode(id="product:p", type=GraphNodeKind.PRODUCT, label=hostile),
            GraphNode(
                id="repo:r",
                type=GraphNodeKind.REPOSITORY,
                label='quoted " repository',
                attrs=GraphAttributes(url="https://github.com/example/repository"),
            ),
        ),
        edges=(GraphEdge(source="product:p", target="repo:r", rel=GraphRelation.SHIPS),),
        stats=RepositoryGraphStats(
            nodes=2,
            edges=1,
            node_types={GraphNodeKind.PRODUCT: 1, GraphNodeKind.REPOSITORY: 1},
            edge_relations={GraphRelation.SHIPS: 1},
            repositories=1,
            repositories_with_findings=0,
            repos_without_findings=1,
            coverage_percent=0,
        ),
    )


def test_data_cannot_escape_into_executable_markup_and_only_renderer_script_is_authorized() -> None:
    graph = model()
    page = Page(
        RepositoryGraphRenderer()
        .render(graph, Report(title="Repo Graph", generated_at=graph.as_of))
        .decode()
    )
    assert not any(tag in ("img", "iframe", "object", "embed") for tag, _ in page.tags)
    assert len(page.scripts) == 2
    data = next(text for attrs, text in page.scripts if attrs.get("type") == "application/json")
    assert json.loads(data)["nodes"][0]["label"] == graph.nodes[0].label
    script = next(text for attrs, text in page.scripts if attrs.get("type") != "application/json")
    digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    csp = next(
        attrs["content"]
        for tag, attrs in page.tags
        if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy"
    )
    assert f"script-src 'sha256-{digest}'" in csp
    assert "default-src 'none'" in csp
    assert not any(attrs.get("src") for tag, attrs in page.tags if tag == "script")
    canvas = next(attrs for tag, attrs in page.tags if tag == "canvas")
    assert canvas["tabindex"] == "0"
    assert canvas["aria-describedby"] == "graph-help"


def test_gephi_and_graphviz_keep_relationship_identity_and_escape_external_labels() -> None:
    graph = model()
    renderer = RepositoryGraphRenderer()
    root = ElementTree.fromstring(renderer.gexf(graph))
    ns = {"g": "http://gexf.net/1.3"}
    nodes = root.findall("g:graph/g:nodes/g:node", ns)
    assert {node.attrib["id"]: node.attrib["label"] for node in nodes} == {
        node.id: node.label for node in graph.nodes
    }
    [edge] = root.findall("g:graph/g:edges/g:edge", ns)
    assert (edge.attrib["source"], edge.attrib["target"], edge.attrib["label"]) == (
        "product:p",
        "repo:r",
        "ships",
    )
    dot = renderer.graphviz(graph)
    assert json.dumps(graph.nodes[0].label) in dot
    assert '"product:p" -> "repo:r"' in dot
