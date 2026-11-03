from __future__ import annotations

import json
from pathlib import Path
from xml.etree import ElementTree

from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.test_insight import context as context
from tests.v1.services.test_insight import engine as engine
from traust_core.v1.context import Context
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.repository_graph import GraphNodeKind, GraphRelation, RepositoryGraph
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def test_graph_is_published_from_native_relations_and_declared_inventory(
    context: Context,
    engine: Engine,
    tmp_path: Path,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        shared = seed.repository(url="https://github.com/example/shared")
        idle = seed.repository(url="https://github.com/example/idle")
        ref = seed.repository_ref(shared, is_default=True)
        first, second = seed.product(slug="first"), seed.product(slug="second")
        for product in (first, second):
            seed.component(seed.release(product, version="1.0"), ref)
        team = seed.team(name="Platform")
        seed.ownership(shared, team)
        audit = seed.assessment(ref)
        artifact = seed.artifact(audit, uri="https://reports.example/shared/report.json")
        seed.occurrence(seed.finding(shared), audit, severity="critical")
        uow.commit()
    inputs = tmp_path / "inputs"
    (inputs / "catalog" / "operator" / "1.0").mkdir(parents=True)
    (inputs / "inventory.yaml").write_text("segments:\n  catalog: {kind: catalog}\n")
    (inputs / "catalog" / "operator" / "1.0" / "bundle-payload-repos.csv").write_text(
        "GitHub URL,Category,Source Branch\n"
        "https://github.com/example/shared,network,release-1.0\n"
        "https://github.com/example/unregistered,network,release-1.0\n"
    )
    context.register_input_segments(inputs)
    insight = context.services().insight
    published = insight.publish(ViewName.REPOSITORY_GRAPH, ViewFilter())
    graph = published.model
    assert isinstance(graph, RepositoryGraph)
    repositories = [n for n in graph.nodes if n.type is GraphNodeKind.REPOSITORY]
    assert {n.attrs.url for n in repositories} == {
        shared.url,
        idle.url,
        "https://github.com/example/unregistered",
    }
    assert published.gexf is not None and published.graphviz is not None
    shared_node = next(n for n in repositories if n.attrs.repository_id == shared.id)
    assert shared_node.attrs.open_findings == 1
    assert shared_node.attrs.max_severity == "critical"
    assert shared_node.attrs.findings_dirs == (artifact.uri,)
    assert (graph.stats.repositories, graph.stats.repositories_with_findings) == (3, 1)
    assert graph.stats.coverage_percent == 33.33
    assert {GraphNodeKind.SEGMENT, GraphNodeKind.PRODUCT_VERSION, GraphNodeKind.CATEGORY} <= {
        n.type for n in graph.nodes
    }
    node_ids = {n.id for n in graph.nodes}
    assert all(e.source in node_ids and e.target in node_ids for e in graph.edges)
    assert (
        sum(e.rel is GraphRelation.SHIPS and e.target == shared_node.id for e in graph.edges) == 3
    )
    branch_node = next(
        n for n in graph.nodes if n.attrs.branch == "release-1.0" and "shared" in n.id
    )
    assert any(
        e.source == shared_node.id and e.target == branch_node.id and e.rel is GraphRelation.HAS_REF
        for e in graph.edges
    )
    assert any(e.target == branch_node.id and e.rel is GraphRelation.SHIPS_REF for e in graph.edges)
    assert graph.stats.top_hubs[0].repository_id == shared.id
    exported = json.loads(graph.model_dump_json(by_alias=True))
    assert set(exported["edges"][0]) == {"from", "to", "rel", "attrs"}
    namespace = {"g": "http://gexf.net/1.3"}
    gephi = ElementTree.fromstring(published.gexf)
    assert {n.attrib["id"] for n in gephi.findall("g:graph/g:nodes/g:node", namespace)} == node_ids
    assert len(gephi.findall("g:graph/g:edges/g:edge", namespace)) == len(graph.edges)
    rendered = tmp_path / "rendered"
    rendered.mkdir()
    (rendered / "repo-graph.html").write_text(published.html)
    (rendered / "repo-graph.json").write_text(graph.model_dump_json(by_alias=True))
    (rendered / "repo-graph.dot").write_text(published.graphviz)
    (rendered / "repo-graph.gexf").write_text(published.gexf)
    (rendered / "repo-graph-stats.md").write_text(published.markdown)

    scoped = insight.build(ViewName.REPOSITORY_GRAPH, ViewFilter(product_ids=(first.id,)))
    assert isinstance(scoped, RepositoryGraph)
    assert {n.attrs.repository_id for n in scoped.nodes if n.type is GraphNodeKind.REPOSITORY} == {
        shared.id
    }


def test_branch_ref_layer_does_not_inflate_repository_hubs(
    context: Context,
    engine: Engine,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        ref = seed.repository_ref(repo, is_default=True)
        product = seed.product()
        seed.component(seed.release(product), ref)
        uow.commit()
    insight = context.services().insight
    before = insight.build(ViewName.REPOSITORY_GRAPH, ViewFilter())
    with SqlTraustUnitOfWork(engine) as uow:
        Seed(uow).repository_ref(repo, sha="b" * 40, name="release-1.0")
        uow.commit()
    after = insight.build(ViewName.REPOSITORY_GRAPH, ViewFilter())
    assert isinstance(before, RepositoryGraph) and isinstance(after, RepositoryGraph)
    assert after.stats.top_hubs == before.stats.top_hubs
    assert (
        after.stats.node_types[GraphNodeKind.REF] == before.stats.node_types[GraphNodeKind.REF] + 1
    )
    assert after.stats.edges == before.stats.edges + 1


def test_tool_observation_is_not_assessment_coverage(
    context: Context,
    engine: Engine,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref(is_default=True)
        observed = seed.assessment(ref, kind="tool_scan")
        seed.artifact(observed, kind="code-facts")
        uow.commit()
    model = context.services().insight.build(ViewName.REPOSITORY_GRAPH, ViewFilter())
    assert isinstance(model, RepositoryGraph)
    assert model.stats.repositories_with_findings == 0
    assert model.stats.repos_without_findings == 1
    assert model.stats.coverage_percent == 0.0
    assert not any(n.type is GraphNodeKind.FINDINGS for n in model.nodes)
