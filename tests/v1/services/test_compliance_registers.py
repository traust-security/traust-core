"""ComplianceService posture, scopes, ADR and doc-variance doors, ported from traust (fabdb13)
tests/test_adr_index.py, test_emit_doc_variance.py, test_fetch_product_docs.py,
harnessing/threat-register (doc_variance_cut) and traust-engine compliance/dashboard.py."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any
from uuid import UUID

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.test_compliance import (
    ALICE,
    NIST,
    NOW,
    SOC2,
    UNVERIFIED,
    World,
    edited,
    provenance,
    recount,
    result,
    scope_doc,
)
from traust_core.v1.errors import ConfigError, ConflictError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import AdrRegistryArtifact, DocVarianceArtifact
from traust_core.v1.models.common import ArtifactRef, PageRequest
from traust_core.v1.models.compliance import (
    AdrStatus,
    ComplianceDimension,
    ComplianceFilter,
    DocVarianceFilter,
    ScopeFilter,
    doc_text,
    evidence_id,
    is_decision_record,
    parse_adr,
)
from traust_core.v1.models.vocabulary import DocVarianceDisposition, DocVarianceKind
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.collaboration import ProductDocument, RegisterFile
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.compliance import evidence_key

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed

REGISTRY_REF = ArtifactRef(id=UUID(int=1), name="adr-registry", digest="0" * 64)


class FakeAdrSource:
    name = "forge"

    def __init__(self, files: dict[str, dict[str, str]], ready: bool = True) -> None:
        self.files_by_repo, self.ready, self.reads = files, ready, 0

    def check(self) -> Readiness:
        return Readiness(ready=self.ready, detail="" if self.ready else "gh not authenticated")

    def files(self, repo: str, pin: str, paths: Sequence[str]) -> Result[list[RegisterFile]]:
        self.reads += 1
        found = [
            RegisterFile(path=p, text=t, url=f"{repo}/blob/{pin}/{p}")
            for p, t in self.files_by_repo[repo].items()
        ]
        return Result(found, Acquisition(provider=self.name, acquired_at=NOW))


class FakeDocs:
    name = "docs"

    def __init__(self, pages: list[ProductDocument], ready: bool = True) -> None:
        self.pages, self.ready = pages, ready

    def check(self) -> Readiness:
        return Readiness(ready=self.ready, detail="" if self.ready else "curl missing")

    def fetch(self, product_id: UUID) -> Result[list[ProductDocument]]:
        return Result(self.pages, Acquisition(provider=self.name, acquired_at=NOW))


ARCH = "https://github.com/org/architecture"
OTHER = "https://github.com/org/other-arch"
DECISIONS = {
    ARCH: {
        "decisions/0001-use-tls.md": "# Use TLS everywhere\n\nStatus: Accepted\n",
        "decisions/0002-old-crypto.md": "# Old crypto\n\n* Status: superseded by 0003\n",
        "decisions/README.md": "# Index\n",
        "decisions/archives/0000-legacy.md": "# Legacy\nStatus: accepted\n",
        "notes/0009-elsewhere.md": "# Not a register path\nStatus: accepted\n",
    },
    OTHER: {"adr/0001-x.md": "# X\nStatus: accepted\n"},
}


def registry(*registers: dict[str, Any]) -> AdrRegistryArtifact:
    return AdrRegistryArtifact.from_document({"version": 1, "registers": list(registers)})


def register(name: str, repo: str, paths: list[str], governs: list[str], **kw: Any) -> dict:
    return {"name": name, "repo": repo, "paths": paths, "pin": "a" * 40, "governs": governs, **kw}


@pytest.fixture
def world(uow: SqlTraustUnitOfWork, seed: Seed) -> World:
    return World(uow, seed)


@pytest.fixture
def adr_world(world: World) -> World:
    world.adr_source = FakeAdrSource(DECISIONS)  # type: ignore[attr-defined]
    world.service = world.compliance(adr_source=world.adr_source)  # type: ignore[attr-defined]
    world.publisher.publish_artifact(
        registry(
            register("arch", ARCH, ["decisions"], ["product:acme"]),
            register("other", OTHER, ["adr"], ["repo:org/elsewhere"]),
        )
    )
    return world


# posture and summary (dashboard)


def test_posture_reports_per_framework_coverage_unsatisfied_controls_and_caveats(
    world: World,
) -> None:
    world.publish_mapping()
    run = world.run(world.declared(), frameworks=(NIST, SOC2), trust_categories=("security",))
    recorded = world.service.record(run.document, provenance())
    posture = recorded.posture()
    doc = json.loads(run.document.payload)
    assert posture.coverage == doc["coverage"]
    assert posture.scope_id == recorded.scope_id and posture.assessed_at == NOW
    assert {r.control_id for r in posture.not_satisfied} == {
        r["control_id"] for r in doc["results"] if r["verdict"] == "not_satisfied"
    }
    assert set(posture.caveats) == {"soc2-tsc"} and posture.skipped == {}


def test_summary_counts_each_declared_pair_once_by_its_newest_assessment(world: World) -> None:
    world.publish_mapping()
    acme = world.declared()
    world.service.set_scope(
        scope_doc(
            "explicit",
            resolves_via="explicit",
            product=None,
            include=[{"repo": "org/c", "reason": "named"}],
            frameworks=["nist-800-53-rev5"],
        ),
        ALICE,
    )
    first = world.run(acme, frameworks=(NIST,))
    world.service.record(first.document, provenance())
    newest = world.run(acme, frameworks=(NIST,), environment="stage")
    world.service.record(newest.document, provenance())
    nist = json.loads(newest.document.payload)["coverage"]["nist-800-53-rev5"]

    by_framework = world.service.summary(ComplianceFilter(), ComplianceDimension.FRAMEWORK)
    assert [(r.key, r.pairs, r.assessed) for r in by_framework] == [
        ("nist-800-53-rev5", 2, 1),
        ("soc2-tsc", 1, 0),
    ]
    assert by_framework[0].coverage == {"nist-800-53-rev5": nist}
    by_scope = world.service.summary(ComplianceFilter(), ComplianceDimension.SCOPE)
    assert [(r.key, r.pairs, r.assessed) for r in by_scope] == [
        ("acme-cde", 2, 1),
        ("explicit", 1, 0),
    ]
    assert set(by_scope[0].coverage) == {"nist-800-53-rev5", "soc2-tsc"}
    only = world.service.summary(
        ComplianceFilter(scope_id=acme, framework=SOC2), ComplianceDimension.SCOPE
    )
    assert [(r.key, r.pairs, r.assessed) for r in only] == [("acme-cde", 1, 0)]


def test_scopes_lists_current_declarations_newest_first_filtered_and_paged(world: World) -> None:
    acme = world.declared()
    draft = world.service.set_scope(
        scope_doc("drafted", frameworks=["soc2-tsc"]), UNVERIFIED
    ).scope_id
    replaced = world.service.set_scope(
        scope_doc(exclude=[{"repo": "org/b", "reason": "moved"}]), ALICE, replace=True
    ).scope_id

    def ids(filter: ScopeFilter, limit: int = 10) -> list[UUID | None]:
        return [s.scope_id for s in world.service.scopes(filter, PageRequest(limit=limit)).items]

    assert ids(ScopeFilter()) == [replaced, draft]
    assert acme not in ids(ScopeFilter())
    assert ids(ScopeFilter(draft=True)) == [draft]
    assert ids(ScopeFilter(framework=NIST)) == [replaced]
    assert ids(ScopeFilter(product="nope")) == []
    first = world.service.scopes(ScopeFilter(), PageRequest(limit=1))
    assert first.next is not None
    rest = world.service.scopes(ScopeFilter(), PageRequest(limit=1, cursor=first.next))
    assert [s.scope_id for s in (*first.items, *rest.items)] == [replaced, draft]
    assert rest.next is None


# ADRs


@pytest.mark.parametrize(
    ("path", "text", "declared", "status"),
    [
        ("d/0001-a.md", "# Alpha\nStatus: Accepted\n", None, "accepted"),
        ("d/0001-a.md", "# Alpha\n- **Status:** approved\n", None, "accepted"),
        ("d/0001-a.md", "# Alpha\nstatus: draft\n", None, "proposed"),
        ("d/0001-a.md", "# Alpha\n## Status\n\nSuperseded by 0004\n", None, "superseded"),
        ("d/0001-a.md", "# Alpha\nno status line\n", None, "unknown"),
        ("d/archives/0001-a.md", "# Alpha\nStatus: accepted\n", None, "archived"),
        ("d/0001-a.md", "# Alpha\nno status line\n", "proposed", "proposed"),
    ],
)
def test_parse_adr_reads_status_without_guessing(
    path: str, text: str, declared: str | None, status: str
) -> None:
    reg = {"name": "r", **({"declared_status": declared} if declared else {})}
    adr = parse_adr(reg, path, text, "u", REGISTRY_REF)
    assert (adr.status, adr.declared, adr.key, adr.title) == (
        status,
        bool(declared),
        "r/0001-a",
        "Alpha",
    )


@pytest.mark.parametrize(
    ("path", "kept"),
    [
        ("decisions/0001-a.md", True),
        ("decisions/sub/0001-a.adoc", True),
        ("decisions/template.md", False),
        ("decisions/README.md", False),
        ("decisions/0001-a.txt", False),
        ("decisionsx/0001-a.md", False),
    ],
)
def test_only_records_under_the_register_paths_are_decisions(path: str, kept: bool) -> None:
    assert is_decision_record(path, ["decisions/"]) is kept


def test_adrs_are_the_decisions_of_registers_governing_the_product(adr_world: World) -> None:
    assert adr_world.product.id is not None
    adrs = adr_world.service.adrs(adr_world.product.id)
    assert [(a.key, a.status) for a in adrs] == [
        ("arch/0001-use-tls", AdrStatus.ACCEPTED),
        ("arch/0002-old-crypto", AdrStatus.SUPERSEDED),
        ("arch/0000-legacy", AdrStatus.ARCHIVED),
    ]
    assert adrs[0].url == f"{ARCH}/blob/{'a' * 40}/decisions/0001-use-tls.md"
    assert adrs[0].artifact.name == "adr-registry"


def test_a_register_governing_a_shipped_repo_counts_for_the_product(world: World) -> None:
    service = world.compliance(adr_source=FakeAdrSource(DECISIONS))
    world.publisher.publish_artifact(
        registry(
            register("arch", ARCH, ["decisions"], ["product:other"]),
            register("other", OTHER, ["adr"], ["repo:org/a"]),
        )
    )
    assert world.product.id is not None
    assert [a.key for a in service.adrs(world.product.id)] == ["other/0001-x"]


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        ("no_registry", "no adr-registry published"),
        ("no_source", "NEED\\(engine\\)"),
        ("not_ready", "not ready: gh not authenticated"),
    ],
)
def test_adrs_need_a_registry_and_a_ready_source(world: World, setup: str, message: str) -> None:
    if setup != "no_registry":
        world.publisher.publish_artifact(
            registry(register("arch", ARCH, ["decisions"], ["product:acme"]))
        )
    if setup == "not_ready":
        world.service = world.compliance(adr_source=FakeAdrSource(DECISIONS, ready=False))
    assert world.product.id is not None
    with pytest.raises(ConfigError, match=message):
        world.service.adrs(world.product.id)


def citing(run: Any, store: Any, *keys: str) -> Any:
    """sc-8 satisfied by an agreed agent verdict citing the ADRs, each a bundle item."""

    def edit(doc: dict[str, Any]) -> None:
        evidence = []
        for key in keys:
            value = {"adr": key}
            store.put(evidence_key(evidence_id(value)), json.dumps(value).encode())
            evidence.append(
                {"sha256": evidence_id(value), "kind": "human_artifact", "locator": f"adr:{key}"}
            )
        sc8 = result(doc, "sc-8")
        sc8.update(
            verdict="satisfied",
            verdict_source="agent",
            evidence=evidence,
            n_pass_agreement={"passes": 2, "agreed": True},
        )
        sc8.pop("reason")
        doc["coverage"] = recount(doc)

    return edited(run, edit)


@pytest.mark.parametrize(
    ("keys", "messages"),
    [
        (("arch/0001-use-tls",), []),
        (("arch/0002-old-crypto",), ["cites superseded decision 'arch/0002-old-crypto'"]),
        (("arch/0000-legacy",), ["cites archived decision"]),
        (("arch/0404-missing",), ["cites unknown decision 'arch/0404-missing'"]),
        (("nowhere/0001-x",), ["cites unknown decision 'nowhere/0001-x'"]),
    ],
)
def test_the_gate_refuses_a_satisfied_verdict_citing_a_non_citable_adr(
    adr_world: World, keys: tuple[str, ...], messages: list[str]
) -> None:
    adr_world.publish_mapping()
    run = adr_world.run(adr_world.declared(), frameworks=(NIST,))
    violations = adr_world.service.check(citing(run, adr_world.store, *keys)).violations
    assert len(violations) == len(messages)
    for v, m in zip(violations, messages, strict=True):
        assert v.rule == "compliance.adr" and m in v.message and "sc-8" in v.item


def test_the_gate_reads_registers_only_when_a_verdict_cites_an_adr(world: World) -> None:
    world.publish_mapping()
    run = world.run(world.declared(), frameworks=(NIST,))
    assert world.service.check(run.document).passed
    with pytest.raises(ConfigError, match="no adr-registry published"):
        world.service.check(citing(run, world.store, "arch/0001-use-tls"))


# doc variance


def variance(rid: str = "dv-tls", **kw: Any) -> dict[str, Any]:
    return {
        "id": rid,
        "source": {
            "product_slug": "acme-docs",
            "version": "4.22",
            "url": "https://docs.redhat.com/en/documentation/acme/4.22/html/security/x",
            "quote": "All traffic is encrypted.",
        },
        "claim": "all traffic is encrypted",
        "code_evidence": [{"repo": "org/c", "path": "server.go", "lines": "10-12"}],
        "variance": "overclaim",
        "verified_at": "2026-10-01T00:00:00Z",
        "disposition": "open",
        **kw,
    }


def register_doc(*records: dict[str, Any], repo: str = "https://github.com/org/c") -> Any:
    return DocVarianceArtifact.from_document(
        {
            "metadata": {
                "repository": repo,
                "created": "2026-10-01T00:00:00Z",
                "harness_version": "9.9.9",
            },
            "records": list(records),
        }
    )


def variance_runs(world: World) -> list[Any]:
    return [
        a
        for a in world.uow.assessments.list_for_refs([world.c.id], "compliance")  # type: ignore[list-item]
        if a.assessor == "doc-variance"
    ]


def test_record_appends_doc_variance_records_to_the_repository_register(world: World) -> None:
    first = world.service.record(register_doc(variance()), provenance())
    assert [(v.record, v.kind, v.disposition, v.repository_id) for v in first] == [
        ("dv-tls", "overclaim", "open", world.c.repository_id)
    ]
    assert len(variance_runs(world)) == 1
    assert world.service.record(register_doc(variance()), provenance()) == first
    assert len(variance_runs(world)) == 1
    both = world.service.record(register_doc(variance("dv-fips")), provenance())
    assert [v.record for v in both] == ["dv-tls", "dv-fips"]
    assert len(variance_runs(world)) == 2


def test_a_changed_record_supersedes_only_with_update(world: World) -> None:
    world.service.record(register_doc(variance()), provenance())
    corrected = variance(disposition="doc_corrected")
    with pytest.raises(ConflictError, match="dv-tls exists with different content"):
        world.service.record(register_doc(corrected), provenance())
    updated = world.service.record(register_doc(corrected), provenance(), update=True)
    assert [(v.record, v.disposition) for v in updated] == [
        ("dv-tls", "superseded"),
        ("dv-tls-r1", "doc_corrected"),
    ]


@pytest.mark.parametrize(
    ("doc", "error", "message"),
    [
        (
            lambda: register_doc(variance(), repo="https://github.com/org/zzz"),
            NotFoundError,
            "not in the inventory",
        ),
        (lambda: register_doc(), ValidationError, "nothing to record is an error"),
    ],
)
def test_record_refuses_an_unknown_repository_or_an_empty_register(
    world: World, doc: Any, error: type[Exception], message: str
) -> None:
    with pytest.raises(error, match=message):
        world.service.record(doc(), provenance())


def test_record_refuses_a_repository_without_an_observed_default_branch_head(world: World) -> None:
    with pytest.raises(NotFoundError, match="no observed default-branch head"):
        world.service.record(
            register_doc(variance(), repo="https://github.com/org/a"), provenance()
        )


def test_doc_variances_lists_current_records_oldest_verified_first(world: World) -> None:
    world.service.record(
        register_doc(
            variance("dv-new", verified_at="2026-10-03T00:00:00Z"),
            variance("dv-old", verified_at="2026-10-01T00:00:00Z", variance="stale"),
            variance("dv-done", verified_at="2026-10-02T00:00:00Z", disposition="accepted"),
        ),
        provenance(),
    )

    def records(filter: DocVarianceFilter, limit: int = 10) -> list[str]:
        return [
            v.record for v in world.service.doc_variances(filter, PageRequest(limit=limit)).items
        ]

    assert records(DocVarianceFilter()) == ["dv-old", "dv-done", "dv-new"]
    assert records(DocVarianceFilter(disposition=DocVarianceDisposition("open"))) == [
        "dv-old",
        "dv-new",
    ]
    assert records(DocVarianceFilter(kind=DocVarianceKind("stale"))) == ["dv-old"]
    assert records(DocVarianceFilter(repository_id=world.a.repository_id)) == []
    assert records(DocVarianceFilter(repository_id=world.c.repository_id, product_slug="x")) == []
    page = world.service.doc_variances(DocVarianceFilter(), PageRequest(limit=2))
    rest = world.service.doc_variances(DocVarianceFilter(), PageRequest(limit=2, cursor=page.next))
    assert [v.record for v in (*page.items, *rest.items)] == ["dv-old", "dv-done", "dv-new"]
    assert rest.next is None


# product docs


PAGE = (
    '<html><nav>menu</nav><body><h1 id="top">Security guide</h1><p>Intro &amp; scope</p>'
    '<h2><a href="#tls">TLS</a>Copy link</h2><p>All   traffic is encrypted.</p>'
    "<script>x()</script><h3>No anchor</h3><p>tail</p></body></html>"
)
URL = "https://docs.redhat.com/en/documentation/acme/4.22/html-single/security/index"


def test_doc_text_keeps_section_anchors_and_drops_chrome() -> None:
    assert doc_text(PAGE, URL) == (
        f"## Security guide [{URL}#top]\nIntro & scope\n\n"
        f"## TLS [{URL}#tls]\nAll traffic is encrypted.\n\n"
        f"## No anchor [{URL}]\ntail"
    )


def page(url: str = URL) -> ProductDocument:
    return ProductDocument(
        product_slug="acme", version="4.22", guide="security", url=url, html=PAGE
    )


def test_collect_product_docs_structures_official_guides(world: World) -> None:
    service = world.compliance(docs=FakeDocs([page()]))
    assert world.product.id is not None
    (guide,) = service.collect_product_docs(world.product.id)
    assert (guide.guide, guide.url, guide.version) == ("security", URL, "4.22")
    assert guide.text.startswith("## Security guide")


@pytest.mark.parametrize(
    ("docs", "error", "message"),
    [
        (None, ConfigError, "NEED\\(engine\\)"),
        (FakeDocs([], ready=False), ConfigError, "not ready: curl missing"),
        (FakeDocs([]), NotFoundError, "found no guides"),
        (FakeDocs([page("https://example.com/notes")]), ValidationError, "variance source"),
    ],
)
def test_collect_product_docs_refuses_without_official_guides(
    world: World, docs: FakeDocs | None, error: type[Exception], message: str
) -> None:
    assert world.product.id is not None
    with pytest.raises(error, match=message):
        world.compliance(docs=docs).collect_product_docs(world.product.id)
