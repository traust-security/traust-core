"""The x/crypto tracker: evidence tiers, the suggested Status table and the workbook columns
(ported from traust tests/test_build_xcrypto_tracker.py), then PqcService.xcrypto_tracker over a
checkout on SQLite and Postgres."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.providers.test_xcrypto import REPO, FakeCallgraph
from tests.v1.services.test_pqc import AT, URL, FakeScanner, World, engine  # noqa: F401
from tests.v1.services.test_pqc_rules import hit
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError, NotFoundError
from traust_core.v1.models.code_facts import (
    GO_CALLGRAPH,
    XcryptoEntrypoint,
    XcryptoImport,
    XcryptoModule,
    XcryptoReachable,
    XcryptoUsageFact,
)
from traust_core.v1.models.common import CodeSpan, ToolRequest
from traust_core.v1.models.pqc import PqcFact, XcryptoStatus, XcryptoTier, XcryptoTracker
from traust_core.v1.models.vocabulary import PqcPathClass
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.crypto import CryptoProbe
from traust_core.v1.providers.tools import ToolProvider
from traust_core.v1.providers.xcrypto import XcryptoUsage
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.code_facts import CodeFactsService
from traust_core.v1.services.pqc import PqcService, xcrypto
from traust_core.v1.services.pqc.facts import map_rule

XC = "golang.org/x/crypto"


def site(package: str, path: str, line: int) -> XcryptoImport:
    return XcryptoImport(package=f"{XC}/{package}", location=CodeSpan(path=path, line=line))


def fact(file: str, line: int, detail: str = "") -> PqcFact:
    return PqcFact(
        fact_id="F0001",
        rule_id="HP_EC_GO_ECDH_X25519",
        file=file,
        line=line,
        detail=detail,
        ir8547=map_rule("HP_EC_GO_ECDH_X25519"),
        provenance_hint="vendored",
        path_class=PqcPathClass.VENDOR,
    )


REPO_A = XcryptoUsageFact(
    imports=(
        site("openpgp", "cmd/main.go", 5),
        site("hkdf", "pkg/x_test.go", 3),
        site("ssh", "cmd/main.go", 6),  # the callgraph's evidence wins
        site("md4", "third_party/lib/lib.go", 3),  # vendored by the pqc path taxonomy
    ),
    modules=(XcryptoModule(path="go.mod", require=("v0.52.0",)),),
    callgraph=(
        XcryptoEntrypoint(
            entrypoint="cmd/app",
            package="example.com/app/cmd/app",
            reachable=(
                XcryptoReachable(
                    function=f"{XC}/ssh.Dial",
                    package=f"{XC}/ssh",
                    witness=("example.com/app/cmd/app.main", f"{XC}/ssh.Dial"),
                ),
            ),
        ),
        XcryptoEntrypoint(
            entrypoint="cmd/other",
            package="example.com/app/cmd/other",
            reachable=(XcryptoReachable(function=f"{XC}/ssh.NewClient", package=f"{XC}/ssh"),),
        ),
        XcryptoEntrypoint(entrypoint="cmd/broken", package="b", error="packages contain errors"),
    ),
)
VENDORED = [fact("vendor/golang.org/x/crypto/curve25519/c.go", 39, "Go ECDH/X25519 usage.")]


def unused() -> list[PqcFact]:
    raise AssertionError("recorded facts read although the checkout had evidence")


def test_tiers_status_and_columns() -> None:
    rows = xcrypto.tracker("https://github.com/org/repo-a", REPO_A, unused)
    by = {r.package: r for r in rows}
    assert list(by) == [f"{XC}/hkdf", f"{XC}/openpgp", f"{XC}/ssh"]
    ssh = by[f"{XC}/ssh"]
    assert (ssh.evidence_tier, ssh.entrypoint, ssh.functions) == (
        XcryptoTier.CALLGRAPH,
        "cmd/app",
        (f"{XC}/ssh.Dial", f"{XC}/ssh.NewClient"),
    )
    assert ssh.witness == ("example.com/app/cmd/app.main", f"{XC}/ssh.Dial")
    assert (by[f"{XC}/openpgp"].evidence_tier, by[f"{XC}/openpgp"].evidence) == (
        XcryptoTier.FIRST_PARTY_IMPORT,
        "cmd/main.go:5",
    )
    assert by[f"{XC}/hkdf"].evidence_tier is XcryptoTier.TEST_DOCS_IMPORT
    assert {r.product_org for r in rows} == {"org"}
    table = xcrypto.table(rows)
    assert table.columns == xcrypto.COLUMNS
    cells = {row[3].split(";")[0]: dict(zip(table.columns, row, strict=True)) for row in table.rows}
    assert cells[f"{XC}/ssh.Dial"] == {
        "product_org": "org",
        "repository": "https://github.com/org/repo-a",
        "entrypoint": "cmd/app",
        "crypto_module_used": f"{XC}/ssh.Dial; {XC}/ssh.NewClient",
        "status_suggested": "Unacceptable?",
        "comment": "callgraph: callgraph-reachable — contains classically-broken/"
        "upstream-deprecated primitives; go.mod: go.mod v0.52.0",
        "dependency_graph": f"example.com/app/cmd/app.main -> {XC}/ssh.Dial",
        "evidence_tier": "callgraph",
    }
    pgp = cells[f"{XC}/openpgp"]
    assert (pgp["entrypoint"], pgp["dependency_graph"]) == (
        "n/a — static scan",
        "not computed (no callgraph)",
    )
    assert pgp["comment"].startswith("first-party-import: cmd/main.go:5 — ")


def test_a_test_import_is_upgraded_by_a_first_party_one() -> None:
    usage = XcryptoUsageFact(imports=(site("hkdf", "x_test.go", 1), site("hkdf", "k/k.go", 9)))
    (row,) = xcrypto.tracker(URL, usage, unused)
    assert (row.evidence_tier, row.evidence) == (XcryptoTier.FIRST_PARTY_IMPORT, "k/k.go:9")


def test_a_reachable_function_without_a_witness_says_no_path() -> None:
    usage = XcryptoUsageFact(
        callgraph=(
            XcryptoEntrypoint(
                entrypoint=".",
                package="m",
                reachable=(XcryptoReachable(function=f"{XC}/ssh.Dial", package=f"{XC}/ssh"),),
            ),
        )
    )
    (row,) = xcrypto.table(xcrypto.tracker(URL, usage, unused)).rows
    assert row[6] == "no path"


def test_vendored_presence_only_without_checkout_evidence() -> None:
    (row,) = xcrypto.tracker("https://github.com/org/repo-b", XcryptoUsageFact(), lambda: VENDORED)
    assert (row.package, row.evidence_tier, row.status_suggested, row.product_org) == (
        f"{XC}/curve25519",
        XcryptoTier.DEPENDENCY_PRESENCE,
        XcryptoStatus.ACCEPTABLE,
        "org",
    )
    assert row.evidence == "vendor/golang.org/x/crypto/curve25519/c.go:39"
    # a go.mod require alone is evidence: no rows, and the recorded facts are not read
    required = XcryptoUsageFact(modules=(XcryptoModule(path="go.mod", require=("v0.1.0",)),))
    assert xcrypto.tracker(URL, required, unused) == []
    assert xcrypto.tracker(URL, XcryptoUsageFact(), list) == []


@pytest.mark.parametrize(
    ("package", "status"),
    [
        (f"{XC}/pkcs12", XcryptoStatus.UNACCEPTABLE),
        (f"{XC}/ssh/agent", XcryptoStatus.UNACCEPTABLE),
        (f"{XC}/nacl/box", XcryptoStatus.ACCEPTABLE),
        (f"{XC}/x509roots/fallback", XcryptoStatus.ACCEPTABLE),
        (f"{XC}/unknownpkg", XcryptoStatus.UNKNOWN),
        (f"{XC}/internal/poly1305", XcryptoStatus.UNKNOWN),
        (XC, XcryptoStatus.UNKNOWN),
    ],
)
def test_status_table(package: str, status: XcryptoStatus) -> None:
    assert xcrypto.status(package) is status


def service(world: World, tool: FakeCallgraph | None = None) -> PqcService:
    tools = ProviderRegistry[ToolProvider[Any]]("tool")
    if tool is not None:
        tools.register(GO_CALLGRAPH, lambda: tool)
    uow = SqlTraustUnitOfWork(world.engine)
    code_facts = CodeFactsService(
        AssessmentService(uow),
        world.publisher,
        (CryptoProbe(FixedClock(AT)), XcryptoUsage(FixedClock(AT), tools)),
        world.exposure,
    )
    return PqcService(
        uow, code_facts, world.portfolio, world.publisher, world.scanner, clock=FixedClock(AT)
    )


def packages(found: XcryptoTracker) -> dict[str, XcryptoTier]:
    return {r.package.removeprefix(f"{XC}/"): r.evidence_tier for r in found.rows}


def test_tracker_over_a_checkout_with_reachability(engine: Engine) -> None:  # noqa: F811
    world = World(engine, FakeScanner())
    ref = world.ref(sbom=None)
    pqc = service(world, FakeCallgraph())
    static = pqc.xcrypto_tracker(ref, ToolRequest(workspace=REPO))
    assert packages(static) == {
        "bcrypt": XcryptoTier.FIRST_PARTY_IMPORT,
        "hkdf": XcryptoTier.TEST_DOCS_IMPORT,
        "openpgp": XcryptoTier.TEST_DOCS_IMPORT,
        "ssh": XcryptoTier.FIRST_PARTY_IMPORT,
    }
    assert {r.repository for r in static.rows} == {URL}
    assert {r.modules for r in static.rows} == {("go.mod v0.43.0",)}
    header, *lines = static.csv.splitlines()
    assert header == ",".join(xcrypto.COLUMNS) and len(lines) == 4
    assert lines[0].startswith("acme,https://github.com/acme/widget,n/a — static scan,")
    reached = pqc.xcrypto_tracker(ref, ToolRequest(workspace=REPO, params={"callgraph": True}))
    tiers = packages(reached)
    assert tiers["ssh"] is tiers["bcrypt"] is tiers["blowfish"] is XcryptoTier.CALLGRAPH
    assert tiers["openpgp"] is XcryptoTier.TEST_DOCS_IMPORT


def test_tracker_falls_back_to_the_recorded_vendored_facts(engine: Engine, tmp_path) -> None:  # noqa: F811
    vendored = hit("HP_EC_GO_ECDH_X25519", "vendor/golang.org/x/crypto/curve25519/c.go", 39)
    world = World(engine, FakeScanner(hits=(vendored,)))
    ref = world.ref()
    pqc = service(world)
    (tmp_path / "main.py").write_text("print('no go')\n")
    assert pqc.xcrypto_tracker(ref, ToolRequest(workspace=tmp_path)).rows == ()
    pqc.prescan(ref, ToolRequest(workspace=tmp_path))
    (row,) = pqc.xcrypto_tracker(ref, ToolRequest(workspace=tmp_path)).rows
    assert (row.package, row.evidence_tier) == (f"{XC}/curve25519", XcryptoTier.DEPENDENCY_PRESENCE)


def test_tracker_of_an_unknown_commit(engine: Engine) -> None:  # noqa: F811
    with pytest.raises(NotFoundError):
        service(World(engine, FakeScanner())).xcrypto_tracker(uuid4(), ToolRequest(workspace=REPO))


def test_context_wires_the_enumerator_and_reads_the_callgraph_from_its_tools(tmp_path) -> None:
    ctx = Context(Config(home=tmp_path))
    code_facts = ctx.services().code_facts
    assert code_facts.xcrypto(ToolRequest(workspace=REPO)).callgraph is None
    asked = ToolRequest(workspace=REPO, params={"callgraph": True})
    with pytest.raises(ConfigError, match="unknown tool provider 'go-callgraph'"):
        code_facts.xcrypto(asked)
    ctx.tools.register(GO_CALLGRAPH, FakeCallgraph)
    assert code_facts.xcrypto(asked).callgraph
