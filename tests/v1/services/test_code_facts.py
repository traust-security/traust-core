from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    ServiceError,
    ValidationError,
)
from traust_core.v1.models.artifacts import CodeFactsArtifact
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.models.code_facts import (
    CodeFactDetail,
    CodeFactKind,
    ConfigFact,
    CryptoFact,
    CryptoProbeId,
    ForkLagFact,
    ForkUpstream,
    LanguageStats,
    RouteGuardFact,
    SanitizerFact,
    SymbolFact,
    SymbolQuery,
)
from traust_core.v1.models.common import ArtifactRef, CodeSpan, Cursor, PageRequest, Provenance
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    AdvisoryRecord,
    PackageAdvisories,
    Version,
)
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.vocabulary import Ecosystem, SourceType
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.route_guards import RouteGuardMatrix
from traust_core.v1.providers.tools import ToolRequest
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects.store import ObjectKey
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpec, PublishSpecs
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.code_facts import CodeFactsService

engine = table_fixtures.engine
FIXTURE = Path(__file__).parents[2] / "fixtures/code_facts/producer-output.json"
KINDS = [CodeFactKind.SYMBOL, CodeFactKind.LANGUAGES]


def document(**overrides: object) -> CodeFactsArtifact:
    recorded = json.loads(FIXTURE.read_bytes())
    return CodeFactsArtifact.from_document(
        {
            "artifact": "code-facts",
            "symbols": [
                dict(zip(("name", "path", "line", "kind", "language"), symbol, strict=True))
                for symbol in recorded["symbols"]
            ],
            "languages": [
                {
                    "name": row["Name"],
                    "files": row["Count"],
                    "code": row["Code"],
                    "comments": row["Comment"],
                    "blanks": row["Blank"],
                }
                for row in recorded["scc"]
            ],
            **overrides,
        }
    )


@dataclass
class Facts:
    uow: SqlTraustUnitOfWork
    store: InMemoryObjectStore
    publisher: ArtifactPublisher
    assessments: AssessmentService
    service: CodeFactsService
    ref_id: UUID

    def record(
        self, doc: CodeFactsArtifact | None = None, *, at: datetime = T0, ref_id: UUID | None = None
    ) -> Assessment:
        artifact = doc if doc is not None else document()
        published = self.publisher.publish_artifact(artifact)
        return self.assessments.record(
            artifact,
            ref_id or self.ref_id,
            AssessmentKind.TOOL_SCAN,
            "tool:recorded-fixture",
            "1",
            Provenance(
                run_id=uuid4(),
                source=SourceType.INTERACTIVE,
                occurred_at=at,
                artifact=ArtifactRef(
                    id=published.artifact_id, name="code-facts", digest=sha256_hex(artifact.payload)
                ),
            ),
        )


@pytest.fixture
def facts(engine: sa.Engine) -> Facts:
    unit, store = SqlTraustUnitOfWork(engine), InMemoryObjectStore()
    with unit:
        ref = Seed(unit).repository_ref()
        unit.commit()
    assert ref.id is not None
    publisher = ArtifactPublisher(PublishSpecs(PublishSpec(CodeFactsArtifact)), store, unit)
    assessments = AssessmentService(unit)
    return Facts(
        unit, store, publisher, assessments, CodeFactsService(assessments, publisher), ref.id
    )


def test_recorded_producers_flow_through_publish_record_and_all_read_doors(facts: Facts) -> None:
    assessment = facts.record()
    result = facts.service.collect(facts.ref_id, KINDS)
    assert result.assessment_id == assessment.id
    assert result.repository_ref_id == facts.ref_id
    assert len(result.facts) == 4
    assert [symbol.name for symbol in facts.service.symbols(facts.ref_id, SymbolQuery())] == [
        "Handle",
        "Parse",
        "handle",
    ]
    stats = facts.service.language_stats(facts.ref_id)
    assert [
        (row.name, row.files, row.code, row.comments, row.blanks) for row in stats.languages
    ] == [
        ("Go", 1, 7, 1, 2),
        ("Python", 1, 2, 0, 0),
    ]
    with facts.uow as unit:
        assert unit.artifacts.get(result.artifact_id).assessment_id == assessment.id
    page = facts.service.list(facts.ref_id, KINDS, PageRequest())
    assert page.items == result.facts and page.next is None


def test_latest_uses_occurred_at_and_is_scoped_to_ref_and_kind(facts: Facts) -> None:
    newest = facts.record(at=T0 + timedelta(days=2))
    facts.record(document(symbols=[]), at=T0)
    with facts.uow as unit:
        seed = Seed(unit)
        ref = unit.repository_refs.get(facts.ref_id)
        other_ref = seed.repository_ref(unit.repositories.get(ref.repository_id), name="release")
        seed.assessment(ref, kind="secure-code", occurred_at=T0 + timedelta(days=4))
        unit.commit()
    facts.record(document(symbols=[]), at=T0 + timedelta(days=3), ref_id=other_ref.id)
    assert facts.service.collect(facts.ref_id, KINDS).assessment_id == newest.id


def test_no_scan_is_not_a_clean_empty_result(facts: Facts) -> None:
    with pytest.raises(NotFoundError, match="no tool_scan"):
        facts.service.collect(facts.ref_id, KINDS)


@pytest.mark.parametrize("status", ["degraded", "failed", "skipped"])
def test_unusable_latest_scan_never_falls_back_to_older_evidence(facts: Facts, status: str) -> None:
    facts.record()
    with facts.uow as unit:
        Seed(unit).assessment(
            unit.repository_refs.get(facts.ref_id),
            kind="tool_scan",
            status=status,
            occurred_at=T0 + timedelta(days=1),
        )
        unit.commit()
    with pytest.raises(ValidationError, match=status):
        facts.service.collect(facts.ref_id, KINDS)


def test_latest_scan_without_code_facts_does_not_reuse_an_older_document(facts: Facts) -> None:
    facts.record()
    with facts.uow as unit:
        scan = Seed(unit).assessment(
            unit.repository_refs.get(facts.ref_id),
            kind="tool_scan",
            occurred_at=T0 + timedelta(days=1),
        )
        Seed(unit).artifact(scan, kind="other")
        unit.commit()
    with pytest.raises(NotFoundError, match="no code-facts artifact"):
        facts.service.collect(facts.ref_id, KINDS)


def test_multiple_candidate_documents_are_ambiguous(facts: Facts) -> None:
    scan = facts.record()
    with facts.uow as unit:
        Seed(unit).artifact(scan, kind="code-facts", digest="another-digest")
        unit.commit()
    with pytest.raises(IntegrityError, match="multiple code-facts"):
        facts.service.collect(facts.ref_id, KINDS)


def test_empty_symbols_are_measured_but_null_languages_are_not(facts: Facts) -> None:
    facts.record(document(symbols=[], languages=None))
    assert facts.service.symbols(facts.ref_id, SymbolQuery()) == []
    assert facts.service.list(facts.ref_id, [CodeFactKind.SYMBOL], PageRequest()).items == ()
    with pytest.raises(NotFoundError, match="languages were not measured"):
        facts.service.language_stats(facts.ref_id)


def test_empty_languages_are_measured_but_null_symbols_are_not(facts: Facts) -> None:
    facts.record(document(symbols=None, languages=[]))
    assert facts.service.language_stats(facts.ref_id) == LanguageStats(languages=())
    with pytest.raises(NotFoundError, match="symbols were not measured"):
        facts.service.symbols(facts.ref_id, SymbolQuery())


def test_unknown_counters_remain_null_instead_of_zero(facts: Facts) -> None:
    facts.record(
        document(
            languages=[{"name": "Go", "code": 7, "files": None, "comments": None, "blanks": None}]
        )
    )
    [language] = facts.service.language_stats(facts.ref_id).languages
    assert language.code == 7
    assert (language.files, language.comments, language.blanks) == (None, None, None)


def test_duplicate_language_totals_are_not_silently_summed(facts: Facts) -> None:
    row = {"name": "Go", "code": 7, "files": 1, "comments": 1, "blanks": 2}
    facts.record(document(languages=[row, row]))
    with pytest.raises(IntegrityError, match="duplicate language"):
        facts.service.language_stats(facts.ref_id)


def test_unsupported_fact_kinds_are_explicit(facts: Facts) -> None:
    with pytest.raises(ValidationError, match="unsupported code fact kinds: crypto"):
        facts.service.collect(facts.ref_id, [CodeFactKind.CRYPTO])


def test_symbols_match_exact_name_and_path_with_a_limit(facts: Facts) -> None:
    facts.record()
    found = facts.service.symbols(facts.ref_id, SymbolQuery(name="Handle", path="app.go"))
    assert len(found) == 1 and found[0].location.line == 4
    assert facts.service.symbols(facts.ref_id, SymbolQuery(name="Hand")) == []
    assert facts.service.symbols(facts.ref_id, SymbolQuery(name="Handle", path="helper.py")) == []
    assert len(facts.service.symbols(facts.ref_id, SymbolQuery(limit=1))) == 1


def test_pages_have_no_duplicates_and_accept_reordered_deduplicated_kinds(facts: Facts) -> None:
    facts.record()
    first = facts.service.list(facts.ref_id, KINDS, PageRequest(limit=2))
    assert len(first.items) == 2 and first.next is not None
    second = facts.service.list(
        facts.ref_id,
        [*reversed(KINDS), CodeFactKind.SYMBOL],
        PageRequest(limit=2, cursor=first.next),
    )
    assert first.items + second.items == facts.service.collect(facts.ref_id, KINDS).facts
    assert second.next is None
    assert facts.service.list(facts.ref_id, [], PageRequest()).items == ()


@pytest.mark.parametrize("limit", [0, -1, 1001])
def test_page_limits_are_bounded(facts: Facts, limit: int) -> None:
    with pytest.raises(ValidationError, match="page limit"):
        facts.service.list(facts.ref_id, KINDS, PageRequest(limit=limit))


@pytest.mark.parametrize("cursor", ["not-json", "{}", '{"offset": -1}'])
def test_malformed_cursors_are_rejected(facts: Facts, cursor: str) -> None:
    facts.record()
    with pytest.raises(ValidationError, match="malformed code-facts cursor"):
        facts.service.list(facts.ref_id, KINDS, PageRequest(cursor=Cursor(cursor)))


def test_cursor_cannot_escape_its_snapshot_or_filter(facts: Facts) -> None:
    facts.record()
    page = facts.service.list(facts.ref_id, KINDS, PageRequest(limit=1))
    with pytest.raises(ConflictError, match="different snapshot or filter"):
        facts.service.list(facts.ref_id, [CodeFactKind.SYMBOL], PageRequest(cursor=page.next))
    facts.record(at=T0 + timedelta(days=1))
    with pytest.raises(ConflictError, match="different snapshot or filter"):
        facts.service.list(facts.ref_id, KINDS, PageRequest(cursor=page.next))


def test_cursor_cannot_point_past_the_snapshot(facts: Facts) -> None:
    facts.record()
    page = facts.service.list(facts.ref_id, KINDS, PageRequest(limit=1))
    cursor = json.loads(page.next)
    cursor["offset"] = 100
    with pytest.raises(ValidationError, match="beyond the snapshot"):
        facts.service.list(facts.ref_id, KINDS, PageRequest(cursor=Cursor(json.dumps(cursor))))


def test_repeated_reads_do_not_write_and_use_a_fixed_number_of_queries(
    facts: Facts, engine: sa.Engine
) -> None:
    facts.record()
    statements: list[str] = []

    def capture(
        _conn: object,
        _cursor: object,
        statement: str,
        _params: object,
        _context: object,
        _many: object,
    ) -> None:
        statements.append(statement)

    keys = list(facts.store.list())
    sa.event.listen(engine, "before_cursor_execute", capture)
    try:
        first = facts.service.collect(facts.ref_id, KINDS)
        again = facts.service.collect(facts.ref_id, KINDS)
    finally:
        sa.event.remove(engine, "before_cursor_execute", capture)
    assert first == again
    assert len(statements) == 6
    assert all(statement.lstrip().upper().startswith("SELECT") for statement in statements)
    assert list(facts.store.list()) == keys


def test_tampered_fact_documents_are_not_consumed(facts: Facts) -> None:
    facts.record()
    result = facts.service.collect(facts.ref_id, KINDS)
    with facts.uow as unit:
        artifact = unit.artifacts.get(result.artifact_id)
    facts.store.put(ObjectKey.parse(artifact.uri), b"{}")
    with pytest.raises(IntegrityError):
        facts.service.collect(facts.ref_id, KINDS)


def test_context_exposes_the_same_code_facts_service(tmp_path: Path) -> None:
    context = Context(Config(home=tmp_path), object_store=InMemoryObjectStore())
    services = context.services()
    with context.unit_of_work(SqlTraustUnitOfWork) as unit:
        ref = Seed(unit).repository_ref()
        unit.commit()
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(CodeFactsArtifact)))
    harness = Facts(
        context.unit_of_work(SqlTraustUnitOfWork),
        context.object_store,
        publisher,
        services.assessment,
        services.code_facts,
        ref.id,
    )
    harness.record()
    assert services.code_facts.language_stats(ref.id).languages[0].code == 7


CRYPTO_REPO = Path(__file__).parents[2] / "fixtures/code_facts/crypto/repo"


class Unready:
    kind = CodeFactKind.CRYPTO

    def check(self) -> Readiness:
        return Readiness(ready=False, detail="probe binary missing")

    def enumerate(self, request: ToolRequest) -> Result[list[CodeFactDetail]]:
        raise AssertionError("an unready enumerator never runs")


def test_context_enumerates_crypto_facts_without_recording_them(tmp_path: Path) -> None:
    context = Context(Config(home=tmp_path), object_store=InMemoryObjectStore())
    facts = context.services().code_facts.enumerate(
        CodeFactKind.CRYPTO, ToolRequest(workspace=CRYPTO_REPO)
    )
    assert {f.probe_id for f in facts if isinstance(f, CryptoFact)} >= {
        CryptoProbeId.GO_TOOLCHAIN,
        CryptoProbeId.GO_FIPS_BACKEND,
        CryptoProbeId.BASE_IMAGE,
    }
    assert list(context.object_store.list()) == []


def test_a_kind_without_an_enumerator_is_refused(facts: Facts) -> None:
    with pytest.raises(ValidationError, match="no enumerator"):
        facts.service.enumerate(CodeFactKind.CRYPTO, ToolRequest(workspace=CRYPTO_REPO))


def test_an_unready_enumerator_is_a_config_error(facts: Facts) -> None:
    service = CodeFactsService(facts.assessments, facts.publisher, [Unready()])
    with pytest.raises(ConfigError, match="probe binary missing"):
        service.enumerate(CodeFactKind.CRYPTO, ToolRequest(workspace=CRYPTO_REPO))


ROUTES = """package api
func routes(mux *http.ServeMux) {
\tmux.HandleFunc("/jobs", requireAuth(handleJobs))
\tmux.HandleFunc("/callback", handleCallback)
}
"""


class Fixed:
    """An enumerator answering `kind` with fixed facts."""

    def __init__(self, kind: CodeFactKind, *facts: CodeFactDetail) -> None:
        self.kind, self._facts = kind, list(facts)

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def enumerate(self, request: ToolRequest) -> Result[list[CodeFactDetail]]:
        return Result(self._facts, Acquisition(provider="fixed", acquired_at=T0))


class Advisories:
    """The exposure service's package read: fixed answers, a ServiceError for `fail`."""

    def __init__(self, fail: frozenset[str] = frozenset()) -> None:
        self.asked: list[tuple[Ecosystem, str, str]] = []
        self._fail = fail

    def package_advisories(
        self, ecosystem: Ecosystem, name: str, version: str
    ) -> PackageAdvisories:
        self.asked.append((ecosystem, name, version))
        if name in self._fail:
            raise ServiceError("osv did not answer: {'unreachable': 1}")
        record = AdvisoryRecord(
            identifier=AdvisoryIdentifier("GHSA-m9w6-wp3h-vq8g"),
            aliases=(AdvisoryIdentifier("CVE-2024-0874"),),
            source="osv",
        )
        return PackageAdvisories(package=f"{ecosystem}/{name}@{version}", advisories=(record,))


def _upstream(name: str, version: str | None) -> ForkUpstream:
    return ForkUpstream(
        identity=name,
        package=name,
        ecosystem=Ecosystem.GO,
        tracked_version=Version(version) if version else None,
    )


FORK = ForkLagFact(
    upstreams=(
        _upstream("github.com/coredns/coredns", "1.11.1"),
        _upstream("github.com/unversioned/x", None),
        _upstream("github.com/envoyproxy/go-control-plane", "0.12.0"),
    )
)


def _forks(facts: Facts, exposure: Advisories | None, fork: ForkLagFact = FORK) -> CodeFactsService:
    return CodeFactsService(
        facts.assessments,
        facts.publisher,
        [Fixed(CodeFactKind.FORK_LAG, fork)],
        exposure,  # type: ignore[arg-type]
    )


def test_fork_lag_reads_each_tracked_versions_advisories(facts: Facts, tmp_path: Path) -> None:
    exposure = Advisories()
    found = _forks(facts, exposure).fork_lag(ToolRequest(workspace=tmp_path))
    assert found.network == "ok"
    assert exposure.asked == [
        (Ecosystem.GO, "github.com/coredns/coredns", "1.11.1"),
        (Ecosystem.GO, "github.com/envoyproxy/go-control-plane", "0.12.0"),
    ]
    assert [len(u.advisories) for u in found.upstreams] == [1, 0, 1]
    assert found.upstreams[0].advisories[0].aliases == ("CVE-2024-0874",)


def test_fork_lag_offline_or_not_a_fork_asks_nothing(facts: Facts, tmp_path: Path) -> None:
    exposure = Advisories()
    request = ToolRequest(workspace=tmp_path)
    assert _forks(facts, exposure).fork_lag(request, offline=True) == FORK
    assert _forks(facts, exposure, ForkLagFact()).fork_lag(request) == ForkLagFact()
    assert exposure.asked == []


def test_fork_lag_failed_read_keeps_stage_one_and_what_was_found(
    facts: Facts, tmp_path: Path
) -> None:
    exposure = Advisories(fail=frozenset({"github.com/envoyproxy/go-control-plane"}))
    found = _forks(facts, exposure).fork_lag(ToolRequest(workspace=tmp_path))
    assert found.network.startswith("error: ") and "unreachable" in found.network
    assert [len(u.advisories) for u in found.upstreams] == [1, 0, 0]
    assert found.fork_detected


def test_fork_lag_online_needs_the_exposure_service(facts: Facts, tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="exposure"):
        _forks(facts, None).fork_lag(ToolRequest(workspace=tmp_path))


def test_route_guards_resolves_handlers_through_the_symbol_index(
    facts: Facts, tmp_path: Path
) -> None:
    (tmp_path / "server.go").write_text(ROUTES)

    def symbol(name: str, path: str, kind: str) -> SymbolFact:
        return SymbolFact(
            name=name, location=CodeSpan(path=path, line=3, symbol=name), kind=kind, language="Go"
        )

    symbols = Fixed(
        CodeFactKind.SYMBOL,
        symbol("handleJobs", "h.go", "variable"),
        symbol("handleCallback", "h.go", "function"),
        symbol("handleCallback", "other.go", "func"),
    )
    service = CodeFactsService(
        facts.assessments, facts.publisher, [RouteGuardMatrix(FixedClock(T0)), symbols]
    )
    request = ToolRequest(workspace=tmp_path)
    plain = service.route_guards(request)
    assert all(r.handler.resolved is None for r in plain.routes)
    by_pattern = {r.pattern: r for r in service.route_guards(request, resolve_handlers=True).routes}
    assert by_pattern["/callback"].handler.resolved == CodeSpan(path="h.go", line=3)
    assert by_pattern["/jobs"].handler.resolved is None  # `requireAuth(handleJobs)` names no symbol
    assert by_pattern["/jobs"].guards == ("requireAuth",)


def test_a_typed_door_refuses_an_enumerator_answering_another_shape(
    facts: Facts, tmp_path: Path
) -> None:
    service = CodeFactsService(
        facts.assessments, facts.publisher, [Fixed(CodeFactKind.ROUTE_GUARD, ConfigFact())]
    )
    with pytest.raises(IntegrityError, match="not one"):
        service.route_guards(ToolRequest(workspace=tmp_path))


@pytest.mark.parametrize(
    ("kind", "shape"),
    [
        (CodeFactKind.ROUTE_GUARD, RouteGuardFact),
        (CodeFactKind.CONFIG, ConfigFact),
        (CodeFactKind.FORK_LAG, ForkLagFact),
    ],
)
def test_context_wires_the_secure_code_pre_scans(
    tmp_path: Path, kind: CodeFactKind, shape: type
) -> None:
    (tmp_path / "util.py").write_text("def sanitize(v):\n    return v\n")
    context = Context(Config(home=tmp_path / "home"), object_store=InMemoryObjectStore())
    code_facts = context.services().code_facts
    request = ToolRequest(workspace=tmp_path)
    [fact] = code_facts.enumerate(kind, request)
    assert isinstance(fact, shape)
    [candidate] = code_facts.enumerate(CodeFactKind.SANITIZER, request)
    assert isinstance(candidate, SanitizerFact)
    assert list(context.object_store.list()) == []
