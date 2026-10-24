"""Threat register, LOC, executive summary and review card views: regroupings of each domain's
reads, built on demand."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.test_insight import FakePortfolio
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import IntegrityError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import CodeFactsArtifact, ThreatModelArtifact
from traust_core.v1.models.assessment import AssessmentKind, Threat, ThreatMitigation
from traust_core.v1.models.code_facts import LanguageCount, LanguageStats
from traust_core.v1.models.common import ArtifactRef, Page, Provenance
from traust_core.v1.models.compliance import DocVariance
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.rendering import MarkdownRenderer
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    AssessmentLog,
    PublishSpec,
    PublishSpecs,
)
from traust_core.v1.services.findings.rating import RatingConfig, RatingPolicy
from traust_core.v1.services.insight import LocView, ThreatRegisterView

A, B = uuid4(), uuid4()
URLS = {A: "https://forge.example/o/a", B: "https://forge.example/o/b"}
MODELS = {A: uuid4(), B: uuid4()}


def md(view: Any, filter: ViewFilter | None = None) -> str:
    return MarkdownRenderer().render(view.report(view.build(filter or ViewFilter()), T0)).decode()


def threat(repository_id: UUID, label: str, status: str = "unmitigated", **kw: Any) -> Threat:
    values: dict[str, Any] = {
        "assessment_id": MODELS[repository_id],
        "repository_id": repository_id,
        "label": label,
        "title": f"{label} reaches tenant data",
        "status": status,
        "actor": "remote_unauth",
    }
    return Threat(**(values | kw))


@dataclass
class FakeAssessment:
    threats_: list[Threat]
    asked: list[Any] = field(default_factory=list)

    def threats(self, filter: Any, page: Any) -> Page[Threat]:
        self.asked.append(filter)
        return Page(
            items=tuple(t for t in self.threats_ if t.repository_id in filter.repository_ids)
        )


@dataclass
class FakeCompliance:
    variances: list[DocVariance] = field(default_factory=list)

    def doc_variances(self, filter: Any, page: Any) -> Page[DocVariance]:
        assert filter.disposition == "open"
        return Page(items=tuple(self.variances))


def register(threats: list[Threat], variances: list[DocVariance] | None = None) -> Any:
    return ThreatRegisterView(
        FakeAssessment(threats),  # type: ignore[arg-type]
        FakeCompliance(variances or []),  # type: ignore[arg-type]
        FakePortfolio(repositories=dict(URLS)),  # type: ignore[arg-type]
        RatingPolicy(RatingConfig()),
        FixedClock(T0),
    )


QUICK = ThreatMitigation(text="parameterize orderBy", closes_class="yes", effort="S")


@pytest.mark.parametrize(
    ("threats", "order", "crosswalked"),
    [
        ([], [], 0),
        # a stated OWASP band outranks a crosswalked one; ties break by status, then repository
        (
            [
                threat(B, "T1", impact="low", likelihood="rare"),
                threat(A, "T2", severity="critical"),
                threat(A, "T3", impact="critical", likelihood="almost_certain"),
                threat(B, "T4", "mitigated", severity="critical"),
            ],
            ["T2", "T3", "T4", "T1"],
            2,
        ),
        # no band and no legacy labels: ranked last, never guessed
        ([threat(A, "T9"), threat(A, "T1", severity="low")], ["T1", "T9"], 0),
    ],
)
def test_threats_rank_by_band_then_status_then_repository(
    threats: list[Threat], order: list[str], crosswalked: int
) -> None:
    model = register(threats).build(ViewFilter())
    assert [r.threat.label for r in model.threats] == order
    assert sum(r.crosswalked for r in model.threats) == crosswalked
    assert model.repository_urls == URLS


@pytest.mark.parametrize(
    ("mitigation", "status", "severity", "wins"),
    [
        (QUICK, "unmitigated", "high", 1),
        (QUICK, "partially_mitigated", "high", 0),
        (QUICK, "unmitigated", "medium", 0),
        (QUICK.model_copy(update={"effort": "M"}), "unmitigated", "critical", 0),
        (QUICK.model_copy(update={"closes_class": "partial"}), "unmitigated", "critical", 0),
    ],
)
def test_quick_wins_are_class_closing_small_fixes_over_unmitigated_high_threats(
    mitigation: ThreatMitigation, status: str, severity: str, wins: int
) -> None:
    threats = [
        threat(A, label, status, severity=severity, mitigations=(mitigation,))
        for label in ("T1", "T2")
    ]
    model = register(threats).build(ViewFilter())
    assert len(model.quick_wins) == wins
    if wins:
        assert model.quick_wins[0].covers == ("T1", "T2")


def test_the_register_reads_models_as_of_the_point_in_time() -> None:
    view = register([])
    view.build(ViewFilter())
    view.build(ViewFilter(as_of=T0 - timedelta(days=90)))
    assert [f.as_of for f in view._assessment.asked] == [T0, T0 - timedelta(days=90)]


def test_the_register_reports_open_exposure_acceptances_and_doc_variances() -> None:
    variance = DocVariance(
        repository_id=A,
        record="DV-1",
        kind="overclaim",
        disposition="open",
        product_slug="widget",
        version="4.18",
        claim="All traffic is encrypted",
        verified_at=T0,
        artifact={"id": uuid4(), "name": "doc-variance", "digest": "0" * 64},
    )
    elsewhere = variance.model_copy(update={"repository_id": uuid4(), "record": "DV-9"})
    threats = [
        threat(A, "T1", severity="critical", evidence=("F-1",), mitigations=(QUICK,)),
        threat(B, "T2", "risk_accepted", impact="high", likelihood="likely"),
        threat(B, "T3", "partially_mitigated", severity="high", linddun=True),
    ]
    text = md(register(threats, [variance, elsewhere]))
    assert "2 threat models across 2 repositories" in text
    assert "3 threats, 2 open" in text and "Evidence-backed: 1" in text
    assert "LINDDUN privacy rows: 1" in text and "legacy crosswalk: 1" in text
    assert "| https://forge.example/o/a | T1 | T1 reaches tenant data | critical |" in text
    assert "| https://forge.example/o/a | parameterize orderBy | S | T1 | critical |" in text
    assert "| https://forge.example/o/b | 1 |" in text
    assert "| https://forge.example/o/a | 1 | 1 | 1 | 0 |" in text
    assert "DV-1" in text and "DV-9" not in text


def test_an_empty_register_says_so() -> None:
    text = md(register([]))
    assert "_No open threats._" in text and "_No threat models recorded._" in text
    assert "_No open doc variances._" in text


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def context(engine: Engine, tmp_path: Path, now: datetime = T0) -> Context:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(now))
    ctx.__dict__["database"] = engine
    return ctx


MODEL = json.loads(
    (
        Path(__file__).parents[2] / "fixtures" / "assessments" / "widget-threat-model.json"
    ).read_text()
)


def test_the_threat_register_renders_through_context(engine: Engine, tmp_path: Path) -> None:
    ctx = context(engine, tmp_path, T0 + timedelta(days=30))
    doc = ThreatModelArtifact.from_document(MODEL)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url="https://github.com/example-org/svc")
        ref = seed.repository_ref(repo, is_default=True)
        a = seed.assessment(ref, kind=AssessmentKind.THREAT_MODEL.value, occurred_at=T0)
        published = ArtifactPublisher(
            PublishSpecs(PublishSpec(ThreatModelArtifact)), ctx.object_store, uow
        ).publish_artifact(doc)
        AssessmentLog(uow).attach(a.id, published.artifact_id, sha256_hex(doc.payload))  # type: ignore[arg-type]
        uow.commit()
    insight = ctx.services().insight
    now = insight.refresh([ViewName.THREAT_REGISTER], ViewFilter())
    assert now.failed == {}
    text = now.rendered[ViewName.THREAT_REGISTER].markdown
    assert "1 threat models across 1 repositories" in text
    assert "Cross-tenant data theft via SQL injection" in text
    before = insight.build(ViewName.THREAT_REGISTER, ViewFilter(as_of=T0 - timedelta(days=1)))
    assert before.threats == ()  # type: ignore[attr-defined]


def lang(name: str, code: int) -> LanguageCount:
    return LanguageCount(name=name, files=1, code=code, comments=None, blanks=None)


@dataclass
class FakeCodeFacts:
    measured: dict[UUID, LanguageStats | Exception]

    def language_stats(self, repository_ref_id: UUID) -> LanguageStats:
        found = self.measured[repository_ref_id]
        if isinstance(found, Exception):
            raise found
        return found


@dataclass
class LocPortfolio(FakePortfolio):
    refs: dict[UUID, UUID] = field(default_factory=dict)

    @property
    def inventory(self) -> Any:
        return self

    def default_ref(self, repository_id: UUID) -> Any:
        ref = self.refs.get(repository_id)
        return None if ref is None else type("Ref", (), {"id": ref})()


def loc(measured: dict[UUID, LanguageStats | Exception], refs: dict[UUID, UUID]) -> LocView:
    portfolio = LocPortfolio(repositories=dict(URLS), refs=refs)
    return LocView(FakeCodeFacts(measured), portfolio)  # type: ignore[arg-type]


RA, RB = uuid4(), uuid4()


@pytest.mark.parametrize(
    ("measured", "refs", "code", "total", "why"),
    [
        ({}, {}, 0, 0, {A: "no default-branch commit", B: "no default-branch commit"}),
        (
            {
                RA: LanguageStats(languages=(lang("Go", 900), lang("Markdown", 50))),
                RB: LanguageStats(languages=(lang("Python", 100),)),
            },
            {A: RA, B: RB},
            1000,
            1050,
            {},
        ),
        (
            {RA: LanguageStats(languages=()), RB: NotFoundError("no tool_scan assessment")},
            {A: RA, B: RB},
            0,
            0,
            {B: "no tool_scan assessment"},
        ),
        (
            {RA: ValidationError("tool_scan assessment is failed")},
            {A: RA},
            0,
            0,
            {A: "tool_scan assessment is failed", B: "no default-branch commit"},
        ),
    ],
)
def test_loc_sums_measured_languages_and_says_why_a_repository_is_not_measured(
    measured: dict[UUID, Any], refs: dict[UUID, UUID], code: int, total: int, why: dict[UUID, str]
) -> None:
    model = loc(measured, refs).build(ViewFilter())
    assert (model.code, model.total) == (code, total)
    assert {r.repository_id: r.unmeasured for r in model.repositories if r.unmeasured} == why


def test_loc_ranks_languages_and_repositories_and_counts_documentation_apart() -> None:
    measured: dict[UUID, Any] = {
        RA: LanguageStats(languages=(lang("Go", 900), lang("Markdown", 50))),
        RB: LanguageStats(languages=(lang("Go", 10), lang("Python", 100))),
    }
    view = loc(measured, {A: RA, B: RB})
    model = view.build(ViewFilter())
    assert [(t.name, t.code, t.repositories, t.documentation) for t in model.languages] == [
        ("Go", 910, 2, False),
        ("Python", 100, 1, False),
        ("Markdown", 50, 1, True),
    ]
    assert [(r.repository_url, r.primary) for r in model.repositories] == [
        (URLS[A], "Go"),
        (URLS[B], "Python"),
    ]
    text = md(view)
    assert "2 of 2 repositories measured: 1,010 lines of code (1,060 with" in text
    assert "| Go | 910 | 90.1% | 2 |" in text
    assert "| Markdown (documentation) | 50 | - | 1 |" in text


def test_loc_refuses_a_point_in_time_it_cannot_read() -> None:
    with pytest.raises(ValidationError, match="no as_of"):
        loc({}, {}).build(ViewFilter(as_of=T0))


def test_loc_never_hides_broken_measurements() -> None:
    with pytest.raises(IntegrityError):
        loc({RA: IntegrityError("duplicate language measurements")}, {A: RA}).build(ViewFilter())


def test_loc_renders_through_context(engine: Engine, tmp_path: Path) -> None:
    ctx = context(engine, tmp_path)
    doc = CodeFactsArtifact.from_document(
        {
            "artifact": "code-facts",
            "symbols": None,
            "languages": [
                {"name": "Go", "files": 3, "code": 1200, "comments": 40, "blanks": 30},
                {"name": "Markdown", "files": 1, "code": 80, "comments": 0, "blanks": 5},
            ],
        }
    )
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        measured = seed.repository(url="https://github.com/example-org/svc")
        ref = seed.repository_ref(measured, is_default=True)
        seed.repository(url="https://github.com/example-org/never-scanned")
        uow.commit()
    services = ctx.services()
    published = ArtifactPublisher(
        PublishSpecs(PublishSpec(CodeFactsArtifact)), ctx.object_store, SqlTraustUnitOfWork(engine)
    ).publish_artifact(doc)
    services.assessment.record(
        doc,
        ref.id,  # type: ignore[arg-type]
        AssessmentKind.TOOL_SCAN,
        "tool:recorded-fixture",
        "1",
        Provenance(
            run_id=uuid4(),
            source=SourceType.INTERACTIVE,
            occurred_at=T0,
            artifact=ArtifactRef(
                id=published.artifact_id, name="code-facts", digest=sha256_hex(doc.payload)
            ),
        ),
    )
    result = services.insight.refresh([ViewName.LOC], ViewFilter())
    assert result.failed == {}
    text = result.rendered[ViewName.LOC].markdown
    assert "1 of 2 repositories measured: 1,200 lines of code (1,280 with" in text
    assert "| https://github.com/example-org/svc | 1,200 | 1,280 | Go |" in text
    assert "| https://github.com/example-org/never-scanned | no default-branch commit |" in text
