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
from traust_core.v1.models.artifacts import ThreatModelArtifact
from traust_core.v1.models.assessment import AssessmentKind, Threat, ThreatMitigation
from traust_core.v1.models.common import Page
from traust_core.v1.models.compliance import DocVariance
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.integrity import sha256_hex
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
from traust_core.v1.services.insight import ThreatRegisterView

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
