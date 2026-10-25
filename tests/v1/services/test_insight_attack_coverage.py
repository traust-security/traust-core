"""The ATT&CK coverage view (attack-coverage): modeled from each repository's latest threat model,
derived from its findings' categories through the pack's category map, never blended."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.test_insight import FakePortfolio
from traust_core.v1.context import Config, Context
from traust_core.v1.context.attack import load_attack_catalog
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import ThreatModelArtifact
from traust_core.v1.models.assessment import AssessmentKind, AttackTechnique, Threat
from traust_core.v1.models.common import Page
from traust_core.v1.models.findings import FindingDimension, FindingRollup
from traust_core.v1.models.insight import AttackCoverage, ViewFilter, ViewName
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
from traust_core.v1.services.insight import AttackCoverageView

FIXTURES = Path(__file__).parents[2] / "fixtures"
TECHNIQUES = FIXTURES / "insight" / "attack" / "attack-techniques.json"
MAPPING = FIXTURES / "insight" / "attack" / "attack-mapping.json"
CATALOG = load_attack_catalog(TECHNIQUES, MAPPING)
A, B = uuid4(), uuid4()
URLS = {A: "https://forge.example/o/a", B: "https://forge.example/o/b"}
MODEL_A, MODEL_B = uuid4(), uuid4()


def threat(model: UUID, repository_id: UUID, *ids: str) -> Threat:
    return Threat(
        assessment_id=model,
        repository_id=repository_id,
        label=f"T{len(ids)}",
        title="reaches tenant data",
        status="unmitigated",
        actor="remote_unauth",
        techniques=tuple(AttackTechnique(id=i) for i in ids),
    )


def rollup(key: str | None, findings: int) -> FindingRollup:
    return FindingRollup(
        key=key,
        findings=findings,
        open=findings,
        hardening=0,
        accepted=0,
        resolved=0,
        false_positives=0,
        open_by_severity={},
    )


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
class FakeFindings:
    groups: dict[UUID, list[FindingRollup]]
    asked: list[Any] = field(default_factory=list)

    def summary(self, filter: Any, group_by: FindingDimension) -> list[FindingRollup]:
        assert group_by is FindingDimension.CATEGORY
        self.asked.append(filter)
        return self.groups.get(filter.repository_id, [])


def coverage(
    threats: list[Threat], groups: dict[UUID, list[FindingRollup]], filter: ViewFilter
) -> tuple[AttackCoverage, FakeAssessment, FakeFindings]:
    assessment, findings = FakeAssessment(threats), FakeFindings(groups)
    view = AttackCoverageView(
        assessment,  # type: ignore[arg-type]
        findings,  # type: ignore[arg-type]
        FakePortfolio(repositories=dict(URLS)),  # type: ignore[arg-type]
        CATALOG,
        FixedClock(T0),
    )
    return view.build(filter), assessment, findings


def test_each_live_technique_counts_once_per_threat_and_bad_ids_are_dropped() -> None:
    threats = [
        threat(MODEL_A, A, "T1078", "T1078", "T9999"),
        threat(MODEL_A, A, "T1190"),
        threat(MODEL_B, B),
        threat(MODEL_B, B, "T1562", "T9999"),
    ]
    model, assessment, _ = coverage(threats, {}, ViewFilter())
    assert [f.repository_ids for f in assessment.asked] == [tuple(sorted(URLS, key=URLS.get))]
    assert assessment.asked[0].as_of == T0
    assert {t.technique_id: t.modeled for t in model.techniques} == {"T1078": 1, "T1190": 1}
    assert (model.threat_models, model.threats_with_techniques) == (2, 2)
    assert model.dropped == {"T9999": 2, "T1562": 1}


def test_findings_categories_imply_candidate_techniques() -> None:
    groups = {
        A: [rollup("injection", 3), rollup("cryptography", 5), rollup(None, 2)],
        B: [rollup("authentication", 1), rollup("injection", 1)],
    }
    as_of = T0 + timedelta(days=3)
    model, _, findings = coverage([], groups, ViewFilter(as_of=as_of))
    assert {f.as_of for f in findings.asked} == {as_of}
    assert model.findings_mapped == 5
    assert {t.technique_id: t.derived for t in model.techniques} == {
        "T1059": 4,
        "T1078": 1,
        "T1110": 1,
        "T1190": 4,
        "T1556": 1,
    }
    assert {t.score for t in model.techniques} == {1}


def test_modeled_outranks_derived_and_the_layer_scores_each_technique() -> None:
    model, _, _ = coverage(
        [threat(MODEL_A, A, "T1611")], {B: [rollup("injection", 2)]}, ViewFilter()
    )
    assert [(t.technique_id, t.score) for t in model.techniques] == [
        ("T1611", 2),
        ("T1059", 1),
        ("T1190", 1),
    ]
    layer = model.navigator_layer
    assert layer["versions"] == {"attack": "19", "navigator": "5.1.0", "layer": "4.5"}
    assert layer["techniques"][0] == {
        "techniqueID": "T1611",
        "score": 2,
        "comment": "modeled in 1 threat(s)",
    }
    assert layer["techniques"][1]["comment"] == "candidate for 2 finding(s) by weakness class"
    assert "MITRE" in layer["description"]
    assert {m["name"]: m["value"] for m in layer["metadata"]}["tactics_covered"] == "3"


def test_an_empty_scope_covers_nothing() -> None:
    model, _, _ = coverage([], {}, ViewFilter())
    assert model.techniques == () and model.dropped == {}
    assert model.navigator_layer["techniques"] == []
    text = report(model)
    assert "_No techniques covered._" in text
    assert "_None._" in text


def report(model: AttackCoverage) -> str:
    view = AttackCoverageView(None, None, None, CATALOG, FixedClock(T0))  # type: ignore[arg-type]
    return MarkdownRenderer().render(view.report(model, T0)).decode()


def test_the_report_keeps_the_classes_apart_and_lists_dropped_ids() -> None:
    model, _, _ = coverage(
        [threat(MODEL_A, A, "T1611", "T9999")], {B: [rollup("tenant-isolation", 1)]}, ViewFilter()
    )
    text = report(model)
    assert "observed" in text.lower() and "not yet recorded in core" in text
    assert "| T1611 | Escape to Host | 2 | modeled in 1 threat(s); candidate for 1" in text
    assert "| privilege-escalation | 1 | 2 | 2 |" in text
    assert "- `T9999` x 1" in text
    assert "ATT&CK v19.1 (pinned), mapping v1.0.0" in text


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def test_the_view_renders_through_context(engine: Engine, tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0 + timedelta(days=30)))
    ctx.__dict__["database"] = engine
    with pytest.raises(ValidationError, match="not built"):
        ctx.services().insight.build(ViewName.ATTACK_COVERAGE, ViewFilter())
    ctx.register_attack_catalog(TECHNIQUES, MAPPING)
    document = json.loads((FIXTURES / "assessments" / "widget-threat-model.json").read_text())
    document["threats"][1]["attack_refs"] = ["T1562"]
    doc = ThreatModelArtifact.from_document(document)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url="https://github.com/example-org/svc")
        ref = seed.repository_ref(repo, is_default=True)
        modeled = seed.assessment(ref, kind=AssessmentKind.THREAT_MODEL.value, occurred_at=T0)
        published = ArtifactPublisher(
            PublishSpecs(PublishSpec(ThreatModelArtifact)), ctx.object_store, uow
        ).publish_artifact(doc)
        AssessmentLog(uow).attach(modeled.id, published.artifact_id, sha256_hex(doc.payload))  # type: ignore[arg-type]
        audit = seed.assessment(ref, occurred_at=T0)
        for category in ("injection", "authentication", "cryptography"):
            finding = seed.finding(repo, title=f"{category} finding")
            seed.occurrence(finding, audit)
            seed.finding_label(finding, taxonomy="category", label=category)
        uow.commit()
    insight = ctx.services().insight
    result = insight.refresh([ViewName.ATTACK_COVERAGE], ViewFilter())
    assert result.failed == {}
    rendered = result.rendered[ViewName.ATTACK_COVERAGE]
    assert rendered.stem == "attack-coverage"
    model = rendered.model
    assert isinstance(model, AttackCoverage)
    assert [(t.technique_id, t.modeled, t.derived) for t in model.techniques] == [
        ("T1078", 1, 1),
        ("T1190", 1, 1),
        ("T1059", 0, 1),
        ("T1110", 0, 1),
        ("T1556", 0, 1),
    ]
    assert (model.repositories, model.threat_models, model.findings_mapped) == (1, 1, 2)
    assert model.dropped == {"T1562": 1}
    before = insight.build(ViewName.ATTACK_COVERAGE, ViewFilter(as_of=T0 - timedelta(days=1)))
    assert before.techniques == ()  # type: ignore[attr-defined]
