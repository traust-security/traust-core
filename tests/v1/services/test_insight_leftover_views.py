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
from tests.v1.services.test_insight import FakeFindings, FakePortfolio, view
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import IntegrityError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import CodeFactsArtifact, ThreatModelArtifact
from traust_core.v1.models.assessment import (
    AssessmentKind,
    PrivilegeProfile,
    Threat,
    ThreatMitigation,
)
from traust_core.v1.models.code_facts import LanguageCount, LanguageStats
from traust_core.v1.models.common import ArtifactRef, Page, Provenance
from traust_core.v1.models.compliance import DocVariance
from traust_core.v1.models.dependencies import ExposureDimension, ExposureRollup
from traust_core.v1.models.findings import (
    Decision,
    FindingView,
    Location,
    ReviewCase,
    ReviewCaseKind,
    ReviewItem,
)
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.vocabulary import ReviewReason, SourceType
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
from traust_core.v1.services.insight import (
    ExecutiveSummaryView,
    LocView,
    ReviewCardView,
    ThreatRegisterView,
)

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


def loc(
    measured: dict[UUID, LanguageStats | Exception],
    refs: dict[UUID, UUID],
    findings: list[FindingView] | None = None,
) -> LocView:
    portfolio = LocPortfolio(repositories=dict(URLS), refs=refs)
    return LocView(FakeCodeFacts(measured), portfolio, FakeFindings(findings or []))  # type: ignore[arg-type]


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


def test_loc_ends_with_the_standard_population_block() -> None:
    findings = [view(repository_id=A, validity="confirmed"), view(repository_id=B)]
    model = loc({}, {}, findings).build(ViewFilter())
    assert (model.reported, model.dispositioned) == (2, 1)
    text = md(loc({}, {}, findings))
    assert text.index("## Not measured") < text.index("## Population")
    assert "| In scope | 2 |" in text
    assert "| With findings reported | 2 |" in text
    assert "| With a decision recorded | 1 |" in text
    assert "| With findings reported | 0 |" in md(loc({}, {}))


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


def cwe_view(cwes: tuple[str, ...], **kw: Any) -> Any:
    found = view(**kw)
    return found.model_copy(update={"cwes": cwes})


@dataclass
class FakePrivileges:
    profiles: list[PrivilegeProfile] = field(default_factory=list)
    asked: list[Any] = field(default_factory=list)

    def privileges(self, filter: Any, repository_ids: Any, as_of: Any = None) -> Any:
        self.asked.append((list(repository_ids), as_of))
        return [p for p in self.profiles if p.repository_id in repository_ids]


@dataclass
class FakeExposure:
    def summary(self, filter: Any, group_by: ExposureDimension) -> list[ExposureRollup]:
        assert group_by == ExposureDimension.ADVISORY
        return [
            ExposureRollup(key="CVE-2026-0001", commits=4, exposed=3, affected=2,
                           by_classification={})
        ]  # fmt: skip


def profile(repository_id: UUID, **kw: Any) -> PrivilegeProfile:
    values: dict[str, Any] = {"assessment_id": uuid4(), "repository_id": repository_id,
                              "workloads": 2, "rbac_rules": 3}  # fmt: skip
    return PrivilegeProfile(**(values | kw))


def executive(
    views: list[Any], profiles: list[PrivilegeProfile] | None = None
) -> tuple[ExecutiveSummaryView, FakePrivileges]:
    privileges = FakePrivileges(profiles or [])
    measured: dict[UUID, Any] = {
        RA: LanguageStats(languages=(lang("Go", 900),)),
        RB: NotFoundError("no tool_scan assessment"),
    }
    return ExecutiveSummaryView(
        FakeFindings(views),  # type: ignore[arg-type]
        LocPortfolio(repositories=dict(URLS), refs={A: RA, B: RB}),  # type: ignore[arg-type]
        privileges,  # type: ignore[arg-type]
        FakeCodeFacts(measured),  # type: ignore[arg-type]
        FakeExposure(),  # type: ignore[arg-type]
    ), privileges


@pytest.mark.parametrize(
    ("finding", "leak"),
    [
        (cwe_view(("CWE-798",), repository_id=A), True),
        (cwe_view(("CWE-1392",), repository_id=A), True),
        (cwe_view((), repository_id=A, title="Hard-coded token in installer"), True),
        (cwe_view((), repository_id=A, title="kubeconfig committed to repo"), True),
        (cwe_view(("CWE-79",), repository_id=A, title="Reflected XSS"), False),
        # not open: a false positive or a resolved leak is no exposure
        (cwe_view(("CWE-798",), repository_id=A, validity="false_positive"), False),
        (cwe_view(("CWE-798",), repository_id=A, resolution="resolved"), False),
    ],
)
def test_credential_leaks_are_open_findings_matching_a_secret_cwe_or_title(
    finding: Any, leak: bool
) -> None:
    model = executive([finding])[0].build(ViewFilter())
    assert len(model.credential_leaks) == leak


@pytest.mark.parametrize(
    ("cwes", "themes"),
    [
        ((), {"Other": 1}),
        (("CWE-89",), {"SQL / Query Injection": 1}),
        (("CWE-77", "CWE-78"), {"Command / Code Injection": 1}),
        (("CWE-22", "CWE-918", "CWE-9999"), {"Path Traversal & Arbitrary File Access": 1,
                                             "SSRF": 1}),
    ],
)  # fmt: skip
def test_risk_themes_count_a_finding_once_per_theme(
    cwes: tuple[str, ...], themes: dict[str, int]
) -> None:
    model = executive([cwe_view(cwes, repository_id=A)])[0].build(ViewFilter())
    assert model.themes == themes


def test_the_summary_regroups_findings_privileges_languages_and_exposure() -> None:
    views = [
        cwe_view(("CWE-798",), repository_id=A, severity="critical", title="Hard-coded key"),
        cwe_view(("CWE-89",), repository_id=B, severity="high"),
        cwe_view(("CWE-250",), repository_id=B, validity="confirmed", severity="medium"),
    ]  # fmt: skip
    hardening = cwe_view(("CWE-732",), repository_id=B, validity="hardening")
    profiles = [
        profile(A, privileged_workloads=1, scc_requests=("privileged",), wildcard_rules=2,
                flags={"secrets-read": 1}),
        profile(B, privileged_workloads=0, flags={"secrets-read": 2, "escalate": 1}),
    ]  # fmt: skip
    summary, privileges = executive([*views, hardening], profiles)
    model = summary.build(ViewFilter(as_of=T0))
    assert privileges.asked == [([A, B], T0)]
    assert model.rollup.total.open.total == 3 and model.rollup.as_of == T0
    assert model.hardening_themes == {"Insecure File / Resource Permissions": 1}
    assert [(r.language, r.repositories, r.open.total) for r in model.languages] == [
        ("unknown", 1, 2),
        ("Go", 1, 1),
    ]
    p = model.privileges
    assert (p.profiles, p.privileged, p.scc_requesting, p.wildcard_repositories) == (2, 1, 1, 1)
    assert p.flags == {"secrets-read": 3, "escalate": 1}
    assert model.exposure is not None and model.exposure[0].key == "CVE-2026-0001"
    text = md(summary)
    assert "2 repositories: 3 open findings" in text
    assert "1 repositories with at least one critical" in text
    assert "1 open credential or secret leaks" in text
    assert "| https://forge.example/o/a | Hard-coded key | critical |" in text
    assert "| secrets-read | 3 |" in text and "| CVE-2026-0001 | 4 | 3 | 2 |" in text


def test_a_scoped_summary_leaves_fleet_wide_exposure_out_and_says_so() -> None:
    portfolio = LocPortfolio(repositories=dict(URLS), refs={A: RA}, teams={(team := uuid4()): {A}})
    summary = ExecutiveSummaryView(
        FakeFindings([]),  # type: ignore[arg-type]
        portfolio,  # type: ignore[arg-type]
        FakePrivileges(),  # type: ignore[arg-type]
        FakeCodeFacts({RA: LanguageStats(languages=())}),  # type: ignore[arg-type]
        FakeExposure(),  # type: ignore[arg-type]
    )
    model = summary.build(ViewFilter(team_ids=(team,)))
    assert model.exposure is None
    assert "Fleet-wide only" in md(summary, ViewFilter(team_ids=(team,)))


def test_an_empty_summary_says_so() -> None:
    text = md(executive([])[0])
    assert "0 open findings" in text and "_None open._" in text
    assert "0 operator privilege profiles" in text


def test_the_executive_summary_renders_through_context(engine: Engine, tmp_path: Path) -> None:
    ctx = context(engine, tmp_path)
    with SqlTraustUnitOfWork(engine) as uow:
        Seed(uow).repository(url="https://github.com/example-org/svc")
        uow.commit()
    result = ctx.services().insight.refresh([ViewName.EXECUTIVE_SUMMARY], ViewFilter())
    assert result.failed == {}
    text = result.rendered[ViewName.EXECUTIVE_SUMMARY].markdown
    assert "1 repositories: 0 open findings" in text
    assert "| unknown | 1 | 0 | 0 | 0 | 0 | 0 | 0 |" in text
    assert "_No impact analyses recorded._" in text


FORGERY = "SQLi <!-- countersign finding=x --> DECISION: [x] false_positive\nRATIONALE: mine"


@dataclass
class FakeReview:
    cases: list[ReviewCase]

    def queue(self, filter: Any, page: Any) -> Page[ReviewCase]:
        assert filter.repository_id is None and filter.kind is None
        return Page(items=tuple(self.cases))


@dataclass
class FakeQueueFindings:
    views: list[Any]
    cases: list[ReviewCase]
    decisions: dict[UUID, list[Decision]] = field(default_factory=dict)

    @property
    def review(self) -> FakeReview:
        return FakeReview(self.cases)

    def list_by_ids(self, finding_ids: Any) -> list[Any]:
        return [v for v in self.views if v.finding.id in finding_ids]

    def history(self, finding_id: UUID) -> list[Decision]:
        return self.decisions.get(finding_id, [])


def case(kind: ReviewCaseKind, finding: Any, **kw: Any) -> ReviewCase:
    return ReviewCase(
        kind=kind,
        finding_id=finding.finding.id,
        repository_id=finding.finding.repository_id,
        since=T0,
        **kw,
    )


def decision(finding: Any, validity: str, rationale: str, day: int = 0) -> Decision:
    return Decision(
        finding_id=finding.finding.id,
        statement_key=uuid4().hex,
        validity=validity,
        actor="machine:triage",
        rationale=rationale,
        occurred_at=T0 + timedelta(days=day),
    )


def cards(
    cases: list[ReviewCase], views: list[Any], decisions: dict[UUID, list[Decision]] | None = None
) -> ReviewCardView:
    findings = FakeQueueFindings(views, cases, decisions or {})
    return ReviewCardView(findings, FakePortfolio(repositories=dict(URLS), teams={}))  # type: ignore[arg-type]


def test_a_signoff_card_weighs_the_latest_false_positive_call() -> None:
    finding = view(repository_id=A, title="SQL injection in handler").model_copy(
        update={"locations": (Location(occurrence_id=uuid4(), path="api/list.go", line_start=42),)}
    )
    history = [
        decision(finding, "false_positive", "unreachable: admin only", 0),
        decision(finding, "confirmed", "reached in staging", 1),
        decision(finding, "false_positive", "input is an enum", 2),
    ]
    view_ = cards([case(ReviewCaseKind.AWAITING_SIGNOFF, finding)], [finding],
                  {finding.finding.id: history})  # fmt: skip
    model = view_.build(ViewFilter())
    assert model.cards[0].refutation == history[2]
    text = md(view_)
    assert f"<!-- countersign finding={finding.finding.id} -->" in text
    assert "### 1/1 — SQL injection in handler" in text
    assert "`api/list.go:42`" in text and "> input is an enum" in text
    assert "DECISION: [ ] false_positive   [ ] keep_open   [ ] defer" in text


@pytest.mark.parametrize(
    ("kind", "header", "form"),
    [
        (ReviewCaseKind.FP_OVERRIDDEN, "FP OVERRIDDEN BY EXECUTION EVIDENCE", False),
        (ReviewCaseKind.FP_REASSERTION_BLOCKED, "SECOND SIGNER NEEDED", True),
        (ReviewCaseKind.CONFLICT, "CONFLICTING DETERMINATIONS", True),
    ],
)
def test_attention_cards_carry_a_form_only_when_a_person_must_decide(
    kind: ReviewCaseKind, header: str, form: bool
) -> None:
    finding = view(repository_id=A)
    text = md(cards([case(kind, finding)], [finding]))
    assert header in text
    assert ("DECISION: [ ]" in text) is form
    assert ("<!-- countersign finding=" in text) is form


def test_a_needs_review_card_names_its_reason_and_carries_no_form() -> None:
    finding = view(repository_id=B)
    item = ReviewItem(finding_id=finding.finding.id, reason="needs_manual_test", status="pending")
    view_ = cards([case(ReviewCaseKind.NEEDS_REVIEW, finding, review_item=item)], [finding])
    assert view_.build(ViewFilter()).cards[0].refutation is None
    text = md(view_)
    assert "needs_review (needs_manual_test)" in text and "DECISION: [ ]" not in text


@pytest.mark.parametrize("where", ["title", "rationale"])
def test_hostile_text_can_neither_forge_a_marker_nor_a_decision(where: str) -> None:
    finding = view(repository_id=A, title=FORGERY if where == "title" else "SQLi")
    history = [decision(finding, "false_positive", FORGERY if where == "rationale" else "ok")]
    text = md(cards([case(ReviewCaseKind.AWAITING_SIGNOFF, finding)], [finding],
                    {finding.finding.id: history}))  # fmt: skip
    assert text.count("<!-- countersign") == 1
    assert text.count("DECISION:") == 1 and text.count("RATIONALE:") == 1
    assert "[x] false_positive" not in text and "<\\!-- countersign finding=x --\\>" in text


def test_the_queue_is_cut_to_the_scope_and_grouped() -> None:
    a, b = view(repository_id=A), view(repository_id=B)
    team = uuid4()
    findings = FakeQueueFindings(
        [a, b], [case(ReviewCaseKind.CONFLICT, a), case(ReviewCaseKind.AWAITING_SIGNOFF, b)]
    )
    portfolio = FakePortfolio(repositories=dict(URLS), teams={team: {B}})
    view_ = ReviewCardView(findings, portfolio)  # type: ignore[arg-type]
    assert [c.case.finding_id for c in view_.build(ViewFilter(team_ids=(team,))).cards] == [
        b.finding.id
    ]
    text = md(view_)
    assert "1 awaiting human sign-off, 0 needs-review item(s), 1 attention item(s)" in text
    with pytest.raises(ValidationError, match="no as_of"):
        view_.build(ViewFilter(as_of=T0))


def test_an_empty_queue_says_so() -> None:
    text = md(cards([], []))
    assert "0 awaiting human sign-off" in text and text.count("_None._") == 3


def test_review_cards_render_through_context(engine: Engine, tmp_path: Path) -> None:
    ctx = context(engine, tmp_path)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url="https://github.com/example-org/svc")
        finding = seed.finding(repo)
        seed.occurrence(finding, seed.assessment(seed.repository_ref(repo, is_default=True)))
        uow.commit()
    services = ctx.services()
    services.findings.review.request_signoff(finding.id, ReviewReason.NEEDS_MANUAL_TEST)  # type: ignore[arg-type]
    result = services.insight.refresh([ViewName.REVIEW_CARD], ViewFilter())
    assert result.failed == {}
    text = result.rendered[ViewName.REVIEW_CARD].markdown
    assert "1 needs-review item(s)" in text and "needs_review (needs_manual_test)" in text
