from __future__ import annotations

from collections.abc import Iterator
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.reporting.documents import valid_report
from tests.v1.services.test_exposure_feeds import (
    EPSS_RAW,
    FILENAME,
    KEV_RAW,
    NamedFeed,
)
from tests.v1.services.test_exposure_feeds import (
    services as feed_service,
)
from traust_core.v1.context import Config, Context
from traust_core.v1.models.artifacts import ReportArtifact
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import Provenance, TimeBucket
from traust_core.v1.models.findings import FindingCandidate, FindingFilter, FindingView
from traust_core.v1.models.insight import FindingsTrend, ViewFilter, ViewName
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.values import ProductSlug
from traust_core.v1.models.vocabulary import OwnershipClass, SourceType
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

T0 = datetime(2026, 10, 26, tzinfo=UTC)
DAY = timedelta(days=1)
VECTOR = "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N"
HUMAN = "human:analyst@example.com"


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as database:
        yield database


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0 + 20 * DAY))
    ctx.__dict__["database"] = engine
    return ctx


def report(
    context: Context,
    ref: RepositoryRef,
    at: datetime,
    *changes: dict[str, Any],
    legacy_cvss: bool = False,
) -> list[FindingView]:
    body = valid_report()
    template = body["findings"][0]
    body["metadata"]["date"] = at.date().isoformat()
    body["findings"] = []
    for index, change in enumerate(changes):
        entry = deepcopy(template)
        entry.update(
            id=f"TEST-{index + 1:03d}",
            title=f"Recorded finding {index + 1}",
            locations=[{"path": f"pkg/webhook/finding-{index + 1}.go", "lines": "42-58"}],
            cvss={"score": 6.0, "vector": VECTOR},
        )
        entry.update(change)
        if entry.get("cvss") is None:
            entry.pop("cvss", None)
        body["findings"].append(entry)
    severities = tuple(body["executive_summary"]["severity_counts"])
    body["executive_summary"]["severity_counts"] = {
        severity: sum(f["severity"] == severity for f in body["findings"])
        for severity in severities
    }
    body["findings_summary"] = [
        {
            "severity": severity,
            "count": sum(f["severity"] == severity for f in body["findings"]),
            "finding_ids": [f["id"] for f in body["findings"] if f["severity"] == severity],
        }
        for severity in severities
        if severity != "informational"
    ]
    body["remediation_roadmap"] = [
        {
            "priority": "P1",
            "action": "Repair the recorded defects",
            "addresses": [f["id"] for f in body["findings"]],
        }
    ]
    services = context.services()
    doc = ReportArtifact.from_document(body)
    recorded = services.assessment.record(
        doc,
        ref.id,
        AssessmentKind.SECURE_CODE_CANONICAL,
        "skill:secure-code-audit",
        "1.0",
        Provenance(run_id=uuid4(), source=SourceType.INTERACTIVE, occurred_at=at),
    )
    candidates = FindingCandidate.of_report(doc.findings, ref.repository_id)
    services.findings.intake.accept(
        recorded.id,
        [
            candidate.model_copy(update={"cvss_vector": None, "cvss_score": None})
            if legacy_cvss
            else candidate
            for candidate in candidates
        ],
    )
    return sorted(
        services.findings.all(FindingFilter(repository_id=ref.repository_id, as_of=at)),
        key=lambda view: view.finding.title,
    )


def trend(context: Context, **filters: Any) -> FindingsTrend:
    model = context.services().insight.build(
        ViewName.FINDINGS_TREND, ViewFilter(bucket=TimeBucket.WEEK, **filters)
    )
    assert isinstance(model, FindingsTrend)
    return model


def test_recorded_report_vectors_and_historical_kev_change_owasp_not_assurance(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        ref = Seed(unit).repository_ref(is_default=True)
        unit.commit()
    first, second = report(context, ref, T0, {"severity": "critical"}, {"severity": "low"})
    assert first.occurrence.cvss_vector == VECTOR
    assert first.occurrence.cvss_score == Decimal("6.0")
    with SqlTraustUnitOfWork(engine) as unit:
        seed = Seed(unit)
        canonical = seed.advisory(identifier="GHSA-aaaa-bbbb-cccc")
        seed.advisory(identifier="CVE-1999-0002", alias_of_id=canonical.id)
        seed.advisory(identifier="CVE-2026-59310", alias_of_id=canonical.id)
        unit.findings.update(
            first.finding.model_copy(
                update={"advisory_id": canonical.id, "advisory_match": "confirmed"}
            )
        )
        unit.commit()
    epss = NamedFeed("epss", FILENAME, EPSS_RAW)
    kev = NamedFeed("kev", "known_exploited_vulnerabilities.json", KEV_RAW)
    epss.fetched_at = kev.fetched_at = T0 + 8 * DAY
    feeds = feed_service(engine, context.object_store, epss, kev)
    feeds.refresh_feeds()

    built = trend(context)
    assert [(dict(p.owasp_open), p.owasp_high_plus_pct) for p in built.points] == [
        ({"medium": 2}, 0.0),
        ({"high": 1, "medium": 1}, 50.0),
        ({"high": 1, "medium": 1}, 50.0),
    ]
    assert all(p.owasp_unrated == 0 for p in built.points)
    assert built.assurance.proven.findings == 0
    direction = next(d for d in built.directions if d.metric == "owasp_high_plus_pct")
    assert (direction.last, direction.baseline, direction.rising, direction.worsening) == (
        50.0,
        25.0,
        True,
        True,
    )
    pinned = trend(context, as_of=T0 + 5 * DAY)
    assert dict(pinned.points[-1].owasp_open) == {"medium": 2}
    assert pinned.points[-1].owasp_high_plus_pct == 0.0
    assert second.disposition is None


def test_maximum_recorded_epss_alias_is_used_when_kev_is_unavailable(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        ref = Seed(unit).repository_ref(is_default=True)
        unit.commit()
    (view,) = report(
        context,
        ref,
        T0,
        {"cvss": {"score": 6.0, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N"}},
    )
    with SqlTraustUnitOfWork(engine) as unit:
        seed = Seed(unit)
        canonical = seed.advisory(identifier="GHSA-aaaa-bbbb-cccc")
        seed.advisory(identifier="CVE-1999-0001", alias_of_id=canonical.id)
        seed.advisory(identifier="CVE-1999-0002", alias_of_id=canonical.id)
        unit.findings.update(
            view.finding.model_copy(
                update={"advisory_id": canonical.id, "advisory_match": "confirmed"}
            )
        )
        unit.commit()
    epss = NamedFeed("epss", FILENAME, EPSS_RAW)
    epss.fetched_at = T0 + 8 * DAY
    feed_service(engine, context.object_store, epss).refresh_feeds()
    built = trend(context)
    assert [dict(point.owasp_open) for point in built.points] == [
        {"medium": 1},
        {"high": 1},
        {"high": 1},
    ]
    assert built.assurance.proven.findings == 0


def test_missing_vectors_remain_unrated_even_when_severity_is_critical(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        ref = Seed(unit).repository_ref(is_default=True)
        unit.commit()
    report(context, ref, T0, {"severity": "critical"}, {"severity": "critical", "cvss": None})
    built = trend(context)
    assert [(dict(p.owasp_open), p.owasp_unrated, p.owasp_high_plus_pct) for p in built.points] == [
        ({"medium": 1}, 1, None),
        ({"medium": 1}, 1, None),
        ({"medium": 1}, 1, None),
    ]
    assert "owasp_high_plus_pct" not in {d.metric for d in built.directions}
    assert built.assurance.proven.findings == 0


def test_final_assurance_replays_static_decisions_and_attributes_overrides(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        ref = Seed(unit).repository_ref(is_default=True)
        unit.commit()
    proven, hardening, static, closed = report(
        context,
        ref,
        T0,
        {},
        {"kind": "weakness"},
        {},
        {},
    )
    with SqlTraustUnitOfWork(engine) as unit:
        seed = Seed(unit)
        seed.decision(
            proven.finding,
            validity="false_positive",
            actor=HUMAN,
            evidence_grade="E1",
            occurred_at=T0 + DAY,
        )
        seed.decision(
            proven.finding,
            validity="confirmed",
            actor="tool:reproducer",
            evidence_grade="E0",
            occurred_at=T0 + 2 * DAY,
        )
        seed.decision(
            static.finding,
            validity="confirmed",
            actor="tool:verifier",
            evidence_grade="E2",
            occurred_at=T0 + DAY,
        )
        seed.decision(
            closed.finding,
            validity="confirmed",
            resolution="resolved",
            actor=HUMAN,
            evidence_grade="E1",
            occurred_at=T0 + DAY,
        )
        seed.decision(
            proven.finding,
            resolution="resolved",
            actor=HUMAN,
            evidence_grade="E0",
            occurred_at=T0 + 30 * DAY,
        )
        unit.commit()

    built = trend(context)
    assert (built.assurance.claimed.findings, built.assurance.claimed.risk_index) == (4, 24.0)
    assert (built.assurance.verified.findings, built.assurance.verified.risk_index) == (1, 6.0)
    assert (built.assurance.proven.findings, built.assurance.proven.risk_index) == (1, 6.0)
    assert (built.assurance.triage_compression_risk, built.assurance.validation_gap_risk) == (
        18.0,
        0.0,
    )
    (override,) = built.fp_overrides
    assert (
        override.finding_id,
        override.asserted_by,
        override.asserted_at,
        override.proven_at,
    ) == (
        proven.finding.id,
        HUMAN,
        T0 + DAY,
        T0 + 2 * DAY,
    )
    (blast,) = built.blast_radius
    assert (blast.component, blast.confirmed_open, blast.hardening_open) == ("pkg/webhook", 2, 1)
    rendered = context.services().insight.publish(
        ViewName.FINDINGS_TREND, ViewFilter(bucket=TimeBucket.WEEK)
    )
    html = Tables()
    html.feed(rendered.html)
    assert {("claimed", "4", "24.0"), ("verified", "1", "6.0"), ("proven", "1", "6.0")} <= set(
        html.rows
    )
    assert (HUMAN, "1") in html.rows
    assert (blast.repository_url, "pkg/webhook", "2", "1") in html.rows
    assert "| proven | 1 | 6.0 |" in rendered.markdown
    assert "| pkg/webhook | 2 | 1 |" in rendered.markdown
    early = trend(context, as_of=T0 + DAY)
    assert early.assurance.proven.findings == 0 and early.fp_overrides == ()
    assert trend(context, as_of=T0 + 35 * DAY).assurance.proven.findings == 0
    evidence = context.services().findings.evidence(
        FindingFilter(repository_id=ref.repository_id, as_of=T0 + 20 * DAY)
    )
    by_id = {item.current.finding.id: item for item in evidence}
    assert by_id[hardening.finding.id].claimed.finding.kind == "weakness"
    assert by_id[proven.finding.id].claimed.disposition is None
    assert by_id[proven.finding.id].verified.state() == "false_positive"
    assert by_id[proven.finding.id].current.disposition.fp_overridden


class Tables(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.rows: list[tuple[str, ...]] = []
        self.row: list[str] = []
        self.cell: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "tr":
            self.row = []
        if tag in {"td", "th"}:
            self.cell = []

    def handle_data(self, data: str) -> None:
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"td", "th"} and self.cell is not None:
            self.row.append("".join(self.cell))
            self.cell = None
        if tag == "tr":
            self.rows.append(tuple(self.row))


def test_ownership_and_cohorts_render_from_recorded_registry_and_report_refs(
    context: Context, engine: Engine
) -> None:
    portfolio = context.services().portfolio
    owned, _ = portfolio.register_corpus_product(
        ProductSlug.parse("owned"), "Owned", OwnershipClass.OWNED, "owned"
    )
    upstream, _ = portfolio.register_corpus_product(
        ProductSlug.parse("upstream"), "Upstream", OwnershipClass.UPSTREAM, "upstream"
    )
    with SqlTraustUnitOfWork(engine) as unit:
        seed = Seed(unit)
        first = seed.repository_ref(is_default=True)
        second_repo = seed.repository()
        seed.repository_ref(second_repo, is_default=True)
        branch = seed.repository_ref(second_repo, name="release", sha="b" * 40)
        unknown = seed.repository_ref(name=None, kind=None)
        seed.component(seed.release(owned), first)
        seed.component(seed.release(upstream), first)
        seed.component(seed.release(upstream), branch)
        unit.commit()
    first_views = report(context, first, T0, {}, {})
    report(context, branch, T0, {})
    report(context, unknown, T0, {})
    with SqlTraustUnitOfWork(engine) as unit:
        Seed(unit).decision(
            first_views[0].finding,
            validity="confirmed",
            evidence_grade="E1",
            actor=HUMAN,
            occurred_at=T0 + DAY,
            repository_ref_id=first.id,
        )
        unit.commit()

    rendered = context.services().insight.publish(
        ViewName.FINDINGS_TREND, ViewFilter(bucket=TimeBucket.WEEK)
    )
    built = rendered.model
    assert isinstance(built, FindingsTrend)
    assert sum(built.points[-1].open_by_severity.values()) == 4
    cuts = {cut.ownership: cut for cut in built.ownership_cuts}
    assert (cuts["owned"].open, cuts["upstream"].open, cuts[None].open) == (2, 3, 1)
    assert (cuts["owned"].risk_index, cuts["upstream"].risk_index, cuts[None].risk_index) == (
        12.0,
        18.0,
        6.0,
    )
    assert {
        (c.ownership, c.cohort, c.reported, c.dispositioned, c.coverage) for c in built.cohorts
    } == {
        ("owned", "HEAD", 1, 1, 100.0),
        ("upstream", "HEAD", 1, 1, 100.0),
        ("upstream", "branch", 1, 0, 0.0),
        (None, "unknown", 1, 0, 0.0),
    }
    html = Tables()
    html.feed(rendered.html)
    assert ("owned", "1", "1", "1", "2", "0", "2", "12.0") in html.rows
    assert ("upstream", "branch", "1", "0", "0.0") in html.rows
    assert "| owned | 1 | 1 | 1 | 2 | 0 | 2 | 12.0 |" in rendered.markdown
    assert "| upstream | branch | 1 | 0 | 0.0 |" in rendered.markdown
    exported = built.model_dump(mode="json")
    assert exported["points"][-1]["owasp_open"] == {"medium": 4}
    assert exported["assurance"]["proven"]["findings"] == 0
    scoped = trend(context, product_ids=(owned.id,))
    assert [(cut.ownership, cut.open) for cut in scoped.ownership_cuts] == [("owned", 2)]


def test_head_decisions_do_not_inflate_branch_reaudit_cohort_coverage(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        seed = Seed(unit)
        repository = seed.repository()
        head = seed.repository_ref(repository, is_default=True)
        branch = seed.repository_ref(repository, name="fix", sha="c" * 40)
        unit.commit()
    (claimed,) = report(context, head, T0, {})
    report(context, branch, T0 + 8 * DAY, {})
    with SqlTraustUnitOfWork(engine) as unit:
        Seed(unit).decision(
            claimed.finding,
            validity="confirmed",
            evidence_grade="E1",
            actor=HUMAN,
            repository_ref_id=head.id,
            occurred_at=T0 + DAY,
        )
        unit.commit()
    built = trend(context)
    assert sum(built.points[-1].open_by_severity.values()) == 1
    assert {(c.cohort, c.reported, c.dispositioned, c.coverage) for c in built.cohorts} == {
        ("HEAD", 1, 1, 100.0),
        ("branch", 1, 0, 0.0),
    }


def test_historical_recorded_vectors_are_read_without_rewriting_append_only_occurrences(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        ref = Seed(unit).repository_ref(is_default=True)
        unit.commit()
    (historical,) = report(context, ref, T0, {}, legacy_cvss=True)
    assert historical.occurrence.cvss_vector is None
    assert historical.occurrence.cvss_score is None
    before = context.services().assessment.report(historical.occurrence.assessment_id).payload
    built = trend(context)
    assert all(dict(point.owasp_open) == {"medium": 1} for point in built.points)
    assert [point.risk_index for point in built.points] == [6.0, 6.0, 6.0]
    assert built.assurance.claimed.risk_index == 6.0
    with SqlTraustUnitOfWork(engine) as unit:
        Seed(unit).decision(
            historical.finding,
            validity="confirmed",
            resolution="risk_accepted",
            evidence_grade="E1",
            actor=HUMAN,
            occurred_at=T0 + DAY,
        )
        unit.commit()
    accepted = trend(context)
    assert accepted.accepted[0].cvss_score == Decimal("6.0")
    assert accepted.points[-1].accepted_risk_index == 6.0
    persisted = context.services().findings.get(historical.finding.id).occurrence
    assert persisted.cvss_vector is None and persisted.cvss_score is None
    assert context.services().assessment.report(persisted.assessment_id).payload == before
