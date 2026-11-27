"""PR C: an advisory-backed finding counts at the selected authority's score and band, the
same on every door (views, census, rollup, trend, SARIF), through Context on SQLite and Postgres."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import RepositoryError
from traust_core.v1.models.assessment import Artifact
from traust_core.v1.models.cvss import AdvisoryCvss, CvssScore, CvssSource, score_of
from traust_core.v1.models.dependencies import AdvisoryMatch
from traust_core.v1.models.findings import FindingView
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.operations import FeedSnapshot
from traust_core.v1.models.vocabulary import Severity
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey
from traust_core.v1.services import exposure as exposure_module
from traust_core.v1.services.artifact_publishing import record_artifact
from traust_core.v1.services.exposure import ADVISORY_CVSS_FEED
from traust_core.v1.services.insight import _sarif_result

HUMAN = "human:analyst@example.com"
CVE = "CVE-2026-0101"
CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 7.5
MEDIUM = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 5.3


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as database:
        yield database


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0 + timedelta(days=1)))
    ctx.__dict__["database"] = engine
    return ctx


def stated(source: CvssSource, vector: str, document: str = f"nvd:{CVE}") -> CvssScore:
    score = score_of(source, vector, document=document, scored_by=str(source))
    assert score is not None
    return score


def reported(context: Context, *, severity: str | None = None, accepted: bool = False) -> tuple:
    """One open finding naming `CVE`, its report scoring it medium (5.3)."""
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repo = seed.repository(url="https://github.com/example-org/svc")
        advisory = seed.advisory(identifier=CVE)
        finding = seed.finding(
            repo, advisory_id=advisory.id, advisory_match=AdvisoryMatch.CONFIRMED
        )
        run = seed.assessment(seed.repository_ref(repo))
        seed.occurrence(
            finding, run, severity="medium", cvss_vector=MEDIUM, cvss_score=Decimal("5.3")
        )
        if severity is not None:
            seed.decision(finding, severity=severity, rationale="the owner re-rated it")
        if accepted:
            seed.decision(finding, validity="confirmed", resolution="risk_accepted", actor=HUMAN)
        uow.commit()
    assert advisory.id is not None and finding.id is not None
    return advisory.id, finding.id


def publish(context: Context, scores: dict[UUID, tuple[CvssScore, ...]]) -> None:
    """A daily `advisory-cvss` build, as `refresh_advisory_cvss` stores it."""
    raw = AdvisoryCvss(scores=scores).to_bytes()
    key = ObjectKey.parse(f"feeds/{ADVISORY_CVSS_FEED}/{sha256_hex(raw)}.json")
    ref = context.object_store.put(key, raw)
    with SqlTraustUnitOfWork(context.database) as uow:
        artifact = record_artifact(uow, Artifact(digest=ref.sha256, kind="feed", uri=str(key)))
        assert artifact.id is not None
        uow.feed_snapshots.add(
            FeedSnapshot(
                run_order_id=None, artifact_id=artifact.id, feed=ADVISORY_CVSS_FEED, retrieved_at=T0
            )
        )
        uow.commit()


def view(context: Context, finding_id: UUID) -> FindingView:
    return context.services().findings.get(finding_id)


def test_an_advisory_backed_finding_counts_at_the_selected_authority(context: Context) -> None:
    advisory_id, finding_id = reported(context)
    publish(
        context,
        {
            advisory_id: (
                stated(CvssSource.NIST, CRITICAL),
                stated(CvssSource.CNA, CRITICAL, f"cve-list:{CVE}"),
            )
        },
    )
    shown = view(context, finding_id)
    assert shown.cvss is not None and shown.cvss.selected is not None
    assert shown.effective_severity is Severity.CRITICAL  # the report said medium
    assert (shown.cvss.basis, shown.cvss.selected.source) == ("authority", CvssSource.NIST)
    assert [s.source for s in shown.cvss.authority_scores] == [CvssSource.NIST, CvssSource.CNA]
    assert (shown.cvss_score, shown.cvss_source) == (Decimal("9.8"), CvssSource.NIST)
    assert shown.cvss.score == Decimal("5.3") and not shown.cvss.conflict  # the report's own
    first = shown.first_reported_at
    assert first is not None and shown.sla_due == first + timedelta(days=30)  # critical's SLA


def test_with_no_build_the_report_scores_it_as_before(context: Context) -> None:
    _, finding_id = reported(context)
    shown = view(context, finding_id)
    assert shown.cvss is not None and shown.cvss.basis == "computed"
    assert shown.effective_severity is Severity.MEDIUM and shown.cvss.authority_scores == ()
    assert shown.cvss.selected is not None and shown.cvss.selected.source is CvssSource.SCANNER
    assert (shown.cvss_score, shown.cvss_source) == (Decimal("5.3"), CvssSource.SCANNER)


def test_a_severity_decision_stands_over_the_authority_band(context: Context) -> None:
    advisory_id, finding_id = reported(context, severity="low")
    publish(context, {advisory_id: (stated(CvssSource.NIST, CRITICAL),)})
    shown = view(context, finding_id)
    assert shown.cvss is not None and shown.cvss.selected is not None
    assert (shown.effective_severity, shown.cvss.basis) == (Severity.LOW, "judgement")
    assert shown.cvss.selected.source is CvssSource.NIST and shown.cvss_score == Decimal("9.8")


@pytest.mark.parametrize(("cna", "conflict"), [(HIGH, True), (CRITICAL, False)])
def test_same_version_authority_bands_that_differ_are_a_conflict(
    context: Context, cna: str, conflict: bool
) -> None:
    advisory_id, finding_id = reported(context)
    publish(
        context,
        {
            advisory_id: (
                stated(CvssSource.NIST, CRITICAL),
                stated(CvssSource.CNA, cna, f"cve-list:{CVE}"),
            )
        },
    )
    shown = view(context, finding_id)
    assert shown.cvss is not None and shown.cvss.conflict is conflict


def test_the_rollup_and_its_stored_census_name_the_authority_and_agree(context: Context) -> None:
    advisory_id, _ = reported(context)
    publish(context, {advisory_id: (stated(CvssSource.NIST, CRITICAL),)})
    insight = context.services().insight
    folded = insight.build(ViewName.FINDINGS_ROLLUP, ViewFilter())  # contract-checked
    insight.record_builds()
    served = insight.serve(ViewName.FINDINGS_ROLLUP, ViewFilter())
    assert served.built_at is not None  # the census path, not the fold
    for model in (folded, served.model):
        [top] = model.top  # type: ignore[attr-defined]
        assert (top.severity, top.cvss_score, top.cvss_source) == (
            Severity.CRITICAL,
            Decimal("9.8"),
            CvssSource.NIST,
        )
        assert model.total.open.critical == 1  # type: ignore[attr-defined]


def test_the_trends_accepted_register_names_the_authority(context: Context) -> None:
    advisory_id, _ = reported(context, accepted=True)
    publish(context, {advisory_id: (stated(CvssSource.NIST, CRITICAL),)})
    trend = context.services().insight.build(ViewName.FINDINGS_TREND, ViewFilter())
    [accepted] = trend.accepted  # type: ignore[attr-defined]
    assert (accepted.cvss_score, accepted.cvss_source) == (Decimal("9.8"), CvssSource.NIST)


def test_sarif_carries_the_selected_statement_and_its_source(context: Context) -> None:
    advisory_id, finding_id = reported(context)
    publish(context, {advisory_id: (stated(CvssSource.NIST, CRITICAL),)})
    result = _sarif_result(view(context, finding_id), 0)
    assert result["properties"]["traust/cvss"] == {
        "vector": CRITICAL,
        "score": "9.8",
        "source": "nist",
    }
    assert result["properties"]["security-severity"] == "9.5"  # critical's


def test_a_report_with_a_vector_and_no_score_stays_unscored(context: Context) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        finding = seed.finding(repo)
        seed.occurrence(finding, seed.assessment(seed.repository_ref(repo)), cvss_vector=CRITICAL)
        uow.commit()
    assert finding.id is not None
    shown = view(context, finding.id)
    assert shown.cvss is not None and shown.cvss.selected is None  # nothing the scanner stated
    assert (shown.cvss_score, shown.cvss_source) == (None, None)
    assert (shown.effective_severity, shown.cvss.basis) == (Severity.CRITICAL, "computed")


def test_one_sources_differing_statements_are_no_conflict(context: Context) -> None:
    advisory_id, finding_id = reported(context)
    publish(
        context,
        {
            advisory_id: (
                stated(CvssSource.NIST, CRITICAL),
                stated(CvssSource.NIST, HIGH, "nvd:CVE-2026-0102"),  # the advisory's second CVE
            )
        },
    )
    shown = view(context, finding_id)
    assert shown.cvss is not None and not shown.cvss.conflict


def test_a_store_outage_reading_the_build_leaves_findings_as_before(
    context: Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    advisory_id, finding_id = reported(context)
    publish(context, {advisory_id: (stated(CvssSource.NIST, CRITICAL),)})

    def outage(*args: object) -> bytes:
        raise RepositoryError("the store is unreachable", operation="get")

    monkeypatch.setattr(exposure_module, "stored_bytes", outage)
    shown = view(context, finding_id)
    assert (shown.effective_severity, shown.cvss_score) == (Severity.MEDIUM, Decimal("5.3"))
    monkeypatch.undo()
    assert view(context, finding_id).effective_severity is Severity.CRITICAL  # never kept
