"""The scoreboard (traust-metrics collect_harness_metrics.py), dependency reach and the exposure
view's malicious-package lane (refresh-dashboards build_dependency_exposure.py), from traust
fabdb13, through Context on SQLite and Postgres."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.test_insight_domain_views import FakeExposure
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import DocumentError, ValidationError
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.dependencies import ExposureRollup, malicious_id
from traust_core.v1.models.insight import (
    AcceptedRisk,
    DependencyReach,
    EcosystemReach,
    PackageReach,
    QuickWin,
    RankedThreat,
    Scoreboard,
    SeverityCounts,
    ViewFilter,
    ViewName,
)
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.rendering import MarkdownRenderer
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services import insight as insight_module
from traust_core.v1.services.insight import ExposureView, FindingsTrendView

HUMAN = "human:analyst@example.com"
DAY = timedelta(days=1)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0 + 20 * DAY))
    ctx.__dict__["database"] = engine
    return ctx


def test_the_scoreboard_reads_its_numbers_off_the_other_views(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        s = Seed(uow)
        svc = s.repository(url="https://github.com/example-org/svc")
        s.repository(url="https://github.com/example-org/quiet")
        audit = s.assessment(s.repository_ref(svc), occurred_at=T0)
        leak = s.finding(svc, title="Hard-coded API key in config")
        s.occurrence(leak, audit, severity="critical")
        s.finding_external_ref(leak)
        fixed = s.finding(svc, title="Fixed")
        s.occurrence(fixed, audit, severity="high")
        s.decision(
            fixed, validity="confirmed", resolution="resolved", actor=HUMAN, occurred_at=T0 + DAY
        )
        uow.commit()

    later = ViewFilter(as_of=datetime.now(UTC) + DAY)  # Jira links are stamped by the database
    board = context.services().insight.build(ViewName.SCOREBOARD, later)

    assert isinstance(board, Scoreboard)
    assert (board.repositories, board.reported, board.dispositioned) == (2, 1, 1)
    assert board.open == SeverityCounts(critical=1)
    assert (board.repositories_with_critical, board.repositories_with_high) == (1, 0)
    assert (board.credential_leaks, board.resolved, board.filed) == (1, 1, 1)
    assert board.trend is not None and board.trend.coverage == 100.0
    assert (board.threat_models, board.threats, board.open_threats) == (0, 0, 0)
    md = context.services().insight.publish(ViewName.SCOREBOARD, later).markdown
    assert "| Repositories with an open critical | 1 |" in md
    assert "| Mean CVSS of open | 9.5 |" in md
    assert "| Findings filed in Jira | 1 |" in md


def test_an_empty_scoreboard_renders_dashes(context: Context) -> None:
    rendered = context.services().insight.publish(ViewName.SCOREBOARD, ViewFilter())
    assert rendered.stem == "traust-metrics"
    assert rendered.model.trend is None  # type: ignore[attr-defined]
    assert "| Ledger coverage, latest bucket (%) | — |" in rendered.markdown
    assert "| Top risk themes | — |" in rendered.markdown


def test_the_scoreboard_keeps_a_pinned_as_of(context: Context) -> None:
    pinned = T0 + 3 * DAY
    board = context.services().insight.build(ViewName.SCOREBOARD, ViewFilter(as_of=pinned))
    assert board.as_of == pinned  # type: ignore[attr-defined]


def test_dependency_reach_counts_repositories_per_package_and_ecosystem(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        s = Seed(uow)
        shared = s.package(ecosystem="npm", name="left-pad")
        go = s.package(ecosystem="go", name="example.com/lib")
        for n, packages in enumerate(((shared, go), (shared,))):
            sbom = s.sbom()
            for p in packages:
                s.dependency(sbom, p)
            repo = s.repository(url=f"https://github.com/example-org/r{n}")
            ref = s.repository_ref(repo, is_default=True, manifest_sbom_id=sbom.id)
            s.assessment(ref, kind=AssessmentKind.REPO_STATE, occurred_at=T0)
        bare = s.repository_ref(
            s.repository(url="https://github.com/example-org/bare"), is_default=True
        )
        s.assessment(bare, kind=AssessmentKind.REPO_STATE, occurred_at=T0)
        s.repository(url="https://github.com/example-org/never")
        uow.commit()

    reach = context.services().insight.build(ViewName.DEPENDENCY_REACH, ViewFilter())

    assert reach == DependencyReach(
        repositories=4,
        unmeasured=2,
        ecosystems=(
            EcosystemReach(ecosystem="npm", repositories=2, packages=1),
            EcosystemReach(ecosystem="go", repositories=1, packages=1),
        ),
        shared=(
            PackageReach(ecosystem="npm", name="left-pad", repositories=2),
            PackageReach(ecosystem="go", name="example.com/lib", repositories=1),
        ),
    )
    md = context.services().insight.publish(ViewName.DEPENDENCY_REACH, ViewFilter()).markdown
    assert "2 of 4 repositories have a manifest SBOM" in md
    assert "| npm | left-pad | 2 |" in md


def test_dependency_reach_of_nothing_says_so_and_takes_no_as_of(context: Context) -> None:
    md = context.services().insight.publish(ViewName.DEPENDENCY_REACH, ViewFilter()).markdown
    assert "_No manifests recorded._" in md
    with pytest.raises(ValidationError, match="no as_of"):
        context.services().insight.build(ViewName.DEPENDENCY_REACH, ViewFilter(as_of=T0))


@pytest.mark.parametrize(
    ("identifier", "malicious"),
    [("MAL-2026-1", True), ("GHSA-xxxx-yyyy-zzzz", False), ("CVE-2026-1", False), ("", False)],
)
def test_a_mal_id_is_malware_by_its_identifier(identifier: str, malicious: bool) -> None:
    assert malicious_id(identifier) is malicious


def test_the_exposure_view_lists_malicious_packages_apart() -> None:
    class WithMalware(FakeExposure):
        def summary(self, filter: object, group_by: object) -> list[ExposureRollup]:
            rows = super().summary(filter, group_by)  # type: ignore[arg-type]
            return [*rows, ExposureRollup(key="MAL-2026-7", commits=2, exposed=2, affected=2,
                                          by_classification={})]  # fmt: skip

    view = ExposureView(WithMalware())  # type: ignore[arg-type]
    md = MarkdownRenderer().render(view.report(view.build(ViewFilter()), T0)).decode()
    lane = md.split("## Malicious packages (MAL- advisories)")[1].split("## By product")[0]
    assert "| MAL-2026-7 | 2 | 2 | 2 |" in lane
    assert "advisory-a" not in lane
    empty = ExposureView(FakeExposure())  # type: ignore[arg-type]
    assert (
        "_No impact analyses recorded._"
        in MarkdownRenderer()
        .render(empty.report(empty.build(ViewFilter()), T0))
        .decode()
        .split("## Malicious packages (MAL- advisories)")[1]
    )


def test_the_scoreboard_survives_trend_drift_in_fields_it_never_reads(
    context: Context, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        s = Seed(uow)
        svc = s.repository(url="https://github.com/example-org/svc")
        s.occurrence(s.finding(svc), s.assessment(s.repository_ref(svc), occurred_at=T0))
        uow.commit()
    real = FindingsTrendView._accepted
    outside = AcceptedRisk(
        finding_id=uuid4(), repository_url="u", title="t", severity=None, rationale="x" * 161
    )

    def drifted(self: FindingsTrendView, *args: Any) -> list[AcceptedRisk]:
        return [*real(self, *args), outside]

    monkeypatch.setattr(FindingsTrendView, "_accepted", drifted)
    with pytest.raises(DocumentError):
        context.services().insight.build(ViewName.FINDINGS_TREND, ViewFilter())
    board = context.services().insight.build(ViewName.SCOREBOARD, ViewFilter())
    assert isinstance(board, Scoreboard) and board.trend is not None


def test_the_scoreboard_reports_an_unknown_risk_index_without_failing(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        s = Seed(uow)
        svc = s.repository(url="https://github.com/example-org/svc")
        audit = s.assessment(s.repository_ref(svc), occurred_at=T0)
        s.occurrence(s.finding(svc, title="Unweighable"), audit, severity="unrated")
        uow.commit()
    board = context.services().insight.build(ViewName.SCOREBOARD, ViewFilter())
    assert isinstance(board, Scoreboard) and board.trend is not None
    assert board.trend.risk_index is None
    md = context.services().insight.publish(ViewName.SCOREBOARD, ViewFilter()).markdown
    assert "| Mean CVSS of open | — |" in md
    assert "| Risk index (CVSS sum of open) | — |" in md


def test_the_scoreboard_survives_register_drift_in_fields_it_never_reads(
    context: Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = insight_module._quick_wins
    outside = QuickWin(
        repository_id=uuid4(), mitigation="m", effort="m", covers=("T1",), band="critical"
    )

    def drifted(threats: Sequence[RankedThreat]) -> tuple[QuickWin, ...]:
        return (*real(threats), outside)

    monkeypatch.setattr(insight_module, "_quick_wins", drifted)
    with pytest.raises(DocumentError):
        context.services().insight.build(ViewName.THREAT_REGISTER, ViewFilter())
    board = context.services().insight.build(ViewName.SCOREBOARD, ViewFilter())
    assert isinstance(board, Scoreboard) and board.threat_models == 0
