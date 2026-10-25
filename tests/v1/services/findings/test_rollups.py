"""FindingService.summary and timeline on SQLite and Postgres: the findings-db views (v_open,
v_hardening, CWE / severity rollups) and build_trends' series, ported from traust fabdb13."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.findings.test_reads import T0, engine, service  # noqa: F401
from traust_core.v1.models.common import TimeBucket
from traust_core.v1.models.findings import (
    Decision,
    Finding,
    FindingDimension,
    FindingFilter,
    FindingRollup,
)
from traust_core.v1.models.inventory import Repository, RepositoryRef
from traust_core.v1.models.vocabulary import Severity
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

HUMAN = "human:alice@example.com"
NOV = datetime(2026, 11, 1, tzinfo=UTC)


@dataclass
class Repo:
    engine: Engine
    repository: Repository
    ref: RepositoryRef

    @property
    def filter(self) -> FindingFilter:
        assert self.repository.id is not None
        return FindingFilter(repository_id=self.repository.id)

    def reported(
        self,
        day: int = 0,
        severity: str = "high",
        cwes: tuple[str, ...] = (),
        labels: tuple[tuple[str, str], ...] = (),
        assessor: str = "skill:audit",
        **occurrence: Any,
    ) -> Finding:
        with SqlTraustUnitOfWork(self.engine) as uow:
            seed = Seed(uow)
            finding = seed.finding(self.repository, fingerprint=str(uuid4()))
            run = seed.assessment(self.ref, assessor=assessor, occurred_at=T0 + timedelta(days=day))
            seed.occurrence(finding, run, severity=severity, **occurrence)
            for identifier in cwes:
                seed.finding_cwe(finding, uow.cwes.get_or_add(seed.new_cwe(identifier=identifier)))
            for taxonomy, label in labels:
                seed.finding_label(finding, taxonomy=taxonomy, label=label)
            uow.commit()
        return finding

    def judged(self, finding: Finding, day: int, **decision: Any) -> Decision:
        """A person's decision on `day`; nothing judged unless named."""
        values: dict[str, Any] = {"validity": None, "actor": HUMAN}
        with SqlTraustUnitOfWork(self.engine) as uow:
            said = Seed(uow).decision(
                finding,
                statement_key=str(uuid4()),
                occurred_at=T0 + timedelta(days=day),
                **{**values, **decision},
            )
            uow.commit()
        return said

    def assessed(self, finding: Finding, kind: str, day: int, **decision: Any) -> Decision:
        """A machine decision made by an assessment of `kind` (triage, validation, ...)."""
        with SqlTraustUnitOfWork(self.engine) as uow:
            at = T0 + timedelta(days=day)
            run = Seed(uow).assessment(self.ref, kind=kind, occurred_at=at)
            uow.commit()
        return self.judged(finding, day, actor=None, assessment_id=run.id, **decision)


def new_repo(engine: Engine) -> Repo:  # noqa: F811
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = seed.repository(url=f"https://github.com/org/{uuid4()}")
        ref = seed.repository_ref(repository)
        uow.commit()
    return Repo(engine, repository, ref)


@pytest.fixture
def repo(engine: Engine) -> Repo:  # noqa: F811
    return new_repo(engine)


def by_key(rollups: list[FindingRollup]) -> dict[str | None, FindingRollup]:
    return {r.key: r for r in rollups}


def severities(**counts: int) -> dict[Severity, int]:
    return {s: counts.get(s.value, 0) for s in Severity}


# summary
def test_summary_counts_each_finding_in_one_state(repo: Repo) -> None:
    open_high = repo.reported(severity="high")
    repo.reported(severity="critical")
    hardening = repo.reported(severity="high")
    repo.judged(hardening, 1, validity="hardening")
    refuted = repo.reported(severity="high")
    repo.judged(refuted, 1, validity="false_positive")
    fixed = repo.reported(severity="medium")
    repo.judged(fixed, 2, resolution="resolved")
    accepted = repo.reported(severity="high")
    repo.judged(accepted, 2, resolution="risk_accepted")
    repo.judged(open_high, 2, resolution="fix_in_progress")

    rollups = service(repo.engine).summary(repo.filter, FindingDimension.SEVERITY)

    assert [r.key for r in rollups] == ["high", "critical", "medium"]
    high = by_key(rollups)["high"]
    assert (high.findings, high.open, high.hardening, high.false_positives, high.accepted) == (
        4,
        1,
        1,
        1,
        1,
    )
    assert high.open_by_severity == severities(high=1)
    assert by_key(rollups)["medium"].resolved == 1
    assert by_key(rollups)["critical"].open_by_severity == severities(critical=1)


def test_summary_groups_by_the_re_rated_severity(repo: Repo) -> None:
    finding = repo.reported(severity="medium")
    repo.judged(finding, 1, severity="critical")
    (rollup,) = service(repo.engine).summary(repo.filter, FindingDimension.SEVERITY)
    assert (rollup.key, rollup.open_by_severity) == ("critical", severities(critical=1))


@pytest.mark.parametrize(
    ("dimension", "expected"),
    [
        (FindingDimension.CWE, {"CWE-20": 1, "CWE-89": 1, None: 1}),
        (FindingDimension.CATEGORY, {"injection": 1, None: 2}),
        (FindingDimension.LABEL, {"category:injection": 1, "attack:T1190": 2, None: 1}),
        (FindingDimension.ORIGIN, {"semgrep": 1, "skill:audit": 2}),
        (FindingDimension.VALIDITY, {"false_positive": 1, None: 2}),
        (FindingDimension.RESOLUTION, {None: 3}),
    ],
)
def test_summary_groups_by_each_dimension(
    repo: Repo, dimension: FindingDimension, expected: dict[str | None, int]
) -> None:
    repo.reported(
        cwes=("CWE-79", "CWE-20"),
        labels=(("category", "injection"), ("attack", "T1190")),
    )
    refuted = repo.reported(cwes=("CWE-89",), labels=(("attack", "T1190"),), assessor="semgrep")
    repo.judged(refuted, 1, validity="false_positive")
    repo.reported()

    rollups = service(repo.engine).summary(repo.filter, dimension)

    assert {r.key: r.findings for r in rollups} == expected


def test_summary_by_repository_is_the_filtered_repository(repo: Repo) -> None:
    repo.reported()
    repo.reported()
    (rollup,) = service(repo.engine).summary(repo.filter, FindingDimension.REPOSITORY)
    assert (rollup.key, rollup.findings) == (str(repo.repository.id), 2)


def test_summary_origin_is_the_first_report_not_the_latest(repo: Repo) -> None:
    finding = repo.reported(assessor="semgrep")
    with SqlTraustUnitOfWork(repo.engine) as uow:
        seed = Seed(uow)
        later = seed.assessment(repo.ref, assessor="skill:audit", occurred_at=T0 + timedelta(1))
        seed.occurrence(finding, later)
        uow.commit()
    (rollup,) = service(repo.engine).summary(repo.filter, FindingDimension.ORIGIN)
    assert rollup.key == "semgrep"


def test_summary_narrows_by_the_filter_and_stands_at_as_of(repo: Repo) -> None:
    fixed = repo.reported()
    repo.judged(fixed, 5, resolution="resolved")
    repo.reported(day=10)
    findings = service(repo.engine)

    (open_now,) = findings.summary(
        repo.filter.model_copy(update={"open": True}), FindingDimension.SEVERITY
    )
    assert (open_now.findings, open_now.resolved) == (1, 0)

    (then,) = findings.summary(
        repo.filter.model_copy(update={"as_of": T0 + timedelta(days=3)}),
        FindingDimension.SEVERITY,
    )
    assert (then.findings, then.open, then.resolved) == (1, 1, 0)


def test_summary_of_a_repository_without_findings_is_empty(repo: Repo) -> None:
    assert service(repo.engine).summary(repo.filter, FindingDimension.SEVERITY) == []


# timeline
def test_timeline_replays_month_by_month(repo: Repo) -> None:
    fixed = repo.reported(severity="high", cvss_score=Decimal("7.5"))
    repo.reported(severity="critical")
    repo.judged(fixed, 35, resolution="resolved")

    october, november = service(repo.engine).timeline(repo.filter, TimeBucket.MONTH)

    assert october.bucket == T0
    assert (october.new, october.resolved, october.mttr_days) == (2, 0, None)
    assert october.open_by_severity == severities(high=1, critical=1)
    assert october.risk_index == 17.0  # 7.5 scored + 9.5 critical band midpoint
    assert november.bucket == NOV
    assert (november.new, november.resolved, november.mttr_days) == (0, 1, 35.0)
    assert november.open_by_severity == severities(critical=1)
    assert november.risk_index == 9.5


@pytest.mark.parametrize(
    ("bucket", "starts"),
    [
        (TimeBucket.DAY, [T0 + timedelta(days=d) for d in range(5)]),
        # 2026-10-01 is a Thursday: ISO weeks start on the Monday before
        (TimeBucket.WEEK, [datetime(2026, 9, 28, tzinfo=UTC), datetime(2026, 10, 5, tzinfo=UTC)]),
        (TimeBucket.MONTH, [T0]),
    ],
)
def test_timeline_buckets_run_from_the_first_report_to_the_last_activity(
    repo: Repo, bucket: TimeBucket, starts: list[datetime]
) -> None:
    finding = repo.reported()
    repo.judged(finding, 4, validity="confirmed")
    assert [p.bucket for p in service(repo.engine).timeline(repo.filter, bucket)] == starts


def test_timeline_counts_flows_once_and_stocks_every_bucket(repo: Repo) -> None:
    refuted = repo.reported()
    repo.judged(refuted, 1, validity="false_positive")
    accepted = repo.reported()
    repo.judged(accepted, 1, resolution="risk_accepted")
    hardening = repo.reported()
    repo.judged(hardening, 1, validity="hardening")
    repo.reported(day=32)

    october, november = service(repo.engine).timeline(repo.filter, TimeBucket.MONTH)

    assert (october.false_positives, october.accepted, october.hardening) == (1, 1, 1)
    assert (november.false_positives, november.accepted, november.hardening) == (0, 1, 1)
    assert (october.new, november.new) == (3, 1)
    assert october.open_by_severity == severities()
    assert november.open_by_severity == severities(high=1)


def test_timeline_a_regression_reopens_and_the_next_fix_resolves_again(repo: Repo) -> None:
    finding = repo.reported()
    repo.judged(finding, 3, resolution="resolved")
    repo.judged(finding, 33, resolution="regression_introduced")
    repo.judged(finding, 65, resolution="resolved")

    october, november, december = service(repo.engine).timeline(repo.filter, TimeBucket.MONTH)

    assert (october.resolved, october.regressions, october.mttr_days) == (1, 0, 3.0)
    assert (november.resolved, november.regressions, november.mttr_days) == (0, 1, None)
    assert november.open_by_severity == severities(high=1)
    # MTTR runs from the first report, as build_trends measured it
    assert (december.resolved, december.regressions, december.mttr_days) == (1, 0, 65.0)


def test_timeline_resolution_flips_inside_one_bucket_count_the_end_state(repo: Repo) -> None:
    finding = repo.reported()
    repo.judged(finding, 3, resolution="resolved")
    repo.judged(finding, 5, resolution="regression_introduced")
    (october,) = service(repo.engine).timeline(repo.filter, TimeBucket.MONTH)
    assert (october.resolved, october.regressions) == (0, 1)
    assert october.open_by_severity == severities(high=1)


def test_timeline_skips_a_regression_a_restatement_replaced(repo: Repo) -> None:
    finding = repo.reported()
    wrong = repo.judged(finding, 2, resolution="regression_introduced")
    repo.judged(
        finding,
        3,
        resolution="open",
        restates_id=wrong.id,
        reason="operator_error",
        ticket="SEC-1",
        rationale="the regression was filed on the wrong finding",
    )
    (october,) = service(repo.engine).timeline(repo.filter, TimeBucket.MONTH)
    assert october.regressions == 0


def test_timeline_counts_decisions_within_and_weighs_accepted_risk_apart(repo: Repo) -> None:
    accepted = repo.reported(severity="high", cvss_score=Decimal("7.5"))
    repo.judged(accepted, 1, validity="confirmed")
    repo.judged(accepted, 2, resolution="risk_accepted")
    refuted = repo.reported(severity="critical")
    repo.judged(refuted, 33, validity="false_positive")

    october, november = service(repo.engine).timeline(repo.filter, TimeBucket.MONTH)

    assert (october.decisions, october.risk_index, october.accepted_risk_index) == (2, 9.5, 7.5)
    assert (november.decisions, november.false_positives) == (1, 1)
    assert (november.risk_index, november.accepted_risk_index) == (0.0, 7.5)


def test_timeline_stops_at_as_of(repo: Repo) -> None:
    finding = repo.reported()
    repo.judged(finding, 35, resolution="resolved")
    as_of = T0 + timedelta(days=20)
    points = service(repo.engine).timeline(
        repo.filter.model_copy(update={"as_of": as_of}), TimeBucket.MONTH
    )
    assert [(p.bucket, p.resolved) for p in points] == [(T0, 0)]


def test_timeline_narrows_by_the_filter_at_each_bucket(repo: Repo) -> None:
    fixed = repo.reported()
    repo.reported()
    repo.judged(fixed, 35, resolution="resolved")
    october, november = service(repo.engine).timeline(
        repo.filter.model_copy(update={"open": True}), TimeBucket.MONTH
    )
    assert (october.new, sum(october.open_by_severity.values())) == (2, 2)
    assert (november.resolved, sum(november.open_by_severity.values())) == (0, 1)


def test_timeline_of_a_repository_without_findings_is_empty(repo: Repo) -> None:
    assert service(repo.engine).timeline(repo.filter, TimeBucket.MONTH) == []


def test_a_finding_never_reported_is_in_no_rollup_or_series(repo: Repo) -> None:
    repo.reported()
    with SqlTraustUnitOfWork(repo.engine) as uow:
        Seed(uow).finding(repo.repository, fingerprint=str(uuid4()))
        uow.commit()
    findings = service(repo.engine)
    (rollup,) = findings.summary(repo.filter, FindingDimension.SEVERITY)
    assert rollup.findings == 1
    (october,) = findings.timeline(repo.filter, TimeBucket.MONTH)
    assert october.new == 1
