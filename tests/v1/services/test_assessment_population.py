"""AssessmentService.population and coverage: what was assessed, and what those audits missed.

Gap rules ported from traust's tests/test_build_coverage_gap_rollup.py; the corpus walk is
replaced by assessment rows on the default line and their recorded report documents.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.artifacts import ReportArtifact
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    ASSESSMENT_DEGRADED,
    AssessmentFilter,
    AssessmentKind,
    Coverage,
    GapSignal,
    ReportGap,
    report_gaps,
)
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import Repository, RepositoryRef
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    AssessmentLog,
    PublishSpec,
    PublishSpecs,
)
from traust_core.v1.services.assessment import AssessmentService

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed

SECURE_CODE = AssessmentKind.SECURE_CODE_CANONICAL.value
NOW = T0 + timedelta(days=30)
SEVERITIES = ("critical", "high", "medium", "low")


def report(additional: dict[str, Any] | None = None, negative: list[Any] | None = None) -> bytes:
    metadata: dict[str, Any] = {"date": "2026-10-01", "scope": "Whole repository review"}
    if additional is not None:
        metadata["additional"] = additional
    return ReportArtifact.from_document(
        {
            "title": "Security Assessment",
            "metadata": metadata,
            "executive_summary": {
                "prose": "Routine audit of the service; findings are listed below.",
                "severity_counts": dict.fromkeys((*SEVERITIES, "informational"), 0),
            },
            "severity_criteria": [
                {"level": s, "definition": "Synthetic severity definition"} for s in SEVERITIES
            ],
            "findings": [],
            "findings_summary": [
                {"severity": s, "count": 0, "finding_ids": []} for s in SEVERITIES
            ],
            "remediation_roadmap": [
                {"priority": "P3", "action": "Synthetic maintenance task", "addresses": ["all"]}
            ],
            "negative_results": negative or [],
        }
    ).payload


class Fleet:
    def __init__(self, uow: SqlTraustUnitOfWork, seed: Seed) -> None:
        self.uow, self.seed = uow, seed
        self.publisher = ArtifactPublisher(
            PublishSpecs(PublishSpec(ReportArtifact)), InMemoryObjectStore(), uow
        )
        self.service = AssessmentService(uow, clock=FixedClock(NOW), publisher=self.publisher)

    def repo(self) -> tuple[Repository, RepositoryRef, RepositoryRef]:
        repo = self.seed.repository()
        main = self.seed.repository_ref(repo, is_default=True)
        branch = self.seed.repository_ref(repo, name="release-1", sha="b" * 40)
        return repo, main, branch

    def audit(self, ref: RepositoryRef, day: int, doc: bytes | None = None, **kw: Any) -> UUID:
        values = {"kind": SECURE_CODE, "occurred_at": T0 + timedelta(days=day), **kw}
        a = self.seed.assessment(ref, **values)
        assert a.id is not None
        if doc is not None:
            published = self.publisher.publish_artifact(ReportArtifact.parse(doc))
            AssessmentLog(self.uow).attach(a.id, published.artifact_id, sha256_hex(doc))
        return a.id


@pytest.fixture
def fleet(uow: SqlTraustUnitOfWork, seed: Seed) -> Fleet:
    return Fleet(uow, seed)


def ids(*repos: Repository) -> list[UUID]:
    return [r.id for r in repos if r.id]


# --- report_gaps: the three signal tiers ------------------------------------------------------


@pytest.mark.parametrize(
    ("additional", "negative", "expected"),
    [
        ({}, [], []),
        (
            {
                "coverage_gaps": [
                    {"tool": "config-matrix", "system": "toml", "reason": "r", "count": 4}
                ]
            },
            [],
            [ReportGap("config-matrix", "toml", GapSignal.STRUCTURED, 4)],
        ),
        (
            {"coverage_gaps": [{"tool": "route-guards", "system": "koa", "reason": "r"}]},
            [],
            [ReportGap("route-guards", "koa", GapSignal.STRUCTURED)],
        ),
        (
            {"deterministic_steps": {"opengrep": "ran", "yara": "skipped: not installed"}},
            [],
            [
                ReportGap(
                    "yara", "pre-scan-skipped", GapSignal.STEPS, quote="skipped: not installed"
                )
            ],
        ),
        (
            {},
            [{"area": "config", "result": "toml/ini/properties config file — no v1 expander"}],
            [
                ReportGap(
                    "config-matrix",
                    "toml-ini-properties",
                    GapSignal.TEXT,
                    quote="toml/ini/properties config file — no v1 expander",
                )
            ],
        ),
        (
            {},
            [{"area": "routes", "result": "flask app routes UNENUMERATED"}],
            [
                ReportGap(
                    "route-guards", "flask", GapSignal.TEXT, quote="flask app routes UNENUMERATED"
                )
            ],
        ),
        (
            {},
            [{"area": "rules", "result": "opengrep pack has 0 TypeScript rules"}],
            [
                ReportGap(
                    "opengrep",
                    "javascript",
                    GapSignal.TEXT,
                    quote="opengrep pack has 0 TypeScript rules",
                )
            ],
        ),
        (
            {},
            [{"area": "helm", "result": "chart defaults resolve only at render time"}],
            [
                ReportGap(
                    "config-matrix",
                    "helm-render-gated",
                    GapSignal.TEXT,
                    quote="defaults resolve only at render time",
                )
            ],
        ),
        (
            {},
            [{"area": "operator", "result": "CRD-shaped config not expanded"}],
            [
                ReportGap(
                    "config-matrix",
                    "crd-operator-config",
                    GapSignal.TEXT,
                    quote="CRD-shaped config",
                )
            ],
        ),
        (
            {},
            [{"area": "sanitizers", "result": "sanitizer probes are Python-only"}],
            [
                ReportGap(
                    "sanitizer-probes",
                    "non-python",
                    GapSignal.TEXT,
                    quote="sanitizer probes are Python-only",
                )
            ],
        ),
        ({}, [{"area": "authz", "result": "No missing checks on any handler."}], []),
    ],
)
def test_report_gaps_reads_each_signal_tier(
    additional: dict[str, Any], negative: list[Any], expected: list[ReportGap]
) -> None:
    body = {"metadata": {"additional": additional}, "negative_results": negative}
    assert list(report_gaps(body)) == expected


@pytest.mark.parametrize(
    ("examined", "total", "ratio"), [(0, 0, 0.0), (1, 4, 0.25), (3, 3, 1.0), (0, 2, 0.0)]
)
def test_coverage_ratio_is_examined_over_total(examined: int, total: int, ratio: float) -> None:
    assert Coverage(examined=examined, total=total).ratio() == ratio


# --- coverage ---------------------------------------------------------------------------------

TOML = {"coverage_gaps": [{"tool": "config-matrix", "system": "toml", "reason": "r", "count": 3}]}
SKIPPED = {"deterministic_steps": {"yara": "skipped: not installed"}}


def test_coverage_ranks_families_from_each_repositorys_latest_default_audit(fleet: Fleet) -> None:
    (a, a_main, a_branch), (b, b_main, _), (c, c_main, _) = fleet.repo(), fleet.repo(), fleet.repo()
    fleet.audit(a_main, 1, report(SKIPPED))  # superseded by day 2
    fleet.audit(a_main, 2, report(TOML))
    fleet.audit(a_branch, 3, report(SKIPPED))  # a branch re-audit never counts
    fleet.audit(b_main, 1, report({**TOML, **SKIPPED}), status=ASSESSMENT_DEGRADED)
    fleet.audit(c_main, 1)  # no report recorded: in scope, not examined
    fleet.audit(c_main, 0, report(SKIPPED), kind=AssessmentKind.CONTAINER.value)

    found = fleet.service.coverage(AssessmentFilter(), ids(a, b, c))

    assert (found.examined, found.total) == (2, 3)
    assert [(g.tool, g.system, g.repositories, g.items) for g in found.gaps] == [
        ("config-matrix", "toml", 2, 6),
        ("yara", "pre-scan-skipped", 1, None),
    ]
    assert found.gaps[0].signals == {GapSignal.STRUCTURED: 2}
    assert set(found.gaps[0].example_repository_ids) == set(ids(a, b))


def test_coverage_of_another_kind_and_status(fleet: Fleet) -> None:
    (a, a_main, _), (b, b_main, _) = fleet.repo(), fleet.repo()
    fleet.audit(a_main, 1, report(SKIPPED), kind=AssessmentKind.CONTAINER.value)
    fleet.audit(b_main, 1, report(TOML), kind=AssessmentKind.CONTAINER.value, status="failed")
    found = fleet.service.coverage(
        AssessmentFilter(kind=AssessmentKind.CONTAINER, status=ASSESSMENT_COMPLETED), ids(a, b)
    )
    assert (found.examined, found.total) == (1, 1)
    assert [g.tool for g in found.gaps] == ["yara"]


def test_coverage_with_nothing_in_scope_is_empty(fleet: Fleet) -> None:
    repo, _, _ = fleet.repo()
    assert fleet.service.coverage(AssessmentFilter(), ids(repo)) == Coverage(examined=0, total=0)
    assert fleet.service.coverage(AssessmentFilter(), []) == Coverage(examined=0, total=0)


def test_coverage_needs_the_report_reader(uow: SqlTraustUnitOfWork) -> None:
    with pytest.raises(ConfigError, match="report reader"):
        AssessmentService(uow).coverage(AssessmentFilter(), [])


# --- population -------------------------------------------------------------------------------


def test_population_counts_default_line_and_branch_runs_per_repository_and_kind(
    fleet: Fleet,
) -> None:
    (a, a_main, a_branch), (b, _, b_branch), (never, _, _) = (
        fleet.repo(),
        fleet.repo(),
        fleet.repo(),
    )
    first = fleet.audit(a_main, 1)
    latest = fleet.audit(a_main, 2, status=ASSESSMENT_DEGRADED)
    fleet.audit(a_branch, 3)
    fleet.audit(a_main, 4, kind=AssessmentKind.THREAT_MODEL_CANONICAL.value)
    fleet.audit(b_branch, 1)
    fleet.audit(a_main, 40)  # after as_of
    unknown = uuid4()

    found = fleet.service.population(NOW, AssessmentFilter(), [*ids(a, b, never, a), unknown])

    rows = {(r.repository_id, r.kind): r for r in found.rows}
    assert set(rows) == {
        (a.id, SECURE_CODE),
        (a.id, AssessmentKind.THREAT_MODEL_CANONICAL.value),
        (b.id, SECURE_CODE),
    }
    a_audits = rows[a.id, SECURE_CODE]
    assert a_audits.latest is not None and a_audits.latest.id == latest != first
    assert (a_audits.default_line, a_audits.branches) == (2, 1)
    b_audits = rows[b.id, SECURE_CODE]
    assert (b_audits.latest, b_audits.default_line, b_audits.branches) == (None, 0, 1)
    assert set(found.never_assessed_repository_ids) == {never.id, unknown}
    assert found.as_of == NOW


@pytest.mark.parametrize(
    ("filter", "expected"),
    [
        (AssessmentFilter(kind=AssessmentKind.SECURE_CODE_CANONICAL), {(SECURE_CODE, 2)}),
        (
            AssessmentFilter(status=ASSESSMENT_COMPLETED),
            {(SECURE_CODE, 1), (AssessmentKind.THREAT_MODEL_CANONICAL.value, 1)},
        ),
        (AssessmentFilter(kind=AssessmentKind.FUZZ), set()),
    ],
)
def test_population_filters_by_kind_and_status(
    fleet: Fleet, filter: AssessmentFilter, expected: set[tuple[str, int]]
) -> None:
    repo, main, _ = fleet.repo()
    fleet.audit(main, 1)
    fleet.audit(main, 2, status=ASSESSMENT_DEGRADED)
    fleet.audit(main, 3, kind=AssessmentKind.THREAT_MODEL_CANONICAL.value)
    found = fleet.service.population(NOW, filter, ids(repo))
    assert {(r.kind, r.default_line) for r in found.rows} == expected
    assert found.never_assessed_repository_ids == (() if expected else (repo.id,))


def test_population_as_of_before_any_run_is_never_assessed(fleet: Fleet) -> None:
    repo, main, _ = fleet.repo()
    fleet.audit(main, 5)
    found = fleet.service.population(T0, AssessmentFilter(), ids(repo))
    assert (found.rows, found.never_assessed_repository_ids) == ((), (repo.id,))


@pytest.mark.parametrize(
    ("as_of", "filter", "match"),
    [
        (datetime(2026, 10, 5), AssessmentFilter(), "timezone-aware"),
        (T0, AssessmentFilter(repository_ref_id=uuid4()), "per repository"),
    ],
)
def test_population_rejects_a_naive_moment_or_a_commit_filter(
    fleet: Fleet, as_of: datetime, filter: AssessmentFilter, match: str
) -> None:
    with pytest.raises(ValidationError, match=match):
        fleet.service.population(as_of, filter, [])
