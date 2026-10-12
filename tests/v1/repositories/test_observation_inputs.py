import json

import pytest
import sqlalchemy as sa

from tests.v1.observation_support import HOSTS, NOW
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.artifacts import Severity
from traust_core.v1.models.assessment import AuditMetadata, AuditRecord
from traust_core.v1.models.findings import FindingCountRecord
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.analysis_results import (
    FileAuditMetadataRepository,
    InMemoryAuditMetadataRepository,
)
from traust_core.v1.repositories.assessment import (
    InMemoryAssessmentUnitOfWork,
    SqlAssessmentUnitOfWork,
)
from traust_core.v1.repositories.findings import InMemoryFindingUnitOfWork, SqlFindingUnitOfWork
from traust_core.v1.repositories.portfolio import (
    InMemoryInventoryUnitOfWork,
    SqlInventoryUnitOfWork,
)
from traust_core.v1.repositories.sql import create_database_engine
from traust_core.v1.services.assessment import AssessmentService

ROWS = [
    AuditRecord(
        repo_key="older",
        repo_url="https://github.com/O/R.git",
        report_path="old",
        audit_date="2026-01-01",
    ),
    AuditRecord(
        repo_key="newer",
        repo_url="https://github.com/o/r",
        report_path="new",
        audit_date="2026-02-01",
    ),
    AuditRecord(repo_key="missing-a"),
    AuditRecord(repo_key="missing-b"),
]
FINDINGS = [
    FindingCountRecord(repo_key="older", severity="high"),
    FindingCountRecord(repo_key="older", severity="critical", validity="true_positive"),
    FindingCountRecord(repo_key="older", severity="high", validity="hardening"),
    FindingCountRecord(repo_key="older", severity="high", resolution="resolved"),
    FindingCountRecord(repo_key="newer", severity="medium"),
]


@pytest.fixture(params=["memory", "sqlite"])
def inputs(request, tmp_path):
    if request.param == "memory":
        yield (
            InMemoryAssessmentUnitOfWork(ROWS),
            InMemoryFindingUnitOfWork(FINDINGS),
            InMemoryInventoryUnitOfWork(["https://github.com/o/new"]),
        )
        return
    engine = create_database_engine(f"sqlite:///{tmp_path}/projection.db")
    with engine.begin() as c:
        c.exec_driver_sql(
            "CREATE TABLE repos (repo_key TEXT, repo_url TEXT, report_path TEXT, "
            "audit_date TEXT, product TEXT, tree TEXT, ownership TEXT, report_kind TEXT, "
            "is_branch_audit INTEGER)"
        )
        c.exec_driver_sql(
            "CREATE TABLE findings (repo_key TEXT, severity TEXT, validity TEXT, resolution TEXT)"
        )
        c.exec_driver_sql("CREATE TABLE nodes (id TEXT)")
        for row in ROWS:
            c.execute(
                sa.text(
                    "INSERT INTO repos VALUES (:repo_key,:repo_url,:report_path,:audit_date,"
                    ":product,:tree,:ownership,'code-audit',0)"
                ),
                row.model_dump(),
            )
        for row in FINDINGS:
            c.execute(
                sa.text("INSERT INTO findings VALUES (:repo_key,:severity,:validity,:resolution)"),
                row.model_dump(),
            )
        c.exec_driver_sql("INSERT INTO nodes VALUES ('repo:github.com/o/new')")
    yield (
        SqlAssessmentUnitOfWork(engine),
        SqlFindingUnitOfWork(engine),
        SqlInventoryUnitOfWork(engine),
    )
    engine.dispose()


def test_selects_latest_normalized_audit_and_keeps_sibling_keys(inputs):
    audits, _, inventory = inputs
    reports = InMemoryAuditMetadataRepository(
        {"new": AuditMetadata(pinned_sha="abcdef1", lines_reviewed=100)}
    )
    assessment = AssessmentService(
        audits, reports=reports, inventory=inventory, clock=FixedClock(NOW), hosts=HOSTS
    )
    by_url = assessment.observation_target(repo_url="https://github.com/O/R")
    by_key = assessment.observation_target(repo_key="older")
    assert by_url == by_key
    assert by_url.repo_key == "newer"
    assert by_url.pinned_sha == "abcdef1"
    assert by_url.sibling_repo_keys == ("older",)
    assert assessment.observation_target(repo_key="missing-a").repo_key == "missing-a"
    assert assessment.observation_target(repo_key="missing-b").repo_key == "missing-b"


def test_inventory_membership_is_required_for_bootstrap(inputs):
    audits, _, inventory = inputs
    assessment = AssessmentService(audits, inventory=inventory, clock=FixedClock(NOW), hosts=HOSTS)
    assert assessment.observation_target(repo_url="https://github.com/o/new").has_audit is False
    with pytest.raises(NotFoundError):
        assessment.observation_target(repo_url="https://github.com/o/unknown")


def test_open_count_preserves_legacy_exclusions_and_empty_result(inputs):
    _, findings, _ = inputs
    with findings as uow:
        assert uow.findings.open_count("older", (Severity.CRITICAL, Severity.HIGH)) == 2
        assert uow.findings.open_count("newer", (Severity.CRITICAL, Severity.HIGH)) == 0
        assert uow.findings.open_count("missing", (Severity.CRITICAL, Severity.HIGH)) == 0
        assert uow.findings.open_count("older", ()) == 0


def test_legacy_metadata_skips_nonnumeric_loc_without_losing_sha(tmp_path):
    path = tmp_path / "audit.json"
    path.write_text(
        json.dumps(
            {
                "metadata": {
                    "commit": "abcdef1234567",
                    "additional": {
                        "lines_reviewed": "100",
                        "loc_reviewed": 12.5,
                        "companion_lanes": ["cloud-config-audit", 1, None],
                    },
                }
            }
        )
    )
    result = FileAuditMetadataRepository().audit_metadata(str(path))
    assert result == AuditMetadata(
        pinned_sha="abcdef1234567",
        lines_reviewed=12,
        companion_lanes=("cloud-config-audit",),
    )
    assert FileAuditMetadataRepository().audit_metadata(str(tmp_path / "absent")) == AuditMetadata()
