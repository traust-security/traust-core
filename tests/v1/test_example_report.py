from datetime import UTC, datetime

from tests.v1.example import services
from tests.v1.example.model import Task
from tests.v1.example.report import build_report, open_tasks_report
from tests.v1.example.repository import InMemoryTaskUnitOfWork
from traust_core.v1.domain import FixedClock, HttpsRepoUrl
from traust_core.v1.repositories import InMemoryObjectStore

CLOCK = FixedClock(datetime(2026, 10, 5, tzinfo=UTC))
REPO = HttpsRepoUrl("example.com", "org/repo")


def test_build_report_is_pure_and_shows_unmeasured_as_dash() -> None:
    report = build_report([Task("t2", REPO)], CLOCK)
    assert report.sections[0].table.rows == (("t2", "https://example.com/org/repo", "—"),)
    assert report.generated_at == CLOCK.now()


def test_job_reads_through_the_repository_renders_and_publishes() -> None:
    uow, artifacts = InMemoryTaskUnitOfWork(), InMemoryObjectStore()
    services.enqueue(uow, "t1", REPO)
    services.enqueue(uow, "t3", REPO)
    services.complete(uow, "t3")
    body = artifacts.get(open_tasks_report(uow, artifacts, CLOCK)).decode()
    assert "# Open tasks" in body
    assert "| t1 | https://example.com/org/repo | — |" in body
    assert "t3" not in body
