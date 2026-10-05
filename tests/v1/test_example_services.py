from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, database
from tests.v1.example import services
from tests.v1.example.model import Task, TaskStatus
from tests.v1.example.repository import InMemoryTaskUnitOfWork, SqlTaskUnitOfWork, TaskUnitOfWork
from traust_core.v1.domain import ConflictError, HttpsRepoUrl, NotFoundError

REPO = HttpsRepoUrl("example.com", "org/repo")


@pytest.fixture(params=["memory", *SQL_BACKENDS])
def uow(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[TaskUnitOfWork]:
    if request.param == "memory":
        yield InMemoryTaskUnitOfWork()
        return
    with database(request.param, tmp_path) as engine:
        yield SqlTaskUnitOfWork(engine)


def test_enqueued_task_is_listed_as_queued(uow: TaskUnitOfWork) -> None:
    services.enqueue(uow, "t1", REPO)
    assert [t.task_id for t in services.queued(uow)] == ["t1"]


def test_complete_marks_done_and_counts_attempt(uow: TaskUnitOfWork) -> None:
    services.enqueue(uow, "t1", REPO)
    done = services.complete(uow, "t1")
    assert (done.status, done.attempts) == (TaskStatus.DONE, 1)
    assert services.queued(uow) == []


def test_unknown_task_raises_not_found(uow: TaskUnitOfWork) -> None:
    with pytest.raises(NotFoundError):
        services.complete(uow, "missing")


def test_duplicate_add_raises_conflict(uow: TaskUnitOfWork) -> None:
    services.enqueue(uow, "t1", REPO)
    with pytest.raises(ConflictError):
        services.enqueue(uow, "t1", REPO)


def test_unmeasured_attempts_stay_none(uow: TaskUnitOfWork) -> None:
    services.enqueue(uow, "t1", REPO)
    assert services.queued(uow)[0].attempts is None


def test_sql_rolls_back_without_commit(engine: Engine) -> None:
    uow = SqlTaskUnitOfWork(engine)
    with uow:
        uow.tasks.add(Task("t1", REPO))
    assert services.queued(uow) == []


def test_same_repository_class_on_every_backend(engine: Engine) -> None:
    make: Callable[[], SqlTaskUnitOfWork] = lambda: SqlTaskUnitOfWork(engine)  # noqa: E731
    services.enqueue(make(), "t1", REPO)
    assert services.queued(make())[0].repo == REPO
