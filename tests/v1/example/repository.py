from __future__ import annotations

from typing import Any, Protocol

import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.example.model import Task, TaskStatus
from traust_core.v1.errors import ConflictError, NotFoundError
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.repositories import InMemoryUnitOfWork, SqlRepository, SqlUnitOfWork, UnitOfWork


class TaskRepository(Protocol):
    def add(self, task: Task) -> None: ...
    def get(self, task_id: str) -> Task: ...
    def list_by_status(self, status: TaskStatus) -> list[Task]: ...
    def update(self, task: Task) -> None: ...


class TaskUnitOfWork(UnitOfWork, Protocol):
    tasks: TaskRepository


metadata = sa.MetaData()

tasks = sa.Table(
    "example_tasks",
    metadata,
    sa.Column("task_id", sa.Text, primary_key=True),
    sa.Column("repo_host", sa.Text, nullable=False),
    sa.Column("repo_path", sa.Text, nullable=False),
    sa.Column("status", sa.Text, nullable=False),
    sa.Column("attempts", sa.Integer, nullable=True),
)


class SqlTaskRepository(SqlRepository):
    def add(self, task: Task) -> None:
        self._execute(f"add {task.task_id}", sa.insert(tasks).values(**_to_row(task)))

    def get(self, task_id: str) -> Task:
        stmt = sa.select(tasks).where(tasks.c.task_id == task_id)
        row = self._execute(f"get {task_id}", stmt).mappings().first()
        if row is None:
            raise NotFoundError(f"task {task_id}")
        return _to_task(row)

    def list_by_status(self, status: TaskStatus) -> list[Task]:
        stmt = sa.select(tasks).where(tasks.c.status == status).order_by(tasks.c.task_id)
        return [_to_task(r) for r in self._execute(f"list {status}", stmt).mappings()]

    def update(self, task: Task) -> None:
        stmt = (
            sa.update(tasks)
            .where(tasks.c.task_id == task.task_id)
            .values(status=task.status, attempts=task.attempts)
        )
        if self._execute(f"update {task.task_id}", stmt).rowcount == 0:
            raise NotFoundError(f"task {task.task_id}")


def _to_row(task: Task) -> dict[str, Any]:
    return {
        "task_id": task.task_id,
        "repo_host": task.repo.host,
        "repo_path": task.repo.path,
        "status": str(task.status),
        "attempts": task.attempts,
    }


def _to_task(row: Any) -> Task:
    return Task(
        row["task_id"],
        HttpsRepoUrl(row["repo_host"], row["repo_path"]),
        TaskStatus(row["status"]),
        row["attempts"],
    )


class SqlTaskUnitOfWork(SqlUnitOfWork):
    tasks: SqlTaskRepository

    def __init__(self, engine: Engine) -> None:
        super().__init__(engine)

    def _open_repositories(self) -> None:
        self.tasks = SqlTaskRepository(self.connection)


class InMemoryTaskRepository:
    def __init__(self) -> None:
        self._rows: dict[str, Task] = {}

    def add(self, task: Task) -> None:
        if task.task_id in self._rows:
            raise ConflictError(f"InMemoryTaskRepository: add {task.task_id}: duplicate")
        self._rows[task.task_id] = task

    def get(self, task_id: str) -> Task:
        try:
            return self._rows[task_id]
        except KeyError:
            raise NotFoundError(f"task {task_id}") from None

    def list_by_status(self, status: TaskStatus) -> list[Task]:
        return sorted(
            (t for t in self._rows.values() if t.status == status), key=lambda t: t.task_id
        )

    def update(self, task: Task) -> None:
        self.get(task.task_id)
        self._rows[task.task_id] = task


class InMemoryTaskUnitOfWork(InMemoryUnitOfWork):
    def __init__(self) -> None:
        super().__init__()
        self.tasks = InMemoryTaskRepository()
