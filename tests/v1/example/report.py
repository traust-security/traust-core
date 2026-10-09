from __future__ import annotations

from tests.v1.example.model import Task, TaskStatus
from tests.v1.example.repository import TaskUnitOfWork
from traust_core.v1.providers.clock import Clock
from traust_core.v1.rendering import MarkdownRenderer, Report, Section, Table, publish
from traust_core.v1.repositories import ObjectKey, ObjectRef, ObjectStore


def build_report(tasks: list[Task], clock: Clock) -> Report:
    table = Table(
        columns=("Task", "Repo", "Attempts"),
        rows=tuple(
            (t.task_id, str(t.repo), "—" if t.attempts is None else str(t.attempts)) for t in tasks
        ),
    )
    return Report(
        title="Open tasks",
        generated_at=clock.now(),
        sections=(Section(heading=f"{len(tasks)} open", table=table),),
        sources=("repository:tasks",),
    )


def open_tasks_report(uow: TaskUnitOfWork, artifacts: ObjectStore, clock: Clock) -> ObjectRef:
    with uow:
        tasks = uow.tasks.list_by_status(TaskStatus.QUEUED)
    return publish(
        build_report(tasks, clock),
        MarkdownRenderer(),
        artifacts,
        ObjectKey.parse("reports/open-tasks.md"),
    )
