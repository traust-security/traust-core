from __future__ import annotations

from dataclasses import replace

from tests.v1.example.model import Task, TaskStatus
from tests.v1.example.repository import TaskUnitOfWork
from traust_core.v1.domain import HttpsRepoUrl


def enqueue(uow: TaskUnitOfWork, task_id: str, repo: HttpsRepoUrl) -> Task:
    task = Task(task_id, repo)
    with uow:
        uow.tasks.add(task)
        uow.commit()
    return task


def complete(uow: TaskUnitOfWork, task_id: str) -> Task:
    with uow:
        task = uow.tasks.get(task_id)
        done = replace(task, status=TaskStatus.DONE, attempts=(task.attempts or 0) + 1)
        uow.tasks.update(done)
        uow.commit()
    return done


def queued(uow: TaskUnitOfWork) -> list[Task]:
    with uow:
        return uow.tasks.list_by_status(TaskStatus.QUEUED)
