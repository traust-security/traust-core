from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from traust_core.v1.models.values import HttpsRepoUrl


class TaskStatus(StrEnum):
    QUEUED = "queued"
    DONE = "done"


@dataclass(frozen=True, slots=True)
class Task:
    task_id: str
    repo: HttpsRepoUrl
    status: TaskStatus = TaskStatus.QUEUED
    attempts: int | None = None
