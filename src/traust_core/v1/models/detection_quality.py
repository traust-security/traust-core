from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.base import Entity


class BenchmarkSuite(Entity):
    version: str


class BenchmarkRun(Entity):
    suite_id: UUID


class RulePack(Entity):
    name: str
