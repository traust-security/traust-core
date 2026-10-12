from __future__ import annotations

from pathlib import Path
from typing import Protocol

from traust_core.v1.models.base import Dto
from traust_core.v1.models.portfolio import Designation, DesignationRecord


class DesignationRepository(Protocol):
    def entries(self) -> list[DesignationRecord]: ...


class _Entry(Dto):
    match: str | None = None
    exposure: str | None = None


class _File(Dto):
    designations: tuple[_Entry, ...] = ()


class FileDesignationRepository:
    def __init__(self, path: Path) -> None:
        self._path = path

    def entries(self) -> list[DesignationRecord]:
        try:
            document = _File.model_validate_json(self._path.read_bytes())
        except (OSError, ValueError):
            return []
        return [
            DesignationRecord(match=row.match, designation=Designation(row.exposure))
            for row in document.designations
            if row.match and row.exposure in set(Designation)
        ]


class InMemoryDesignationRepository:
    def __init__(self, rows: list[DesignationRecord] | None = None) -> None:
        self.rows = list(rows or [])

    def entries(self) -> list[DesignationRecord]:
        return list(self.rows)
