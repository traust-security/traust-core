from __future__ import annotations

from typing import Protocol

from traust_core.v1.repositories.unit_of_work import UnitOfWork


class AttestationRepository(Protocol): ...


class AttestationUnitOfWork(UnitOfWork, Protocol):
    attestations: AttestationRepository
