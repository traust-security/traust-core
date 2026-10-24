from __future__ import annotations

from collections.abc import Collection
from uuid import UUID

from traust_core.v1.errors import ConflictError
from traust_core.v1.models.findings import Finding, FindingExternalRef
from traust_core.v1.repositories.contract import TraustUnitOfWork


class FindingRecords:
    """A finding and its links to other systems, as stored (no fold), on the caller's unit of work:
    the door services outside findings read and link them through. Needs only the findings uow, so
    any service can be built with it (attestation and exposure are built without FindingService)."""

    def __init__(self, uow: TraustUnitOfWork) -> None:
        self._uow = uow

    def get(self, finding_id: UUID) -> Finding:
        with self._uow as uow:
            return uow.findings.get(finding_id)

    def ids_for_repository(self, repository_id: UUID) -> list[UUID]:
        with self._uow as uow:
            return [f.id for f in uow.findings.list_for_repository(repository_id) if f.id]

    def external_refs(
        self, finding_ids: Collection[UUID], system: str | None = None
    ) -> list[FindingExternalRef]:
        """The findings' links to other systems (tickets, comments), only `system`'s when given."""
        if not finding_ids:
            return []
        with self._uow as uow:
            if system is None:
                return [
                    r for f in finding_ids for r in uow.finding_external_refs.list_for_finding(f)
                ]
            return uow.finding_external_refs.list_for_findings(finding_ids, system)

    def link_external(self, finding_id: UUID, system: str, ref: str) -> bool:
        """Link the finding to `system`'s `ref` in the caller's work; False if already linked."""
        with self._uow as uow:
            known = uow.finding_external_refs.list_for_ref(system, ref)
            if any(r.finding_id == finding_id for r in known):
                return False
            uow.finding_external_refs.add(
                FindingExternalRef(finding_id=finding_id, system=system, ref=ref)
            )
            return True

    def link_advisory(self, finding_id: UUID, advisory_id: UUID, match: str) -> Finding:
        """Record the advisory the finding became, in the caller's work; ConflictError when it
        already names one."""
        with self._uow as uow:
            finding = uow.findings.get(finding_id)
            if finding.advisory_id is not None:
                raise ConflictError(
                    f"finding {finding_id} already names advisory {finding.advisory_id}"
                )
            return uow.findings.update(
                finding.model_copy(update={"advisory_id": advisory_id, "advisory_match": match})
            )
