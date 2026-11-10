"""Every contract table spec, and one unit of work over all of them.

Section protocols (InventoryUnitOfWork, FindingsUnitOfWork, ...) are what a
service declares it needs; SqlTraustUnitOfWork satisfies every one of them on
a single connection, so work that spans sections - intake writes an
assessment, occurrences, findings and decisions - commits or rolls back as
one transaction. Services that collaborate share the same instance.
"""

from __future__ import annotations

from collections.abc import Collection
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.engine import Connection

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.assessment import Assessment
from traust_core.v1.models.findings import FindingExternalRef
from traust_core.v1.repositories import traust_ledger, traust_ops
from traust_core.v1.repositories.sql import SqlRepository
from traust_core.v1.repositories.tables import SqlTablesUnitOfWork, TableFactory, TableSpec
from traust_core.v1.repositories.traust import assessments, dependencies, findings, inventory
from traust_core.v1.repositories.traust.assessments import AssessmentsUnitOfWork
from traust_core.v1.repositories.traust.assessments.assessment import ASSESSMENT
from traust_core.v1.repositories.traust.dependencies import DependenciesUnitOfWork
from traust_core.v1.repositories.traust.findings import FindingsUnitOfWork
from traust_core.v1.repositories.traust.inventory import InventoryUnitOfWork
from traust_core.v1.repositories.traust.inventory.repository_ref import REPOSITORY_REF
from traust_core.v1.repositories.traust_ledger import LedgerUnitOfWork
from traust_core.v1.repositories.traust_ops import OpsUnitOfWork

CONTRACT_TABLES: tuple[TableSpec, ...] = (
    *inventory.TABLES,
    *dependencies.TABLES,
    *assessments.TABLES,
    *findings.TABLES,
    *traust_ops.TABLES,
    *traust_ledger.TABLES,
)


class TraustUnitOfWork(
    InventoryUnitOfWork,
    DependenciesUnitOfWork,
    AssessmentsUnitOfWork,
    FindingsUnitOfWork,
    OpsUnitOfWork,
    LedgerUnitOfWork,
    Protocol,
):
    """Every repository, one transaction."""


class SqlTraustUnitOfWork(SqlTablesUnitOfWork):
    def _open_repositories(self) -> None:
        conn, tables = self.connection, self.tables
        self.products = inventory.SqlProductRepository(conn, tables)
        self.releases = inventory.SqlReleaseRepository(conn, tables)
        self.components = inventory.SqlComponentRepository(conn, tables)
        self.repositories = inventory.SqlRepositoryRepository(conn, tables)
        self.repository_refs = inventory.SqlRepositoryRefRepository(conn, tables)
        self.teams = inventory.SqlTeamRepository(conn, tables)
        self.ownerships = inventory.SqlOwnershipRepository(conn, tables)
        self.packages = dependencies.SqlPackageRepository(conn, tables)
        self.sboms = dependencies.SqlSbomRepository(conn, tables)
        self.dependencies = dependencies.SqlDependencyRepository(conn, tables)
        self.images = dependencies.SqlImageRepository(conn, tables)
        self.advisories = dependencies.SqlAdvisoryRepository(conn, tables)
        self.advisory_packages = dependencies.SqlAdvisoryPackageRepository(conn, tables)
        self.assessments = assessments.SqlAssessmentRepository(conn, tables)
        self.assessment_reads = AssessmentReads(conn, tables)
        self.artifacts = assessments.SqlArtifactRepository(conn, tables)
        self.occurrences = assessments.SqlOccurrenceRepository(conn, tables)
        self.locations = assessments.SqlLocationRepository(conn, tables)
        self.location_hashes = findings.SqlLocationHashRepository(conn, tables)
        self.findings = findings.SqlFindingRepository(conn, tables)
        self.cwes = findings.SqlCweRepository(conn, tables)
        self.finding_cwes = findings.SqlFindingCweRepository(conn, tables)
        self.finding_labels = findings.SqlFindingLabelRepository(conn, tables)
        self.finding_external_refs = findings.SqlFindingExternalRefRepository(
            conn, tables, pairing=TrackerPairing(self).validate
        )
        self.decisions = findings.SqlDecisionRepository(conn, tables)
        self.decision_approvers = findings.SqlDecisionApproverRepository(conn, tables)
        self.review_items = findings.SqlReviewItemRepository(conn, tables)
        self.run_batches = traust_ops.SqlRunBatchRepository(conn, tables)
        self.run_orders = traust_ops.SqlRunOrderRepository(conn, tables)
        self.spend_events = traust_ops.SqlSpendEventRepository(conn, tables)
        self.feed_snapshots = traust_ops.SqlFeedSnapshotRepository(conn, tables)
        self.assessment_inputs = traust_ops.SqlAssessmentInputRepository(conn, tables)
        self.layers = traust_ledger.SqlLayerRepository(conn, tables)
        self.events = traust_ledger.SqlEventRepository(conn, tables)


class TrackerPairing:
    """The scoped tracker write constraint, shared by repository add and update."""

    def __init__(self, uow: TraustUnitOfWork) -> None:
        self._uow = uow

    def validate(self, record: FindingExternalRef) -> None:
        if record.assessment_id is None:
            return
        with self._uow.write() as uow:
            finding = uow.findings.get_for_update(record.finding_id)
            assessment = uow.assessments.get(record.assessment_id)
            repository_ref = uow.repository_refs.get_for_update(assessment.repository_ref_id)
            if repository_ref.repository_id != finding.repository_id:
                raise ValidationError(
                    "tracker assessment and finding must belong to the same repository"
                )


class AssessmentReads(SqlRepository):
    """Composite assessment reads scoped through inventory ownership."""

    def __init__(self, connection: Connection, tables: TableFactory) -> None:
        super().__init__(connection)
        self._assessments = tables.table(ASSESSMENT)
        self._refs = tables.table(REPOSITORY_REF)

    def latest_for_repository(
        self, repository_id: UUID, kinds: Collection[str], statuses: Collection[str]
    ) -> Assessment | None:
        assessments, refs = self._assessments, self._refs
        c = assessments.c
        stmt = (
            sa.select(assessments)
            .select_from(assessments.join(refs, refs.c.id == c.repository_ref_id))
            .where(
                refs.c.repository_id == repository_id,
                c.kind.in_(kinds),
                c.status.in_(statuses),
            )
            .order_by(c.occurred_at.desc(), c.created_at.desc(), c.id.desc())
            .limit(1)
        )
        row = (
            self._execute(f"latest assessment for repository {repository_id}", stmt)
            .mappings()
            .one_or_none()
        )
        return None if row is None else Assessment.model_validate(dict(row))
