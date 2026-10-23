"""Every contract table spec, and one unit of work over all of them.

Section protocols (InventoryUnitOfWork, FindingsUnitOfWork, ...) are what a
service declares it needs; SqlTraustUnitOfWork satisfies every one of them on
a single connection, so work that spans sections - intake writes an
assessment, occurrences, findings and decisions - commits or rolls back as
one transaction. Services that collaborate share the same instance.
"""

from __future__ import annotations

from typing import Protocol

from traust_core.v1.repositories import traust_ledger, traust_ops
from traust_core.v1.repositories.tables import SqlTablesUnitOfWork, TableSpec
from traust_core.v1.repositories.traust import assessments, dependencies, findings, inventory
from traust_core.v1.repositories.traust.assessments import AssessmentsUnitOfWork
from traust_core.v1.repositories.traust.dependencies import DependenciesUnitOfWork
from traust_core.v1.repositories.traust.findings import FindingsUnitOfWork
from traust_core.v1.repositories.traust.inventory import InventoryUnitOfWork
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
        self.artifacts = assessments.SqlArtifactRepository(conn, tables)
        self.occurrences = assessments.SqlOccurrenceRepository(conn, tables)
        self.locations = assessments.SqlLocationRepository(conn, tables)
        self.findings = findings.SqlFindingRepository(conn, tables)
        self.cwes = findings.SqlCweRepository(conn, tables)
        self.finding_cwes = findings.SqlFindingCweRepository(conn, tables)
        self.finding_labels = findings.SqlFindingLabelRepository(conn, tables)
        self.finding_external_refs = findings.SqlFindingExternalRefRepository(conn, tables)
        self.decisions = findings.SqlDecisionRepository(conn, tables)
        self.decision_approvers = findings.SqlDecisionApproverRepository(conn, tables)
        self.review_items = findings.SqlReviewItemRepository(conn, tables)
        self.open_counts = findings.SqlOpenCounts(conn)
        self.run_batches = traust_ops.SqlRunBatchRepository(conn, tables)
        self.run_orders = traust_ops.SqlRunOrderRepository(conn, tables)
        self.spend_events = traust_ops.SqlSpendEventRepository(conn, tables)
        self.feed_snapshots = traust_ops.SqlFeedSnapshotRepository(conn, tables)
        self.assessment_inputs = traust_ops.SqlAssessmentInputRepository(conn, tables)
        self.layers = traust_ledger.SqlLayerRepository(conn, tables)
        self.events = traust_ledger.SqlEventRepository(conn, tables)
