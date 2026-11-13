"""Every contract table spec, and one unit of work over all of them.

Section protocols (InventoryUnitOfWork, FindingsUnitOfWork, ...) are what a
service declares it needs; SqlTraustUnitOfWork satisfies every one of them on
a single connection, so work that spans sections - intake writes an
assessment, occurrences, findings and decisions - commits or rolls back as
one transaction. Services that collaborate share the same instance.
"""

from __future__ import annotations

from collections.abc import Collection
from datetime import datetime
from decimal import Decimal
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.engine import Connection

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.assessment import Assessment
from traust_core.v1.models.findings import CensusDecision, FindingExternalRef
from traust_core.v1.repositories import traust_ledger, traust_ops
from traust_core.v1.repositories.sql import SqlRepository
from traust_core.v1.repositories.tables import (
    SqlTablesUnitOfWork,
    TableFactory,
    TableSpec,
    batches,
)
from traust_core.v1.repositories.traust import assessments, dependencies, findings, inventory
from traust_core.v1.repositories.traust.assessments import AssessmentsUnitOfWork
from traust_core.v1.repositories.traust.assessments.assessment import ASSESSMENT
from traust_core.v1.repositories.traust.assessments.occurrence import OCCURRENCE
from traust_core.v1.repositories.traust.dependencies import DependenciesUnitOfWork
from traust_core.v1.repositories.traust.findings import FindingsUnitOfWork
from traust_core.v1.repositories.traust.findings.decision import DECISION
from traust_core.v1.repositories.traust.findings.finding import FINDING
from traust_core.v1.repositories.traust.findings.finding_label import FINDING_LABEL
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
        self.census_reads = CensusReads(conn, tables)
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


class CensusReads(SqlRepository):
    """The findings census's composite reads (the performance lane's wave (e), foundry#56):
    a scope's counted facts in one bounded statement per table, joined through the
    sections that own them. The single-table reads would fetch the same rows keyed by
    finding id — one 500-id statement per table per batch — which at an estate's scale
    is thousands of round trips; these are hundreds, batched by repository."""

    def __init__(self, connection: Connection, tables: TableFactory) -> None:
        super().__init__(connection)
        self._findings = tables.table(FINDING)
        self._decisions = tables.table(DECISION)
        self._labels = tables.table(FINDING_LABEL)
        self._occurrences = tables.table(OCCURRENCE)
        self._assessments = tables.table(ASSESSMENT)

    def decisions_for_repositories(
        self, repository_ids: Collection[UUID], until: datetime | None = None
    ) -> list[CensusDecision]:
        """The decisions' census columns of the repositories' findings, those made after
        `until` left out, in judgement order (occurred_at, created_at, id): the
        disposition folds over these rows without a model per decision."""
        d, f = self._decisions, self._findings
        columns = (
            d.c.id,
            d.c.finding_id,
            d.c.restates_id,
            d.c.validity,
            d.c.resolution,
            d.c.severity,
            d.c.evidence_grade,
            d.c.reason,
            d.c.source_channel,
            d.c.actor,
            d.c.auto_accept_tier,
            d.c.occurred_at,
            d.c.created_at,
            d.c.assessment_id,
            d.c.repository_ref_id,
        )
        found: list[CensusDecision] = []
        for batch in batches(repository_ids):
            stmt = (
                sa.select(*columns)
                .select_from(d.join(f, f.c.id == d.c.finding_id))
                .where(f.c.repository_id.in_(batch))
                .order_by(d.c.occurred_at, d.c.created_at, d.c.id)
            )
            if until is not None:
                stmt = stmt.where(d.c.occurred_at <= until)
            rows = self._execute(f"census decisions of {len(batch)} repositories", stmt)
            found.extend(CensusDecision(*row) for row in rows)
        return found

    def labels_for_repositories(self, repository_ids: Collection[UUID]) -> list[tuple[UUID, str]]:
        """(finding_id, label) of the repositories' findings' `category` labels,
        (created_at, id) order: the one taxonomy a census counts, without a model or a
        row per label it never reads."""
        labels, findings = self._labels, self._findings
        found: list[tuple[UUID, str]] = []
        for batch in batches(repository_ids):
            stmt = (
                sa.select(labels.c.finding_id, labels.c.label)
                .select_from(labels.join(findings, findings.c.id == labels.c.finding_id))
                .where(findings.c.repository_id.in_(batch), labels.c.taxonomy == "category")
                .order_by(labels.c.created_at, labels.c.id)
            )
            rows = self._execute(f"census labels of {len(batch)} repositories", stmt)
            found.extend((row[0], row[1]) for row in rows)
        return found

    def occurrences_for_repositories(
        self, repository_ids: Collection[UUID], until: datetime | None = None
    ) -> list[tuple[UUID, str | None, Decimal | None, datetime]]:
        """Each of the repositories' findings' latest occurrence's (severity, cvss_score)
        in the report order the views fold (the reporting assessment's time, then the
        occurrence's own), with its first report's assessment time — the clock an SLA
        reads — reports after `until` left out: one windowed read, never an occurrence
        row per finding through the caller."""
        o, a, f = self._occurrences, self._assessments, self._findings
        found: list[tuple[UUID, str | None, Decimal | None, datetime]] = []
        for batch in batches(repository_ids):
            ranked = (
                sa.select(o.c.finding_id, o.c.severity, o.c.cvss_score)
                .add_columns(
                    sa.func.row_number()
                    .over(
                        partition_by=o.c.finding_id,
                        order_by=(
                            a.c.occurred_at.desc(),
                            o.c.created_at.desc(),
                            o.c.id.desc(),
                        ),
                    )
                    .label("rank"),
                    sa.func.min(a.c.occurred_at).over(partition_by=o.c.finding_id).label("first"),
                )
                .select_from(
                    o.join(a, a.c.id == o.c.assessment_id).join(f, f.c.id == o.c.finding_id)
                )
                .where(f.c.repository_id.in_(batch))
            )
            if until is not None:
                ranked = ranked.where(a.c.occurred_at <= until)
            window = ranked.subquery()
            stmt = sa.select(
                window.c.finding_id, window.c.severity, window.c.cvss_score, window.c.first
            ).where(window.c.rank == 1)
            rows = self._execute(f"census occurrences of {len(batch)} repositories", stmt)
            found.extend((row[0], row[1], row[2], row[3]) for row in rows)
        return found
