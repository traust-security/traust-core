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
from traust_core.v1.models.findings import CensusDecision, FindingExternalRef, FindingState
from traust_core.v1.models.operations import (
    OrderQueryPosition,
    OrderQueryRequest,
    OrderSortBy,
    OrderSortOrder,
    RunOrder,
)
from traust_core.v1.models.vocabulary import (
    DecisionReason,
    Severity,
)
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
from traust_core.v1.repositories.traust.inventory.repository import REPOSITORY
from traust_core.v1.repositories.traust.inventory.repository_ref import REPOSITORY_REF
from traust_core.v1.repositories.traust_ledger import LedgerUnitOfWork
from traust_core.v1.repositories.traust_ops import OpsUnitOfWork
from traust_core.v1.repositories.traust_ops.run_order import RUN_ORDER, order_conditions

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
        self.order_reads = OrderReads(conn, tables)
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

    def _materialized(self, select: sa.Select, name: str) -> sa.CTE:
        """A CTE evaluated once, never re-run per joined row: postgres inlines CTEs by
        default, and the planner re-runs an inlined window subquery on the inner side of
        a nested loop — the projected reads join three of them. SQLite CTEs never
        inline, and its planner rejects the keyword."""
        cte = select.cte(name=name)
        if self._connection.dialect.name == "postgresql":
            cte = cte.prefix_with("MATERIALIZED")
        return cte

    def _stamped_latest(self, batch: Collection[UUID]) -> sa.CTE:
        """The latest decision's folded columns per finding of these repositories: the
        projection read, windowed so each finding contributes one row."""
        d, f = self._decisions, self._findings
        ranked = (
            sa.select(
                d.c.finding_id,
                d.c.folded_state,
                d.c.folded_severity,
                d.c.folded_decided,
                d.c.folded_proven,
                d.c.folded_unverified,
                sa.func.row_number()
                .over(
                    partition_by=d.c.finding_id,
                    order_by=(d.c.created_at.desc(), d.c.id.desc()),
                )
                .label("rn"),
            )
            .select_from(d.join(f, f.c.id == d.c.finding_id))
            .where(f.c.repository_id.in_([*batch]))
        )
        window = ranked.subquery()
        return self._materialized(
            sa.select(
                window.c.finding_id,
                window.c.folded_state,
                window.c.folded_severity,
                window.c.folded_decided,
                window.c.folded_proven,
                window.c.folded_unverified,
            ).where(window.c.rn == 1),
            "stamped_latest",
        )

    def _first_labels(self, batch: Collection[UUID]) -> sa.CTE:
        """Each finding's first `category` label, (created_at, id) order."""
        labels, f = self._labels, self._findings
        ranked = (
            sa.select(
                labels.c.finding_id,
                labels.c.label,
                sa.func.row_number()
                .over(partition_by=labels.c.finding_id, order_by=(labels.c.created_at, labels.c.id))
                .label("rn"),
            )
            .select_from(labels.join(f, f.c.id == labels.c.finding_id))
            .where(f.c.repository_id.in_([*batch]), labels.c.taxonomy == "category")
        )
        window = ranked.subquery()
        return self._materialized(
            sa.select(window.c.finding_id, window.c.label).where(window.c.rn == 1), "first_labels"
        )

    def _latest_occurrences(self, batch: Collection[UUID]) -> sa.CTE:
        """Each finding's latest occurrence's (severity, cvss_score) with its first
        report's assessment time — the same windowed read `occurrences_for_repositories`
        serves, as a joinable subquery."""
        o, a, f = self._occurrences, self._assessments, self._findings
        ranked = (
            sa.select(
                o.c.finding_id,
                o.c.severity,
                o.c.cvss_score,
                sa.func.row_number()
                .over(
                    partition_by=o.c.finding_id,
                    order_by=(a.c.occurred_at.desc(), o.c.created_at.desc(), o.c.id.desc()),
                )
                .label("rank"),
                sa.func.min(a.c.occurred_at).over(partition_by=o.c.finding_id).label("first"),
            )
            .select_from(o.join(a, a.c.id == o.c.assessment_id).join(f, f.c.id == o.c.finding_id))
            .where(f.c.repository_id.in_([*batch]))
        )
        window = ranked.subquery()
        return self._materialized(
            sa.select(
                window.c.finding_id, window.c.severity, window.c.cvss_score, window.c.first
            ).where(window.c.rank == 1),
            "latest_occurrences",
        )

    def _claimed_findings(self) -> sa.Select:
        """The findings carrying retained claims: the one condition the census resolves
        claims for, as a subquery every projected read can join against."""
        d = self._decisions
        return (
            sa.select(d.c.finding_id)
            .where(d.c.reason == DecisionReason.BASELINE_REWRITE, d.c.artifact_id.is_not(None))
            .distinct()
        )

    def current_tallies(
        self, repository_ids: Collection[UUID]
    ) -> list[tuple[UUID, str, str | None, bool, bool, bool, str | None, int]]:
        """The repositories' findings' counted facts, one grouped row per distinct
        (repository, state, severity, decided, proven, unverified, category): the
        rollup's tallies read from the stamped projection, never a row per finding.
        Claim-carrying findings are left out — their category is a claim's, folded in
        Python. Findings without a decision read their defaults: open (hardening for a
        weakness), unverified, the latest report's severity."""
        f = self._findings
        found: list[tuple[UUID, str, str | None, bool, bool, bool, str | None, int]] = []
        for batch in batches(repository_ids):
            latest, label = self._stamped_latest(batch), self._first_labels(batch)
            cur = self._current()
            state, severity = cur.c.current_state, cur.c.current_severity
            stmt = (
                sa.select(
                    f.c.repository_id,
                    state,
                    severity,
                    cur.c.current_decided,
                    sa.func.coalesce(latest.c.folded_proven, sa.false()),
                    sa.func.coalesce(latest.c.folded_unverified, sa.true()),
                    label.c.label,
                    sa.func.count(),
                )
                .select_from(f)
                .join(cur, cur.c.id == f.c.id)
                .outerjoin(latest, latest.c.finding_id == f.c.id)
                .outerjoin(label, label.c.finding_id == f.c.id)
                .where(
                    f.c.repository_id.in_([*batch]),
                    f.c.id.not_in(self._claimed_findings()),
                )
                .group_by(
                    f.c.repository_id,
                    cur.c.current_state,
                    cur.c.current_severity,
                    cur.c.current_decided,
                    latest.c.folded_proven,
                    latest.c.folded_unverified,
                    label.c.label,
                )
            )
            rows = self._execute(f"current tallies of {len(batch)} repositories", stmt)
            found.extend(tuple(row) for row in rows)
        return found

    def _current(self) -> sa.Alias:
        """The finding's current answer, stamped by core's write doors from the fold: a table
        clause of just the projection columns, joined by id (they stay off the model)."""
        f = self._findings
        return sa.table(
            f.name,
            sa.column("id", f.c.id.type),
            sa.column("current_state", sa.Text),
            sa.column("current_severity", sa.Text),
            sa.column("current_decided", sa.Boolean),
            schema=f.schema,
        ).alias("cur")

    def current_claimed_rows(
        self, repository_ids: Collection[UUID]
    ) -> list[
        tuple[
            UUID,
            UUID,
            str,
            datetime,
            str | None,
            str,
            str | None,
            bool,
            bool,
            bool,
            Decimal | None,
            datetime | None,
        ]
    ]:
        """The claim-carrying findings of these repositories, one row each: the stamped
        state the tallies count and the title a claim overrides, with the label and the
        latest report's facts — the few rows whose category and title are a claim's,
        folded in Python where the review machinery lives."""
        f = self._findings
        found: list[
            tuple[
                UUID,
                UUID,
                str,
                datetime,
                str,
                str | None,
                str,
                str | None,
                bool,
                bool,
                bool,
                Decimal | None,
                datetime | None,
            ]
        ] = []
        for batch in batches(repository_ids):
            latest, label, occ = (
                self._stamped_latest(batch),
                self._first_labels(batch),
                self._latest_occurrences(batch),
            )
            cur = self._current()
            stmt = (
                sa.select(
                    f.c.id,
                    f.c.repository_id,
                    f.c.title,
                    f.c.created_at,
                    label.c.label,
                    cur.c.current_state,
                    cur.c.current_severity,
                    cur.c.current_decided,
                    sa.func.coalesce(latest.c.folded_proven, sa.false()),
                    sa.func.coalesce(latest.c.folded_unverified, sa.true()),
                    occ.c.cvss_score,
                    occ.c.first,
                )
                .select_from(f)
                .join(cur, cur.c.id == f.c.id)
                .outerjoin(latest, latest.c.finding_id == f.c.id)
                .outerjoin(label, label.c.finding_id == f.c.id)
                .outerjoin(occ, occ.c.finding_id == f.c.id)
                .where(
                    f.c.repository_id.in_([*batch]),
                    f.c.id.in_(self._claimed_findings()),
                )
            )
            rows = self._execute(f"claimed rows of {len(batch)} repositories", stmt)
            found.extend(tuple(row) for row in rows)
        return found

    def current_top(
        self, repository_ids: Collection[UUID]
    ) -> list[
        tuple[
            UUID,
            UUID,
            str,
            datetime,
            str | None,
            str,
            Decimal | None,
            bool,
            str | None,
            datetime | None,
        ]
    ]:
        """The open critical and high findings of these repositories: the top cut as one
        bounded read off the stamped projection — claim-carrying findings left out, their
        titles a claim's. The counting order is the caller's (a stable sort's ties must
        break as the fold road broke them)."""
        f = self._findings
        found: list[
            tuple[
                UUID,
                UUID,
                str,
                datetime,
                str | None,
                str,
                Decimal | None,
                bool,
                str | None,
                datetime | None,
            ]
        ] = []
        for batch in batches(repository_ids):
            latest, label, occ = (
                self._stamped_latest(batch),
                self._first_labels(batch),
                self._latest_occurrences(batch),
            )
            cur = self._current()
            state, severity = cur.c.current_state, cur.c.current_severity
            stmt = (
                sa.select(
                    f.c.id,
                    f.c.repository_id,
                    f.c.title,
                    f.c.created_at,
                    label.c.label,
                    severity,
                    occ.c.cvss_score,
                    sa.func.coalesce(latest.c.folded_proven, sa.false()),
                    occ.c.first,
                )
                .select_from(f)
                .join(cur, cur.c.id == f.c.id)
                .outerjoin(latest, latest.c.finding_id == f.c.id)
                .outerjoin(label, label.c.finding_id == f.c.id)
                .outerjoin(occ, occ.c.finding_id == f.c.id)
                .where(
                    f.c.repository_id.in_([*batch]),
                    f.c.id.not_in(self._claimed_findings()),
                    state == FindingState.OPEN,
                    severity.in_((Severity.CRITICAL, Severity.HIGH)),
                )
            )
            rows = self._execute(f"current top of {len(batch)} repositories", stmt)
            found.extend(tuple(row) for row in rows)
        return found

    def occurrences_for_repositories(
        self, repository_ids: Collection[UUID], until: datetime | None = None
    ) -> list[tuple[UUID, str | None, str | None, Decimal | None, datetime]]:
        """Each of the repositories' findings' latest occurrence's (severity, cvss_vector,
        cvss_score) in the report order the views fold (the reporting assessment's time,
        then the occurrence's own), with its first report's assessment time — the clock
        an SLA reads — reports after `until` left out: one windowed read, never an
        occurrence row per finding through the caller. The vector rides along so the
        census bands the same severity the views compute from it."""
        o, a, f = self._occurrences, self._assessments, self._findings
        found: list[tuple[UUID, str | None, str | None, Decimal | None, datetime]] = []
        for batch in batches(repository_ids):
            ranked = (
                sa.select(o.c.finding_id, o.c.severity, o.c.cvss_vector, o.c.cvss_score)
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
                window.c.finding_id,
                window.c.severity,
                window.c.cvss_vector,
                window.c.cvss_score,
                window.c.first,
            ).where(window.c.rank == 1)
            rows = self._execute(f"census occurrences of {len(batch)} repositories", stmt)
            found.extend((row[0], row[1], row[2], row[3], row[4]) for row in rows)
        return found


class OrderReads(SqlRepository):
    """Bounded order reads composed with inventory's displayed repository reference."""

    def __init__(self, connection: Connection, tables: TableFactory) -> None:
        super().__init__(connection)
        self._orders = tables.table(RUN_ORDER)
        self._repositories = tables.table(REPOSITORY)

    def query(
        self, query: OrderQueryRequest, after: OrderQueryPosition | None
    ) -> list[tuple[RunOrder, str | None, str | int | None]]:
        if query.ids == ():
            return []
        orders, repositories = self._orders, self._repositories
        c = orders.c
        collation = "C" if self._connection.dialect.name == "postgresql" else "BINARY"
        reference = sa.func.coalesce(
            sa.func.nullif(repositories.c.url, ""),
            sa.cast(c.repository_id, sa.Text),
            sa.cast(c.id, sa.Text),
        )
        if query.sort_by is OrderSortBy.IDS:
            value = sa.case(
                *((c.id == order_id, index) for index, order_id in enumerate(query.ids or ())),
                else_=-1,
            )
        elif query.sort_by is OrderSortBy.REPOSITORY:
            value = reference.collate(collation)
        else:
            value = c[query.sort_by.value]
            if query.sort_by in {OrderSortBy.ASSET, OrderSortBy.STATE, OrderSortBy.REASON}:
                value = value.collate(collation)
        stmt = sa.select(
            orders, repositories.c.url.label("repository_url"), value.label("sort_value")
        )
        stmt = stmt.select_from(
            orders.outerjoin(repositories, c.repository_id == repositories.c.id)
        )
        stmt = stmt.where(
            *order_conditions(
                orders,
                states=query.states,
                repository_id=query.repository_id,
                repository_ids=query.repository_ids,
                run_batch_id=query.run_batch_id,
                asset=query.asset,
            )
        )
        if query.ids is not None:
            stmt = stmt.where(c.id.in_(query.ids))
        if query.exclude_ids:
            stmt = stmt.where(c.id.not_in(query.exclude_ids))
        if query.q:
            escaped = query.q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            pattern = f"%{escaped}%"
            lower = (
                sa.func.lower
                if self._connection.dialect.name == "postgresql"
                else sa.func.unicode_lower
            )
            stmt = stmt.where(
                sa.or_(
                    *(
                        lower(column).like(pattern, escape="\\")
                        for column in (reference, c.asset, c.state)
                    )
                )
            )
        descending = (
            query.sort_order is OrderSortOrder.DESC and query.sort_by is not OrderSortBy.IDS
        )
        direction = sa.desc if descending else sa.asc
        nullable = query.sort_by in {
            OrderSortBy.STARTED_AT,
            OrderSortBy.FINISHED_AT,
            OrderSortBy.REASON,
        }
        position = after.value if after is not None else None
        if position is not None:
            if query.sort_by in {
                OrderSortBy.CREATED_AT,
                OrderSortBy.STARTED_AT,
                OrderSortBy.FINISHED_AT,
            }:
                position = datetime.fromisoformat(position)
            elif query.sort_by is OrderSortBy.ID:
                position = UUID(position)
        target = query.limit + 1
        rows = []
        if after is None or position is not None:
            nonnull = stmt.where(value.is_not(None)) if nullable else stmt
            if after is not None:
                if query.sort_by is OrderSortBy.ID:
                    seek = c.id < after.order_id if descending else c.id > after.order_id
                else:
                    key = sa.tuple_(value, c.id)
                    cursor = (position, after.order_id)
                    seek = key < cursor if descending else key > cursor
                nonnull = nonnull.where(seek)
            keys = (c.id,) if query.sort_by is OrderSortBy.ID else (value, c.id)
            nonnull = nonnull.order_by(*(direction(key) for key in keys)).limit(target)
            rows = list(self._execute("query orders", nonnull).mappings())
        if nullable and len(rows) < target:
            nulls = stmt.where(value.is_(None))
            if after is not None and position is None:
                nulls = nulls.where(c.id < after.order_id if descending else c.id > after.order_id)
            nulls = nulls.order_by(direction(c.id)).limit(target - len(rows))
            rows.extend(self._execute("query orders without sort value", nulls).mappings())
        return [
            (
                RunOrder.model_validate({column.name: row[column.name] for column in orders.c}),
                row["repository_url"],
                row["sort_value"].isoformat()
                if isinstance(row["sort_value"], datetime)
                else str(row["sort_value"])
                if isinstance(row["sort_value"], UUID)
                else row["sort_value"],
            )
            for row in rows
        ]
