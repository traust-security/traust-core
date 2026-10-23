"""Repository-layer harness: a fresh contracts database per test, on SQLite and Postgres.

Every test that takes `engine`, `uow` or `seed` runs once per backend; Postgres
runs when TRAUST_TEST_DATABASE_URL is set (make db-up; make test-integration).
Seed builds valid rows with their parents, so a test states only what it is
about: `seed.decision(seed.finding(), severity="high")`.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from decimal import Decimal
from itertools import count
from pathlib import Path
from time import sleep
from typing import Any, TypeVar

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from traust_core.v1.models.assessment import Artifact, Assessment
from traust_core.v1.models.base import Model
from traust_core.v1.models.dependencies import (
    Advisory,
    AdvisoryPackage,
    Dependency,
    Image,
    Package,
    Sbom,
)
from traust_core.v1.models.findings import (
    Cwe,
    Decision,
    DecisionApprover,
    Finding,
    FindingCwe,
    FindingExternalRef,
    FindingLabel,
    Location,
    Occurrence,
    ReviewItem,
)
from traust_core.v1.models.inventory import (
    Component,
    Ownership,
    Product,
    Release,
    Repository,
    RepositoryRef,
    Team,
)
from traust_core.v1.models.ledger import Event, Layer
from traust_core.v1.models.operations import (
    AssessmentInput,
    FeedSnapshot,
    RunBatch,
    RunOrder,
    SpendEvent,
)
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.tables import SqlTableRepository

T0 = datetime(2026, 10, 5, tzinfo=UTC)
SHA = "a" * 40
M = TypeVar("M", bound=Model)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def uow(engine: Engine) -> Iterator[SqlTraustUnitOfWork]:
    """An open unit of work; uncommitted work rolls back when the test ends."""
    with SqlTraustUnitOfWork(engine) as u:
        yield u


@pytest.fixture
def seed(uow: SqlTraustUnitOfWork) -> Seed:
    return Seed(uow)


def repository_for(uow: SqlTraustUnitOfWork, table: str) -> SqlTableRepository[Any]:
    for value in vars(uow).values():
        if isinstance(value, SqlTableRepository) and value.spec.name == table:
            return value
    raise KeyError(table)


def same_rows(actual: Sequence[Model], expected: Sequence[Model]) -> bool:
    """Equal as sets of rows; list order is asserted only where a query defines it."""
    key = lambda m: str(m.id)  # type: ignore[attr-defined]  # noqa: E731
    return sorted(actual, key=key) == sorted(expected, key=key)


def apart() -> None:
    """Separate created_at: SQLite stamps milliseconds per statement."""
    sleep(0.002)


def saved_id(model: Model) -> Any:
    assert getattr(model, "id", None) is not None, f"{type(model).__name__} is not saved"
    return model.id  # type: ignore[attr-defined]


class Seed:
    """Valid rows with their parents: new_<table>() is unsaved, <table>() is added."""

    def __init__(self, uow: SqlTraustUnitOfWork) -> None:
        self.uow = uow
        self._n = count(1)

    def _next(self) -> int:
        return next(self._n)

    def _add(self, table: str, model: M) -> M:
        return repository_for(self.uow, table).add(model)  # type: ignore[no-any-return]

    def new(self, table: str) -> Model:
        """An unsaved, valid row for any contract table (parents saved)."""
        return getattr(self, f"new_{table}")()  # type: ignore[no-any-return]

    # 1 · Inventory
    def new_product(self, **kw: Any) -> Product:
        n = self._next()
        return Product(**{"slug": f"product-{n}", "name": f"Product {n}", **kw})

    def product(self, **kw: Any) -> Product:
        return self._add("product", self.new_product(**kw))

    def new_release(self, product: Product | None = None, **kw: Any) -> Release:
        parent = product or self.product()
        return Release(**{"product_id": saved_id(parent), "version": f"{self._next()}.0", **kw})

    def release(self, product: Product | None = None, **kw: Any) -> Release:
        return self._add("release", self.new_release(product, **kw))

    def new_repository(self, **kw: Any) -> Repository:
        return Repository(
            **{"url": f"https://github.com/org/repo-{self._next()}", "public": True, **kw}
        )

    def repository(self, **kw: Any) -> Repository:
        return self._add("repository", self.new_repository(**kw))

    def new_repository_ref(self, repository: Repository | None = None, **kw: Any) -> RepositoryRef:
        parent = repository or self.repository()
        values = {"repository_id": saved_id(parent), "name": "main", "kind": "branch", "sha": SHA}
        return RepositoryRef(**{**values, **kw})

    def repository_ref(self, repository: Repository | None = None, **kw: Any) -> RepositoryRef:
        return self._add("repository_ref", self.new_repository_ref(repository, **kw))

    def new_component(
        self, release: Release | None = None, ref: RepositoryRef | None = None
    ) -> Component:
        return Component(
            release_id=saved_id(release or self.release()),
            repository_ref_id=saved_id(ref or self.repository_ref()),
        )

    def component(
        self, release: Release | None = None, ref: RepositoryRef | None = None
    ) -> Component:
        return self._add("component", self.new_component(release, ref))

    def new_team(self, **kw: Any) -> Team:
        return Team(**{"name": f"team-{self._next()}", **kw})

    def team(self, **kw: Any) -> Team:
        return self._add("team", self.new_team(**kw))

    def new_ownership(
        self, repository: Repository | None = None, team: Team | None = None, **kw: Any
    ) -> Ownership:
        values = {
            "repository_id": saved_id(repository or self.repository()),
            "team_id": saved_id(team or self.team()),
            "valid_from": T0,
        }
        return Ownership(**{**values, **kw})

    def ownership(
        self, repository: Repository | None = None, team: Team | None = None, **kw: Any
    ) -> Ownership:
        return self._add("ownership", self.new_ownership(repository, team, **kw))

    # 2 · Dependencies
    def new_sbom(self, **kw: Any) -> Sbom:
        return Sbom(**{"digest": f"sha256:sbom-{self._next()}", **kw})

    def sbom(self, **kw: Any) -> Sbom:
        return self._add("sbom", self.new_sbom(**kw))

    def new_package(self, **kw: Any) -> Package:
        return Package(**{"ecosystem": "go", "name": f"example.com/pkg-{self._next()}", **kw})

    def package(self, **kw: Any) -> Package:
        return self._add("package", self.new_package(**kw))

    def new_dependency(
        self, sbom: Sbom | None = None, package: Package | None = None, **kw: Any
    ) -> Dependency:
        values = {
            "sbom_id": saved_id(sbom or self.sbom()),
            "package_id": saved_id(package or self.package()),
            "version": "1.0.0",
            "direct": True,
        }
        return Dependency(**{**values, **kw})

    def dependency(
        self, sbom: Sbom | None = None, package: Package | None = None, **kw: Any
    ) -> Dependency:
        return self._add("dependency", self.new_dependency(sbom, package, **kw))

    def new_image(self, **kw: Any) -> Image:
        return Image(**{"digest": f"sha256:image-{self._next()}", "platform": "linux/amd64", **kw})

    def image(self, **kw: Any) -> Image:
        return self._add("image", self.new_image(**kw))

    def new_advisory(self, **kw: Any) -> Advisory:
        return Advisory(**{"identifier": f"CVE-2026-{self._next():04d}", **kw})

    def advisory(self, **kw: Any) -> Advisory:
        return self._add("advisory", self.new_advisory(**kw))

    def new_advisory_package(
        self, advisory: Advisory | None = None, package: Package | None = None
    ) -> AdvisoryPackage:
        return AdvisoryPackage(
            advisory_id=saved_id(advisory or self.advisory()),
            package_id=saved_id(package or self.package()),
        )

    def advisory_package(
        self, advisory: Advisory | None = None, package: Package | None = None
    ) -> AdvisoryPackage:
        return self._add("advisory_package", self.new_advisory_package(advisory, package))

    # 3a · Assessments
    def new_assessment(self, ref: RepositoryRef | None = None, **kw: Any) -> Assessment:
        values = {
            "repository_ref_id": saved_id(ref or self.repository_ref()),
            "kind": "audit",
            "status": "completed",
            "assessor": "skill:audit",
            "assessor_version": "1.0",
            "occurred_at": T0,
        }
        return Assessment(**{**values, **kw})

    def assessment(self, ref: RepositoryRef | None = None, **kw: Any) -> Assessment:
        return self._add("assessment", self.new_assessment(ref, **kw))

    def new_artifact(self, assessment: Assessment | None = None, **kw: Any) -> Artifact:
        n = self._next()
        values = {
            "assessment_id": saved_id(assessment or self.assessment()),
            "digest": f"sha256:doc-{n}",
            "kind": "report",
            "uri": f"file:///artifacts/{n}.json",
        }
        return Artifact(**{**values, **kw})

    def artifact(self, assessment: Assessment | None = None, **kw: Any) -> Artifact:
        return self._add("artifact", self.new_artifact(assessment, **kw))

    def new_occurrence(
        self, finding: Finding | None = None, assessment: Assessment | None = None, **kw: Any
    ) -> Occurrence:
        values = {
            "finding_id": saved_id(finding or self.finding()),
            "assessment_id": saved_id(assessment or self.assessment()),
            "severity": "high",
        }
        return Occurrence(**{**values, **kw})

    def occurrence(
        self, finding: Finding | None = None, assessment: Assessment | None = None, **kw: Any
    ) -> Occurrence:
        return self._add("occurrence", self.new_occurrence(finding, assessment, **kw))

    def new_location(self, occurrence: Occurrence | None = None, **kw: Any) -> Location:
        values = {
            "occurrence_id": saved_id(occurrence or self.occurrence()),
            "path": "pkg/api/handler.go",
            "line_start": 10,
            "line_end": 12,
        }
        return Location(**{**values, **kw})

    def location(self, occurrence: Occurrence | None = None, **kw: Any) -> Location:
        return self._add("location", self.new_location(occurrence, **kw))

    # 3b · Findings
    def new_finding(self, repository: Repository | None = None, **kw: Any) -> Finding:
        values = {
            "repository_id": saved_id(repository or self.repository()),
            "fingerprint_algo": "v3",
            "fingerprint": f"fp-{self._next()}",
            "title": "SQL injection in handler",
        }
        return Finding(**{**values, **kw})

    def finding(self, repository: Repository | None = None, **kw: Any) -> Finding:
        return self._add("finding", self.new_finding(repository, **kw))

    def new_cwe(self, **kw: Any) -> Cwe:
        return Cwe(**{"identifier": f"CWE-{self._next()}", "abstraction": "base", **kw})

    def cwe(self, **kw: Any) -> Cwe:
        return self._add("cwe", self.new_cwe(**kw))

    def new_finding_cwe(self, finding: Finding | None = None, cwe: Cwe | None = None) -> FindingCwe:
        return FindingCwe(
            finding_id=saved_id(finding or self.finding()), cwe_id=saved_id(cwe or self.cwe())
        )

    def finding_cwe(self, finding: Finding | None = None, cwe: Cwe | None = None) -> FindingCwe:
        return self._add("finding_cwe", self.new_finding_cwe(finding, cwe))

    def new_finding_label(self, finding: Finding | None = None, **kw: Any) -> FindingLabel:
        values = {"finding_id": saved_id(finding or self.finding()), "taxonomy": "attack"}
        return FindingLabel(**{**values, "label": "T1190", **kw})

    def finding_label(self, finding: Finding | None = None, **kw: Any) -> FindingLabel:
        return self._add("finding_label", self.new_finding_label(finding, **kw))

    def new_finding_external_ref(
        self, finding: Finding | None = None, **kw: Any
    ) -> FindingExternalRef:
        values = {"finding_id": saved_id(finding or self.finding()), "system": "jira"}
        return FindingExternalRef(**{**values, "ref": f"SEC-{self._next()}", **kw})

    def finding_external_ref(self, finding: Finding | None = None, **kw: Any) -> FindingExternalRef:
        return self._add("finding_external_ref", self.new_finding_external_ref(finding, **kw))

    def new_decision(self, finding: Finding | None = None, **kw: Any) -> Decision:
        values = {
            "finding_id": saved_id(finding or self.finding()),
            "statement_key": f"stmt-{self._next()}",
            "actor": "user:analyst",
            "validity": "true_positive",
            "occurred_at": T0,
        }
        return Decision(**{**values, **kw})

    def decision(self, finding: Finding | None = None, **kw: Any) -> Decision:
        return self._add("decision", self.new_decision(finding, **kw))

    def new_decision_approver(
        self, decision: Decision | None = None, **kw: Any
    ) -> DecisionApprover:
        values = {
            "decision_id": saved_id(decision or self.decision()),
            "approver": f"human:approver-{self._next()}@example.com",
        }
        return DecisionApprover(**{**values, **kw})

    def decision_approver(self, decision: Decision | None = None, **kw: Any) -> DecisionApprover:
        return self._add("decision_approver", self.new_decision_approver(decision, **kw))

    def new_review_item(self, finding: Finding | None = None, **kw: Any) -> ReviewItem:
        values = {"finding_id": saved_id(finding or self.finding()), "status": "pending"}
        return ReviewItem(**{**values, "reason": "auto_accept_blocked", **kw})

    def review_item(self, finding: Finding | None = None, **kw: Any) -> ReviewItem:
        return self._add("review_item", self.new_review_item(finding, **kw))

    # 4 · Operations
    def new_run_batch(self, **kw: Any) -> RunBatch:
        return RunBatch(**{"kind": "drain_tranche", "period": f"2026-W{self._next():02d}", **kw})

    def run_batch(self, **kw: Any) -> RunBatch:
        return self._add("run_batch", self.new_run_batch(**kw))

    def new_run_order(self, **kw: Any) -> RunOrder:
        values = {"asset": "audit", "state": "queued", "priority": 5, "requested_by": "user:me"}
        return RunOrder(**{**values, **kw})

    def run_order(self, **kw: Any) -> RunOrder:
        return self._add("run_order", self.new_run_order(**kw))

    def new_spend_event(self, **kw: Any) -> SpendEvent:
        values = {
            "provider": "anthropic",
            "model": "claude",
            "tokens_in": 100,
            "tokens_out": 20,
            "cost_usd": Decimal("0.25"),
            "occurred_at": T0,
        }
        return SpendEvent(**{**values, **kw})

    def spend_event(self, **kw: Any) -> SpendEvent:
        return self._add("spend_event", self.new_spend_event(**kw))

    def new_feed_snapshot(self, **kw: Any) -> FeedSnapshot:
        doc = self.artifact(assessment_id=None, kind="feed")
        values = {"artifact_id": saved_id(doc), "feed": "osv", "retrieved_at": T0}
        return FeedSnapshot(**{**values, **kw})

    def feed_snapshot(self, **kw: Any) -> FeedSnapshot:
        return self._add("feed_snapshot", self.new_feed_snapshot(**kw))

    def new_assessment_input(
        self, assessment: Assessment | None = None, snapshot: FeedSnapshot | None = None
    ) -> AssessmentInput:
        return AssessmentInput(
            assessment_id=saved_id(assessment or self.assessment()),
            feed_snapshot_id=saved_id(snapshot or self.feed_snapshot()),
        )

    def assessment_input(
        self, assessment: Assessment | None = None, snapshot: FeedSnapshot | None = None
    ) -> AssessmentInput:
        return self._add("assessment_input", self.new_assessment_input(assessment, snapshot))

    # 5 · Ledger
    def new_layers(self, repository: Repository | None = None, **kw: Any) -> Layer:
        values = {"repository_id": saved_id(repository or self.repository())}
        return Layer(**{**values, "merkle_signing_method": "none", **kw})

    def layer(self, repository: Repository | None = None, **kw: Any) -> Layer:
        return self._add("layers", self.new_layers(repository, **kw))

    def new_events(
        self, layer: Layer | None = None, decision: Decision | None = None, **kw: Any
    ) -> Event:
        values = {
            "layer_id": saved_id(layer or self.layer()),
            "decision_id": saved_id(decision or self.decision()),
            "seq": 0,
            "event_payload": b"\x00\x01",
        }
        return Event(**{**values, **kw})

    def event(
        self, layer: Layer | None = None, decision: Decision | None = None, **kw: Any
    ) -> Event:
        return self._add("events", self.new_events(layer, decision, **kw))
