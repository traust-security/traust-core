"""Below-range as a lane, on SQLite and Postgres: packets recorded for a repository's head, read
back and refetched for review, and the review recorded (applicable cases become exposure
findings; the protocol is checked, never the judgement)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.test_below_range import (
    ABOVE,
    COMMIT,
    GO_LIB,
    GO_PAGES,
    HOSTS,
    MODULE_ZIP,
    Http,
    Lookup,
    cdx,
    osv,
)
from traust_core.v1.errors import ConfigError, IntegrityError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import BelowRangePacketsArtifact, BelowRangeVerdictsArtifact
from traust_core.v1.models.assessment import ASSESSMENT_COMPLETED, ASSESSMENT_DEGRADED
from traust_core.v1.models.common import Provenance, SourceType
from traust_core.v1.models.dependencies import AdvisoryRecord
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.feeds import FeedProvider, FeedSource
from traust_core.v1.providers.package_source import PackageSources
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    AssessmentLog,
    PublishSpec,
    PublishSpecs,
)
from traust_core.v1.services.below_range import BelowRangeService
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy
from traust_core.v1.services.portfolio import Inventory, PortfolioPolicy, PortfolioService

AT = datetime(2026, 10, 26, tzinfo=UTC)
CASE = "example.com_lib@v1.4.0--GHSA-test-0001"
A, B, JUDGE = "claude-opus-5-5", "claude-sonnet-5-5", "claude-opus-5-5"


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


class Lane:
    """A below-range service wired as Context wires it, over one database and object store."""

    def __init__(self, engine: Engine, *records: AdvisoryRecord, pages: dict[str, bytes]) -> None:
        self.engine = engine
        self.lookup = Lookup(*records)
        self.http = Http(pages)
        self.store = InMemoryObjectStore()

    def service(self, *, recording: bool = True) -> BelowRangeService:
        uow = SqlTraustUnitOfWork(self.engine)
        intake = FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy())
        exposure = ExposureService(
            uow,
            intake,
            feeds=ProviderRegistry[FeedProvider]("feed"),
            objects=self.store,
            advisories=self.lookup,  # type: ignore[arg-type]
            portfolio=PortfolioService(uow, PortfolioPolicy()),
        )
        publisher = ArtifactPublisher(
            PublishSpecs(
                PublishSpec(BelowRangePacketsArtifact), PublishSpec(BelowRangeVerdictsArtifact)
            ),
            self.store,
            uow,
        )
        parts = {"inventory": Inventory(uow), "log": AssessmentLog(uow), "intake": intake}
        store = {**parts, "publisher": publisher} if recording else {}
        return BelowRangeService(
            exposure,
            advisories=self.lookup,  # type: ignore[arg-type]
            sources=PackageSources(HOSTS, http=self.http),  # type: ignore[arg-type]
            feed_sources=ProviderRegistry[FeedSource]("feed-source"),
            clock=FixedClock(AT),
            **store,  # type: ignore[arg-type]
        )

    def repository(self, sbom: bytes | None = cdx(GO_LIB), *, default: bool = True) -> UUID:
        with SqlTraustUnitOfWork(self.engine) as uow:
            seed = Seed(uow)
            repo = seed.repository(url=f"https://github.com/example/{uuid4()}")
            ref = seed.repository_ref(repo, is_default=default)
            uow.commit()
        assert repo.id is not None and ref.id is not None
        if sbom is not None:
            self.service()._exposure.ingest_sbom(sbom, ref.id)
        return repo.id


def go_lane(engine: Engine, pages: dict[str, bytes] | None = None) -> Lane:
    rec = osv(ABOVE, refs=(COMMIT + "3" * 40, COMMIT + "4" * 40))
    return Lane(engine, rec, pages=dict(GO_PAGES if pages is None else pages))


def review(verdict: str = "applicable", b: str | None = None, **row: Any) -> dict[str, Any]:
    return {
        "case": CASE,
        "reviews": [
            {"model": A, "verdict": verdict, "evidence": "parse.go:3 still calls parse"},
            {"model": B, "verdict": b or verdict, "evidence": "parse.go:3"},
        ],
        "verdict": verdict,
        **row,
    }


def verdicts(
    packets_id: UUID, *cases: dict[str, Any], gaps: Any = ()
) -> BelowRangeVerdictsArtifact:
    return BelowRangeVerdictsArtifact.from_document(
        {
            "artifact": "below-range-verdicts",
            "packets_assessment_id": str(packets_id),
            "cases": list(cases),
            "coverage_gaps": list(gaps),
        }
    )


PROVENANCE = Provenance(run_id=uuid4(), source=SourceType.IMPACT_REPORT, occurred_at=AT)


def test_scan_records_the_heads_packets_and_reads_them_back(engine: Engine, tmp_path: Path) -> None:
    lane = go_lane(engine)
    repo = lane.repository()
    scan = lane.service().scan(repo, tmp_path)
    [packet] = scan.packets.packets
    assert packet.case == CASE
    stored = lane.service().latest(repo)
    assert (stored.assessment_id, stored.artifact_id) == (scan.assessment_id, scan.artifact_id)
    assert stored.packets == scan.packets
    with SqlTraustUnitOfWork(engine) as uow:
        assessment = uow.assessments.get(scan.assessment_id)
    assert (assessment.kind, assessment.status, assessment.assessor) == (
        "impact",
        ASSESSMENT_COMPLETED,
        "below-range",
    )


def test_scanning_unchanged_packets_again_is_the_same_assessment(
    engine: Engine, tmp_path: Path
) -> None:
    lane = go_lane(engine)
    repo = lane.repository()
    first = lane.service().scan(repo, tmp_path / "a")
    again = lane.service().scan(repo, tmp_path / "b")
    assert (again.assessment_id, again.artifact_id) == (first.assessment_id, first.artifact_id)


def test_a_degraded_scan_is_a_degraded_assessment_linked_to_its_order(
    engine: Engine, tmp_path: Path
) -> None:
    lane = go_lane(engine)
    lane.lookup.unanswered = {"example.com/lib"}
    repo = lane.repository()
    with SqlTraustUnitOfWork(engine) as uow:
        order = Seed(uow).run_order(asset="below_range_packets", repository_id=repo)
        uow.commit()
    scan = lane.service().scan(repo, tmp_path, run_order_id=order.id)
    with SqlTraustUnitOfWork(engine) as uow:
        assessment = uow.assessments.get(scan.assessment_id)
    assert (assessment.status, assessment.run_order_id) == (ASSESSMENT_DEGRADED, order.id)
    assert [g.reason for g in scan.packets.coverage_gaps] == ["osv_unanswered"]


@pytest.mark.parametrize(
    ("sbom", "default", "error"),
    [(cdx(GO_LIB), False, NotFoundError), (None, True, NotFoundError)],
    ids=["no default-branch commit", "no manifest SBOM on the head"],
)
def test_scan_refuses_a_repository_it_cannot_read(
    engine: Engine, tmp_path: Path, sbom: bytes | None, default: bool, error: type[Exception]
) -> None:
    lane = go_lane(engine)
    repo = lane.repository(sbom, default=default)
    with pytest.raises(error):
        lane.service().scan(repo, tmp_path)


def test_latest_needs_recorded_packets(engine: Engine) -> None:
    lane = go_lane(engine)
    with pytest.raises(NotFoundError, match="no below-range packets"):
        lane.service().latest(lane.repository())


def test_recording_without_its_store_is_a_config_error(engine: Engine, tmp_path: Path) -> None:
    lane = go_lane(engine)
    with pytest.raises(ConfigError, match="recording"):
        lane.service(recording=False).scan(lane.repository(), tmp_path)


def test_fetch_restores_the_reviewed_source_and_refuses_changed_bytes(
    engine: Engine, tmp_path: Path
) -> None:
    lane = go_lane(engine)
    repo = lane.repository()
    packets = lane.service().scan(repo, tmp_path / "scan").packets
    lane.service().fetch(packets, tmp_path / "review")
    root = tmp_path / "review" / packets.packets[0].installed_source.root
    assert (root / "parse.go").is_file()

    lane.http.pages[MODULE_ZIP] = lane.http.pages[MODULE_ZIP] + b"\0"
    with pytest.raises(IntegrityError, match="not the reviewed"):
        lane.service().fetch(packets, tmp_path / "again")


def test_an_applicable_case_becomes_one_exposure_finding_once(
    engine: Engine, tmp_path: Path
) -> None:
    lane = go_lane(engine)
    repo = lane.repository()
    scan = lane.service().scan(repo, tmp_path)
    doc = verdicts(scan.assessment_id, review())
    outcome = lane.service().record(doc, PROVENANCE)
    assert list(outcome.findings) == [CASE]
    assert (outcome.not_applicable, outcome.undetermined, outcome.coverage_gaps) == ((), (), 0)
    again = lane.service().record(doc, PROVENANCE)
    assert (again.assessment_id, again.findings) == (outcome.assessment_id, outcome.findings)
    with SqlTraustUnitOfWork(engine) as uow:
        finding = uow.findings.get(outcome.findings[CASE])
        assessment = uow.assessments.get(outcome.assessment_id)
    assert finding.repository_id == repo
    assert "GHSA-test-0001" in finding.title
    assert (assessment.kind, assessment.assessor) == ("impact", "skill:dependency-watch")


def test_a_new_review_of_the_same_case_files_no_duplicate(engine: Engine, tmp_path: Path) -> None:
    lane = go_lane(engine)
    scan = lane.service().scan(lane.repository(), tmp_path)
    first = lane.service().record(verdicts(scan.assessment_id, review()), PROVENANCE)
    split = review(
        "applicable",
        b="undetermined",
        judge={"model": JUDGE, "verdict": "applicable", "ruling": "parse.go:3"},
    )
    second = lane.service().record(verdicts(scan.assessment_id, split), PROVENANCE)
    assert second.assessment_id != first.assessment_id
    assert second.findings == first.findings


@pytest.mark.parametrize(
    ("row", "bucket"),
    [
        (review("not_applicable"), "not_applicable"),
        (
            review(
                "undetermined",
                b="applicable",
                judge={"model": JUDGE, "verdict": "undetermined", "ruling": "x", "settle": "y"},
            ),
            "undetermined",
        ),
    ],
)
def test_other_verdicts_file_nothing_and_stay_in_the_document(
    engine: Engine, tmp_path: Path, row: dict[str, Any], bucket: str
) -> None:
    lane = go_lane(engine)
    scan = lane.service().scan(lane.repository(), tmp_path)
    outcome = lane.service().record(verdicts(scan.assessment_id, row), PROVENANCE)
    assert outcome.findings == {}
    assert getattr(outcome, bucket) == (CASE,)


def test_coverage_gaps_are_carried_and_counted(engine: Engine, tmp_path: Path) -> None:
    lane = go_lane(engine, pages={})
    scan = lane.service().scan(lane.repository(), tmp_path)
    gaps = [g.model_dump(mode="json") for g in scan.packets.coverage_gaps]
    assert scan.packets.packets == () and len(gaps) == 1
    outcome = lane.service().record(verdicts(scan.assessment_id, gaps=gaps), PROVENANCE)
    assert (outcome.coverage_gaps, outcome.findings) == (1, {})


JUDGED = {"model": JUDGE, "verdict": "applicable", "ruling": "parse.go:3"}


@pytest.mark.parametrize(
    ("cases", "message"),
    [
        ((), "leave out"),
        ((review(), review()), "twice"),
        ((review(), {**review(), "case": "other@1--GHSA-x"}), "name no packet"),
        ((review("applicable", b="not_applicable"),), "needs a judge"),
        ((review("applicable", b="undetermined"),), "needs a judge"),
        ((review(judge=JUDGED),), "takes no judge"),
        (({**review("not_applicable", b="applicable", judge=JUDGED)},), "is not applicable"),
    ],
    ids=["missing", "twice", "extra", "split", "undetermined", "judge on agreement", "overruled"],
)
def test_a_review_off_protocol_is_refused(
    engine: Engine, tmp_path: Path, cases: tuple[dict[str, Any], ...], message: str
) -> None:
    lane = go_lane(engine)
    scan = lane.service().scan(lane.repository(), tmp_path)
    with pytest.raises(ValidationError, match=message):
        lane.service().record(verdicts(scan.assessment_id, *cases), PROVENANCE)


def test_dropped_coverage_gaps_are_refused(engine: Engine, tmp_path: Path) -> None:
    lane = go_lane(engine, pages={})
    scan = lane.service().scan(lane.repository(), tmp_path)
    with pytest.raises(ValidationError, match="unchanged"):
        lane.service().record(verdicts(scan.assessment_id), PROVENANCE)


def test_a_review_of_something_other_than_packets_is_not_found(engine: Engine) -> None:
    lane = go_lane(engine)
    with SqlTraustUnitOfWork(engine) as uow:
        other = Seed(uow).assessment()
        uow.commit()
    assert other.id is not None
    with pytest.raises(NotFoundError, match="no below-range packets"):
        lane.service().record(verdicts(other.id), PROVENANCE)
