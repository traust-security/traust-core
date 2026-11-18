"""VerificationService over SQLite and Postgres: the legacy emit_verification_ledger_events,
route_regressions, scanner_differential, check_fix_propagation and build_verify_sweep paths, on
core's work items, decisions and assessments."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.test_exposure_advisories import GRPC, FakeLookup
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import IntegrityError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import VerificationArtifact
from traust_core.v1.models.common import ArtifactRef, PageRequest, Provenance
from traust_core.v1.models.findings import Finding
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import Repository, RepositoryRef
from traust_core.v1.models.remediation import VerificationFilter, WorkItem
from traust_core.v1.models.vocabulary import (
    DispositionResolution,
    RemediationStatus,
    SourceType,
    Validity,
)
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.ledger import LedgerConfig
from traust_core.v1.services.remediation import (
    RemediationConfig,
    RemediationService,
    VerificationService,
)

FIXTURES = Path(__file__).parents[2] / "fixtures" / "remediation"
REPORT = json.loads((FIXTURES / "verification-report.json").read_text())
BASE_SHA = REPORT["metadata"]["original_commit"]
PATCHED_SHA = REPORT["metadata"]["patched_commit"]
BRANCH = REPORT["metadata"]["patched_ref"]
WHEN = datetime(2026, 10, 24, 9, tzinfo=UTC)
RULE = "traust-python-injection-subprocess-shell"
PRIVATE = RemediationConfig(fork_org="mirror-org")


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def make_context(engine: Engine, tmp_path: Path, **config: Any) -> Context:
    # Work items open before WHEN, the time every verification report states.
    ctx = Context(
        Config(home=tmp_path, remediation=PRIVATE, **config),
        clock=FixedClock(WHEN - timedelta(hours=1)),
    )
    ctx.__dict__["database"] = engine
    ctx.advisories = FakeLookup(GRPC)
    return ctx


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    return make_context(engine, tmp_path)


@pytest.fixture
def service(context: Context) -> VerificationService:
    return context.services().verification


@pytest.fixture
def remediation(context: Context) -> RemediationService:
    return context.services().remediation


class World:
    """A repository on its default branch, confirmed findings on that commit, and the patched
    commit on the fix branch."""

    def __init__(
        self, engine: Engine, findings: int = 1, patched_name: str | None = BRANCH, **finding: Any
    ) -> None:
        with SqlTraustUnitOfWork(engine) as uow:
            seed = Seed(uow)
            self.repo: Repository = seed.repository(
                url=f"https://github.com/example-org/svc-{uuid4().hex[:8]}"
            )
            self.base: RepositoryRef = seed.repository_ref(self.repo, sha=BASE_SHA, is_default=True)
            seed.assessment(self.base, kind="repo-state", occurred_at=WHEN - timedelta(days=1))
            self.patched: RepositoryRef = seed.repository_ref(
                self.repo,
                name=patched_name,
                kind="branch" if patched_name is not None else None,
                sha=PATCHED_SHA,
            )
            self.findings: list[Finding] = [
                seed.finding(self.repo, **finding) for _ in range(findings)
            ]
            for f in self.findings:
                seed.decision(
                    f, validity="confirmed", severity="high", actor="human:analyst@example.com"
                )
            uow.commit()

    @property
    def ids(self) -> list[UUID]:
        return [f.id for f in self.findings]  # type: ignore[misc]


def opened(remediation: RemediationService, world: World) -> WorkItem:
    return remediation.open(world.ids, world.base.id)  # type: ignore[arg-type]


def report(
    world: World, verdicts: dict[UUID, str] | None = None, **changes: Any
) -> VerificationArtifact:
    raw = json.loads(json.dumps(REPORT))
    raw["metadata"]["repository"] = world.repo.url
    if world.patched.name is None:
        del raw["metadata"]["patched_ref"]
    else:
        raw["metadata"]["patched_ref"] = world.patched.name
    template = raw["verified_findings"][0]
    verdicts = verdicts or dict.fromkeys(world.ids, "resolved")
    raw["verified_findings"] = []
    for finding_id, verdict in verdicts.items():
        entry = {**template, "original_id": str(finding_id), "verdict": verdict}
        if verdict in ("false_positive", "risk_accepted"):
            entry["disposition_rationale"] = (
                "the owning team's ticket SEC-7 shows it is unreachable"
            )
        if verdict in ("partially_resolved", "new_approach"):
            entry["residual_risk"] = "the product still pins the vulnerable library version"
        if verdict in ("unresolved", "false_positive", "risk_accepted"):
            entry.update(remediation_commits=[], unattributed=True)
        raw["verified_findings"].append(entry)
    raw["summary"]["total_findings"] = len(verdicts)
    counts = dict.fromkeys(raw["summary"]["by_verdict"], 0)
    for v in verdicts.values():
        counts[v] += 1
    raw["summary"]["by_verdict"] = counts
    attributed = [
        str(f)
        for f, v in verdicts.items()
        if v not in ("unresolved", "false_positive", "risk_accepted")
    ]
    raw["commit_timeline"] = (
        [{**raw["commit_timeline"][0], "addresses": attributed}] if attributed else []
    )
    for path, value in changes.items():
        section, _, key = path.partition("__")
        if key:
            raw[section][key] = value
        else:
            raw[section] = value
    return VerificationArtifact.from_document(raw)


def provenance(artifact: ArtifactRef | None = None, at: datetime = WHEN) -> Provenance:
    return Provenance(
        run_id=uuid4(), artifact=artifact, source=SourceType.VERIFICATION_REPORT, occurred_at=at
    )


def decisions(engine: Engine, finding_id: UUID) -> list[Any]:
    with SqlTraustUnitOfWork(engine) as uow:
        return uow.decisions.list_for_finding(finding_id)


# record


def test_record_states_each_verdict_and_takes_the_regressions(
    service: VerificationService,
    remediation: RemediationService,
    context: Context,
    engine: Engine,
) -> None:
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    item = opened(remediation, world)
    got = service.record(report(world), provenance())
    assert (got.repository_ref_id, got.verified_at, got.work_item_ids) == (
        world.patched.id,
        WHEN,
        (item.work_item_id,),
    )
    assert [(v.finding_id, v.verdict) for v in got.verdicts] == [(world.ids[0], "resolved")]
    said = [d for d in decisions(engine, world.ids[0]) if d.assessment_id == got.verification_id]
    assert [(d.resolution, d.reason, d.validity) for d in said] == [("resolved", "resolved", None)]
    assert (said[0].fixed_repository_ref_id, said[0].artifact_id) == (
        world.patched.id,
        got.artifact.id,
    )
    assert said[0].rationale.startswith("The read is now bounded")
    assert not context.services().findings.get(world.ids[0]).is_open()
    (regression,) = got.regression_ids
    new = context.services().findings.get(regression)
    assert (new.finding.repository_id, new.finding.title, new.is_open()) == (
        world.repo.id,
        "Upload limit error leaks the internal path",
        True,
    )
    assert [(s.path, s.line_start) for s in new.locations] == [("pkg/upload/handler.go", 61)]
    with SqlTraustUnitOfWork(engine) as uow:
        run = uow.assessments.get(got.verification_id)
    assert (run.kind, run.assessor, run.assessor_version) == (
        "verification",
        "skill:verify-remediation",
        "1.4.0-abcdef1",
    )


def test_replayed_verification_does_not_log_another_outcome(
    service: VerificationService, engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    world = World(engine)
    doc = report(world)
    logger = logging.getLogger("traust_core.v1.services.remediation")
    with caplog.at_level(logging.INFO, logger=logger.name):
        logger.addHandler(caplog.handler)
        try:
            assert service.record(doc, provenance()) == service.record(doc, provenance())
        finally:
            logger.removeHandler(caplog.handler)
    events = [
        record
        for record in caplog.records
        if record.name == logger.name and record.getMessage().startswith("verification ")
    ]
    assert len({id(record) for record in events}) == 1


def test_recording_again_changes_nothing(service: VerificationService, engine: Engine) -> None:
    world = World(engine)
    doc = report(world)
    first = service.record(doc, provenance())
    before = len(decisions(engine, world.ids[0]))
    again = service.record(doc, provenance(at=WHEN + timedelta(hours=1)))
    assert again == first
    assert len(decisions(engine, world.ids[0])) == before
    assert (
        len(service.list(VerificationFilter(repository_id=world.repo.id), PageRequest()).items) == 1
    )  # type: ignore[arg-type]


def test_recording_again_finishes_a_run_that_stopped_part_way(
    service: VerificationService, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(engine, findings=2)
    doc = report(world, {world.ids[0]: "resolved", world.ids[1]: "unresolved"})
    decide = service._findings.decisions.record_resolution
    calls = iter([decide, RuntimeError])

    def flaky(*args: Any, **kwargs: Any) -> Any:
        step = next(calls)
        if step is RuntimeError:
            raise RuntimeError("connection lost")
        return step(*args, **kwargs)

    monkeypatch.setattr(service._findings.decisions, "record_resolution", flaky)
    with pytest.raises(RuntimeError):
        service.record(doc, provenance())
    monkeypatch.undo()
    # the verdicts are one transaction (as they already were through the record door):
    # the stopped run left nothing behind to finish
    assert not service.list(  # type: ignore[arg-type]
        VerificationFilter(repository_id=world.repo.id), PageRequest()
    ).items
    got = service.record(doc, provenance())
    assert {v.verdict for v in got.verdicts} == {"resolved", "unresolved"}


@pytest.mark.parametrize(
    ("verdict", "cross", "resolution", "validity", "is_open"),
    [
        ("new_approach", None, "resolved", None, False),
        ("partially_resolved", None, None, None, True),
        ("partially_resolved", "pending", "open", None, True),
        ("unresolved", None, "open", None, True),
        ("regression", None, "open", None, True),
        ("risk_accepted", None, "risk_accepted", None, False),
    ],
)
def test_each_verdict_maps_to_its_resolution(
    service: VerificationService,
    context: Context,
    engine: Engine,
    verdict: str,
    cross: str | None,
    resolution: str | None,
    validity: str | None,
    is_open: bool,
) -> None:
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    doc = report(world, {world.ids[0]: verdict})
    if cross:
        raw = json.loads(doc.payload)
        raw["verified_findings"][0]["cross_repo"] = {
            "fix_repo": "https://github.com/example-org/library",
            "propagation": cross,
        }
        doc = VerificationArtifact.from_document(raw)
    got = service.record(doc, provenance())
    assert [(v.finding_id, v.verdict) for v in got.verdicts] == [(world.ids[0], verdict)]
    (said,) = [d for d in decisions(engine, world.ids[0]) if d.assessment_id == got.verification_id]
    assert (said.resolution, said.validity, said.reason) == (resolution, validity, verdict)
    assert said.fixed_repository_ref_id == (world.patched.id if verdict == "new_approach" else None)
    assert context.services().findings.get(world.ids[0]).is_open() is is_open
    before = decisions(engine, world.ids[0])
    assert service.record(doc, provenance(at=WHEN + timedelta(hours=1))) == got
    assert decisions(engine, world.ids[0]) == before


def test_a_verified_false_positive_needs_a_person_to_stand(
    service: VerificationService, context: Context, engine: Engine
) -> None:
    world = World(engine)
    got = service.record(report(world, {world.ids[0]: "false_positive"}), provenance())
    (said,) = [d for d in decisions(engine, world.ids[0]) if d.assessment_id == got.verification_id]
    assert (said.validity, said.resolution, said.auto_accept_tier) == (
        "false_positive",
        None,
        False,
    )
    # The analyst's confirmation stands; the verifier's refutation is a conflict for a person.
    view = context.services().findings.get(world.ids[0])
    assert view.is_open() and view.disposition.validity == "confirmed"  # type: ignore[union-attr]
    assert view.disposition.conflict  # type: ignore[union-attr]


def test_record_takes_an_already_published_report(
    service: VerificationService, engine: Engine
) -> None:
    world = World(engine)
    doc = report(world)
    published = service._publisher.publish_artifact(doc)
    ref = ArtifactRef(id=published.artifact_id, name=doc.name, digest=sha256_hex(doc.payload))
    assert service.record(doc, provenance(ref)).artifact.digest == sha256_hex(doc.payload)


def test_record_refuses_a_published_artifact_that_is_not_the_report(
    service: VerificationService, engine: Engine
) -> None:
    world = World(engine)
    other = service._publisher.publish_artifact(report(world, title="Remediation verification two"))
    ref = ArtifactRef(id=other.artifact_id, name="remediation-verification", digest="0" * 64)
    with pytest.raises(IntegrityError, match="doc digest"):
        service.record(report(world), provenance(ref))


def test_an_unnamed_patched_commit_is_its_one_registered_ref(
    service: VerificationService, engine: Engine
) -> None:
    world = World(engine)
    raw = json.loads(report(world).payload)
    del raw["metadata"]["patched_ref"]
    doc = VerificationArtifact.from_document(raw)
    assert service.record(doc, provenance()).repository_ref_id == world.patched.id
    with SqlTraustUnitOfWork(engine) as uow:
        Seed(uow).repository_ref(world.repo, name="release-1", sha=PATCHED_SHA)
        uow.commit()
    raw["title"] = "Remediation verification, again"
    with pytest.raises(ValidationError, match="2 registered refs"):
        service.record(VerificationArtifact.from_document(raw), provenance())


def _refusals(world: World, other: World) -> dict[str, tuple[Any, type[Exception], str]]:
    resolved = report(world)
    raw = json.loads(resolved.payload)
    return {
        "unknown finding": (report(world, {uuid4(): "resolved"}), NotFoundError, "findings"),
        "not a finding id": (
            VerificationArtifact.from_document(
                {
                    **raw,
                    "verified_findings": [{**raw["verified_findings"][0], "original_id": "FIND-1"}],
                    "commit_timeline": [{**raw["commit_timeline"][0], "addresses": ["FIND-1"]}],
                }
            ),
            ValidationError,
            "not a finding id",
        ),
        "two repositories": (
            report(world, {world.ids[0]: "resolved", other.ids[0]: "resolved"}),
            ValidationError,
            "several repositories",
        ),
        "another repository's url": (
            report(world, metadata__repository=other.repo.url),
            ValidationError,
            "is not the findings' repository",
        ),
        "unregistered branch": (
            report(world, metadata__patched_ref="other-branch"),
            NotFoundError,
            "not a registered ref",
        ),
        "whole-run fix repository": (
            report(world, metadata__fix_repository="https://github.com/example-org/library"),
            ValidationError,
            "metadata.fix_repository",
        ),
        "inconsistent": (
            report(world, summary__regressions=0),
            ValidationError,
            "summary.regressions",
        ),
    }


@pytest.mark.parametrize(
    "case",
    [
        "unknown finding",
        "not a finding id",
        "two repositories",
        "another repository's url",
        "unregistered branch",
        "whole-run fix repository",
        "inconsistent",
    ],
)
def test_record_refuses_a_report_it_cannot_place(
    service: VerificationService, engine: Engine, case: str
) -> None:
    world, other = World(engine), World(engine)
    doc, error, said = _refusals(world, other)[case]
    with pytest.raises(error, match=said):
        service.record(doc, provenance())
    assert decisions(engine, world.ids[0])[-1].assessment_id is None  # nothing stated


def test_verdicts_go_on_the_ledger_when_it_is_on(engine: Engine, tmp_path: Path) -> None:
    service = make_context(engine, tmp_path, ledger=LedgerConfig()).services().verification
    world = World(engine)
    service.record(report(world), provenance())
    with SqlTraustUnitOfWork(engine) as uow:
        events = uow.connection.execute(sa.select(sa.func.count()).select_from(uow.events.table))
        assert events.scalar() == 1  # the seeded verdict is not on the ledger


# list and prepare


def test_list_pages_verifications_oldest_first_and_by_work_item(
    service: VerificationService, remediation: RemediationService, engine: Engine
) -> None:
    world = World(engine, findings=2)
    item = remediation.open(world.ids[:1], world.base.id)  # type: ignore[arg-type]
    first = service.record(report(world, {world.ids[1]: "unresolved"}), provenance())
    second = service.record(
        report(world, {world.ids[0]: "resolved"}), provenance(at=WHEN + timedelta(days=1))
    )
    repo = world.repo.id
    page = service.list(VerificationFilter(repository_id=repo), PageRequest(limit=1))  # type: ignore[arg-type]
    assert [v.verification_id for v in page.items] == [first.verification_id]
    rest = service.list(
        VerificationFilter(repository_id=repo), PageRequest(limit=1, cursor=page.next)
    )  # type: ignore[arg-type]
    assert [v.verification_id for v in rest.items] == [second.verification_id] and rest.next is None
    mine = service.list(
        VerificationFilter(repository_id=repo, work_item_id=item.work_item_id),  # type: ignore[arg-type]
        PageRequest(),
    )
    assert [v.verification_id for v in mine.items] == [second.verification_id]
    assert service.list(VerificationFilter(repository_id=uuid4()), PageRequest()).items == ()


def test_prepare_hands_the_skill_the_work_item_its_findings_and_earlier_runs(
    service: VerificationService, remediation: RemediationService, engine: Engine
) -> None:
    world = World(engine)
    audited(engine, world, world.base)
    item = opened(remediation, world)
    before = service.prepare(item.work_item_id)
    assert (before.subject.sha, before.subject.assessment_id, before.work_item.work_item_id) == (
        BASE_SHA,
        item.work_item_id,
        item.work_item_id,
    )
    assert [i.finding.finding.id for i in before.items] == world.ids
    assert len(before.items[0].decisions) == 2  # the confirmation, then the work item's step
    assert [v.finding.id for v in before.findings.baseline] == world.ids
    assert before.verifications == ()
    done = service.record(report(world), provenance())
    assert service.prepare(item.work_item_id).verifications == (done,)


def test_prepare_knows_only_work_items(service: VerificationService, engine: Engine) -> None:
    with pytest.raises(NotFoundError):
        service.prepare(uuid4())


# differential


def scanned(engine: Engine, ref: RepositoryRef, facts: list[tuple[Finding, str, str]]) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        run = seed.assessment(
            ref, kind="scanner", assessor="opengrep", assessor_version="1.25.0", occurred_at=WHEN
        )
        for finding, rule, path in facts:
            seed.location(seed.occurrence(finding, run, rule=rule), path=path, line_start=7)
        uow.commit()


@pytest.mark.parametrize(
    ("patched", "outcome"),
    [
        ([(RULE, "app.py")], "fails_to_prove"),
        ([(RULE, "other.py")], "proves"),
        ([("another-rule", "app.py")], "proves"),
        ([], "proves"),
        (None, "not_attempted: no opengrep 1.25.0 scan of the patched revision"),
    ],
)
def test_differential_compares_the_backing_scan_on_both_commits(
    service: VerificationService,
    remediation: RemediationService,
    engine: Engine,
    patched: list[tuple[str, str]] | None,
    outcome: str,
) -> None:
    world = World(engine)
    item = opened(remediation, world)
    scanned(engine, world.base, [(world.findings[0], RULE, "app.py")])
    if patched is not None:
        scanned(engine, world.patched, [(world.findings[0], r, p) for r, p in patched])
    got = service.differential(item.work_item_id, world.patched.id)  # type: ignore[arg-type]
    assert got.outcome == outcome
    assert got.tool == "opengrep 1.25.0" and got.kind == "scanner_differential"


def test_a_finding_no_scanner_backed_has_no_differential(
    service: VerificationService, remediation: RemediationService, engine: Engine
) -> None:
    world = World(engine)
    item = opened(remediation, world)
    got = service.differential(item.work_item_id, world.patched.id)  # type: ignore[arg-type]
    assert got.outcome.startswith("not_attempted: no scanner fact backs")


def test_differential_needs_another_commit_of_the_repository(
    service: VerificationService, remediation: RemediationService, engine: Engine
) -> None:
    world, other = World(engine), World(engine)
    item = opened(remediation, world)
    with pytest.raises(ValidationError, match="own commit"):
        service.differential(item.work_item_id, world.base.id)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="not in the base commit's repository"):
        service.differential(item.work_item_id, other.patched.id)  # type: ignore[arg-type]


def test_differential_of_needs_no_work_item_the_base_is_the_callers(
    service: VerificationService, engine: Engine
) -> None:
    world = World(engine)
    scanned(engine, world.base, [(world.findings[0], RULE, "app.py")])
    scanned(engine, world.patched, [(world.findings[0], RULE, "other.py")])
    got = service.differential_of(world.ids, world.base.id, world.patched.id)  # type: ignore[arg-type]
    assert (got.outcome, got.tool) == ("proves", "opengrep 1.25.0")
    unknown = service.differential_of([uuid4()], world.base.id, world.patched.id)  # type: ignore[arg-type]
    assert unknown.outcome.startswith("not_attempted: no scanner fact backs")


def test_differential_of_needs_findings_and_known_commits(
    service: VerificationService, engine: Engine
) -> None:
    world = World(engine)
    with pytest.raises(ValidationError, match="at least one finding"):
        service.differential_of([], world.base.id, world.patched.id)  # type: ignore[arg-type]
    with pytest.raises(NotFoundError):
        service.differential_of(world.ids, uuid4(), world.patched.id)  # type: ignore[arg-type]


# propagation


def sbom(*pins: tuple[str, str]) -> bytes:
    components = [{"purl": f"pkg:golang/{n}@{v}"} for n, v in pins]
    return json.dumps({"bomFormat": "CycloneDX", "components": components}).encode()


def advisory_world(engine: Engine) -> World:
    with SqlTraustUnitOfWork(engine) as uow:
        advisory = Seed(uow).advisory(identifier="GHSA-m425-mq94-257g")
        uow.commit()
    return World(engine, advisory_id=advisory.id, advisory_match="confirmed")


def consumer(engine: Engine) -> tuple[UUID, UUID]:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref(seed.repository(url="https://github.com/example-org/product"))
        component = seed.component(ref=ref)
        uow.commit()
    return component.id, ref.id  # type: ignore[return-value]


@pytest.mark.parametrize(
    ("pins", "status", "consumed"),
    [
        ((("google.golang.org/grpc", "v1.56.3"),), "consumed", [True]),
        ((("google.golang.org/grpc", "v1.57.1"),), "consumed", [True]),
        ((("google.golang.org/grpc", "v1.57.0"),), "pending", [False]),
        ((("google.golang.org/grpc", "v1.40.0"),), "pending", [False]),
    ],
)
def test_propagation_judges_the_versions_the_component_ships(
    service: VerificationService,
    remediation: RemediationService,
    context: Context,
    engine: Engine,
    pins: tuple[tuple[str, str], ...],
    status: str,
    consumed: list[bool],
) -> None:
    world = advisory_world(engine)
    item = opened(remediation, world)
    component, ref = consumer(engine)
    context.services().exposure.ingest_sbom(sbom(*pins), ref)
    got = service.propagation(item.work_item_id, component)
    assert (got.status, got.work_item_id, got.component_id) == (
        status,
        item.work_item_id,
        component,
    )
    (package,) = got.evidence
    assert (package.name, package.fixed) == ("google.golang.org/grpc", "1.56.3")
    assert [c.consumed for c in package.checked] == consumed


def test_propagation_over_a_document_sbom_lacking_the_package_is_unknown(
    service: VerificationService,
    remediation: RemediationService,
    context: Context,
    engine: Engine,
) -> None:
    item = opened(remediation, advisory_world(engine))
    component, ref = consumer(engine)
    context.services().exposure.ingest_sbom(sbom(("example.com/other", "v1.0.0")), ref)
    with pytest.raises(NotFoundError, match="coverage leaves the package unknown"):
        service.propagation(item.work_item_id, component)


def test_propagation_needs_an_sbom_and_an_advisory(
    service: VerificationService, remediation: RemediationService, engine: Engine
) -> None:
    component, _ = consumer(engine)
    item = opened(remediation, advisory_world(engine))
    with pytest.raises(NotFoundError, match="no SBOM"):
        service.propagation(item.work_item_id, component)
    plain = opened(remediation, World(engine))
    with pytest.raises(ValidationError, match="fixes no advisory"):
        service.propagation(plain.work_item_id, component)
    with pytest.raises(NotFoundError):
        service.propagation(item.work_item_id, uuid4())


# sweep


def audited(engine: Engine, world: World, ref: RepositoryRef) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        run = seed.assessment(ref, kind="secure-code", occurred_at=WHEN - timedelta(days=30))
        for f in world.findings:
            seed.occurrence(f, run)
        uow.commit()


def moved_head(engine: Engine, world: World) -> RepositoryRef:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        head = seed.repository_ref(world.repo, sha="c" * 40, is_default=True)
        seed.assessment(head, kind="repo-state", occurred_at=WHEN)
        uow.commit()
    return head


def test_sweep_tiers_and_skips_repositories(
    service: VerificationService, remediation: RemediationService, engine: Engine
) -> None:
    unchanged = World(engine)
    audited(engine, unchanged, unchanged.base)
    drifted = World(engine)
    audited(engine, drifted, drifted.base)
    moved_head(engine, drifted)
    claimed = World(engine)
    audited(engine, claimed, claimed.base)
    item = opened(remediation, claimed)
    remediation.record_progress(item.work_item_id, RemediationStatus("forked"))
    verified = World(engine)
    audited(engine, verified, verified.base)
    service.record(report(verified, {verified.ids[0]: "unresolved"}), provenance())
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        verified_head = seed.repository_ref(
            verified.repo, name="main", sha=PATCHED_SHA, is_default=True
        )
        seed.assessment(verified_head, kind="repo-state", occurred_at=WHEN)
        unobserved = seed.repository()
        seed.repository_ref(unobserved, is_default=True)
        uow.commit()
    sweep = service.sweep(
        [r.repo.id for r in (unchanged, drifted, claimed, verified)]
        + [unobserved.id, drifted.repo.id]  # type: ignore[misc]
    )
    assert [(e.repository_id, e.tier) for e in sweep.queued] == [
        (claimed.repo.id, "T1"),
        (drifted.repo.id, "T3"),
    ]
    assert {e.repository_id: e.skip for e in sweep.skipped} == {
        unchanged.repo.id: "head_unchanged",
        verified.repo.id: "already_verified",
        unobserved.id: "unobserved",
    }
    (t3,) = [e for e in sweep.queued if e.tier == "T3"]
    assert (t3.pinned_sha, t3.head_sha, t3.highs, t3.open_findings, t3.claims) == (
        BASE_SHA,
        "c" * 40,
        1,
        1,
        0,
    )


def test_sweep_uses_the_returning_observed_head(
    service: VerificationService, engine: Engine
) -> None:
    world = World(engine)
    audited(engine, world, world.base)
    moved_head(engine, world)
    with SqlTraustUnitOfWork(engine) as uow:
        Seed(uow).assessment(world.base, kind="repo-state", occurred_at=WHEN + timedelta(seconds=1))
        uow.commit()
    (entry,) = service.sweep([world.repo.id]).skipped
    assert (entry.head_sha, entry.skip) == (BASE_SHA, "head_unchanged")


def test_a_verified_claim_no_longer_queues(
    service: VerificationService, remediation: RemediationService, engine: Engine
) -> None:
    world = World(engine)
    audited(engine, world, world.base)
    item = opened(remediation, world)
    remediation.record_progress(item.work_item_id, RemediationStatus("forked"))
    assert service.sweep([world.repo.id]).queued[0].claims == 1  # type: ignore[list-item]
    service.record(report(world, {world.ids[0]: "partially_resolved"}), provenance())
    moved_head(engine, world)
    (entry,) = service.sweep([world.repo.id]).queued  # type: ignore[list-item]
    assert (entry.claims, entry.tier, entry.pinned_sha) == (0, "T3", PATCHED_SHA)


def test_a_merged_fix_is_a_claim_until_a_verification_resolves_it(
    service: VerificationService,
    remediation: RemediationService,
    context: Context,
    engine: Engine,
) -> None:
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    item = opened(remediation, world)
    remediation.record_progress(item.work_item_id, RemediationStatus("merged"))
    claimed = context.services().findings.get(world.ids[0])
    assert claimed.is_open()
    assert claimed.disposition and claimed.disposition.resolution == "open"
    (entry,) = service.sweep([world.repo.id]).queued  # type: ignore[list-item]
    assert (entry.claims, entry.tier) == (1, "T1")
    got = service.record(report(world, {world.ids[0]: "resolved"}), provenance())
    (said,) = [d for d in decisions(engine, world.ids[0]) if d.assessment_id == got.verification_id]
    assert (said.resolution, said.fixed_repository_ref_id) == ("resolved", world.patched.id)
    assert not context.services().findings.get(world.ids[0]).is_open()


def test_mixed_work_item_progress_preserves_closed_findings_and_open_claims(
    service: VerificationService,
    remediation: RemediationService,
    context: Context,
    engine: Engine,
) -> None:
    world = World(engine, findings=2)
    audited(engine, world, world.base)
    item = opened(remediation, world)
    closed_id, open_id = world.ids
    with SqlTraustUnitOfWork(engine) as uow:
        Seed(uow).decision(
            world.findings[0],
            validity=None,
            resolution="resolved",
            repository_ref_id=world.base.id,
            actor="human:analyst@example.com",
            occurred_at=context.clock.now(),
        )
        uow.commit()

    progressed = remediation.record_progress(item.work_item_id, RemediationStatus.MERGED)
    assert progressed.status == "merged"
    (closed_progress,) = [
        d
        for d in decisions(engine, closed_id)
        if d.assessment_id == item.work_item_id and d.reason == "merged"
    ]
    (open_progress,) = [
        d
        for d in decisions(engine, open_id)
        if d.assessment_id == item.work_item_id and d.reason == "merged"
    ]
    assert closed_progress.resolution is None
    assert open_progress.resolution == "open"
    closed = context.services().findings.get(closed_id)
    still_open = context.services().findings.get(open_id)
    assert not closed.is_open()
    assert closed.disposition is not None and closed.disposition.resolution == "resolved"
    assert still_open.is_open()
    assert still_open.disposition is not None and still_open.disposition.resolution == "open"
    assert world.repo.id is not None
    (entry,) = service.sweep([world.repo.id]).queued
    assert (entry.open_findings, entry.claims, entry.tier) == (1, 1, "T1")


def test_a_verified_fix_outranks_later_ungraded_progress(
    service: VerificationService,
    remediation: RemediationService,
    context: Context,
    engine: Engine,
) -> None:
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    item = opened(remediation, world)
    service.record(report(world, {world.ids[0]: "resolved"}), provenance())
    (verdict,) = [d for d in decisions(engine, world.ids[0]) if d.resolution == "resolved"]
    assert verdict.evidence_grade == "E1"
    remediation.record_progress(item.work_item_id, RemediationStatus("merged"))
    assert not context.services().findings.get(world.ids[0]).is_open()


def test_a_verified_fix_resolves_the_audited_line_only(
    service: VerificationService, context: Context, engine: Engine
) -> None:
    world = World(engine, patched_name="release-1")
    with SqlTraustUnitOfWork(engine) as uow:
        release = Seed(uow).repository_ref(world.repo, name="release-1", sha=BASE_SHA)
        uow.commit()
    audited(engine, world, release)
    got = service.record(report(world, {world.ids[0]: "resolved"}), provenance())
    assert got.repository_ref_id == world.patched.id
    assert not context.services().findings.on_ref(world.patched.id)[0].is_open()
    assert context.services().findings.get(world.ids[0]).is_open()


def test_without_a_recorded_audit_a_verdict_resolves_the_patched_line(
    service: VerificationService, context: Context, engine: Engine
) -> None:
    world = World(engine)
    service.record(report(world, {world.ids[0]: "resolved"}), provenance())
    assert context.services().findings.get(world.ids[0]).is_open()


def test_a_statement_is_never_both_a_validity_and_a_resolution(
    context: Context, engine: Engine
) -> None:
    world = World(engine)
    with pytest.raises(ValidationError, match="never both"):
        context.services().findings.decisions.record_resolution(
            uuid4(),
            world.ids,
            DispositionResolution("resolved"),
            "resolved",
            validity=Validity("false_positive"),
        )
    assert len(decisions(engine, world.ids[0])) == 1


def test_branch_sweep_keeps_default_and_release_evidence_separate(
    service: VerificationService,
    remediation: RemediationService,
    context: Context,
    engine: Engine,
) -> None:
    world = World(engine)
    audited(engine, world, world.base)
    item = opened(remediation, world)
    remediation.record_progress(item.work_item_id, RemediationStatus.PATCHED)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        base = seed.repository_ref(world.repo, name="release-1", sha="b" * 40)
        tip = seed.repository_ref(world.repo, name="release-1", sha=PATCHED_SHA)
        run = seed.assessment(base, kind="secure-code", occurred_at=WHEN - timedelta(days=10))
        finding = seed.finding(world.repo, title="Release-only critical flaw")
        seed.decision(finding, validity="confirmed", severity="critical")
        seed.occurrence(finding, run)
        seed.assessment(tip, kind="repo-state", occurred_at=WHEN)
        default = seed.repository_ref(world.repo, sha=PATCHED_SHA, is_default=True)
        seed.assessment(default, kind="repo-state", occurred_at=WHEN)
        uow.commit()
    service.record(
        report(world, {world.ids[0]: "unresolved"}, regressions=[], summary__regressions=0),
        provenance(),
    )
    assert service.sweep([world.repo.id]).queued == ()
    sweep = service.sweep([world.repo.id, world.repo.id], include_branches=True)
    release = next(e for e in sweep.queued if e.ref_name == "release-1")
    assert (
        release.repository_ref_id,
        release.head_sha,
        release.pinned_sha,
        release.head_source,
        release.criticals,
        release.highs,
        release.open_findings,
        release.tier,
    ) == (tip.id, PATCHED_SHA, "b" * 40, "observed_branch", 1, 0, 1, "T2")
    assert len([e for e in (*sweep.queued, *sweep.skipped) if e.ref_name == "release-1"]) == 1
    doc = report(
        world,
        {finding.id: "resolved"},
        metadata__original_commit="b" * 40,
        metadata__patched_ref="release-1",
        regressions=[],
        summary__regressions=0,
    )
    recorded = service.record(doc, provenance())
    result = next(
        v
        for v in service.list(VerificationFilter(repository_id=world.repo.id), PageRequest()).items
        if v.verification_id == recorded.verification_id
    )
    assert [(v.finding_id, v.verdict) for v in result.verdicts] == [(finding.id, "resolved")]
    assert not context.services().findings.on_ref(tip.id)[0].is_open()
    assert context.services().findings.get(world.ids[0]).is_open()
    assert remediation.get(item.work_item_id).status == RemediationStatus.PATCHED
    after = service.sweep([world.repo.id], include_branches=True)
    assert next(e for e in after.skipped if e.ref_name == "release-1").skip == "already_verified"


def test_branch_sweep_uses_returning_observation_instead_of_latest_inserted_ref(
    service: VerificationService, engine: Engine
) -> None:
    world = World(engine)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        base = seed.repository_ref(world.repo, name="release-1", sha="b" * 40)
        newer = seed.repository_ref(world.repo, name="release-1", sha="c" * 40)
        audit = seed.assessment(base, kind="secure-code", occurred_at=WHEN - timedelta(days=1))
        seed.occurrence(world.findings[0], audit)
        seed.assessment(newer, kind="repo-state", occurred_at=WHEN)
        seed.assessment(base, kind="repo-state", occurred_at=WHEN + timedelta(seconds=1))
        uow.commit()
    sweep = service.sweep([world.repo.id], include_branches=True)
    entry = next(e for e in sweep.skipped if e.ref_name == "release-1")
    assert (entry.repository_ref_id, entry.head_sha, entry.skip) == (
        base.id,
        "b" * 40,
        "head_unchanged",
    )


def test_unfinished_verification_assessment_is_not_a_completed_result(
    service: VerificationService, engine: Engine
) -> None:
    world = World(engine)
    audited(engine, world, world.base)
    head = moved_head(engine, world)
    with SqlTraustUnitOfWork(engine) as uow:
        Seed(uow).assessment(head, kind="verification", occurred_at=WHEN)
        uow.commit()
    assert service.list(VerificationFilter(repository_id=world.repo.id), PageRequest()).items == ()
    (entry,) = service.sweep([world.repo.id]).queued
    assert (entry.tier, entry.verified_at_head, entry.pinned_sha) == ("T3", False, BASE_SHA)


def test_shared_sha_baseline_requires_the_verified_branch_and_does_not_break_replay(
    service: VerificationService, context: Context, engine: Engine
) -> None:
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    original = report(world, regressions=[], summary__regressions=0)
    first = service.record(original, provenance())
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        release = seed.repository_ref(world.repo, name="release-1", sha=BASE_SHA)
        patched = seed.repository_ref(world.repo, name="release-1", sha=PATCHED_SHA)
        audit = seed.assessment(release, kind="secure-code", occurred_at=WHEN - timedelta(hours=1))
        seed.occurrence(world.findings[0], audit)
        uow.commit()
    assert service.record(original, provenance()) == first
    reopened = service.record(
        report(world, {world.ids[0]: "unresolved"}, regressions=[], summary__regressions=0),
        provenance(),
    )
    with SqlTraustUnitOfWork(engine) as uow:
        assert (
            uow.assessments.get(reopened.verification_id).baseline_assessment_id
            == uow.assessments.get(first.verification_id).baseline_assessment_id
        )
    branch_report = report(
        world, metadata__patched_ref="release-1", regressions=[], summary__regressions=0
    )
    result = service.record(branch_report, provenance())
    assert result.repository_ref_id == patched.id
    with SqlTraustUnitOfWork(engine) as uow:
        stored = uow.assessments.get(result.verification_id)
    assert stored.baseline_assessment_id == audit.id
    assert not context.services().findings.on_ref(patched.id)[0].is_open()
    assert context.services().findings.get(world.ids[0]).is_open()


@pytest.mark.parametrize("audit_name", ["main", "release-1", None])
def test_an_unaudited_line_never_borrows_another_original_audit(
    service: VerificationService, context: Context, engine: Engine, audit_name: str | None
) -> None:
    world = World(engine)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        audited_ref = (
            world.base
            if audit_name == "main"
            else seed.repository_ref(
                world.repo,
                name=audit_name,
                kind="branch" if audit_name else None,
                sha=BASE_SHA,
            )
        )
        original = seed.repository_ref(world.repo, name=BRANCH, sha=BASE_SHA)
        uow.commit()
    audited(engine, world, audited_ref)
    doc = report(world, regressions=[], summary__regressions=0)
    done = service.record(doc, provenance())
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.assessments.get(done.verification_id).baseline_assessment_id is None
    assert done.repository_ref_id == world.patched.id
    assert [(v.finding_id, v.verdict) for v in done.verdicts] == [(world.ids[0], "resolved")]
    assert context.services().findings.on_ref(audited_ref.id)[0].is_open()
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        later = seed.assessment(original, kind="secure-code", occurred_at=WHEN)
        seed.occurrence(world.findings[0], later)
        uow.commit()
    assert service.record(doc, provenance()) == done
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.assessments.get(done.verification_id).baseline_assessment_id is None
    assert context.services().findings.on_ref(audited_ref.id)[0].is_open()


def test_two_unnamed_refs_do_not_share_a_baseline_or_resolve_main(
    service: VerificationService, context: Context, engine: Engine
) -> None:
    world = World(engine, patched_name=None)
    with SqlTraustUnitOfWork(engine) as uow:
        original = Seed(uow).repository_ref(world.repo, name=None, kind=None, sha=BASE_SHA)
        uow.commit()
    audited(engine, world, original)
    audited(engine, world, world.patched)
    findings = context.services().findings
    assert findings.on_ref(world.base.id)[0].is_open()
    done = service.record(report(world, regressions=[], summary__regressions=0), provenance())
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.assessments.get(done.verification_id).baseline_assessment_id is None
    assert findings.on_ref(world.base.id)[0].is_open()
    assert findings.get(world.ids[0]).is_open()
    assert not findings.on_ref(world.patched.id)[0].is_open()


def test_an_unnamed_ref_can_use_its_own_audit_as_a_baseline(
    service: VerificationService, context: Context, engine: Engine
) -> None:
    world = World(engine, patched_name=None)
    audited(engine, world, world.patched)
    done = service.record(
        report(
            world,
            metadata__original_commit=PATCHED_SHA,
            regressions=[],
            summary__regressions=0,
        ),
        provenance(),
    )
    with SqlTraustUnitOfWork(engine) as uow:
        baseline = uow.assessments.get(done.verification_id).baseline_assessment_id
        assert baseline is not None
        assert uow.assessments.get(baseline).repository_ref_id == world.patched.id
    assert context.services().findings.get(world.ids[0]).is_open()
    assert not context.services().findings.on_ref(world.patched.id)[0].is_open()


def test_sweep_markdown_renders_every_classified_entry_without_changing_state(
    service: VerificationService, engine: Engine
) -> None:
    world = World(engine)
    audited(engine, world, world.base)
    head = moved_head(engine, world)
    sweep = service.sweep([world.repo.id])
    markdown = service.sweep_markdown(sweep)
    assert markdown.startswith("# Remediation verification worklist\n")
    assert f"{len(sweep.queued)} queued; {len(sweep.skipped)} skipped." in markdown
    for tier in ("T1", "T2", "T3", "T4"):
        assert f"| {tier} |" in markdown
    (entry,) = sweep.queued
    ref = entry.ref_name or "(default)"
    assert f"| {entry.tier} | {world.repo.url} | {ref} | observed_default |" in markdown
    assert head.sha in markdown
    assert service.sweep([world.repo.id]) == sweep


def test_sweep_markdown_of_an_empty_sweep_lists_no_targets(service: VerificationService) -> None:
    markdown = service.sweep_markdown(service.sweep([]))
    assert "0 queued; 0 skipped." in markdown
    assert "| T1 | 0 |" in markdown


def test_default_sweep_entries_name_their_head_ref(
    service: VerificationService, engine: Engine
) -> None:
    world = World(engine)
    audited(engine, world, world.base)
    head = moved_head(engine, world)
    (entry,) = service.sweep([world.repo.id]).queued
    assert (entry.repository_ref_id, entry.ref_name, entry.head_source) == (
        head.id,
        head.name,
        "observed_default",
    )


def test_default_sweep_weighs_off_line_verifications_and_claims_as_development_did(
    service: VerificationService, remediation: RemediationService, engine: Engine
) -> None:
    world = World(engine, findings=2)
    audited(engine, world, world.base)
    claimed = remediation.open([world.ids[1]], world.patched.id)  # type: ignore[list-item]
    remediation.record_progress(claimed.work_item_id, RemediationStatus("forked"))
    service.record(report(world, {world.ids[0]: "unresolved"}), provenance())
    (entry,) = service.sweep([world.repo.id]).queued
    assert (
        entry.head_sha,
        entry.pinned_sha,
        entry.verified_at_head,
        entry.claims,
        entry.open_findings,
        entry.tier,
    ) == (BASE_SHA, PATCHED_SHA, False, 1, 2, "T1")


def test_a_tag_of_a_branchs_name_never_replaces_the_branch_sweep_target(
    service: VerificationService, engine: Engine
) -> None:
    world = World(engine)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        branch = seed.repository_ref(world.repo, name="release-1", sha="b" * 40)
        tag = seed.repository_ref(world.repo, name="release-1", kind="tag", sha="c" * 40)
        seed.assessment(tag, kind="repo-state", occurred_at=WHEN)
        uow.commit()
    sweep = service.sweep([world.repo.id], include_branches=True)
    [entry] = [e for e in (*sweep.queued, *sweep.skipped) if e.ref_name == "release-1"]
    assert (entry.repository_ref_id, entry.head_sha, entry.head_source) == (
        branch.id,
        "b" * 40,
        "registered_branch",
    )


def test_a_branch_sweep_reads_each_repositorys_verifications_once(
    service: VerificationService, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    worlds = [World(engine), World(engine)]
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        for world in worlds:
            for name in ("release-1", "release-2"):
                seed.repository_ref(world.repo, name=name, sha=uuid4().hex + "0" * 8)
        uow.commit()
    read: list[UUID] = []
    verifications = VerificationService._verifications

    def counted(self: VerificationService, repository_id: UUID) -> Any:
        read.append(repository_id)
        return verifications(self, repository_id)

    monkeypatch.setattr(VerificationService, "_verifications", counted)
    sweep = service.sweep([w.repo.id for w in worlds], include_branches=True)
    assert len((*sweep.queued, *sweep.skipped)) == 2 * (1 + 3)
    assert sorted(read, key=str) == sorted((w.repo.id for w in worlds), key=str)


def test_a_default_sweep_reads_no_verification_reports(
    service: VerificationService, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(engine)
    audited(engine, world, world.base)
    service.record(report(world, {world.ids[0]: "unresolved"}), provenance())

    def unread(self: VerificationService, repository_id: UUID) -> Any:
        pytest.fail(f"a default sweep read {repository_id}'s verification reports")

    monkeypatch.setattr(VerificationService, "_verifications", unread)
    (entry,) = (*(sweep := service.sweep([world.repo.id])).queued, *sweep.skipped)
    assert entry.pinned_sha == PATCHED_SHA


def test_a_default_sweep_counts_a_verdicted_run_without_a_report_as_development_did(
    service: VerificationService, engine: Engine
) -> None:
    world = World(engine)
    audited(engine, world, world.base)
    head = moved_head(engine, world)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        run = seed.assessment(head, kind="verification", occurred_at=WHEN)
        seed.decision(
            world.findings[0],
            validity=None,
            resolution="resolved",
            assessment_id=run.id,
            actor=None,
            occurred_at=WHEN,
        )
        uow.commit()
    (entry,) = (*(sweep := service.sweep([world.repo.id])).queued, *sweep.skipped)
    assert (entry.verified_at_head, entry.pinned_sha, entry.skip) == (
        True,
        head.sha,
        "already_verified",
    )
