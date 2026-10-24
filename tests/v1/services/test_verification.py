"""VerificationService over SQLite and Postgres: the legacy emit_verification_ledger_events,
route_regressions, scanner_differential, check_fix_propagation and build_verify_sweep paths, on
core's work items, decisions and assessments."""

from __future__ import annotations

import json
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
from traust_core.v1.models.vocabulary import RemediationStatus, SourceType
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
    ctx = Context(Config(home=tmp_path, remediation=PRIVATE, **config))
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

    def __init__(self, engine: Engine, findings: int = 1, **finding: Any) -> None:
        with SqlTraustUnitOfWork(engine) as uow:
            seed = Seed(uow)
            self.repo: Repository = seed.repository(
                url=f"https://github.com/example-org/svc-{uuid4().hex[:8]}"
            )
            self.base: RepositoryRef = seed.repository_ref(self.repo, sha=BASE_SHA, is_default=True)
            self.patched: RepositoryRef = seed.repository_ref(
                self.repo, name=BRANCH, sha=PATCHED_SHA
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
    world = World(engine)
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
    (partial,) = service.list(VerificationFilter(repository_id=world.repo.id), PageRequest()).items  # type: ignore[arg-type]
    assert [v.verdict for v in partial.verdicts] == ["resolved"]
    got = service.record(doc, provenance())
    assert {v.verdict for v in got.verdicts} == {"resolved", "unresolved"}


@pytest.mark.parametrize(
    ("verdict", "cross", "resolution", "validity", "is_open"),
    [
        ("new_approach", None, "resolved", None, False),
        ("partially_resolved", None, "partially_resolved", None, True),
        ("partially_resolved", "pending", "fix_in_progress", None, True),
        ("unresolved", None, "open", None, True),
        ("regression", None, "regression_introduced", None, True),
        ("risk_accepted", None, "risk_accepted", None, False),
    ],
)
def test_each_verdict_maps_to_its_resolution(
    service: VerificationService,
    context: Context,
    engine: Engine,
    verdict: str,
    cross: str | None,
    resolution: str,
    validity: str | None,
    is_open: bool,
) -> None:
    world = World(engine)
    doc = report(world, {world.ids[0]: verdict})
    if cross:
        raw = json.loads(doc.payload)
        raw["verified_findings"][0]["cross_repo"] = {
            "fix_repo": "https://github.com/example-org/library",
            "propagation": cross,
        }
        doc = VerificationArtifact.from_document(raw)
    got = service.record(doc, provenance())
    (said,) = [d for d in decisions(engine, world.ids[0]) if d.assessment_id == got.verification_id]
    assert (said.resolution, said.validity, said.reason) == (resolution, validity, verdict)
    assert said.fixed_repository_ref_id == (world.patched.id if verdict == "new_approach" else None)
    assert context.services().findings.get(world.ids[0]).is_open() is is_open


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
    with pytest.raises(ValidationError, match="not in work item's repository"):
        service.differential(item.work_item_id, other.patched.id)  # type: ignore[arg-type]


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
        ((("example.com/other", "v1.0.0"),), "module_absent", []),
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
        head = Seed(uow).repository_ref(world.repo, sha="c" * 40, is_default=True)
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
        Seed(uow).repository_ref(verified.repo, name="main", sha=PATCHED_SHA, is_default=True)
        unobserved = Seed(uow).repository()
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
