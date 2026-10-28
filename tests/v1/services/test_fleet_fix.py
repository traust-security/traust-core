"""Fleet fix over SQLite and Postgres: the spec's golden gate (ported from traust
tests/test_fleet_fix.py), the fleet (tests/test_fleet_targets.py) and one target's application."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    ForbiddenError,
    IntegrityError,
    NotFoundError,
    ValidationError,
)
from traust_core.v1.models.artifacts import FleetFixArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.inventory import Repository
from traust_core.v1.models.operations import OrderReason, OrderRequest, OrderState, WorkerId
from traust_core.v1.models.remediation import (
    FleetFixDiff,
    FleetScope,
    golden_failures,
    in_scope,
    rewrite_pinned_refs,
)
from traust_core.v1.models.vocabulary import ActorKind, SourceType
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.remediation import (
    FLEET_FIX_ORDER,
    RemediationConfig,
    RemediationService,
)

FIXTURES = Path(__file__).parents[2] / "fixtures" / "remediation"
SPEC = json.loads((FIXTURES / "fleet-fix-konflux.json").read_text())
WHEN = datetime(2026, 7, 18, 9, tzinfo=UTC)
PIN = "a" * 40
TEKTON = """\
apiVersion: tekton.dev/v1
kind: PipelineRun
spec:
  pipelineRef:
    resolver: git
    params:
      - name: url
        value: "https://github.com/example/konflux-build-catalog"
      - name: revision
        value: main
      - name: pathInRepo
        value: pipelines/docker-build.yaml
"""


def spec(**changes: Any) -> FleetFixArtifact:
    raw = json.loads(json.dumps(SPEC))
    for path, value in changes.items():
        section, _, key = path.partition("__")
        if key:
            raw[section][key] = value
        else:
            raw[section] = value
    return FleetFixArtifact.from_document(raw)


# the spec (pure)


def test_the_pilot_spec_passes_its_own_golden_tests() -> None:
    assert golden_failures(spec(), "2026-07-18") == []


def test_a_spec_whose_goldens_fail_says_which() -> None:
    broken = spec(rewrite={"template": "{indent}value: {ref}"})
    assert golden_failures(broken, "2026-07-18") == [
        "pins a git-resolver revision under .tekton/: missing "
        "'value: {sha}  # fleet-fix({id}): pinned from main'",
        "pins a git-resolver revision under .tekton/: still contains 'value: main'",
    ]


@pytest.mark.parametrize(
    ("path", "text", "resolve", "want", "unresolved"),
    [
        (
            ".tekton/pr.yaml",
            TEKTON,
            PIN,
            f"value: {PIN}  # fleet-fix(konflux-mutable-pipelineref): pinned from main 2026-07-18",
            [],
        ),
        (
            ".tekton/pr.yaml",
            TEKTON,
            {"https://github.com/example/konflux-build-catalog": "b" * 40}.get,
            f"value: {'b' * 40}",
            [],
        ),
        (
            ".tekton/pr.yaml",
            TEKTON,
            lambda _: None,
            "value: main",
            [".tekton/pr.yaml:10: no commit for https://github.com/example/konflux-build-catalog"],
        ),
        (
            ".tekton/pr.yaml",
            "params:\n  - name: revision\n    value: main\n",
            lambda _: PIN,
            "value: main",
            [".tekton/pr.yaml:3: no URL in window"],
        ),
        ("config/deploy.yaml", TEKTON, PIN, "value: main", []),
        (".tekton/pr.yaml", "spec: {}\n", PIN, "spec: {}", []),
    ],
    ids=["pinned", "resolved", "unresolvable", "no-url", "out-of-scope", "no-match"],
)
def test_pinned_ref_rewrites(
    path: str, text: str, resolve: Any, want: str, unresolved: list[str]
) -> None:
    after, missed = rewrite_pinned_refs(spec(), path, text, "2026-07-18", resolve)
    assert want in after
    assert missed == unresolved


@pytest.mark.parametrize(
    ("globs", "path", "inside"),
    [
        ([".tekton/*.yaml"], ".tekton/pr.yaml", True),
        ([".tekton/*.yaml"], ".tekton/sub/pr.yaml", False),
        ([".tekton/*.yaml"], "x/.tekton/pr.yaml", False),
        (["**/*.yaml"], "a/b/c.yaml", True),
        (["**/*.yaml"], "c.yaml", True),
        ([".github/workflows/*.yml", ".tekton/*.yaml"], ".github/workflows/ci.yml", True),
    ],
)
def test_file_glob_scope(globs: list[str], path: str, inside: bool) -> None:
    assert in_scope(globs, path) is inside


def test_fleet_scope_is_exactly_one_source() -> None:
    for bad in ({}, {"cwe": "CWE-1104", "package_id": uuid4()}, {"cwe": "1104"}):
        with pytest.raises(ValueError):
            FleetScope(**bad)


# the service


class FakeApplier:
    def __init__(self, diff: FleetFixDiff) -> None:
        self.diff = diff
        self.calls: list[tuple[str, str, str]] = []

    def apply(self, spec: FleetFixArtifact, repository_url: str, sha: str) -> FleetFixDiff:
        self.calls.append((spec.id, repository_url, sha))
        return self.diff


APPLIED = FleetFixDiff(files_changed=(".tekton/pr.yaml",), diff="--- a\n+++ b\n")


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path, remediation=RemediationConfig()))
    ctx.__dict__["database"] = engine
    return ctx


@pytest.fixture
def applier(context: Context) -> FakeApplier:
    context.fleet_fix_applier = FakeApplier(APPLIED)
    return context.fleet_fix_applier  # type: ignore[return-value]


@pytest.fixture
def service(context: Context, applier: FakeApplier) -> RemediationService:
    return context.services().remediation


def provenance() -> Provenance:
    return Provenance(run_id=uuid4(), source=SourceType.TRIAGE_REPORT, occurred_at=WHEN)


def test_record_publishes_a_spec_once(service: RemediationService) -> None:
    fix = service.record(spec(), provenance())
    assert (fix.spec_id, fix.matcher, fix.pattern_ref) == (
        "konflux-mutable-pipelineref",
        "pinned_ref_line",
        SPEC["pattern_ref"],
    )
    assert service.record(spec(), provenance()) == fix
    assert service.get_fleet_fix(fix.fleet_fix_id) == fix


def test_sensitive_spec_id_is_not_logged_or_repeated(
    service: RemediationService, caplog: pytest.LogCaptureFixture
) -> None:
    secret = "synthetic-only-never-a-real-credential"
    document = spec(id=secret)
    core = logging.getLogger("traust_core")
    with caplog.at_level(logging.INFO, logger=core.name):
        core.addHandler(caplog.handler)
        try:
            first = service.record(document, provenance())
            assert service.record(document, provenance()) == first
        finally:
            core.removeHandler(caplog.handler)
    events = {
        id(record): record.getMessage()
        for record in caplog.records
        if "artifact published" in record.getMessage() and "fleet-fix" in record.getMessage()
    }
    assert len(events) == 1 and str(first.fleet_fix_id) in next(iter(events.values()))
    assert secret not in caplog.text


@pytest.mark.parametrize(
    ("doc", "error", "message"),
    [
        (
            lambda: spec(rewrite={"template": "{indent}value: {ref}"}),
            ValidationError,
            "golden test failed",
        ),
        (
            lambda: spec(matcher={"kind": "ast_grep", "file_glob": ["**/*.go"], "pattern": "x"}),
            ConfigError,
            r"NEED\(engine: ast-grep",
        ),
    ],
    ids=["failing-golden", "ast-grep"],
)
def test_record_refuses_a_spec_it_cannot_prove(
    service: RemediationService, doc: Any, error: type[Exception], message: str
) -> None:
    with pytest.raises(error, match=message):
        service.record(doc(), provenance())


AST_GREP = {"kind": "ast_grep", "file_glob": ["**/*.yaml"], "pattern": "x", "lang": "yaml"}


class FakeGoldens:
    """Plays ast-grep over a fixture: replaces `old` after a `- name: revision` line."""

    def __init__(self, old: str, new: str) -> None:
        self.old, self.new = old, new
        self.ran: list[str] = []

    def after(self, spec: FleetFixArtifact, file: str, before: str) -> str:
        self.ran.append(file)
        head, mark, tail = before.partition("- name: revision\n")
        return head + mark + tail.replace(self.old, self.new, 1)


@pytest.mark.parametrize(
    ("swap", "failure"),
    [
        (
            (
                "value: main",
                f"value: {'0' * 40}  # fleet-fix(konflux-mutable-pipelineref): pinned from main",
            ),
            None,
        ),
        (("nothing", "matches"), "still contains 'value: main'"),
    ],
    ids=["passing", "failing"],
)
def test_a_registered_golden_runner_proves_an_ast_grep_spec(
    context: Context, applier: FakeApplier, swap: tuple[str, str], failure: str | None
) -> None:
    context.fleet_fix_goldens = goldens = FakeGoldens(*swap)
    service = context.services().remediation
    doc = spec(matcher=AST_GREP)
    if failure is None:
        assert service.record(doc, provenance()).matcher == "ast_grep"
    else:
        with pytest.raises(ValidationError, match=failure):
            service.record(doc, provenance())
    assert goldens.ran == [t.file for t in doc.tests]


def test_get_fleet_fix_knows_only_fleet_fixes(service: RemediationService) -> None:
    with pytest.raises(NotFoundError):
        service.get_fleet_fix(uuid4())


def fleet(engine: Engine) -> dict[str, Any]:
    """Three repositories: one shipped by two products with an open CWE-1104 finding and the
    package, one with a closed CWE-1104 finding, one with the package only."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repos = [
            seed.repository(url=f"https://github.com/example-org/r{i}-{uuid4().hex[:6]}")
            for i in range(3)
        ]
        package = seed.package()
        refs = []
        for repo in repos:
            sbom = seed.sbom()
            ref = seed.repository_ref(repo, manifest_sbom_id=sbom.id, is_default=True)
            refs.append(ref)
            seed.assessment(ref, kind="repo-state", occurred_at=WHEN)
            if repo is not repos[1]:
                seed.dependency(sbom, package)
        for _ in range(2):
            seed.component(seed.release(), refs[0])
        cwe = seed.cwe(identifier="CWE-1104")
        open_, closed = seed.finding(repos[0]), seed.finding(repos[1])
        seed.finding_cwe(open_, cwe)
        seed.finding_cwe(closed, cwe)
        for f in (open_, closed):
            seed.decision(f, validity="confirmed", severity="high", actor="human:a@example.com")
        seed.decision(closed, resolution="resolved", validity=None, actor="human:a@example.com")
        teams = [seed.team(name=f"{n}-{uuid4().hex[:6]}") for n in ("team-b", "team-a")]
        for team in teams:
            seed.ownership(repos[0], team)
        uow.commit()
    return {"repos": repos, "refs": refs, "package": package, "teams": [t.name for t in teams]}


def ids(repos: list[Repository]) -> list[UUID]:
    return [r.id for r in repos]  # type: ignore[misc]


def test_fleet_targets_by_cwe_package_and_name(service: RemediationService, engine: Engine) -> None:
    f = fleet(engine)
    r0, r1, r2 = ids(f["repos"])
    by_cwe = service.fleet_targets(FleetScope(cwe="CWE-1104"))
    assert [(t.repository_id, t.product_reach, t.evidence) for t in by_cwe] == [
        (r0, 2, "open finding with CWE-1104")
    ]
    by_package = service.fleet_targets(FleetScope(package_id=f["package"].id))
    assert [t.repository_id for t in by_package] == [r0, r2]
    named = service.fleet_targets(FleetScope(repository_ids=(r2, r1, r0)))
    assert named[0].repository_id == r0
    assert {t.evidence for t in named} == {"named"}
    assert service.fleet_targets(FleetScope(cwe="CWE-9999")) == []


def test_fleet_targets_carry_their_owner_teams_by_name(
    service: RemediationService, engine: Engine
) -> None:
    f = fleet(engine)
    r0, r1, _ = ids(f["repos"])
    owned, unowned = service.fleet_targets(FleetScope(repository_ids=(r1, r0)))
    assert owned.owner_teams == tuple(reversed(f["teams"]))  # team-a before team-b
    assert (unowned.repository_id, unowned.owner_teams) == (r1, ())


def test_fleet_targets_never_drop_an_unknown_repository(service: RemediationService) -> None:
    with pytest.raises(NotFoundError):
        service.fleet_targets(FleetScope(repository_ids=(uuid4(),)))


HUMAN = Principal(
    identity="lead@example.com",
    kind=ActorKind.HUMAN,
    display="lead",
    verified_by=IdentitySource.OIDC,
)
WORKER = WorkerId("worker-1")
LEASE = timedelta(minutes=5)


def leased(context: Context, fix_id: UUID, repository_id: UUID, state: str = "leased") -> UUID:
    """A fleet-fix order through its real path: submitted, then approved and leased."""
    services = context.services()
    (order,) = services.remediation.submit_fleet_fix(fix_id, [repository_id], HUMAN)
    assert order.id is not None
    if state == "leased":
        services.remediation.approve_fleet_fix(order.id, HUMAN)
        services.ops.claim(WORKER, LEASE, (FLEET_FIX_ORDER,))
    return order.id


def test_apply_records_one_fleet_fix_assessment_per_commit(
    service: RemediationService, context: Context, engine: Engine, applier: FakeApplier
) -> None:
    f = fleet(engine)
    repo, ref = f["repos"][0], f["refs"][0]
    fix = service.record(spec(), provenance())
    order = leased(context, fix.fleet_fix_id, repo.id)
    first = service.apply_fleet_fix(fix.fleet_fix_id, repo.id, order)
    again = service.apply_fleet_fix(fix.fleet_fix_id, repo.id, order)
    assert first == again
    assert (first.applied, first.repository_ref_id, first.files_changed) == (
        True,
        ref.id,
        (".tekton/pr.yaml",),
    )
    assert applier.calls[0] == ("konflux-mutable-pipelineref", repo.url, ref.sha)
    with SqlTraustUnitOfWork(engine) as uow:
        held = uow.artifacts.list_for_assessment(first.assessment_id)
        kinds = {a.kind for a in uow.assessments.list_for_refs([ref.id], "fleet_fix")}
    assert [a.digest for a in held] == [fix.artifact.digest]
    assert kinds == {"fleet_fix"}


def test_apply_uses_the_returning_observed_head(
    service: RemediationService, context: Context, engine: Engine, applier: FakeApplier
) -> None:
    f = fleet(engine)
    repo, first = f["repos"][0], f["refs"][0]
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        second = seed.repository_ref(repo, sha="c" * 40, is_default=True)
        seed.assessment(second, kind="repo-state", occurred_at=WHEN + timedelta(seconds=1))
        seed.assessment(first, kind="repo-state", occurred_at=WHEN + timedelta(seconds=2))
        uow.commit()
    fix = service.record(spec(), provenance())
    result = service.apply_fleet_fix(
        fix.fleet_fix_id, repo.id, leased(context, fix.fleet_fix_id, repo.id)
    )
    assert result.repository_ref_id == first.id
    assert applier.calls[-1][2] == first.sha


def test_apply_refuses_a_repository_whose_head_was_never_observed(
    service: RemediationService, context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/example-org/unobserved-{uuid4().hex[:6]}")
        seed.repository_ref(repo, is_default=True)  # a default ref, but no repo-state observation
        uow.commit()
    fix = service.record(spec(), provenance())
    with pytest.raises(NotFoundError, match="no observed default-branch head"):
        service.apply_fleet_fix(
            fix.fleet_fix_id, repo.id, leased(context, fix.fleet_fix_id, repo.id)
        )


def test_applied_fleet_fix_logs_safe_id_only_for_a_new_assessment(
    service: RemediationService,
    context: Context,
    engine: Engine,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "synthetic-only-never-a-real-credential"
    repo = fleet(engine)["repos"][0]
    fix = service.record(spec(id=secret), provenance())
    order = leased(context, fix.fleet_fix_id, repo.id)
    logger = logging.getLogger("traust_core.v1.services.remediation")
    with caplog.at_level(logging.INFO, logger=logger.name):
        logger.addHandler(caplog.handler)
        try:
            first = service.apply_fleet_fix(fix.fleet_fix_id, repo.id, order)
            assert service.apply_fleet_fix(fix.fleet_fix_id, repo.id, order) == first
        finally:
            logger.removeHandler(caplog.handler)
    events = {
        id(record): record.getMessage()
        for record in caplog.records
        if record.name == logger.name and " on ref " in record.getMessage()
    }
    assert len(events) == 1 and str(fix.fleet_fix_id) in next(iter(events.values()))
    assert secret not in caplog.text


def test_apply_refuses_without_the_target_s_leased_order(
    service: RemediationService, context: Context, engine: Engine
) -> None:
    f = fleet(engine)
    r0, r1, _ = ids(f["repos"])
    fix = service.record(spec(), provenance())
    other = leased(context, fix.fleet_fix_id, r1)
    for order in (other, leased(context, fix.fleet_fix_id, r0, "awaiting_approval")):
        with pytest.raises(ForbiddenError, match="not a leased order"):
            service.apply_fleet_fix(fix.fleet_fix_id, r0, order)
    with pytest.raises(NotFoundError):
        service.apply_fleet_fix(fix.fleet_fix_id, r0, uuid4())


@pytest.mark.parametrize(
    ("diff", "error", "message"),
    [
        (
            FleetFixDiff(files_changed=("config/deploy.yaml",)),
            IntegrityError,
            "outside its file_glob",
        ),
        (
            FleetFixDiff(files_changed=tuple(f".tekton/p{i}.yaml" for i in range(13))),
            ValidationError,
            "max_files_changed=12",
        ),
    ],
    ids=["out-of-scope", "too-many-files"],
)
def test_apply_enforces_the_spec_s_guards(
    service: RemediationService,
    context: Context,
    engine: Engine,
    applier: FakeApplier,
    diff: FleetFixDiff,
    error: type[Exception],
    message: str,
) -> None:
    f = fleet(engine)
    repo = f["repos"][0]
    fix = service.record(spec(), provenance())
    applier.diff = diff
    with pytest.raises(error, match=message):
        service.apply_fleet_fix(
            fix.fleet_fix_id, repo.id, leased(context, fix.fleet_fix_id, repo.id)
        )
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.assessments.list_for_refs([f["refs"][0].id], "fleet_fix") == []


def test_apply_without_an_engine_applier_is_a_config_error(
    context: Context, engine: Engine
) -> None:
    service = context.services().remediation
    f = fleet(engine)
    repo = f["repos"][0]
    fix = service.record(spec(), provenance())
    with pytest.raises(ConfigError, match=r"NEED\(engine: fleet-fix applier\)"):
        service.apply_fleet_fix(
            fix.fleet_fix_id, repo.id, leased(context, fix.fleet_fix_id, repo.id)
        )


# the human-gated order: submit, approve, claim


def other_spec() -> FleetFixArtifact:
    return spec(id="konflux-other")


def test_submit_holds_one_order_per_target_for_approval(
    service: RemediationService, context: Context, engine: Engine
) -> None:
    f = fleet(engine)
    r0, _, r2 = ids(f["repos"])
    fix = service.record(spec(), provenance())
    orders = service.submit_fleet_fix(fix.fleet_fix_id, [r2, r0], HUMAN)
    assert [(o.repository_id, o.priority, o.state) for o in orders] == [
        (r0, 0, OrderState.AWAITING_APPROVAL),
        (r2, 1, OrderState.AWAITING_APPROVAL),
    ]
    assert {o.requested_by for o in orders} == {"human:lead@example.com"}
    (config,) = context.services().ops.manifest(orders[0].id).config  # type: ignore[arg-type]
    assert (config.name, config.digest, config.artifact_id) == (
        "fleet-fix:konflux-mutable-pipelineref",
        fix.artifact.digest,
        fix.fleet_fix_id,
    )
    assert service.submit_fleet_fix(fix.fleet_fix_id, [r0, r2], HUMAN) == orders


def test_submit_refuses_a_target_with_another_fix_open(
    service: RemediationService, engine: Engine
) -> None:
    r0 = fleet(engine)["repos"][0].id
    first = service.record(spec(), provenance())
    second = service.record(other_spec(), provenance())
    service.submit_fleet_fix(first.fleet_fix_id, [r0], HUMAN)
    with pytest.raises(ConflictError, match="for another fix"):
        service.submit_fleet_fix(second.fleet_fix_id, [r0], HUMAN)


def test_submit_refuses_what_it_cannot_target(service: RemediationService, engine: Engine) -> None:
    r0 = fleet(engine)["repos"][0].id
    fix = service.record(spec(), provenance())
    with pytest.raises(ValidationError, match="at least one target"):
        service.submit_fleet_fix(fix.fleet_fix_id, [], HUMAN)
    with pytest.raises(NotFoundError):
        service.submit_fleet_fix(fix.fleet_fix_id, [r0, uuid4()], HUMAN)
    with pytest.raises(NotFoundError):
        service.submit_fleet_fix(uuid4(), [r0], HUMAN)


@pytest.mark.parametrize(
    "principal",
    [
        Principal(
            identity="engine", kind=ActorKind.MACHINE, display="m", verified_by=IdentitySource.OIDC
        ),
        Principal(identity="engine", kind=ActorKind.MACHINE, display="m"),
        Principal(identity="lead@example.com", kind=ActorKind.HUMAN, display="unverified"),
    ],
    ids=["verified-machine", "machine", "unverified-human"],
)
def test_approval_needs_a_verified_human(
    service: RemediationService, context: Context, engine: Engine, principal: Principal
) -> None:
    r0 = fleet(engine)["repos"][0].id
    fix = service.record(spec(), provenance())
    (order,) = service.submit_fleet_fix(fix.fleet_fix_id, [r0], principal)
    assert order.id is not None
    with pytest.raises(ForbiddenError, match="verified human"):
        service.approve_fleet_fix(order.id, principal)
    ops = context.services().ops
    assert ops.get(order.id).state == OrderState.AWAITING_APPROVAL
    assert ops.manifest(order.id).approval is None
    assert service.claim_fleet_fix(WORKER, LEASE) is None


def test_approve_fleet_fix_refuses_any_other_order(
    service: RemediationService, engine: Engine
) -> None:
    r0 = fleet(engine)["repos"][0].id
    with SqlTraustUnitOfWork(engine) as uow:
        other = Seed(uow).run_order(asset="repo-state", repository_id=r0, state="awaiting_approval")
        uow.commit()
    assert other.id is not None
    with pytest.raises(ForbiddenError, match="not a fleet-fix order"):
        service.approve_fleet_fix(other.id, HUMAN)


def test_claim_applies_an_approved_order_and_finishes_it(
    service: RemediationService, context: Context, engine: Engine, applier: FakeApplier
) -> None:
    f = fleet(engine)
    repo = f["repos"][0]
    fix = service.record(spec(), provenance())
    (order,) = service.submit_fleet_fix(fix.fleet_fix_id, [repo.id], HUMAN)  # type: ignore[list-item]
    assert order.id is not None
    approved = service.approve_fleet_fix(order.id, HUMAN)
    assert approved.state == OrderState.QUEUED
    run = service.claim_fleet_fix(WORKER, LEASE)
    assert run is not None
    assert (run.order.id, run.order.state, run.order.lease_holder) == (
        order.id,
        OrderState.SUCCEEDED,
        None,
    )
    assert (run.patch.fleet_fix_id, run.patch.files_changed) == (
        fix.fleet_fix_id,
        (".tekton/pr.yaml",),
    )
    approval = context.services().ops.manifest(order.id).approval
    assert approval is not None and approval.approver == "human:lead@example.com"
    assert applier.calls == [("konflux-mutable-pipelineref", repo.url, f["refs"][0].sha)]
    assert service.claim_fleet_fix(WORKER, LEASE) is None


def test_a_refused_application_finishes_the_order_then_raises(
    service: RemediationService, context: Context, engine: Engine, applier: FakeApplier
) -> None:
    repo = fleet(engine)["repos"][0]
    fix = service.record(spec(), provenance())
    order = leased(context, fix.fleet_fix_id, repo.id, "awaiting_approval")  # type: ignore[arg-type]
    service.approve_fleet_fix(order, HUMAN)
    applier.diff = FleetFixDiff(files_changed=("config/deploy.yaml",))
    with pytest.raises(IntegrityError, match="outside its file_glob"):
        service.claim_fleet_fix(WORKER, LEASE)
    done = context.services().ops.get(order)
    assert (done.state, done.reason) == (OrderState.REFUSED, OrderReason.BAD_REQUEST)


def test_apply_refuses_an_order_no_person_approved(
    service: RemediationService, context: Context, engine: Engine, applier: FakeApplier
) -> None:
    r0, r1, _ = ids(fleet(engine)["repos"])
    fix = service.record(spec(), provenance())
    ops = context.services().ops
    request = OrderRequest(asset=FLEET_FIX_ORDER, priority=0, repository_id=r0)
    ops.submit(request, HUMAN)
    queued = ops.claim(WORKER, LEASE, (FLEET_FIX_ORDER,))
    assert queued is not None and queued.id is not None
    with pytest.raises(ForbiddenError, match="is not for fleet fix"):
        service.apply_fleet_fix(fix.fleet_fix_id, r0, queued.id)
    (planned,) = service.submit_fleet_fix(fix.fleet_fix_id, [r1], HUMAN)
    assert planned.id is not None
    with SqlTraustUnitOfWork(engine) as uow:  # admitted around the approval gate
        held = uow.run_orders.get_for_update(planned.id)
        uow.run_orders.update(held.model_copy(update={"state": OrderState.QUEUED}))
        uow.commit()
    ops.claim(WORKER, LEASE, (FLEET_FIX_ORDER,))
    with pytest.raises(ForbiddenError, match="no human approval"):
        service.apply_fleet_fix(fix.fleet_fix_id, r1, planned.id)
    assert applier.calls == []


def test_record_evidence_has_no_home_yet(service: RemediationService) -> None:
    from traust_core.v1.models.remediation import EvidenceItem

    with pytest.raises(NotFoundError):
        service.record_evidence(uuid4(), EvidenceItem(kind="mutation", outcome="not_attempted: x"))
