"""Fleet fix over SQLite and Postgres: the spec's golden gate (ported from traust
tests/test_fleet_fix.py), the fleet (tests/test_fleet_targets.py) and one target's application."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
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
    ForbiddenError,
    IntegrityError,
    NotFoundError,
    ValidationError,
)
from traust_core.v1.models.artifacts import FleetFixArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.inventory import Repository
from traust_core.v1.models.remediation import (
    FleetFixDiff,
    FleetScope,
    golden_failures,
    in_scope,
    rewrite_pinned_refs,
)
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.remediation import RemediationConfig, RemediationService

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
            refs.append(seed.repository_ref(repo, manifest_sbom_id=sbom.id, is_default=True))
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
        uow.commit()
    return {"repos": repos, "refs": refs, "package": package}


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


def test_fleet_targets_never_drop_an_unknown_repository(service: RemediationService) -> None:
    with pytest.raises(NotFoundError):
        service.fleet_targets(FleetScope(repository_ids=(uuid4(),)))


def leased(engine: Engine, repository_id: UUID, state: str = "leased") -> UUID:
    with SqlTraustUnitOfWork(engine) as uow:
        lease = {"lease_holder": "worker-1", "lease_expires_at": WHEN} if state == "leased" else {}
        order = Seed(uow).run_order(
            asset="fleet-fix", repository_id=repository_id, state=state, **lease
        )
        uow.commit()
    return order.id  # type: ignore[return-value]


def test_apply_records_one_fleet_fix_assessment_per_commit(
    service: RemediationService, engine: Engine, applier: FakeApplier
) -> None:
    f = fleet(engine)
    repo, ref = f["repos"][0], f["refs"][0]
    fix = service.record(spec(), provenance())
    order = leased(engine, repo.id)
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


def test_apply_refuses_without_the_target_s_leased_order(
    service: RemediationService, engine: Engine
) -> None:
    f = fleet(engine)
    r0, r1, _ = ids(f["repos"])
    fix = service.record(spec(), provenance())
    for order in (leased(engine, r1), leased(engine, r0, "awaiting_approval")):
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
        service.apply_fleet_fix(fix.fleet_fix_id, repo.id, leased(engine, repo.id))
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
        service.apply_fleet_fix(fix.fleet_fix_id, repo.id, leased(engine, repo.id))


def test_record_evidence_has_no_home_yet(service: RemediationService) -> None:
    from traust_core.v1.models.remediation import EvidenceItem

    with pytest.raises(NotFoundError):
        service.record_evidence(uuid4(), EvidenceItem(kind="mutation", outcome="not_attempted: x"))
