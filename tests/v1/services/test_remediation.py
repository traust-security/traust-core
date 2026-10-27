"""RemediationService over SQLite and Postgres: work items (legacy remediation manifest), steps,
forks (ported from traust tests/test_fork_map.py) and the report."""

from __future__ import annotations

import hashlib
import itertools
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, commit_all, contract_db, git
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import ProcessConfig
from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    ValidationError,
)
from traust_core.v1.models.artifacts import RemediationArtifact, ReportArtifact, ValidationArtifact
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import ArtifactRef, PageRequest, Provenance
from traust_core.v1.models.findings import Finding, FindingCandidate, Label
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.remediation import (
    Check,
    CheckOutcome,
    EvidenceItem,
    PatchNarrative,
    WorkItemFilter,
    checks_status,
)
from traust_core.v1.models.validation import (
    ValidationFindingBinding,
    ValidationRecordInput,
    ValidationSourceBinding,
)
from traust_core.v1.models.vocabulary import RemediationStatus, SourceType, ValidationVerdict
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.ledger import LedgerConfig
from traust_core.v1.services.remediation import (
    ForkPolicy,
    RemediationConfig,
    RemediationService,
)

FIXTURES = Path(__file__).parents[2] / "fixtures" / "remediation"
REPORT = json.loads((FIXTURES / "remediation-report.json").read_text())
WHEN = datetime(2026, 10, 23, 9, tzinfo=UTC)
FORGES = {"github.com": "github", "gitlab.com": "gitlab"}
GIT = ProcessConfig(allowed_binaries=("git",))
PRIVATE = RemediationConfig(fork_org="mirror-org", private_forge_hosts=("forge.example.internal",))


# forks (pure)


def fork(url: str, config: RemediationConfig = PRIVATE, mirror: str | None = None) -> Any:
    return ForkPolicy(config, FORGES).resolve(url, mirror)


def test_a_github_repo_maps_into_the_configured_mirror_org() -> None:
    f = fork("https://github.com/some-org/some-repo.git")
    assert (str(f.url), f.owner, f.host, f.visibility) == (
        "https://github.com/mirror-org/some-repo",
        "mirror-org",
        "github",
        "private",
    )


def test_a_github_repo_without_a_fork_org_is_a_config_error() -> None:
    with pytest.raises(ConfigError, match=r"remediation\.fork_org"):
        fork("https://github.com/o/r", RemediationConfig())


@pytest.mark.parametrize(
    "url",
    [
        "https://forge.example.internal/group/repo",
        "https://forge.example.internal/group/subgroup/repo.git",
        "https://sub.forge.example.internal/group/repo",
    ],
)
def test_a_private_forge_repo_is_its_own_downstream_fork(url: str) -> None:
    f = fork(url)
    assert str(f.url) == url.removesuffix(".git")
    assert (f.host, f.visibility, f.owner) == ("other", "internal", "group")


@pytest.mark.parametrize(
    ("url", "config"),
    [
        ("https://evil.example.com/forge.example.internal/repo", PRIVATE),
        ("https://gitlab.com/some-org/some-repo", PRIVATE),
        ("https://forge.example.internal/group/repo", RemediationConfig(fork_org="o")),
        ("https://git.example.org/group/repo", PRIVATE),
    ],
)
def test_no_fork_for_a_host_the_deployment_did_not_name(
    url: str, config: RemediationConfig
) -> None:
    with pytest.raises(NotFoundError, match="no fork"):
        fork(url, config)


def test_an_inventory_mirror_wins_and_takes_its_forge_kind() -> None:
    f = fork("https://github.com/o/r", mirror="https://gitlab.com/mirrors/r")
    assert (str(f.url), f.host, f.owner, f.visibility) == (
        "https://gitlab.com/mirrors/r",
        "gitlab",
        "mirrors",
        "private",
    )


def test_configured_forge_hosts_are_bare_lowercase_hosts() -> None:
    config = RemediationConfig(
        private_forge_hosts=("https://Forge.Example.Internal/", " other.host", "")
    )
    assert config.private_forge_hosts == ("forge.example.internal", "other.host")


def test_fix_branches_carry_the_prefix_the_finding_and_a_slug() -> None:
    finding = UUID(int=5)
    policy = ForkPolicy(RemediationConfig(fix_branch_prefix="security"), FORGES)
    assert policy.fix_branch(finding, "Unbounded read: of body!") == (
        f"security/{finding}/unbounded-read-of-body"
    )
    assert policy.fix_branch(finding, "") == f"security/{finding}"


# the service


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path, remediation=PRIVATE, process=GIT))
    ctx.__dict__["database"] = engine
    return ctx


@pytest.fixture
def service(context: Context) -> RemediationService:
    return context.services().remediation


def seeded(
    engine: Engine, *, findings: int = 1, **finding: Any
) -> tuple[RepositoryRef, list[Finding]]:
    """A commit of a GitHub repository and confirmed findings on it."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/example-org/svc-{uuid4().hex[:8]}")
        ref = seed.repository_ref(repo)
        made = [seed.finding(repo, **finding) for _ in range(findings)]
        for f in made:
            seed.decision(
                f, validity="confirmed", severity="high", actor="human:analyst@example.com"
            )
        uow.commit()
    return ref, made


def ids(findings: list[Finding]) -> list[UUID]:
    return [f.id for f in findings]  # type: ignore[misc]


def report(finding_ids: list[UUID], **changes: Any) -> RemediationArtifact:
    raw = json.loads(json.dumps(REPORT))
    raw["source_findings"] = [
        {**raw["source_findings"][0], "finding_ref": str(f)} for f in finding_ids
    ]
    for path, value in changes.items():
        section, _, key = path.partition("__")
        if key:
            raw[section][key] = value
        else:
            raw[section] = value
    return RemediationArtifact.parse(json.dumps(raw).encode())


def provenance(artifact: ArtifactRef | None = None) -> Provenance:
    return Provenance(
        run_id=uuid4(), artifact=artifact, source=SourceType.TRIAGE_REPORT, occurred_at=WHEN
    )


def decisions(engine: Engine, finding: Finding) -> list[Any]:
    with SqlTraustUnitOfWork(engine) as uow:
        return uow.decisions.list_for_finding(finding.id)  # type: ignore[arg-type]


def test_open_makes_a_candidate_work_item_on_the_commit(
    service: RemediationService, engine: Engine
) -> None:
    ref, found = seeded(engine, findings=2)
    item = service.open(ids(found)[::-1], ref.id)  # type: ignore[arg-type]
    assert (item.status, item.repository_ref_id, set(item.finding_ids)) == (
        "candidate",
        ref.id,
        set(ids(found)),
    )
    assert not item.is_done() and item.report is None and item.tracker is None
    said = decisions(engine, found[0])[-1]
    assert (said.assessment_id, said.reason, said.resolution, said.actor) == (
        item.work_item_id,
        "candidate",
        None,
        None,
    )
    assert service.get(item.work_item_id) == item


def test_opening_the_same_findings_again_is_the_same_work_item(
    service: RemediationService, engine: Engine
) -> None:
    ref, found = seeded(engine, findings=2)
    first = service.open(ids(found), ref.id)  # type: ignore[arg-type]
    assert service.open(ids(found) * 2, ref.id) == first  # type: ignore[arg-type]
    with pytest.raises(ConflictError, match=f"work item {first.work_item_id} already covers"):
        service.open(ids(found)[:1], ref.id)  # type: ignore[arg-type]


def test_open_refuses_what_is_not_a_confirmed_open_finding_of_the_commit(
    service: RemediationService, engine: Engine
) -> None:
    ref, (found,) = seeded(engine)
    _, (elsewhere,) = seeded(engine)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = uow.repositories.get(ref.repository_id)
        unjudged = seed.finding(repo, fingerprint="fp-unjudged")
        closed = seed.finding(repo, fingerprint="fp-closed")
        seed.decision(unjudged, validity=None, severity="low", actor="human:a@example.com")
        seed.decision(closed, validity="confirmed", severity="high", actor="human:a@example.com")
        seed.decision(closed, resolution="resolved", validity=None, actor="human:a@example.com")
        uow.commit()
    cases = [
        ([], ValidationError, "at least one finding"),
        ([elsewhere.id], ValidationError, "is not in commit"),
        ([unjudged.id], ValidationError, "is not confirmed"),
        ([closed.id], ValidationError, "is closed"),
        ([uuid4()], NotFoundError, "findings"),
    ]
    for finding_ids, error, message in cases:
        with pytest.raises(error, match=message):
            service.open(finding_ids, ref.id)  # type: ignore[arg-type]
    with pytest.raises(NotFoundError):
        service.open([found.id], uuid4())  # type: ignore[list-item]


def test_get_knows_only_remediation_assessments(
    service: RemediationService, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        scan = Seed(uow).assessment(kind="scanner")
        uow.commit()
    for missing in (uuid4(), scan.id):
        with pytest.raises(NotFoundError):
            service.get(missing)  # type: ignore[arg-type]


def test_record_progress_moves_forward_and_says_where_fixing_stands(
    service: RemediationService, context: Context, engine: Engine
) -> None:
    ref, (found,) = seeded(engine)
    item = service.open([found.id], ref.id)  # type: ignore[list-item]
    forked = service.record_progress(item.work_item_id, RemediationStatus("forked"))
    assert forked.status == "forked"
    view = context.services().findings.get(found.id)  # type: ignore[arg-type]
    assert view.disposition and view.disposition.resolution == "open"
    said = decisions(engine, found)[-1]
    assert (said.reason, said.resolution) == ("forked", "open")
    before = len(decisions(engine, found))
    assert service.record_progress(item.work_item_id, RemediationStatus("forked")) == forked
    assert len(decisions(engine, found)) == before
    with pytest.raises(ConflictError, match="forked can't move to candidate"):
        service.record_progress(item.work_item_id, RemediationStatus("candidate"))
    service.record_progress(item.work_item_id, RemediationStatus("merged"))
    merged = context.services().findings.get(found.id)  # type: ignore[arg-type]
    assert merged.is_open()
    assert merged.disposition and merged.disposition.resolution == "open"
    said = decisions(engine, found)[-1]
    assert (said.reason, said.resolution) == ("merged", "open")


def test_next_pending_is_the_oldest_candidate_without_a_report(
    service: RemediationService, engine: Engine
) -> None:
    ref, found = seeded(engine, findings=3)
    repository = WorkItemFilter(repository_id=ref.repository_id)
    assert service.next_pending(repository) is None
    first, second, third = (service.open([f], ref.id) for f in ids(found))  # type: ignore[arg-type]
    assert service.next_pending(repository) == first
    service.record_progress(first.work_item_id, RemediationStatus("patched"))
    service.record(report([found[1].id]), provenance())  # type: ignore[list-item]
    assert service.next_pending(repository) == third
    assert service.next_pending(WorkItemFilter(repository_id=uuid4())) is None
    assert second.work_item_id != third.work_item_id


def test_list_pages_a_repositorys_work_items_oldest_first(
    service: RemediationService, engine: Engine
) -> None:
    ref, found = seeded(engine, findings=3)
    opened = [service.open([f], ref.id) for f in ids(found)]  # type: ignore[arg-type]
    service.record_progress(opened[1].work_item_id, RemediationStatus("abandoned"))
    repository = WorkItemFilter(repository_id=ref.repository_id)
    page = service.list(repository, PageRequest(limit=2))
    rest = service.list(repository, PageRequest(limit=2, cursor=page.next))
    seen = [i.work_item_id for i in (*page.items, *rest.items)]
    assert seen == [i.work_item_id for i in opened] and rest.next is None
    abandoned = service.list(
        WorkItemFilter(repository_id=ref.repository_id, status=RemediationStatus("abandoned")),
        PageRequest(),
    )
    assert [i.work_item_id for i in abandoned.items] == [opened[1].work_item_id]
    with pytest.raises(ValidationError):
        service.list(repository, PageRequest(limit=0))


def test_resolve_fork_prefers_the_inventory_mirror(
    service: RemediationService, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        upstream = seed.repository(url="https://github.com/example-org/svc")
        bare = seed.repository(url="https://github.com/example-org/bare")
        seed.repository(url="https://github.com/somebody/svc", upstream_id=upstream.id, public=True)
        seed.repository(url="https://gitlab.com/mirrors/svc", upstream_id=upstream.id, public=False)
        uow.commit()
    assert str(service.resolve_fork(upstream.id).url) == "https://gitlab.com/mirrors/svc"  # type: ignore[arg-type]
    assert str(service.resolve_fork(bare.id).url) == "https://github.com/mirror-org/bare"  # type: ignore[arg-type]
    with pytest.raises(NotFoundError):
        service.resolve_fork(uuid4())


def test_prepare_hands_the_skill_the_findings_the_commit_and_where_to_push(
    service: RemediationService, engine: Engine
) -> None:
    ref, (found,) = seeded(engine, title="Unbounded read of the body")
    with SqlTraustUnitOfWork(engine) as uow:
        Seed(uow).finding_cwe(found, Seed(uow).cwe(identifier="CWE-400"))
        uow.commit()
    item = service.open([found.id], ref.id)  # type: ignore[list-item]
    given = service.prepare(item.work_item_id)
    assert (given.subject.repository_ref_id, given.subject.sha, given.subject.assessment_id) == (
        ref.id,
        ref.sha,
        item.work_item_id,
    )
    assert given.work_item == item
    (only,) = given.items
    assert only.finding.finding.id == found.id
    assert [d.validity for d in only.decisions] == ["confirmed", None]
    assert only.strategy == "bound-resource"
    assert given.fork.owner == "mirror-org" and given.fork.visibility == "private"
    assert given.fix_branch == f"fix/{found.id}/unbounded-read-of-the-body"


def test_record_attaches_the_report_links_its_tickets_and_moves_the_item(
    service: RemediationService, context: Context, engine: Engine
) -> None:
    ref, (found,) = seeded(engine)
    item = service.open([found.id], ref.id)  # type: ignore[list-item]
    done = service.record(report([found.id]), provenance())  # type: ignore[list-item]
    assert done.work_item_id == item.work_item_id and done.is_done()
    assert (done.status, done.strategy, done.tracker) == (
        "checks_passed",
        "bound-resource",
        done.tracker.model_copy(update={"system": "jira", "ref": "SEC-101"}),  # type: ignore[union-attr]
    )
    assert str(done.fork.url) == "https://github.com/example-mirrors/example-service"  # type: ignore[union-attr]
    assert [e.outcome for e in done.evidence] == ["proves"]
    said = decisions(engine, found)[-1]
    assert (said.reason, said.resolution) == ("checks_passed", "open")
    assert said.artifact_id is not None
    before = len(decisions(engine, found))
    assert service.record(report([found.id]), provenance()) == done  # type: ignore[list-item]
    assert len(decisions(engine, found)) == before


def test_record_takes_an_already_published_report(
    service: RemediationService, context: Context, engine: Engine
) -> None:
    ref, (found,) = seeded(engine)
    service.open([found.id], ref.id)  # type: ignore[list-item]
    doc = report([found.id], summary__status="pr_opened")  # type: ignore[list-item]
    publisher = context.services().remediation._publisher
    published = publisher.publish_artifact(doc).artifact_id
    ref_ = ArtifactRef(id=published, name=doc.name, digest="sha256:x")
    assert service.record(doc, provenance(ref_)).status == "pr_opened"


def test_record_refuses_what_the_safety_controls_forbid(
    service: RemediationService, engine: Engine
) -> None:
    ref, (found,) = seeded(engine)
    service.open([found.id], ref.id)  # type: ignore[list-item]
    fork = {**REPORT["fork"], "visibility": "public"}
    upstream_pr = {
        "url": "https://github.com/example-org/example-service/pull/1",
        "target": "upstream",
    }
    cases = [
        (report([found.id], fork=fork), "public fork"),  # type: ignore[list-item]
        (report([found.id], pull_request=upstream_pr), "upstream PR"),  # type: ignore[list-item]
        (report([uuid4()]), "findings"),
    ]
    for doc, message in cases:
        with pytest.raises((ValidationError, NotFoundError), match=message):
            service.record(doc, provenance())
    raw = json.loads(json.dumps(REPORT))
    raw["source_findings"][0]["finding_ref"] = "svc-triage.json#f005"
    with pytest.raises(ValidationError, match="not a finding id from prepare"):
        service.record(RemediationArtifact.parse(json.dumps(raw).encode()), provenance())


def test_record_needs_one_open_work_item_and_a_forward_status(
    service: RemediationService, engine: Engine
) -> None:
    ref, found = seeded(engine, findings=2)
    with pytest.raises(ValidationError, match="no single open work item"):
        service.record(report(ids(found)), provenance())
    item = service.open(ids(found), ref.id)  # type: ignore[arg-type]
    service.record_progress(item.work_item_id, RemediationStatus("pr_opened"))
    with pytest.raises(ConflictError, match="pr_opened can't move to checks_passed"):
        service.record(report(ids(found)), provenance())
    service.record_progress(item.work_item_id, RemediationStatus("abandoned"))
    with pytest.raises(ValidationError, match="no single open work item"):
        service.record(report(ids(found)), provenance())


def test_record_refuses_a_published_artifact_that_is_not_the_report(
    service: RemediationService, engine: Engine
) -> None:
    ref, (found,) = seeded(engine)
    _, (elsewhere,) = seeded(engine)
    service.open([found.id], ref.id)  # type: ignore[list-item]
    other = report([found.id], summary__status="patched")  # type: ignore[list-item]
    published = service._publisher.publish_artifact(other).artifact_id
    claimed = provenance(ArtifactRef(id=published, name=other.name, digest="sha256:x"))
    with pytest.raises(IntegrityError, match="doc digest"):
        service.record(report([found.id]), claimed)  # type: ignore[list-item]
    with pytest.raises(ValidationError, match="several repositories"):
        service.record(report([found.id, elsewhere.id]), provenance())  # type: ignore[list-item]


def test_steps_go_on_the_ledger_when_it_is_on(engine: Engine, tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path, remediation=PRIVATE, ledger=LedgerConfig()))
    ctx.__dict__["database"] = engine
    service = ctx.services().remediation
    ref, (found,) = seeded(engine)
    item = service.open([found.id], ref.id)  # type: ignore[list-item]
    service.record_progress(item.work_item_id, RemediationStatus("forked"))
    with SqlTraustUnitOfWork(engine) as uow:
        events = uow.connection.execute(sa.select(sa.func.count()).select_from(uow.events.table))
        assert events.scalar() == 2  # the seeded verdict is not on the ledger


# assemble: the report from the workspace (legacy emit_remediation_report.py)


def check(outcome: str, name: str = "go test") -> Check:
    return Check(name=name, command=f"{name} ./...", outcome=CheckOutcome(outcome))


@pytest.mark.parametrize(
    ("outcomes", "status"),
    [
        ((), "patched"),
        (("pass",), "checks_passed"),
        (("pass", "skip"), "checks_passed"),
        (("skip",), "checks_passed"),
        (("pass", "fail"), "checks_failed"),
        (("error", "pass"), "checks_failed"),
    ],
)
def test_checks_decide_the_status_failed_or_broken_fails_it(
    outcomes: tuple[str, ...], status: str
) -> None:
    assert checks_status([check(o) for o in outcomes]) == status


NARRATIVE = PatchNarrative(
    logical_product="example-product",
    harness_version="1.2.3-abcdef0",
    strategy="bound-resource",
    rationale="Caps the request body with http.MaxBytesReader so the unbounded read the triage "
    "rationale names can no longer exhaust memory.",
    tests_added=("pkg/api/handler_test.go:TestBodyCap",),
)


@pytest.fixture
def workspace(tmp_path: Path) -> tuple[Path, str]:
    """A checkout at the work item's commit with the fix committed on top."""
    r = tmp_path / "svc"
    (r / "pkg" / "api").mkdir(parents=True)
    git(r, "init", "-q")
    (r / "pkg" / "api" / "handler.go").write_text("package api\n\nfunc Read() {}\n")
    (r / "README.md").write_text("svc\n")
    base = commit_all(r, "base")
    (r / "pkg" / "api" / "handler.go").write_text("package api\n\nfunc Read() { cap() }\n")
    (r / "pkg" / "api" / "handler_test.go").write_text("package api\n")
    commit_all(r, "fix: cap the body")
    return r, base


_CWES = itertools.count(1000)


def work_item(engine: Engine, service: RemediationService, sha: str, **finding: Any) -> Any:
    """A work item on commit `sha` for one confirmed finding with a CWE and a location."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/example-org/svc-{uuid4().hex[:8]}")
        ref = seed.repository_ref(repo, sha=sha)
        found = seed.finding(repo, title="Unbounded read of the body", **finding)
        seed.decision(found, validity="confirmed", severity="high", actor="human:a@example.com")
        seed.finding_cwe(found, seed.cwe(identifier=f"CWE-{next(_CWES)}"))
        seed.location(seed.occurrence(found, seed.assessment(ref)))
        uow.commit()
    return service.open([found.id], ref.id), found  # type: ignore[list-item, arg-type]


def test_assemble_drafts_the_report_from_the_workspace_and_the_work_item(
    service: RemediationService, engine: Engine, workspace: tuple[Path, str]
) -> None:
    path, base = workspace
    item, found = work_item(engine, service, base)
    evidence = EvidenceItem(kind="mutation", outcome="not_attempted: no tool")  # type: ignore[arg-type]
    narrative = NARRATIVE.model_copy(update={"evidence": (evidence,), "notes": "reviewed"})
    draft = service.assemble(item.work_item_id, path, narrative, [check("pass")])
    doc = json.loads(draft.report.payload)
    head = git(path, "rev-parse", "HEAD")
    assert doc["title"].endswith("automated remediation for Unbounded read of the body")
    assert doc["metadata"] == {
        "date": doc["metadata"]["date"],
        "harness_version": "1.2.3-abcdef0",
        "logical_product": "example-product",
        "repository": doc["fork"]["upstream_remote"],
        "audited_commit": base,
    }
    (source,) = doc["source_findings"]
    assert (source["finding_ref"], source["severity"], source["validation_verdict"]) == (
        str(found.id),
        "high",
        "not_validated",
    )
    assert source["locations"] == [{"path": "pkg/api/handler.go", "lines": "10-12"}]
    assert source["cwes"][0].startswith("CWE-")
    assert (doc["fork"]["base_commit"], doc["fork"]["fix_commit"]) == (base, head)
    assert doc["fork"]["fix_branch"] == f"fix/{found.id}/unbounded-read-of-the-body"
    assert doc["fork"]["visibility"] == "private"
    patch = doc["patch"]
    assert {f["path"]: f["change_type"] for f in patch["files_changed"]} == {
        "pkg/api/handler.go": "modified",
        "pkg/api/handler_test.go": "added",
    }
    assert patch["diffstat"] == {"files": 2, "additions": 2, "deletions": 1}
    assert patch["diff_path"] == f"{item.work_item_id}-patch.diff"
    assert patch["diff_sha256"] == hashlib.sha256(draft.diff).hexdigest()
    assert b"+func Read() { cap() }" in draft.diff
    assert doc["summary"] == {
        "status": "checks_passed",
        "checks_passed": 1,
        "checks_total": 1,
        "findings_addressed": 1,
        "ready_for_review": True,
    }
    assert [e["outcome"] for e in doc["evidence"]] == ["not_attempted: no tool"]
    assert doc["notes"] == "reviewed"
    assert service.get(item.work_item_id).report is None
    recorded = service.record(draft.report, provenance())
    assert (recorded.status, recorded.fix_branch) == ("checks_passed", doc["fork"]["fix_branch"])


@pytest.mark.parametrize(
    ("checks", "override", "status", "ready"),
    [
        (["fail", "pass"], None, "checks_failed", False),
        (["pass"], "abandoned", "abandoned", False),
    ],
)
def test_assemble_status_comes_from_the_checks_unless_the_agent_says_otherwise(
    service: RemediationService,
    engine: Engine,
    workspace: tuple[Path, str],
    checks: list[str],
    override: str | None,
    status: str,
    ready: bool,
) -> None:
    path, base = workspace
    item, _ = work_item(engine, service, base)
    narrative = NARRATIVE.model_copy(update={"status": override})
    draft = service.assemble(item.work_item_id, path, narrative, [check(c) for c in checks])
    summary = json.loads(draft.report.payload)["summary"]
    assert (summary["status"], summary["ready_for_review"]) == (status, ready)


def test_assemble_refuses_a_report_it_cannot_make_true(
    service: RemediationService, engine: Engine, workspace: tuple[Path, str]
) -> None:
    path, base = workspace
    item, _ = work_item(engine, service, base)
    elsewhere, _ = work_item(engine, service, "f" * 40)
    unchanged, _ = work_item(engine, service, git(path, "rev-parse", "HEAD"))
    cases = [
        (item.work_item_id, [], ValidationError, "at least one check"),
        (elsewhere.work_item_id, [check("pass")], ValidationError, "is not in the workspace"),
        (unchanged.work_item_id, [check("pass")], ValidationError, "nothing committed since"),
        (uuid4(), [check("pass")], NotFoundError, "assessment"),
    ]
    for work_item_id, checks, error, message in cases:
        with pytest.raises(error, match=message):
            service.assemble(work_item_id, path, NARRATIVE, checks)


def test_assemble_marks_a_finding_without_cwe_or_location_for_review(
    service: RemediationService, engine: Engine, workspace: tuple[Path, str]
) -> None:
    path, base = workspace
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url="https://github.com/example-org/bare-svc")
        ref = seed.repository_ref(repo, sha=base)
        found = seed.finding(repo, title="Something is wrong here")
        seed.decision(found, validity="confirmed", severity="low", actor="human:a@example.com")
        uow.commit()
    item = service.open([found.id], ref.id)  # type: ignore[list-item, arg-type]
    draft = service.assemble(item.work_item_id, path, NARRATIVE, [check("pass")])
    (source,) = json.loads(draft.report.payload)["source_findings"]
    assert (source["cwes"], source["locations"]) == (["CWE-0"], [{"path": "(unknown)"}])


def test_assemble_an_abandoned_item_with_nothing_committed(
    service: RemediationService, engine: Engine, workspace: tuple[Path, str]
) -> None:
    path, _ = workspace
    item, _ = work_item(engine, service, git(path, "rev-parse", "HEAD"))
    narrative = NARRATIVE.model_copy(update={"status": "abandoned", "notes": "fixed upstream"})
    draft = service.assemble(item.work_item_id, path, narrative, [check("skip")])
    doc = json.loads(draft.report.payload)
    assert doc["patch"]["files_changed"] == [
        {"path": "(no changes)", "change_type": "modified", "additions": 0, "deletions": 0}
    ]
    assert (doc["summary"]["status"], doc["notes"]) == ("abandoned", "fixed upstream")


# candidates: the bulk selection by product (legacy run_batch.sh)


def test_candidates_are_a_products_unworked_confirmed_open_findings_worst_first(
    service: RemediationService, context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        product, empty = seed.product(), seed.product()
        release = seed.release(product)
        repos = [seed.repository(url=f"https://github.com/example-org/{n}") for n in "abc"]
        refs = [seed.repository_ref(r) for r in repos]
        for ref in refs[:2]:
            seed.component(release, ref)
        other = seed.repository_ref(seed.repository())

        def judged(repo: Any, severity: str, **kw: Any) -> Finding:
            f = seed.finding(repo, fingerprint=f"fp-{uuid4().hex}")
            seed.decision(f, validity="confirmed", severity=severity, actor="human:a@example.com")
            for k, v in kw.items():
                seed.decision(f, **{k: v, "validity": None}, actor="human:a@example.com")
            return f

        a_low, a_high = judged(repos[0], "low"), judged(repos[0], "high")
        b_high, b_crit = judged(repos[1], "high"), judged(repos[1], "critical")
        b_worked = judged(repos[1], "critical")
        judged(repos[1], "high", resolution="resolved")
        unjudged = seed.finding(repos[1], fingerprint="fp-unjudged")
        seed.decision(unjudged, validity=None, severity="high", actor="human:a@example.com")
        judged(repos[2], "critical")
        judged(uow.repositories.get(other.repository_id), "critical")
        uow.commit()
    service.open([b_worked.id], refs[1].id)  # type: ignore[list-item, arg-type]
    found = service.candidates(product.id)  # type: ignore[arg-type]
    assert [(c.url, c.repository_ref_ids) for c in found] == [
        (repos[1].url, (refs[1].id,)),
        (repos[0].url, (refs[0].id,)),
    ]
    assert [[v.finding.id for v in c.findings] for c in found] == [
        [b_crit.id, b_high.id],
        [a_high.id, a_low.id],
    ]
    assert service.candidates(empty.id) == []  # type: ignore[arg-type]
    with pytest.raises(NotFoundError):
        service.candidates(uuid4())


# the remediation index view (legacy emit_product_index.py)


def test_the_remediation_index_lists_each_products_work_items(
    service: RemediationService, context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        product = seed.product()
        repo = seed.repository(url="https://github.com/example-org/indexed")
        ref = seed.repository_ref(repo)
        seed.component(seed.release(product), ref)
        found = [seed.finding(repo, fingerprint=f"fp-{n}") for n in range(2)]
        for f in found:
            seed.decision(f, validity="confirmed", severity="high", actor="human:a@example.com")
        uow.commit()
    pending = service.open([found[0].id], ref.id)  # type: ignore[list-item, arg-type]
    done = service.open([found[1].id], ref.id)  # type: ignore[list-item, arg-type]
    service.record(report([found[1].id]), provenance())  # type: ignore[list-item]
    insight = context.services().insight
    scope = ViewFilter(product_ids=(product.id,))  # type: ignore[arg-type]
    index = insight.build(ViewName.REMEDIATION_INDEX, scope)
    assert [
        (r.product, r.work_item_id, r.status, r.fork_url, r.fix_branch) for r in index.rows
    ] == [  # type: ignore[attr-defined]
        (product.slug, pending.work_item_id, "candidate", None, None),
        (
            product.slug,
            done.work_item_id,
            "checks_passed",
            "https://github.com/example-mirrors/example-service",
            REPORT["fork"]["fix_branch"],
        ),
    ]
    assert index.by_status == {"candidate": 1, "checks_passed": 1}  # type: ignore[attr-defined]
    rendered = insight.publish(ViewName.REMEDIATION_INDEX, scope).markdown
    assert product.slug in rendered and REPORT["fork"]["fix_branch"] in rendered
    everything = insight.build(ViewName.REMEDIATION_INDEX, ViewFilter())
    assert {r.product for r in everything.rows} == {None}  # type: ignore[attr-defined]
    with pytest.raises(ValidationError, match="no as_of"):
        insight.build(ViewName.REMEDIATION_INDEX, ViewFilter(as_of=WHEN))


AUDIT = json.loads((FIXTURES.parent / "reporting" / "widget-report.json").read_text())


def test_prepare_carries_the_latest_validation_and_the_audits_remediation_hint(
    context: Context, service: RemediationService, engine: Engine, workspace: tuple[Path, str]
) -> None:
    path, base = workspace
    services = context.services()
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/example-org/svc-{uuid4().hex[:8]}")
        ref = seed.repository_ref(repo, sha=base)
        stamped, scanned = seed.finding(repo, fingerprint="a" * 64), seed.finding(repo)
        seed.occurrence(scanned, seed.assessment(ref))
        uow.commit()
    raw = json.loads(json.dumps(AUDIT))
    del raw["metadata"]["additional"]  # a legacy, unstamped report: identity is recomputed
    raw["remediation_roadmap"] = [  # recorded canonically, so priorities are the canonical enum
        {**item, "priority": item["priority"].lower()} for item in raw["remediation_roadmap"]
    ]
    rows = [{k: v for k, v in f.items() if k != "fingerprint"} for f in raw["findings"]]
    rows[2] |= {"fingerprint": stamped.fingerprint, "fingerprint_algo": stamped.fingerprint_algo}
    doc = ReportArtifact.parse(json.dumps({**raw, "findings": rows}).encode())
    audit = services.assessment.record(
        doc, ref.id, AssessmentKind.SECURE_CODE_CANONICAL, "skill:audit", "1", provenance()
    )
    (audit_report,) = services.findings.artifacts.list_for_assessment(audit.id)
    taken = services.findings.intake.accept(
        audit.id, FindingCandidate.of_report(doc.findings[:1], repo.id)
    )
    matched = taken.findings[Label(rows[0]["id"])]
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        seed.occurrence(stamped, audit)
        for f in (uow.findings.get(matched), stamped, scanned):
            seed.decision(f, validity="confirmed", severity="high", actor="human:a@example.com")
        uow.commit()
    validated = services.validation.record(
        ValidationArtifact.parse(
            json.dumps(
                {
                    "title": "Live validation of example application",
                    "metadata": {
                        "date": "2026-10-23",
                        "harness_version": "0.34.3",
                        "scope_binding_mode": "explicit",
                        "target_fingerprint": [{"adapter": "k8s", "identity": "example-lab"}],
                        "target_environment": "example-lab",
                        "target_attestation": {"artifact": "target-attestation", "attested": True},
                    },
                    "source_reports": [
                        {
                            "kind": "security-audit",
                            "path": "audit.json",
                            "sha256": audit_report.digest,
                        }
                    ],
                    "summary": {
                        "by_verdict": {v.value: int(v == "confirmed") for v in ValidationVerdict},
                        "by_technique": {"replay": 1},
                    },
                    "validated_findings": [
                        {
                            "source_id": rows[0]["id"],
                            "source_report": "audit.json",
                            "verdict": "confirmed",
                            "technique": "replay",
                            "evidence_grade": "E1",
                            "observed_impact": "The injected query returned another tenant's rows.",
                        }
                    ],
                    "attack_chains": [],
                    "novel_findings": [],
                    "execution_log_ref": "validation-audit.jsonl",
                }
            ).encode()
        ),
        Provenance(run_id=uuid4(), source=SourceType.VALIDATION_REPORT, occurred_at=WHEN),
        ValidationRecordInput(
            sources=(
                ValidationSourceBinding(
                    source_report="audit.json",
                    assessment_id=audit.id,
                    artifact_id=audit_report.id,
                    findings=(
                        ValidationFindingBinding(source_id=rows[0]["id"], finding_id=matched),
                    ),
                ),
            )
        ),
    )
    item = service.open([matched, stamped.id, scanned.id], ref.id)  # type: ignore[list-item]
    given = {i.finding.finding.id: i for i in service.prepare(item.work_item_id).items}
    assert given[matched].validation == services.validation.attempts(matched)[0]
    assert given[matched].validation.assessment_id == validated.assessment_ids[0]
    assert (given[matched].validation.verdict, given[matched].remediation_hint) == (
        "confirmed",
        rows[0]["remediation"],
    )
    assert (given[stamped.id].validation, given[stamped.id].remediation_hint) == (
        None,
        rows[2]["remediation"],
    )
    assert (given[scanned.id].validation, given[scanned.id].remediation_hint) == (None, None)
    draft = service.assemble(item.work_item_id, path, NARRATIVE, [check("pass")])
    verdicts = {
        s["finding_ref"]: s["validation_verdict"]
        for s in json.loads(draft.report.payload)["source_findings"]
    }
    assert verdicts == {
        str(matched): "confirmed",
        str(stamped.id): "not_validated",
        str(scanned.id): "not_validated",
    }
