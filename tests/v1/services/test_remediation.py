"""RemediationService over SQLite and Postgres: work items (legacy remediation manifest), steps,
forks (ported from traust tests/test_fork_map.py) and the report."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    ValidationError,
)
from traust_core.v1.models.artifacts import RemediationArtifact
from traust_core.v1.models.common import ArtifactRef, PageRequest, Provenance
from traust_core.v1.models.findings import Finding
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.remediation import WorkItemFilter
from traust_core.v1.models.vocabulary import RemediationStatus, SourceType
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
    ctx = Context(Config(home=tmp_path, remediation=PRIVATE))
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
    assert view.disposition and view.disposition.resolution == "fix_in_progress"
    before = len(decisions(engine, found))
    assert service.record_progress(item.work_item_id, RemediationStatus("forked")) == forked
    assert len(decisions(engine, found)) == before
    with pytest.raises(ConflictError, match="forked can't move to candidate"):
        service.record_progress(item.work_item_id, RemediationStatus("candidate"))
    service.record_progress(item.work_item_id, RemediationStatus("merged"))
    merged = context.services().findings.get(found.id)  # type: ignore[arg-type]
    assert merged.is_open()
    assert merged.disposition and merged.disposition.resolution == "fix_in_progress"


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
    assert (said.reason, said.resolution) == ("checks_passed", "fix_in_progress")
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
