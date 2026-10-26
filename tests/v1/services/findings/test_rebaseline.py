"""Identity moves and rebaseline, ported from traust-engine tests/test_finding_identity.py
(match_findings tiers): a moved finding keeps its id, and the move needs a person."""

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
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.models.findings import (
    CweId,
    Finding,
    FindingCandidate,
    FindingView,
    Label,
    Location,
    RecordDecision,
)
from traust_core.v1.models.identity import IdentitySource, Principal, Role
from traust_core.v1.models.integrity import Fingerprint, sha256_hex
from traust_core.v1.models.vocabulary import ActorKind, Severity
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings import IdentityPolicy

REPO = uuid4()


def hx(name: str) -> str:
    return sha256_hex(name.encode())


PERSON = Principal(
    identity="analyst@example.com",
    kind=ActorKind.HUMAN,
    display="Analyst",
    verified_by=IdentitySource.OIDC,
    roles=frozenset({Role.ADMIN}),
)


def view(title: str, paths: tuple[str, ...], cwes: tuple[str, ...], fp: str) -> FindingView:
    finding = Finding(
        id=uuid4(), repository_id=REPO, fingerprint_algo="v3", fingerprint=hx(fp), title=title
    )
    return FindingView(
        finding=finding,
        effective_severity=Severity.HIGH,
        locations=tuple(Location(occurrence_id=uuid4(), path=p) for p in paths),
        cwes=cwes,
    )


def cand(label: str, title: str, paths: tuple[str, ...], cwes: tuple[str, ...]) -> FindingCandidate:
    return FindingCandidate(
        label=Label(label),
        repository_id=REPO,
        title=title,
        cwes=tuple(CweId(c) for c in cwes),
        locations=tuple(CodeSpan(path=RepoPath(p)) for p in paths),
        reported_severity=Severity.HIGH,
    )


SQLI = "SQL injection in the reconcile handler"
OLD = [
    view(SQLI, ("a/db.go", "a/h.go"), ("CWE-89",), "fp-sqli"),
    view("Missing auth on admin route", ("api/admin.go",), ("CWE-306",), "fp-auth"),
    view("Reflected XSS in search page", ("web/search.go",), ("CWE-79",), "fp-xss"),
    view("Hardcoded token", ("cfg/token.go",), ("CWE-798",), "fp-kept"),
    view("Something unrelated entirely", ("x/y.go",), ("CWE-20",), "fp-gone"),
]


@pytest.mark.parametrize(
    ("new", "want"),
    [
        (  # same paths, same primary CWE, another fingerprint (e.g. a recipe change)
            [cand("N1", "SQLi in reconcile", ("./a/h.go", "a/db.go"), ("CWE-89", "CWE-564"))],
            {0: ("N1", "path_cwe", None, None)},
        ),
        (  # CWE reclassified, paths overlap 2/3
            [cand("N1", SQLI, ("a/db.go", "a/h.go", "a/q.go"), ("CWE-943",))],
            {0: ("N1", "path_set", 1.0, 0.667)},
        ),
        (  # file moved, title kept
            [cand("N1", "Missing auth on the admin route", ("srv/admin.go",), ("CWE-306",))],
            {1: ("N1", "title", 0.931, None)},
        ),
        (  # the fingerprint still matches: intake keeps it, no move
            [cand("N1", "Hardcoded token", ("cfg/token.go",), ("CWE-798",))],
            {},
        ),
        ([cand("N1", "Brand new finding", ("new/thing.go",), ("CWE-400",))], {}),
        ([], {}),
    ],
    ids=["path-cwe", "path-set", "title", "fingerprint", "unmatched", "empty"],
)
def test_the_move_ladder(new: list[FindingCandidate], want: dict[int, tuple[Any, ...]]) -> None:
    keys = [
        Fingerprint("v3", hx("fp-kept" if c.title == "Hardcoded token" else f"new-{c.label}"))
        for c in new
    ]
    moves = IdentityPolicy().moves(OLD, new, keys)
    got = {
        next(i for i, v in enumerate(OLD) if v.finding.id == m.finding_id): (
            m.label,
            m.matched_by,
            m.similarity,
            m.path_overlap,
        )
        for m in moves
    }
    assert got == want
    assert all(m.fingerprint == hx(f"new-{m.label}") for m in moves)


def test_a_candidate_is_claimed_once() -> None:
    twins = [view(SQLI, ("a/db.go",), ("CWE-89",), f"fp-{i}") for i in range(2)]
    new = [cand("N1", SQLI, ("a/db.go",), ("CWE-89",))]
    moves = IdentityPolicy().moves(twins, new, [Fingerprint("v3", hx("new"))])
    assert [m.finding_id for m in moves] == [twins[0].finding.id]


# the service


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def services(engine: Engine, tmp_path: Path) -> Any:
    ctx = Context(Config(home=tmp_path))
    ctx.__dict__["database"] = engine
    return ctx.services()


def audited(engine: Engine, services: Any, paths: tuple[str, ...]) -> tuple[UUID, UUID]:
    """A repository audited once: the repository and its one finding."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/example/svc-{uuid4().hex[:6]}")
        ref = seed.repository_ref(repo)
        run = seed.assessment(ref, kind="secure-code")
        uow.commit()
    candidate = reaudit(repo.id, paths)  # type: ignore[arg-type]
    taken = services.findings.intake.accept(run.id, [candidate])
    return repo.id, taken.findings[candidate.label]  # type: ignore[return-value]


def reaudit(repository_id: UUID, paths: tuple[str, ...]) -> FindingCandidate:
    return FindingCandidate(
        label=Label("OPERATOR-abcdef0-001"),
        repository_id=repository_id,
        title=SQLI,
        cwes=(CweId("CWE-89"),),
        locations=tuple(CodeSpan(path=RepoPath(p), line=1) for p in paths),
        reported_severity=Severity.HIGH,
    )


def attest(services: Any, finding_id: UUID, **changes: Any) -> UUID:
    command = RecordDecision(
        finding_id=finding_id,
        rationale="same injection: the handler moved files",
        reason="rebaseline_mapping",
        occurred_at=datetime(2026, 10, 23, 9, tzinfo=UTC),
    ).model_copy(update=changes)
    return services.findings.decisions.decide(command, PERSON).id  # type: ignore[no-any-return]


def test_a_moved_finding_keeps_its_id_and_history(engine: Engine, services: Any) -> None:
    repo, finding_id = audited(engine, services, ("a/db.go", "a/h.go"))
    again = reaudit(repo, ("a/db.go", "a/h.go", "a/q.go"))
    (move,) = services.findings.moves(repo, [again])
    assert (move.finding_id, move.matched_by) == (finding_id, "path_set")
    decision = attest(services, finding_id)
    (moved,) = services.findings.intake.rebaseline([move], decision)
    assert (moved.id, moved.fingerprint) == (finding_id, move.fingerprint)
    assert services.findings.intake.rebaseline([move], decision) == [moved]
    with SqlTraustUnitOfWork(engine) as uow:
        run = Seed(uow).assessment(uow.repository_refs.list_for(repo)[0], kind="secure-code")
        uow.commit()
    taken = services.findings.intake.accept(run.id, [again])
    assert (taken.findings[again.label], taken.created) == (finding_id, ())
    assert services.findings.moves(repo, [again]) == []
    assert [d.id for d in services.findings.history(finding_id)] == [decision]


def test_a_move_needs_a_person_s_mapping_decision_on_that_finding(
    engine: Engine, services: Any
) -> None:
    repo, finding_id = audited(engine, services, ("a/db.go", "a/h.go"))
    _, other = audited(engine, services, ("b/x.go",))
    (move,) = services.findings.moves(repo, [reaudit(repo, ("a/db.go", "a/h.go", "a/q.go"))])
    with SqlTraustUnitOfWork(engine) as uow:
        machine = Seed(uow).decision(
            uow.findings.get(finding_id),
            reason="rebaseline_mapping",
            actor="skill:triage",
            validity=None,
        )
        uow.commit()
    cases = [
        (attest(services, finding_id, reason="severity_proposal"), ForbiddenError, "not a person"),
        (machine.id, ForbiddenError, "not a person"),
        (attest(services, other), ForbiddenError, "attests one move"),
    ]
    for decision, error, message in cases:
        with pytest.raises(error, match=message):
            services.findings.intake.rebaseline([move], decision)
    with pytest.raises(ValidationError, match="needs a move"):
        services.findings.intake.rebaseline([], cases[0][0])
    with pytest.raises(NotFoundError):
        services.findings.intake.rebaseline([move], uuid4())


def test_a_move_onto_a_held_fingerprint_conflicts(engine: Engine, services: Any) -> None:
    repo, finding_id = audited(engine, services, ("a/db.go", "a/h.go"))
    again = reaudit(repo, ("a/db.go", "a/h.go", "a/q.go"))
    (move,) = services.findings.moves(repo, [again])
    with SqlTraustUnitOfWork(engine) as uow:
        run = Seed(uow).assessment(uow.repository_refs.list_for(repo)[0], kind="secure-code")
        uow.commit()
    services.findings.intake.accept(run.id, [again])
    with pytest.raises(ConflictError, match="already holds"):
        services.findings.intake.rebaseline([move], attest(services, finding_id))


def test_moves_compare_one_repository(engine: Engine, services: Any) -> None:
    repo, _ = audited(engine, services, ("a/db.go",))
    other, _ = audited(engine, services, ("a/db.go",))
    with pytest.raises(ValidationError, match="one repository"):
        services.findings.intake.moves([], [reaudit(repo, ("x",)), reaudit(other, ("y",))])
