"""FindingReview.queue on SQLite and Postgres: countersign's discover_pending (traust fabdb13),
over review_item rows and the folded disposition instead of layer files."""

from __future__ import annotations

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.findings.test_reads import engine, service  # noqa: F401
from tests.v1.services.findings.test_rollups import Repo, new_repo
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.findings import Finding, ReviewCaseKind, ReviewFilter, ReviewItem
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings import FindingReview

ALL = ReviewFilter()


@pytest.fixture
def repo(engine: Engine) -> Repo:  # noqa: F811
    return new_repo(engine)


def review(engine: Engine) -> FindingReview:  # noqa: F811
    return service(engine).review


def item(repo: Repo, finding: Finding, **kw: object) -> ReviewItem:
    with SqlTraustUnitOfWork(repo.engine) as uow:
        made = Seed(uow).review_item(finding, **kw)
        uow.commit()
    return made


def kinds(repo: Repo, filter: ReviewFilter = ALL) -> dict[object, ReviewCaseKind]:
    return {c.finding_id: c.kind for c in review(repo.engine).queue(filter, PageRequest()).items}


def static_refutation(repo: Repo, finding: Finding, day: int = 1) -> None:
    repo.assessed(finding, "triage", day, validity="false_positive")


@pytest.mark.parametrize(
    ("story", "expected"),
    [
        ("machine_fp", ReviewCaseKind.AWAITING_SIGNOFF),
        ("human_fp_then_execution_proof", ReviewCaseKind.FP_OVERRIDDEN),
        ("execution_proof_then_one_human_fp", ReviewCaseKind.FP_REASSERTION_BLOCKED),
        ("human_confirmed_machine_fp", ReviewCaseKind.CONFLICT),
        # a severity-only re-rating judges nothing: the refutation still waits
        ("machine_fp_then_human_re_rating", ReviewCaseKind.AWAITING_SIGNOFF),
        ("machine_fp_then_human_fp", None),
        ("auto_accepted_machine_fp", None),
        ("human_fp", None),
        ("undecided", None),
    ],
)
def test_queue_holds_the_fold_states_that_need_a_person(
    repo: Repo, story: str, expected: ReviewCaseKind | None
) -> None:
    f = repo.reported()
    match story:
        case "machine_fp":
            static_refutation(repo, f)
        case "human_fp_then_execution_proof":
            repo.judged(f, 1, validity="false_positive")
            repo.assessed(f, "validation", 2, validity="confirmed", evidence_grade="E0")
        case "execution_proof_then_one_human_fp":
            repo.assessed(f, "validation", 1, validity="confirmed", evidence_grade="E0")
            repo.judged(f, 2, validity="false_positive", evidence_grade="E0")
        case "human_confirmed_machine_fp":
            repo.judged(f, 1, validity="confirmed")
            static_refutation(repo, f, day=2)
        case "machine_fp_then_human_re_rating":
            static_refutation(repo, f)
            repo.judged(f, 2, severity="low")
        case "machine_fp_then_human_fp":
            static_refutation(repo, f)
            repo.judged(f, 2, validity="false_positive")
        case "auto_accepted_machine_fp":
            repo.assessed(f, "triage", 1, validity="false_positive", auto_accept_tier=True)
        case "human_fp":
            repo.judged(f, 1, validity="false_positive")
    assert kinds(repo).get(f.id) == expected
    assert kinds(repo, ReviewFilter(repository_id=repo.repository.id)).get(f.id) == expected


def test_queue_holds_pending_review_items_only(repo: Repo) -> None:
    f = repo.reported()
    waiting = item(repo, f, reason="fp_audit_valve")
    item(repo, f, status="confirmed")
    item(repo, f, status="rejected")
    (case,) = review(repo.engine).queue(ALL, PageRequest()).items
    assert (case.kind, case.review_item, case.repository_id) == (
        ReviewCaseKind.NEEDS_REVIEW,
        waiting,
        repo.repository.id,
    )
    assert case.since == waiting.created_at


def test_a_finding_with_an_item_and_a_fold_state_is_two_cases(repo: Repo) -> None:
    f = repo.reported()
    static_refutation(repo, f)
    item(repo, f)
    cases = review(repo.engine).queue(ALL, PageRequest()).items
    assert sorted(c.kind for c in cases) == [
        ReviewCaseKind.AWAITING_SIGNOFF,
        ReviewCaseKind.NEEDS_REVIEW,
    ]
    only = review(repo.engine).queue(
        ReviewFilter(kind=ReviewCaseKind.AWAITING_SIGNOFF), PageRequest()
    )
    assert [c.kind for c in only.items] == [ReviewCaseKind.AWAITING_SIGNOFF]


def test_queue_is_oldest_first_and_pages_by_cursor(repo: Repo) -> None:
    found = [repo.reported() for _ in range(3)]
    for day, f in zip((3, 1, 2), found, strict=True):
        static_refutation(repo, f, day=day)
    queue = review(repo.engine)

    first = queue.queue(ALL, PageRequest(limit=2))
    assert [c.finding_id for c in first.items] == [found[1].id, found[2].id]
    assert first.next is not None
    rest = queue.queue(ALL, PageRequest(limit=2, cursor=first.next))
    assert ([c.finding_id for c in rest.items], rest.next) == ([found[0].id], None)


def test_queue_by_repository_leaves_other_repositories_out(repo: Repo) -> None:
    mine = repo.reported()
    static_refutation(repo, mine)
    other = new_repo(repo.engine)
    theirs = other.reported()
    static_refutation(other, theirs)
    item(other, theirs)

    assert set(kinds(repo)) == {mine.id, theirs.id}
    assert set(kinds(repo, ReviewFilter(repository_id=repo.repository.id))) == {mine.id}


def test_an_empty_queue(repo: Repo) -> None:
    repo.reported()
    assert review(repo.engine).queue(ALL, PageRequest()).items == ()


def test_queue_rejects_a_non_positive_limit(repo: Repo) -> None:
    with pytest.raises(ValidationError):
        review(repo.engine).queue(ALL, PageRequest(limit=0))
