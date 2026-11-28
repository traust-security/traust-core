"""Finding reads on SQLite and Postgres, over decisions made through decide: track-findings."""

from __future__ import annotations

import json
import logging
import shutil
from collections import Counter
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConflictError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import ReportArtifact
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import PageRequest, Provenance, RecordBudget
from traust_core.v1.models.findings import (
    Finding,
    FindingCandidate,
    FindingEvidence,
    FindingFilter,
    FindingSetFilter,
    FindingState,
    Label,
    RecordDecision,
)
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import Repository, RepositoryRef
from traust_core.v1.models.vocabulary import (
    ActorKind,
    DispositionAssurance,
    Severity,
    SourceType,
    Validity,
)
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.tables import SqlTableRepository
from traust_core.v1.services.artifact_publishing import AssessmentLog
from traust_core.v1.services.findings import (
    FindingDecisions,
    FindingIntake,
    FindingPrecedents,
    FindingReview,
    FindingService,
    FindingViewQuery,
    IdentityPolicy,
    RatingPolicy,
    ReviewPolicy,
    TaxonomyPolicy,
)
from traust_core.v1.services.findings.rating import RatingConfig
from traust_core.v1.services.findings.windows import WindowMemo
from traust_core.v1.services.lint import Lint

T0 = datetime(2026, 10, 1, tzinfo=UTC)
NOW = T0 + timedelta(days=40)
ALICE = Principal(
    identity="alice@example.com",
    kind=ActorKind.HUMAN,
    display="Alice",
    verified_by=IdentitySource.OIDC,
)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def service(engine: Engine, *, windows: WindowMemo | None = None) -> FindingService:
    uow = SqlTraustUnitOfWork(engine)
    precedents = FindingPrecedents(uow)
    decisions = FindingDecisions(
        uow,
        None,
        Lint({}),
        precedents,
        clock=FixedClock(NOW),
        objects=InMemoryObjectStore(),
        review=ReviewPolicy(),
        rating=RatingPolicy(RatingConfig()),
    )
    rating = RatingPolicy(RatingConfig())
    views = FindingViewQuery(rating)
    return FindingService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        decisions,
        FindingReview(uow, ReviewPolicy(), decisions, views),
        precedents,
        rating,
        InMemoryObjectStore(),
        windows=windows,
    )


@dataclass
class Audited:
    repository: Repository
    ref: RepositoryRef
    finding: Finding


def audited(engine: Engine, severity: str = "high", **occurrence: Any) -> Audited:
    """A repository whose audit on T0 reported one finding."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        ref = seed.repository_ref(repo)
        finding = seed.finding(repo)
        seed.occurrence(
            finding, seed.assessment(ref, occurred_at=T0), severity=severity, **occurrence
        )
        uow.commit()
    return Audited(repo, ref, finding)


def reported(engine: Engine, a: Audited, kind: str, day: int, **decision: Any) -> None:
    """A report of `kind` judged the finding on `day`."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        at = T0 + timedelta(days=day)
        run = seed.assessment(a.ref, kind=kind, occurred_at=at)
        seed.decision(a.finding, assessment_id=run.id, actor=None, occurred_at=at, **decision)
        uow.commit()


def said(finding: Finding, day: int, **kw: Any) -> RecordDecision:
    values: dict[str, Any] = {
        "finding_id": finding.id,
        "source_channel": SourceType.INTERACTIVE,
        "occurred_at": T0 + timedelta(days=day),
        "rationale": "validated in the admission webhook",
    }
    return RecordDecision(**{**values, **kw})


# get
def test_get_undecided_finding_is_rated_by_its_report_with_a_deadline(engine: Engine) -> None:
    a = audited(engine, severity="critical")
    view = service(engine).get(a.finding.id)  # type: ignore[arg-type]
    assert view.finding == a.finding
    assert view.disposition is None
    assert view.effective_severity is Severity.CRITICAL
    assert view.sla_due == T0 + timedelta(days=30)


def test_a_scored_finding_labels_from_its_band_over_a_judgement(engine: Engine) -> None:
    # the defect's shape: reported medium, re-rated low, scored 9.8 — the view says critical
    a = audited(
        engine,
        severity="medium",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=Decimal("9.8"),
    )
    findings = service(engine)
    findings.decisions.decide(said(a.finding, 1, severity=Severity.LOW), ALICE)
    view = findings.get(a.finding.id)  # type: ignore[arg-type]
    assert view.effective_severity is Severity.CRITICAL


def test_an_unscored_finding_keeps_its_judgement_over_its_word(engine: Engine) -> None:
    a = audited(engine, severity="high")
    findings = service(engine)
    findings.decisions.decide(said(a.finding, 1, severity=Severity.LOW), ALICE)
    view = findings.get(a.finding.id)  # type: ignore[arg-type]
    assert view.effective_severity is Severity.LOW


def test_get_unknown_finding_is_not_found(engine: Engine) -> None:
    with pytest.raises(NotFoundError):
        service(engine).get(uuid4())


@pytest.mark.parametrize("closed", [False, True])
def test_report_times_follow_assessments_not_insertion_or_decision_times(
    engine: Engine, closed: bool
) -> None:
    """The view's first/last report times — the occurrence→assessment join the census
    reads for its SLA `first` — so a listing can show a date per finding (the item
    findings page's datetime column); an `as_of` before the later report still sees
    only the earlier one, on the single-repository listing and on the set listing."""
    a = audited(engine)
    earlier = T0 - timedelta(days=5)
    later = T0 + timedelta(days=10)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        for at in (later, earlier, T0 + timedelta(days=2)):
            seed.occurrence(a.finding, seed.assessment(a.ref, occurred_at=at), severity="high")
        uow.commit()
    findings = service(engine)
    if closed:
        findings.decisions.decide(said(a.finding, 20, validity="false_positive"), ALICE)
    view = findings.get(a.finding.id)
    assert (view.first_reported_at, view.last_reported_at) == (earlier, later)
    assert a.finding.created_at not in (earlier, later)
    for cutoff, expected in (
        (None, (earlier, later)),
        (earlier, (earlier, earlier)),
        (T0 + timedelta(days=5), (earlier, T0 + timedelta(days=2))),
        (later, (earlier, later)),
    ):
        pages = (
            findings.list(
                FindingFilter(repository_id=a.repository.id, as_of=cutoff), PageRequest()
            ),
            findings.list_in(
                FindingSetFilter(repository_ids=(a.repository.id,), as_of=cutoff), PageRequest()
            ),
        )
        for page in pages:
            assert len(page.items) == 1
            listed = page.items[0]
            assert (listed.first_reported_at, listed.last_reported_at) == expected
    before = FindingFilter(repository_id=a.repository.id, as_of=earlier - timedelta(seconds=1))
    assert findings.list(before, PageRequest()).items == ()


def test_a_finding_without_reports_has_no_report_times(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        seed.repository_ref(repo)
        finding = seed.finding(repo)
        uow.commit()
    findings = service(engine)
    views = [
        findings.get(finding.id),
        *findings.list(FindingFilter(repository_id=repo.id), PageRequest()).items,
        *findings.list_in(FindingSetFilter(repository_ids=(repo.id,)), PageRequest()).items,
    ]
    assert len(views) == 3
    assert all((v.first_reported_at, v.last_reported_at) == (None, None) for v in views)


@pytest.mark.parametrize("with_algorithm", [False, True])
def test_get_by_fingerprint_returns_the_same_rich_view_without_changing_opaque_identity(
    engine: Engine, with_algorithm: bool
) -> None:
    a = audited(engine, severity="critical")
    opaque = " legacy:/A+B?x=%2F &Ω "
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        finding = uow.findings.update(a.finding.model_copy(update={"fingerprint": opaque}))
        other = seed.repository(url="https://forge.example/other-fingerprint-repository")
        seed.finding(other, fingerprint=opaque, fingerprint_algo=finding.fingerprint_algo)
        seed.finding(a.repository, fingerprint=opaque.strip())
        seed.finding(a.repository, fingerprint=opaque.lower())
        seed.finding_cwe(finding, seed.cwe(identifier="CWE-89"))
        seed.finding_label(finding, taxonomy="attack", label="T1190")
        uow.commit()
    svc = service(engine)
    algorithm = finding.fingerprint_algo if with_algorithm else None
    found = svc.get_by_fingerprint(a.repository.id, opaque, algorithm)
    assert found == svc.get(finding.id)
    assert found.finding.fingerprint == opaque
    assert found.effective_severity is Severity.CRITICAL
    assert found.occurrence is not None
    assert found.cwes == ("CWE-89",)
    assert found.labels


def test_get_by_fingerprint_refuses_ambiguity_but_an_explicit_algorithm_resolves_it(
    engine: Engine,
) -> None:
    a = audited(engine)
    with SqlTraustUnitOfWork(engine) as uow:
        other = Seed(uow).finding(
            a.repository, fingerprint=a.finding.fingerprint, fingerprint_algo="other"
        )
        uow.commit()
    svc = service(engine)
    with pytest.raises(ConflictError):
        svc.get_by_fingerprint(a.repository.id, a.finding.fingerprint)
    assert svc.get_by_fingerprint(
        a.repository.id, a.finding.fingerprint, a.finding.fingerprint_algo
    ) == svc.get(a.finding.id)
    assert svc.get_by_fingerprint(
        a.repository.id, a.finding.fingerprint, other.fingerprint_algo
    ) == svc.get(other.id)


@pytest.mark.parametrize("missing", ["repository", "fingerprint", "algorithm", "other-repository"])
def test_get_by_fingerprint_reports_missing_exact_identity(engine: Engine, missing: str) -> None:
    a = audited(engine)
    with SqlTraustUnitOfWork(engine) as uow:
        empty = Seed(uow).repository(url="https://forge.example/empty-fingerprint-repository")
        uow.commit()
    repository_id = a.repository.id
    if missing == "repository":
        repository_id = uuid4()
    elif missing == "other-repository":
        repository_id = empty.id
    fingerprint = "missing" if missing == "fingerprint" else a.finding.fingerprint
    algorithm = "missing" if missing == "algorithm" else None
    with pytest.raises(NotFoundError):
        service(engine).get_by_fingerprint(repository_id, fingerprint, algorithm)


def test_latest_report_rates_it_and_the_first_starts_the_clock(engine: Engine) -> None:
    a = audited(engine, severity="medium")
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        later = seed.assessment(a.ref, occurred_at=T0 + timedelta(days=5))
        seed.occurrence(a.finding, later, severity="high", cvss_score=Decimal("8.1"))
        uow.commit()
    view = service(engine).get(a.finding.id)  # type: ignore[arg-type]
    assert view.effective_severity is Severity.HIGH
    assert view.occurrence is not None and view.occurrence.cvss_score == Decimal("8.1")
    assert view.sla_due == T0 + timedelta(days=60)


# reads over decisions
def test_a_human_false_positive_closes_the_finding(engine: Engine) -> None:
    a = audited(engine)
    findings = service(engine)
    findings.decisions.decide(said(a.finding, 3, validity="false_positive"), ALICE)
    view = findings.get(a.finding.id)  # type: ignore[arg-type]
    assert view.disposition is not None
    assert (view.disposition.validity, view.disposition.assurance) == (
        "false_positive",
        DispositionAssurance.CLAIMED,
    )
    assert view.sla_due is None


def test_a_static_refutation_awaits_signoff_and_keeps_the_clock(engine: Engine) -> None:
    a = audited(engine)
    reported(engine, a, "triage", day=2, validity="false_positive")
    view = service(engine).get(a.finding.id)  # type: ignore[arg-type]
    assert view.disposition is not None
    assert view.disposition.awaiting_signoff
    assert view.disposition.validity is None
    assert view.sla_due == T0 + timedelta(days=60)


def test_execution_proof_outranks_a_human_false_positive(engine: Engine) -> None:
    a = audited(engine)
    findings = service(engine)
    findings.decisions.decide(said(a.finding, 3, validity="false_positive"), ALICE)
    reported(engine, a, "validation", day=5, validity="confirmed", evidence_grade="E0")
    view = findings.get(a.finding.id)  # type: ignore[arg-type]
    assert view.disposition is not None
    assert (view.disposition.validity, view.disposition.fp_overridden) == ("confirmed", True)
    assert view.disposition.assurance is DispositionAssurance.EXECUTION_PROVEN


def test_a_scored_finding_carries_its_cvss_block(engine: Engine) -> None:
    # the defect's shape: reported medium, scored 9.8 — the view says critical and shows its work
    a = audited(
        engine,
        severity="medium",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=Decimal("9.8"),
    )
    findings = service(engine)
    findings.decisions.decide(said(a.finding, 1, severity=Severity.LOW), ALICE)
    view = findings.get(a.finding.id)  # type: ignore[arg-type]
    assert view.effective_severity is Severity.CRITICAL
    assert view.cvss is not None
    assert (view.cvss.basis, view.cvss.severity) == ("computed", Severity.CRITICAL)
    assert view.cvss.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert view.cvss.score == Decimal("9.8")
    assert view.model_dump(mode="json")["cvss"]["score"] == "9.8"


def test_an_unscored_finding_labels_from_its_word_and_says_so(engine: Engine) -> None:
    a = audited(engine, severity="high")
    view = service(engine).get(a.finding.id)  # type: ignore[arg-type]
    assert view.effective_severity is Severity.HIGH
    assert view.cvss is not None
    assert (view.cvss.basis, view.cvss.severity, view.cvss.score) == ("scanner", None, None)


def test_a_re_rating_changes_severity_and_deadline(engine: Engine) -> None:
    a = audited(engine, severity="high")
    findings = service(engine)
    findings.decisions.decide(said(a.finding, 3, severity=Severity.CRITICAL), ALICE)
    view = findings.get(a.finding.id)  # type: ignore[arg-type]
    assert view.effective_severity is Severity.CRITICAL
    assert view.sla_due == T0 + timedelta(days=30)


# history and baseline
def test_history_keeps_every_decision_in_order(engine: Engine) -> None:
    a = audited(engine)
    findings = service(engine)
    findings.decisions.decide(said(a.finding, 5, resolution="resolved"), ALICE)
    findings.decisions.decide(said(a.finding, 3, validity="confirmed"), ALICE)
    history = findings.history(a.finding.id)  # type: ignore[arg-type]
    assert [(d.validity, d.resolution) for d in history] == [
        ("confirmed", None),
        (None, "resolved"),
    ]


def test_history_of_an_unknown_finding_is_not_found(engine: Engine) -> None:
    with pytest.raises(NotFoundError):
        service(engine).history(uuid4())


def test_baseline_is_the_state_at_as_of(engine: Engine) -> None:
    a = audited(engine)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        late = seed.finding(a.repository)
        seed.occurrence(late, seed.assessment(a.ref, occurred_at=T0 + timedelta(days=20)))
        uow.commit()
    findings = service(engine)
    findings.decisions.decide(said(a.finding, 3, validity="confirmed"), ALICE)
    findings.decisions.decide(said(a.finding, 10, resolution="resolved"), ALICE)

    (then,) = findings.baseline(a.repository.id, T0 + timedelta(days=5))  # type: ignore[arg-type]
    assert then.finding == a.finding
    assert then.disposition is not None and then.disposition.resolution is None
    assert then.sla_due == T0 + timedelta(days=60)

    now = {v.finding.id: v for v in findings.baseline(a.repository.id, NOW)}  # type: ignore[arg-type]
    assert set(now) == {a.finding.id, late.id}
    resolved = now[a.finding.id].disposition
    assert resolved is not None and resolved.resolution == "resolved"
    assert now[a.finding.id].sla_due is None


def test_baseline_before_any_report_is_empty(engine: Engine) -> None:
    a = audited(engine)
    assert service(engine).baseline(a.repository.id, T0 - timedelta(days=1)) == []  # type: ignore[arg-type]


def test_baseline_of_a_repository_without_findings_is_empty(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        repo = Seed(uow).repository()
        uow.commit()
    assert service(engine).baseline(repo.id, NOW) == []  # type: ignore[arg-type]


def test_views_charge_the_read_budget_only_for_decisions_made_by_as_of(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = audited(engine)
    findings = service(engine)
    findings.decisions.decide(said(a.finding, 3, validity="confirmed"), ALICE)
    findings.decisions.decide(said(a.finding, 10, resolution="resolved"), ALICE)
    findings.decisions.decide(said(a.finding, 20, resolution="resolved", severity="high"), ALICE)
    with SqlTraustUnitOfWork(engine) as uow:
        rows = uow.decisions.list_for_findings([a.finding.id])  # type: ignore[list-item]
        assert len(rows) == 3
    counts: Counter[str] = Counter()
    original = SqlTableRepository._to_record

    def counted(
        repository: SqlTableRepository[object], row: Mapping[str, object] | object
    ) -> object:
        counts[repository.spec.name] += 1
        return original(repository, row)  # type: ignore[arg-type, return-value]

    monkeypatch.setattr(SqlTableRepository, "_to_record", counted)
    with SqlTraustUnitOfWork(engine) as uow, pytest.raises(ValidationError):
        FindingViewQuery(RatingPolicy(RatingConfig())).views(
            uow, [a.finding], T0 + timedelta(days=5), read_budget=RecordBudget(1, "as-of view")
        )
    assert counts["decision"] == 1  # the one made by as_of, not the two after it


def test_open_count_counts_open_findings_by_effective_severity(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        critical, high, medium = (seed.finding(repo) for _ in range(3))
        seed.occurrence(critical, severity="critical")
        seed.occurrence(high, severity="high")
        seed.occurrence(medium, severity="medium")
        seed.decision(critical, actor="human:reviewer@example.com", validity="false_positive")
        seed.decision(medium, resolution="resolved")
        uow.commit()
    findings = service(engine)
    assert findings.open_count(repo.id, (Severity.CRITICAL, Severity.HIGH)) == 1  # type: ignore[arg-type]
    assert findings.open_count(repo.id, (Severity.HIGH, Severity.HIGH)) == 1  # type: ignore[arg-type]
    assert findings.open_count(repo.id, ()) == 0  # type: ignore[arg-type]
    assert findings.open_by_severity(repo.id) == {Severity.HIGH: 1}  # type: ignore[arg-type]


def test_open_count_of_a_repository_without_findings_is_zero(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        repo = Seed(uow).repository()
        uow.commit()
    assert service(engine).open_count(repo.id, list(Severity)) == 0  # type: ignore[arg-type]


def test_open_count_agrees_with_the_folded_view(engine: Engine) -> None:
    a = audited(engine)
    accepted = {"resolution": "risk_accepted", "evidence_grade": "E2", "statement_key": "a"}
    reported(engine, a, "triage", day=1, **accepted)
    reported(engine, a, "triage", day=2, resolution="open", evidence_grade="E3", statement_key="b")
    findings = service(engine)
    assert not findings.get(a.finding.id).is_open()  # type: ignore[arg-type]
    assert findings.open_count(a.repository.id, (Severity.HIGH,)) == 0  # type: ignore[arg-type]


def lines(engine: Engine, *, observed: bool) -> tuple[Repository, Finding, Finding, Finding]:
    """Findings reported on the default line, on it and a release branch, and only on the branch."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        main = seed.repository_ref(repo, is_default=observed)
        release = seed.repository_ref(repo, name="release-1", sha="b" * 40)
        head, branch = (seed.assessment(ref, occurred_at=T0) for ref in (main, release))
        on_main, on_both, branch_only = (seed.finding(repo) for _ in range(3))
        seed.occurrence(on_main, head, severity="high")
        seed.occurrence(on_both, head, severity="high")
        seed.occurrence(on_both, branch, severity="high")
        seed.occurrence(branch_only, branch, severity="high")
        uow.commit()
    return repo, on_main, on_both, branch_only


def test_open_count_leaves_out_findings_only_a_branch_re_audit_reported(engine: Engine) -> None:
    repo, *_ = lines(engine, observed=True)
    assert service(engine).open_count(repo.id, (Severity.HIGH,)) == 2  # type: ignore[arg-type]


def test_until_a_default_branch_is_observed_every_line_counts(engine: Engine) -> None:
    repo, *_ = lines(engine, observed=False)
    assert service(engine).open_count(repo.id, (Severity.HIGH,)) == 3  # type: ignore[arg-type]


def test_a_finding_judged_but_never_reported_still_counts(engine: Engine) -> None:
    repo, *_ = lines(engine, observed=True)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        seed.decision(seed.finding(repo), severity="high", statement_key="judged")
        uow.commit()
    assert service(engine).open_count(repo.id, (Severity.HIGH,)) == 3  # type: ignore[arg-type]


def test_open_count_leaves_out_judged_hardening_only(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        audit = seed.assessment(seed.repository_ref(repo), occurred_at=T0)
        exposure, weakness, hardened = (
            seed.finding(repo),
            seed.finding(repo, kind="weakness"),
            seed.finding(repo, kind=None),
        )
        for f in (exposure, weakness, hardened):
            seed.occurrence(f, audit, severity="high")
        seed.decision(hardened, validity="hardening", statement_key="hardening")
        uow.commit()
    findings = service(engine)
    # the judged hardening leaves the count; an unjudged weakness is identified, so open
    assert findings.open_count(repo.id, (Severity.HIGH,)) == 2  # type: ignore[arg-type]
    undecided = findings.get(weakness.id)  # type: ignore[arg-type]
    assert undecided.is_open() and undecided.state() == FindingState.OPEN


# reads across repositories
def test_list_by_validity_is_the_folded_answer_not_any_decision(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        ref = seed.repository_ref(repo)
        audit = seed.assessment(ref, occurred_at=T0)
        found = [seed.finding(repo) for _ in range(4)]
        for f in found:
            seed.occurrence(f, audit)
        uow.commit()
    proven, refuted, awaiting, undecided = (Audited(repo, ref, f) for f in found)
    findings = service(engine)
    assert findings.list_by_validity(Validity.CONFIRMED) == []
    findings.decisions.decide(said(proven.finding, 3, validity="false_positive"), ALICE)
    reported(engine, proven, "validation", day=5, validity="confirmed")
    findings.decisions.decide(said(refuted.finding, 3, validity="false_positive"), ALICE)
    reported(engine, awaiting, "triage", day=2, validity="false_positive")
    assert [v.finding for v in findings.list_by_validity(Validity.CONFIRMED)] == [proven.finding]
    assert [v.finding for v in findings.list_by_validity(Validity.FALSE_POSITIVE)] == [
        refuted.finding
    ]
    views = findings.list_by_ids([undecided.finding.id, refuted.finding.id])  # type: ignore[list-item]
    assert {v.finding.id for v in views} == {undecided.finding.id, refuted.finding.id}
    assert findings.list_by_ids([]) == []


# get: the report row's prose
AUDIT = json.loads(
    (Path(__file__).parents[3] / "fixtures" / "reporting" / "widget-report.json").read_text()
)


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path))
    ctx.__dict__["database"] = engine
    return ctx


def recorded_audit(context: Context) -> tuple[Any, tuple[UUID, ...]]:
    """A recorded audit report whose intake admitted every row, plus a seeded finding the
    same assessment reports without intake ever binding it."""
    services = context.services()
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/example-org/svc-{uuid4().hex[:8]}")
        ref = seed.repository_ref(repo)
        unbound = seed.finding(repo, fingerprint="a" * 64)
        uow.commit()
    raw = json.loads(json.dumps(AUDIT))
    del raw["metadata"]["additional"]  # a legacy, unstamped report: identity is recomputed
    raw["remediation_roadmap"] = [  # recorded canonically, so priorities are the canonical enum
        {**item, "priority": item["priority"].lower()} for item in raw["remediation_roadmap"]
    ]
    rows = [{k: v for k, v in f.items() if k != "fingerprint"} for f in raw["findings"]]
    rows[0]["evidence"] = [{"code": 'q := "SELECT * FROM t WHERE id = " + id', "language": "go"}]
    doc = ReportArtifact.parse(json.dumps({**raw, "findings": rows}).encode())
    audit = services.assessment.record(
        doc, ref.id, AssessmentKind.SECURE_CODE_CANONICAL, "skill:audit", "1", provenance()
    )
    taken = services.findings.intake.accept(
        audit.id, FindingCandidate.of_report(doc.findings, repo.id)
    )
    bound = tuple(taken.findings[Label(row["id"])] for row in rows)
    with SqlTraustUnitOfWork(context.database) as uow:
        Seed(uow).occurrence(unbound, audit)
        uow.commit()
    return rows, (*bound, unbound.id)


def provenance() -> Provenance:
    return Provenance(run_id=uuid4(), source=SourceType.TRIAGE_REPORT, occurred_at=T0)


def test_get_carries_the_prose_of_the_report_row_it_was_recorded_from(
    context: Context,
) -> None:
    rows, (first, second, third, unbound) = recorded_audit(context)
    findings = context.services().findings
    view = findings.get(first)
    assert view.description == rows[0]["description"]
    assert view.remediation == rows[0]["remediation"]
    assert view.evidence == (
        FindingEvidence(code='q := "SELECT * FROM t WHERE id = " + id', language="go"),
    )
    assert sorted(loc.path for loc in view.locations) == ["pkg/db/other.go", "pkg/db/query.go"]
    assert (findings.get(second).description, findings.get(second).remediation) == (
        rows[1]["description"],
        rows[1]["remediation"],
    )
    assert findings.get(third).evidence == ()
    # reported by the same assessment but never bound by its intake: no prose
    assert (findings.get(unbound).description, findings.get(unbound).evidence) == (None, ())


def test_get_leaves_the_prose_empty_without_a_report(context: Context) -> None:
    """An imported finding (no occurrence) and one reported by an assessment holding no
    report carry no prose; the locations a report-less occurrence states still stand."""
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        ref = seed.repository_ref(repo)
        imported = seed.finding(repo)
        placed = seed.finding(repo)
        occurrence = seed.occurrence(placed, seed.assessment(ref))
        seed.location(occurrence, path="pkg/db/query.go")
        uow.commit()
    findings = context.services().findings
    for finding_id in (imported.id, placed.id):
        view = findings.get(finding_id)  # type: ignore[arg-type]
        assert (view.description, view.evidence, view.remediation) == (None, (), None)
    assert [loc.path for loc in findings.get(placed.id).locations] == ["pkg/db/query.go"]  # type: ignore[union-attr]


def test_get_stands_bare_when_the_intake_refuses_the_report(
    context: Context, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Prose is optional: when the intake can no longer bind the report (a retained claim
    identity now conflicting, a row today's fingerprinting refuses), the finding's page
    stands, its prose bare — the doors still refuse the same state."""
    rows, (first, *_) = recorded_audit(context)
    findings = context.services().findings
    assert findings.get(first).description == rows[0]["description"]

    def refused(*args: Any, **kw: Any) -> Any:
        raise ConflictError("a retained claim identity belongs to another finding")

    monkeypatch.setattr(findings.intake, "row_findings", refused)
    with caplog.at_level(logging.ERROR, logger="traust_core.v1.services.findings.service"):
        view = findings.get(first)
    assert (view.description, view.evidence, view.remediation) == (None, (), None)
    # a broken report is told apart from an absent one: the log says which report, at
    # ERROR (the stored report contradicts its admissions), with the traceback (Qodo #554)
    (record,) = [r for r in caplog.records if "cannot be bound" in r.getMessage()]
    assert record.levelno == logging.ERROR and record.exc_info is not None
    (occurrence,) = findings.occurrences(finding_ids=[first])
    assert str(occurrence.assessment_id) in record.getMessage()


def test_get_stands_bare_when_the_reports_object_is_gone(
    context: Context, caplog: pytest.LogCaptureFixture
) -> None:
    """The report's stored object lost (an object store failure) leaves the finding's page
    standing, prose bare: the view's own fields never depended on the report read."""
    rows, (first, *_) = recorded_audit(context)
    findings = context.services().findings
    assert findings.get(first).description == rows[0]["description"]
    shutil.rmtree(context.config.artifacts_path())
    with caplog.at_level(logging.WARNING, logger="traust_core.v1.services.findings.service"):
        view = findings.get(first)
    assert (view.description, view.evidence, view.remediation) == (None, (), None)
    (record,) = [r for r in caplog.records if "cannot be read" in r.getMessage()]
    assert record.levelno == logging.WARNING and record.exc_info is not None


def test_a_later_report_less_occurrence_never_hides_the_prose(context: Context) -> None:
    """An impact analysis re-reporting the finding under no report leaves the prose of the
    report the finding was recorded from standing — the view's own newest-fit rule."""
    rows, (first, *_) = recorded_audit(context)
    findings = context.services().findings
    (occurrence,) = findings.occurrences(finding_ids=[first])
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        audit = uow.assessments.get(occurrence.assessment_id)
        ref = uow.repository_refs.get(audit.repository_ref_id)
        later = seed.assessment(ref, kind="impact", occurred_at=T0 + timedelta(days=1))
        seed.occurrence(uow.findings.get(first), later, severity="high")
        uow.commit()
    view = findings.get(first)
    assert view.occurrence is not None and view.occurrence.assessment_id == later.id
    assert view.description == rows[0]["description"]
    assert view.evidence == (
        FindingEvidence(code='q := "SELECT * FROM t WHERE id = " + id', language="go"),
    )
    assert view.remediation == rows[0]["remediation"]


def report_doc(rows: list[dict[str, Any]]) -> ReportArtifact:
    raw = json.loads(json.dumps(AUDIT))
    del raw["metadata"]["additional"]
    raw["remediation_roadmap"] = [
        {**item, "priority": item["priority"].lower()} for item in raw["remediation_roadmap"]
    ]
    return ReportArtifact.parse(json.dumps({**raw, "findings": rows}).encode())


def test_a_newer_unreadable_report_leaves_the_older_reports_prose(context: Context) -> None:
    """A newer assessment's report that can't be read is skipped, not the end of the
    search: the older report's prose still stands."""
    rows, (first, *_) = recorded_audit(context)
    findings = context.services().findings
    (occurrence,) = findings.occurrences(finding_ids=[first])
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        audit = uow.assessments.get(occurrence.assessment_id)
        ref = uow.repository_refs.get(audit.repository_ref_id)
        later = seed.assessment(ref, occurred_at=T0 + timedelta(days=1))
        seed.artifact(later, kind=ReportArtifact.schema)  # its stored object never existed
        seed.occurrence(uow.findings.get(first), later)
        uow.commit()
    view = findings.get(first)
    assert view.occurrence is not None and view.occurrence.assessment_id == later.id
    assert (view.description, view.remediation) == (rows[0]["description"], rows[0]["remediation"])


def test_a_finding_admitted_from_an_assessments_second_report_carries_its_prose(
    context: Context,
) -> None:
    """Every report artifact the assessment holds is a candidate, not only its first."""
    rows, (first, *_) = recorded_audit(context)
    services = context.services()
    findings = services.findings
    (occurrence,) = findings.occurrences(finding_ids=[first])
    audit = services.assessment.get(occurrence.assessment_id)
    extra = {
        **rows[0],
        "id": "F-EXTRA",
        "title": "Unbounded upload size in the import handler",
        "description": "The import handler reads the whole request body into memory.",
        "remediation": "Cap the request body with http.MaxBytesReader.",
        "locations": [{"path": "pkg/api/import.go", "lines": "12"}],
    }
    second = report_doc([extra])
    published = findings.artifacts.publish_artifact(second)
    with SqlTraustUnitOfWork(context.database) as uow:
        AssessmentLog(uow).attach(
            occurrence.assessment_id, published.artifact_id, sha256_hex(second.payload)
        )
        uow.commit()
    repository_id = findings.get(first).finding.repository_id
    taken = findings.intake.accept(
        audit.id, FindingCandidate.of_report(second.findings, repository_id)
    )
    view = findings.get(taken.findings[Label("F-EXTRA")])
    assert (view.description, view.remediation) == (extra["description"], extra["remediation"])
    assert findings.get(first).description == rows[0]["description"]  # the first still reads


def test_report_less_occurrences_cost_the_prose_read_nothing(context: Context) -> None:
    """Later report-less occurrences (impact analyses, say) are skipped by one batched
    listing, not one assessment-and-artifact read each: the statements a detail read runs
    don't grow with the finding's history."""
    rows, (first, *_) = recorded_audit(context)
    findings = context.services().findings
    (occurrence,) = findings.occurrences(finding_ids=[first])

    def analysed(times: int, start: int) -> None:
        with SqlTraustUnitOfWork(context.database) as uow:
            seed = Seed(uow)
            audit = uow.assessments.get(occurrence.assessment_id)
            ref = uow.repository_refs.get(audit.repository_ref_id)
            for day in range(start, start + times):
                later = seed.assessment(ref, kind="impact", occurred_at=T0 + timedelta(days=day))
                seed.occurrence(uow.findings.get(first), later)
            uow.commit()

    def statements() -> int:
        seen: list[str] = []

        def count(conn: Any, cursor: Any, statement: str, *args: Any) -> None:
            seen.append(statement)

        event.listen(context.database, "before_cursor_execute", count)
        try:
            assert findings.get(first).description == rows[0]["description"]
        finally:
            event.remove(context.database, "before_cursor_execute", count)
        return len(seen)

    analysed(1, 1)
    few = statements()
    analysed(15, 2)
    assert statements() == few


def test_rows_sharing_a_label_each_give_their_own_finding_its_prose(context: Context) -> None:
    """Two rows may share a label while naming different findings: each finding's page and
    fix hint read its own row, never the other's (the per-row binding, Qodo #554)."""
    services = context.services()
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/example-org/svc-{uuid4().hex[:8]}")
        ref = seed.repository_ref(repo)
        uow.commit()
    rows = [{k: v for k, v in f.items() if k != "fingerprint"} for f in AUDIT["findings"]]
    rows[1]["id"] = rows[0]["id"]
    doc = report_doc(rows)
    audit = services.assessment.record(
        doc, ref.id, AssessmentKind.SECURE_CODE_CANONICAL, "skill:audit", "1", provenance()
    )
    services.findings.intake.accept(audit.id, FindingCandidate.of_report(doc.findings, repo.id))
    findings = services.findings
    admitted = [o.finding_id for o in findings.occurrences(assessment_id=audit.id)]
    assert len(admitted) == len(rows)
    by_title = {row["title"]: row for row in rows}
    for finding_id in admitted:
        view = findings.get(finding_id)
        row = by_title[view.finding.title]
        assert (view.description, view.remediation) == (row["description"], row["remediation"])
