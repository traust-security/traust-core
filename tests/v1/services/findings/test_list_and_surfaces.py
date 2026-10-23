"""FindingService.list, the details on a view, and review-surface coverage, on SQLite and Postgres
(the merge rule from traust fabdb13, harnessing/3-audit/secure-code-audit/review-surfaces.md)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.findings.test_reads import ALICE, NOW, T0
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.common import CodeSpan, PageRequest, RepoPath
from traust_core.v1.models.findings import (
    CweId,
    FindingCandidate,
    FindingFilter,
    Label,
    RecordDecision,
)
from traust_core.v1.models.inventory import Repository, RepositoryRef
from traust_core.v1.models.vocabulary import (
    FindingOrigin,
    ReviewItemStatus,
    ReviewReason,
    ScannerSeverity,
)
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore, ObjectKey
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
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
from traust_core.v1.services.lint import Lint

SURFACES = (
    "credential-acceptance",
    "ownership-resolution",
    "security-flags",
    "outbound-fetch",
    "stored-content-integrity",
    "scope-enforcement",
)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@dataclass
class Repo:
    engine: Engine
    objects: InMemoryObjectStore
    repository: Repository
    ref: RepositoryRef

    def service(self) -> FindingService:
        uow = SqlTraustUnitOfWork(self.engine)
        precedents = FindingPrecedents(uow)
        decisions = FindingDecisions(
            uow,
            None,
            Lint({}),
            precedents,
            clock=FixedClock(NOW),
            objects=self.objects,
            review=ReviewPolicy(),
        )
        views = FindingViewQuery(RatingPolicy(RatingConfig()))
        return FindingService(
            uow,
            FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
            decisions,
            FindingReview(uow, ReviewPolicy(), decisions, views),
            precedents,
            views,
            self.objects,
        )

    @property
    def id(self) -> UUID:
        assert self.repository.id is not None
        return self.repository.id

    def report(
        self,
        kind: str,
        doc_kind: str,
        day: int,
        entries: dict[str, tuple[str, str]],
        coverage: dict[str, dict[str, Any]],
        accept: bool = True,
        severity: ScannerSeverity = ScannerSeverity.HIGH,
    ) -> dict[str, UUID]:
        """An assessment on `day` whose artifact names `entries` (label → path, CWE) and records
        `coverage`; its findings are accepted through intake so they have real fingerprints."""
        with SqlTraustUnitOfWork(self.engine) as uow:
            run = Seed(uow).assessment(self.ref, kind=kind, occurred_at=T0 + timedelta(days=day))
            uow.commit()
        assert run.id is not None
        found: dict[str, UUID] = {}
        if accept and entries:
            taken = self.service().intake.accept(
                run.id,
                [
                    FindingCandidate(
                        label=Label(label),
                        repository_id=self.id,
                        title=f"{label} title",
                        cwes=(CweId(cwe),),
                        category="injection",  # type: ignore[arg-type]
                        locations=(CodeSpan(path=RepoPath(path), line=3),),
                        reported_severity=severity,
                        origin=FindingOrigin.VULN_SCAN,
                    )
                    for label, (path, cwe) in entries.items()
                ],
            )
            found = dict(taken.findings)
        body = {
            "findings": [
                {"id": label, "cwes": [cwe], "locations": [{"path": path}]}
                for label, (path, cwe) in entries.items()
            ],
            "review_surface_coverage": coverage,
        }
        ref = self.objects.put(ObjectKey.parse(f"reports/{run.id}.json"), json.dumps(body).encode())
        with SqlTraustUnitOfWork(self.engine) as uow:
            Seed(uow).artifact(run, kind=doc_kind, digest=ref.sha256, uri=str(ref.key))
            uow.commit()
        return found


@pytest.fixture
def repo(engine: Engine) -> Repo:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = seed.repository(url="https://github.com/example/operator")
        ref = seed.repository_ref(repository)
        uow.commit()
    return Repo(engine, InMemoryObjectStore(), repository, ref)


def finding(ids: str) -> dict[str, Any]:
    return {"status": "finding", "finding_ids": ids.split()}


NEG, NA, OOS = (
    {"status": "negative"},
    {"status": "not_applicable", "note": "no store"},
    {
        "status": "out_of_scope",
        "note": "diff",
    },
)


def audited(repo: Repo) -> dict[str, UUID]:
    return repo.report(
        "secure_code",
        "report",
        0,
        {"APP-1": ("a.go", "CWE-89"), "APP-2": ("b.go", "CWE-79")},
        {
            "credential-acceptance": finding("APP-1"),
            "ownership-resolution": NEG,
            "security-flags": finding("APP-2"),
            "outbound-fetch": {"status": "not_assessed", "note": "scoped"},
            "stored-content-integrity": NA,
            "scope-enforcement": NEG,
        },
    )


def statuses(merged: dict[str, Any]) -> dict[str, str]:
    return {s: merged[s].status for s in SURFACES}


# list and view details
def test_views_carry_locations_cwes_and_labels(repo: Repo) -> None:
    ids = audited(repo)
    (view,) = [v for v in repo.service().baseline(repo.id, NOW) if v.finding.id == ids["APP-1"]]
    assert [(loc.path, loc.line_start) for loc in view.locations] == [("a.go", 3)]
    assert view.cwes == ("CWE-89",)
    assert view.label("category") == "injection"


def test_list_narrows_by_validity_and_openness_newest_first(repo: Repo) -> None:
    ids = audited(repo)
    findings = repo.service()
    findings.decisions.decide(said_on(ids["APP-2"], validity="false_positive"), ALICE)
    page = findings.list(FindingFilter(repository_id=repo.id), PageRequest())
    assert {v.finding.id for v in page.items} == set(ids.values())
    fps = findings.list(
        FindingFilter(repository_id=repo.id, validity="false_positive"), PageRequest()
    )
    assert [v.finding.id for v in fps.items] == [ids["APP-2"]]
    still = findings.list(FindingFilter(repository_id=repo.id, open=True), PageRequest())
    assert [v.finding.id for v in still.items] == [ids["APP-1"]]


def test_list_pages_with_a_cursor(repo: Repo) -> None:
    ids = audited(repo)
    findings = repo.service()
    first = findings.list(FindingFilter(repository_id=repo.id), PageRequest(limit=1))
    assert first.next is not None
    second = findings.list(
        FindingFilter(repository_id=repo.id), PageRequest(limit=1, cursor=first.next)
    )
    assert second.next is None
    assert {first.items[0].finding.id, second.items[0].finding.id} == set(ids.values())


def test_list_needs_a_positive_limit(repo: Repo) -> None:
    with pytest.raises(ValidationError):
        repo.service().list(FindingFilter(repository_id=repo.id), PageRequest(limit=0))


def said_on(finding_id: UUID, **kw: Any) -> RecordDecision:
    return RecordDecision(
        finding_id=finding_id,
        rationale="checked the webhook by hand today",
        occurred_at=T0 + timedelta(days=3),
        **kw,
    )


# review surfaces
def test_without_an_audit_there_is_no_coverage(repo: Repo) -> None:
    assert repo.service().review_surfaces(repo.id) == {}


def test_the_audit_alone_is_its_own_coverage(repo: Repo) -> None:
    ids = audited(repo)
    merged = repo.service().review_surfaces(repo.id)
    assert statuses(merged)["credential-acceptance"] == "finding"
    assert merged["credential-acceptance"].finding_ids == (ids["APP-1"],)
    assert merged["outbound-fetch"].notes == ("scoped",)


def test_later_scans_merge_by_the_rule(repo: Repo) -> None:
    ids = audited(repo)
    findings = repo.service()
    findings.decisions.decide(said_on(ids["APP-2"], validity="false_positive"), ALICE)
    vs = repo.report(
        "vuln_scan",
        "vuln-findings",
        5,
        {"VS-1": ("c.go", "CWE-22")},
        {
            "credential-acceptance": NEG,  # APP-1 still open: stays a finding
            "ownership-resolution": OOS,  # a scan's out_of_scope changes nothing
            "security-flags": {"status": "negative", "note": "re-checked flags"},  # APP-2 closed
            "outbound-fetch": finding("VS-1"),  # replaces not_assessed
            "stored-content-integrity": {"status": "negative", "note": "no store found"},
            "scope-enforcement": finding("VS-1"),
        },
    )
    merged = repo.service().review_surfaces(repo.id)
    assert statuses(merged) == {
        "credential-acceptance": "finding",
        "ownership-resolution": "negative",
        "security-flags": "negative",
        "outbound-fetch": "finding",
        "stored-content-integrity": "negative",
        "scope-enforcement": "finding",
    }
    assert merged["security-flags"].notes == ("re-checked flags",)
    assert merged["outbound-fetch"].finding_ids == (vs["VS-1"],)


def test_a_finding_adds_to_a_finding(repo: Repo) -> None:
    ids = audited(repo)
    vs = repo.report(
        "vuln_scan",
        "vuln-findings",
        5,
        {"VS-1": ("c.go", "CWE-22")},
        {"credential-acceptance": finding("VS-1")},
    )
    merged = repo.service().review_surfaces(repo.id)
    assert merged["credential-acceptance"].finding_ids == (ids["APP-1"], vs["VS-1"])


def test_scans_before_the_audit_and_after_as_of_dont_count(repo: Repo) -> None:
    repo.report("vuln_scan", "vuln-findings", -3, {}, {"scope-enforcement": finding("OLD-1")})
    audited(repo)
    repo.report("vuln_scan", "vuln-findings", 9, {}, {"ownership-resolution": finding("NEW-1")})
    merged = repo.service().review_surfaces(repo.id, as_of=T0 + timedelta(days=5))
    assert statuses(merged)["scope-enforcement"] == "negative"
    assert statuses(merged)["ownership-resolution"] == "negative"


def test_an_unmatched_label_counts_as_open(repo: Repo) -> None:
    repo.report(
        "secure_code",
        "report",
        0,
        {"APP-9": ("z.go", "CWE-89")},
        {"credential-acceptance": finding("APP-9")},
        accept=False,
    )
    repo.report("vuln_scan", "vuln-findings", 5, {}, {"credential-acceptance": NEG})
    merged = repo.service().review_surfaces(repo.id)
    assert merged["credential-acceptance"].status == "finding"
    assert (
        merged["credential-acceptance"].labels,
        merged["credential-acceptance"].finding_ids,
    ) == (
        ("APP-9",),
        (),
    )


def test_the_latest_audit_is_the_base(repo: Repo) -> None:
    audited(repo)
    repo.report("secure_code", "report", 7, {}, {"credential-acceptance": NEG})
    merged = repo.service().review_surfaces(repo.id)
    assert {s: c.status for s, c in merged.items()} == {"credential-acceptance": "negative"}


def test_list_keeps_an_unreported_finding_open_without_a_rating(repo: Repo) -> None:
    with SqlTraustUnitOfWork(repo.engine) as uow:
        unreported = Seed(uow).finding(repo.repository)
        uow.commit()
    (view,) = (
        repo.service().list(FindingFilter(repository_id=repo.id, open=True), PageRequest()).items
    )
    assert view.finding == unreported
    assert view.occurrence is None and view.effective_severity is None and view.sla_due is None
    assert view.locations == () and view.cwes == () and view.labels == ()


def test_list_preserves_unrated_reports_until_a_human_rates_them(repo: Repo) -> None:
    ids = repo.report(
        "secure_code",
        "report",
        0,
        {"APP-1": ("a.go", "CWE-89")},
        {"credential-acceptance": finding("APP-1")},
        severity=ScannerSeverity.UNRATED,
    )
    findings = repo.service()
    (unrated,) = findings.list(FindingFilter(repository_id=repo.id), PageRequest()).items
    assert unrated.occurrence is not None and unrated.occurrence.severity == "unrated"
    assert unrated.effective_severity is None and unrated.sla_due is None
    findings.decisions.decide(said_on(ids["APP-1"], severity="high"), ALICE)
    (rated,) = findings.list(FindingFilter(repository_id=repo.id), PageRequest()).items
    assert rated.effective_severity == "high" and rated.sla_due == T0 + timedelta(days=60)


def test_surfaces_keep_execution_proof_open_until_two_independent_review_answers(
    repo: Repo,
) -> None:
    ids = audited(repo)
    with SqlTraustUnitOfWork(repo.engine) as uow:
        seed = Seed(uow)
        assessment = seed.assessment(
            repo.ref, kind="validation", occurred_at=T0 + timedelta(days=1)
        )
        proof = seed.decision(
            uow.findings.get(ids["APP-1"]),
            assessment_id=assessment.id,
            actor=None,
            validity="confirmed",
            evidence_grade="E0",
            occurred_at=T0 + timedelta(days=1),
        )
        uow.commit()
    repo.report("vuln_scan", "vuln-findings", 5, {}, {"credential-acceptance": NEG})
    findings = repo.service()
    first = findings.review.request_signoff(
        ids["APP-1"], ReviewReason.FALSE_POSITIVE_DISPUTE, decision_id=proof.id
    )
    assert first.id is not None
    findings.review.resolve(
        first.id,
        said_on(ids["APP-1"], validity="false_positive", evidence_grade="E0"),
        ALICE,
    )
    assert findings.review.get(first.id).status == "accepted"
    assert findings.review_surfaces(repo.id)["credential-acceptance"].status == "finding"
    assert ids["APP-1"] in {
        view.finding.id
        for view in findings.list(
            FindingFilter(repository_id=repo.id, open=True), PageRequest()
        ).items
    }
    second = findings.review.request_signoff(
        ids["APP-1"], ReviewReason.FALSE_POSITIVE_DISPUTE, decision_id=proof.id
    )
    assert second.id is not None
    findings.review.resolve(
        second.id,
        said_on(ids["APP-1"], validity="false_positive", evidence_grade="E0"),
        ALICE.model_copy(update={"identity": "bob@example.com"}),
        status=ReviewItemStatus.REJECTED,
    )
    assert findings.review_surfaces(repo.id)["credential-acceptance"].status == "negative"
    assert ids["APP-1"] not in {
        view.finding.id
        for view in findings.list(
            FindingFilter(repository_id=repo.id, open=True), PageRequest()
        ).items
    }
