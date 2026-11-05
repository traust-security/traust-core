"""Bulk provenance preserves report dates while writing only explicit, idempotent links."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.findings.test_reads import service as finding_service
from tests.v1.services.test_exposure_provenance import (
    SSRF,
    exposure,
    stored,
)
from tests.v1.services.test_exposure_provenance import (
    engine as engine,
)
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.dependencies import AdvisoryMatch
from traust_core.v1.models.findings import Finding
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy
from traust_core.v1.services.findings.records import FindingRecords

TITLE = "Server-Side Request Forgery via unvalidated request URI"


def corpus(engine: Engine) -> tuple[Finding, Finding, Finding]:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = seed.repository(url="https://github.com/example/authlib.git")
        first, second = (seed.finding(repository, title=TITLE) for _ in range(2))
        decoy = seed.finding(repository, title=TITLE + " in a different endpoint")
        for day, name, kind, found in (
            (0, "main", AssessmentKind.SECURE_CODE_CANONICAL, first),
            (5, "release", AssessmentKind.SECURE_CODE, second),
            (17, "same-day", AssessmentKind.SECURE_CODE_CANONICAL, first),
            (20, "after-publication", AssessmentKind.SECURE_CODE_CANONICAL, first),
            (0, "scanner", AssessmentKind.TOOL_SCAN, first),
        ):
            run = seed.assessment(
                seed.repository_ref(repository, name=name),
                kind=kind,
                occurred_at=T0 + timedelta(days=day),
            )
            seed.occurrence(found, run)
            seed.occurrence(decoy, run)
        seed.assessment(
            seed.repository_ref(repository, name="empty"),
            kind=AssessmentKind.SECURE_CODE_CANONICAL,
        )
        uow.commit()
    return first, second, decoy


def test_bulk_dry_run_keeps_branch_dates_and_best_finding_without_writes(engine: Engine) -> None:
    first, second, decoy = corpus(engine)
    before = [stored(engine, found.id) for found in (first, second, decoy)]
    result = exposure(engine).reconcile_all_provenance()

    assert (result.apply, result.cves, result.reports) == (False, 3, 5)
    assert [(r.finding_id, r.identifier, r.audit_date, r.lead_days) for r in result.matches] == [
        (first.id, SSRF, T0.date(), 17),
        (second.id, SSRF, (T0 + timedelta(days=5)).date(), 12),
    ]
    assert len({r.repository_ref_id for r in result.matches}) == 2
    assert {r.component for r in result.matches} == {"authlib"}
    assert (result.distinct_cves, result.distinct_confirmed, result.distinct_probable_only) == (
        1,
        1,
        0,
    )
    assert (result.confirmed_lead_min, result.confirmed_lead_median, result.confirmed_lead_max) == (
        12,
        17,
        17,
    )
    assert (result.links_planned, result.links_written, result.findings_linked) == (2, 0, 0)
    assert [stored(engine, found.id) for found in (first, second, decoy)] == before
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.advisories.find_by_identifier(SSRF) is None
    records = FindingRecords(SqlTraustUnitOfWork(engine))
    assert records.external_refs([first.id, second.id], "cve") == []


def test_apply_links_both_branches_once_without_touching_decisions(engine: Engine) -> None:
    first, second, decoy = corpus(engine)
    service = exposure(engine)
    records = FindingRecords(SqlTraustUnitOfWork(engine))
    before_decisions = records.decisions([first.id, second.id, decoy.id])
    applied = service.reconcile_all_provenance(apply=True)
    assert (applied.links_planned, applied.links_written, applied.findings_linked) == (2, 2, 2)
    saved = [stored(engine, found.id) for found in (first, second, decoy)]
    assert saved[0].advisory_id == saved[1].advisory_id is not None
    assert saved[0].advisory_match == saved[1].advisory_match == "confirmed"
    assert saved[2].advisory_id is None
    refs = records.external_refs([first.id, second.id], "cve")
    assert {(ref.finding_id, ref.ref) for ref in refs} == {
        (first.id, SSRF),
        (second.id, SSRF),
    }
    again = service.reconcile_all_provenance(apply=True)
    assert (again.links_planned, again.links_written, again.findings_linked) == (0, 0, 0)
    assert again.matches == applied.matches
    assert [stored(engine, found.id) for found in (first, second, decoy)] == saved
    assert records.decisions([first.id, second.id, decoy.id]) == before_decisions


def test_each_cve_is_retained_even_when_one_finding_has_multiple_matches(engine: Engine) -> None:
    first, second, _ = corpus(engine)
    payload = json.dumps(
        [
            {
                "CVE": identifier,
                "public_date": "2026-10-22",
                "bugzilla_description": "authlib: " + TITLE,
            }
            for identifier in ("CVE-2026-1000", "CVE-2026-2000")
        ]
    ).encode()
    service = exposure(engine, payload)
    result = service.reconcile_all_provenance(apply=True)
    assert (len(result.matches), result.distinct_cves, result.links_written) == (4, 2, 4)
    records = FindingRecords(SqlTraustUnitOfWork(engine))
    refs = records.external_refs([first.id, second.id], "cve")
    assert {(ref.finding_id, ref.ref) for ref in refs} == {
        (found.id, cve) for found in (first, second) for cve in ("CVE-2026-1000", "CVE-2026-2000")
    }
    assert {a.identifier for a in service.advisories_for(first.id)} == {"CVE-2026-1000"}
    assert service.reconcile_all_provenance(apply=True).links_written == 0


def test_existing_primary_advisory_is_a_conflict_never_overwritten(engine: Engine) -> None:
    first, _, _ = corpus(engine)
    with SqlTraustUnitOfWork(engine) as uow:
        other = Seed(uow).advisory(identifier="CVE-2026-9999")
        original = uow.findings.get(first.id)
        uow.findings.update(
            original.model_copy(update={"advisory_id": other.id, "advisory_match": "probable"})
        )
        uow.commit()
    service = exposure(engine)
    dry = service.reconcile_all_provenance()
    assert [row.conflict for row in dry.matches] == [True, False]
    result = service.reconcile_all_provenance(apply=True)
    assert result.findings_linked == 1
    assert stored(engine, first.id).advisory_id == other.id
    assert stored(engine, first.id).advisory_match == "probable"


@pytest.mark.parametrize(
    "cwe, confidence",
    [("CWE-863", AdvisoryMatch.CONFIRMED), ("CWE-302", AdvisoryMatch.PROBABLE)],
)
def test_threshold_filters_before_cwe_promotion_and_probable_matches_remain_eligible(
    engine: Engine, cwe: str, confidence: AdvisoryMatch
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = seed.repository(url="https://github.com/example/authlib")
        found = seed.finding(
            repository, title="Tenant isolation bypass through admin console routes"
        )
        seed.finding_cwe(found, seed.cwe(identifier=cwe))
        run = seed.assessment(
            seed.repository_ref(repository), kind=AssessmentKind.SECURE_CODE_CANONICAL
        )
        seed.occurrence(found, run)
        uow.commit()
    payload = json.dumps(
        [
            {
                "CVE": "CVE-2026-1000",
                "public_date": "2026-10-22",
                "bugzilla_description": "authlib: Tenant isolation bypass in API",
                "CWE": "CWE-863",
            }
        ]
    ).encode()
    service = exposure(engine, payload)
    [row] = service.reconcile_all_provenance().matches
    assert row.match == confidence and 0.55 <= row.score < 0.75
    filtered = service.reconcile_all_provenance(min_score=0.75, apply=True)
    assert (filtered.matches, filtered.links_written, filtered.findings_linked) == ((), 0, 0)
    assert stored(engine, found.id).advisory_id is None
    result = service.reconcile_all_provenance(min_score=0, apply=True)
    assert (result.links_written, stored(engine, found.id).advisory_match) == (1, confidence.value)
    assert result.distinct_confirmed == int(confidence == AdvisoryMatch.CONFIRMED)
    assert result.distinct_probable_only == int(confidence == AdvisoryMatch.PROBABLE)


@pytest.mark.parametrize("min_score", [-0.01, 1.01, float("nan"), float("inf")])
def test_invalid_threshold_never_applies_links(engine: Engine, min_score: float) -> None:
    first, _, _ = corpus(engine)
    with pytest.raises(ValidationError):
        exposure(engine).reconcile_all_provenance(min_score=min_score, apply=True)
    assert stored(engine, first.id).advisory_id is None


def test_empty_corpus_is_measured_as_empty_not_a_failure(engine: Engine) -> None:
    result = exposure(engine).reconcile_all_provenance()
    assert (result.reports, result.matches, result.links_planned) == (0, (), 0)
    assert (result.confirmed_lead_min, result.confirmed_lead_median, result.confirmed_lead_max) == (
        None,
        None,
        None,
    )


def test_bulk_requires_the_snapshot_even_for_an_empty_corpus(engine: Engine) -> None:
    uow = SqlTraustUnitOfWork(engine)
    service = ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry[FeedProvider]("feed"),
        objects=InMemoryObjectStore(),
        findings=finding_service(engine),
    )
    with pytest.raises(NotFoundError):
        service.reconcile_all_provenance()


def test_a_cve_confirmed_on_one_branch_is_not_counted_again_as_probable_only(
    engine: Engine,
) -> None:
    first, second, _ = corpus(engine)
    with SqlTraustUnitOfWork(engine) as uow:
        for found, title in (
            (first, "Tenant isolation bypass in API"),
            (second, "Tenant isolation bypass through admin console routes"),
        ):
            uow.findings.update(found.model_copy(update={"title": title}))
        uow.commit()
    payload = json.dumps(
        [
            {
                "CVE": "CVE-2026-1000",
                "public_date": "2026-10-22",
                "bugzilla_description": "authlib: Tenant isolation bypass in API",
            }
        ]
    ).encode()
    result = exposure(engine, payload).reconcile_all_provenance(min_score=0.55)
    assert [row.match for row in result.matches] == [
        AdvisoryMatch.CONFIRMED,
        AdvisoryMatch.PROBABLE,
    ]
    assert (result.distinct_cves, result.distinct_confirmed, result.distinct_probable_only) == (
        1,
        1,
        0,
    )
