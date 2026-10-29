from datetime import timedelta
from uuid import uuid4

from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

from .conftest import T0, Seed, same_rows


def test_bulk_anchor_reads_keep_locations_and_schemes_separate(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    first, second, absent = seed.location(), seed.location(), seed.location()
    a = seed.location_hash(first)
    b = seed.location_hash(first, algorithm="function-bytes-sha256/v1")
    seed.location_hash(second)
    assert same_rows(uow.location_hashes.list_for_locations([first.id, absent.id]), [a, b])
    assert uow.location_hashes.list_for_locations([]) == []


def test_symbol_pages_preserve_tied_symbols_and_locations_without_anchors(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    locations = [seed.location(symbol="Parse") for _ in range(7)]
    locations += [seed.location(symbol="Render") for _ in range(4)]
    seed.location(symbol=None)
    seed.location(symbol="Other")
    seed.location_hash(locations[0])
    found = []
    after = None
    while page := uow.locations.list_with_symbols_page(["Parse", "Render"], 3, after):
        assert len(page) <= 3
        found.extend(page)
        after = (page[-1].symbol, page[-1].id)
    assert found == sorted(locations, key=lambda loc: (loc.symbol, loc.id))


def test_binding_and_eligibility_lookups_preserve_membership_and_history_order(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    assessment = seed.assessment()
    first, second = seed.finding(), seed.finding()
    early = seed.decision(first, occurred_at=T0)
    late = seed.decision(second, occurred_at=T0 + timedelta(days=1))
    first_link = seed.finding_cwe(first)
    second_link = seed.finding_cwe(second)
    unknown = [uuid4() for _ in range(1000)]
    assert uow.assessments.list_by_ids([assessment.id, *unknown]) == [assessment]
    findings = [second.id, *unknown, first.id]
    assert uow.decisions.list_for_findings(findings) == [early, late]
    assert uow.decisions.list_for_findings(findings, until=T0) == [early]
    assert same_rows(uow.finding_cwes.list_for_findings(findings), [first_link, second_link])


def test_repeated_lookup_ids_do_not_duplicate_rows_across_batches(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    assessment = seed.assessment()
    finding = seed.finding()
    decision = seed.decision(finding)
    link = seed.finding_cwe(finding)
    location = seed.location()
    claim = seed.location_hash(location)
    assert uow.assessments.list_by_ids([assessment.id] * 1001) == [assessment]
    assert uow.decisions.list_for_findings([finding.id] * 1001) == [decision]
    assert uow.finding_cwes.list_for_findings([finding.id] * 1001) == [link]
    assert uow.location_hashes.list_for_locations([location.id] * 1001) == [claim]
