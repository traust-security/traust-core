"""5 · Ledger at a year's volume: every recorded decision appends, restamps and signs its layer."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from perf.conftest import Clocked
from perf.harness import Explained, Profile, profile
from perf.seed import DECISIONS, HOT_REPOSITORY, TYPICAL_REPOSITORY, UNLEDGERED
from traust_core.v1.models.attestation import AttestationDecision
from traust_core.v1.models.findings import Decision, RecordDecision
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.ledger import Event, Layer
from traust_core.v1.models.vocabulary import ActorKind, ReviewReason
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.attestation import AttestationService, StatementPolicy
from traust_core.v1.services.findings import FindingDecisions, FindingPrecedents
from traust_core.v1.services.findings.rating import RatingConfig, RatingPolicy
from traust_core.v1.services.findings.review import FindingReview, ReviewPolicy
from traust_core.v1.services.findings.views import FindingViewQuery
from traust_core.v1.services.ledger import LedgerConfig, LedgerService
from traust_core.v1.services.lint import Lint

LAYERS = {
    "hot (10k events)": (HOT_REPOSITORY, 1),
    "typical (~24)": (TYPICAL_REPOSITORY, 1 + UNLEDGERED),
}


def unledgered(uow: SqlTraustUnitOfWork, url: str, n: int) -> tuple[Decision, UUID]:
    """Seeded decision n (not in the ledger yet) and the repository whose layer it joins."""
    repo_id = _repo(uow, url)
    fingerprint = f"fp-{DECISIONS + n}"
    finding = uow.findings.find_by_fingerprint(repo_id, "v2", fingerprint)
    assert finding is not None and finding.id is not None
    decision = uow.decisions.find_by_statement(finding.id, f"sk-{fingerprint}")
    assert decision is not None
    return decision, repo_id


def append(uow: SqlTraustUnitOfWork, url: str, n: int) -> None:
    decision, repo_id = unledgered(uow, url, n)
    LedgerService(uow, LedgerConfig()).append_decision(decision, repo_id)


def append_without_restamp(uow: SqlTraustUnitOfWork, url: str, n: int) -> None:
    """The floor: insert the event and nothing else."""
    decision, repo_id = unledgered(uow, url, n)
    layer = uow.layers.find_for_update(repo_id)
    assert layer is not None and layer.id is not None and decision.id is not None
    if uow.events.find_by_decision(decision.id) is None:
        last = uow.events.last_seq(layer.id)
        uow.events.add(
            Event(
                layer_id=layer.id,
                decision_id=decision.id,
                seq=0 if last is None else last + 1,
                event_payload=b"{}",
            )
        )


def fast(e: Explained, index: str, budget_ms: float) -> None:
    assert e.uses_index(index), e.plan
    assert not e.seq_scans(), e.plan
    assert e.execution_ms < budget_ms, e.plan


def test_append_reads_its_layer_by_index(explained: Profile) -> None:
    *_, lock, proved, last, _insert, _update = explained(lambda uow: append(uow, HOT_REPOSITORY, 1))
    fast(lock, "uq_ledger_layers_repository", 1)
    fast(proved, "events_decision_id_key", 1)
    fast(last, "events_layer_id_seq_key", 1)  # and no read of the layer's events


def test_verify_reads_one_layer_by_index(explained: Profile) -> None:
    def verify(uow: SqlTraustUnitOfWork) -> None:
        layer = uow.layers.find_for_update(_repo(uow, HOT_REPOSITORY))
        assert isinstance(layer, Layer) and layer.id is not None
        LedgerService(uow, LedgerConfig()).verify(layer.id)

    *_, events = explained(verify)
    fast(events, "events_layer_id_seq_key", 50)


@pytest.mark.parametrize("layer", LAYERS)
def test_an_append_costs_about_an_insert(clocked: Clocked, layer: str) -> None:
    url, n = LAYERS[layer]
    frontier = clocked(f"{layer}: append (frontier + root)", lambda uow: append(uow, url, n))
    insert = clocked(f"{layer}: insert only", lambda uow: append_without_restamp(uow, url, n))
    assert frontier < insert + 5  # ms: the tree costs microseconds at any size


def _repo(uow: SqlTraustUnitOfWork, url: str) -> UUID:
    repo = uow.repositories.find_by_url(url)
    assert repo is not None and repo.id is not None
    return repo.id


def _layer_id(uow: SqlTraustUnitOfWork, url: str) -> UUID:
    layer = uow.layers.find_for_update(_repo(uow, url))
    assert layer is not None and layer.id is not None
    return layer.id


@pytest.mark.parametrize("after", [None, 9_000], ids=["first page", "a late page"])
def test_an_events_page_reads_by_index_in_seq_order(explained: Profile, after: int | None) -> None:
    *_, page = explained(
        lambda uow: uow.events.page_for_layer(_layer_id(uow, HOT_REPOSITORY), after, 101)
    )
    fast(page, "events_layer_id_seq_key", 5)


def countersign(uow: SqlTraustUnitOfWork, url: str, n: int, outcome: AttestationDecision) -> None:
    original, _repository_id = unledgered(uow, url, n)
    policy = ReviewPolicy()
    decisions = FindingDecisions(
        uow,
        LedgerService(uow, LedgerConfig()),
        Lint({}),
        FindingPrecedents(uow),
        clock=FixedClock(datetime.now(UTC)),
        objects=InMemoryObjectStore(),
        review=policy,
    )
    review = FindingReview(uow, policy, decisions, FindingViewQuery(RatingPolicy(RatingConfig())))
    attestation = AttestationService(uow, decisions, review, {}, StatementPolicy())
    item = attestation.request(original.finding_id, original.id, ReviewReason.ANALYST_REVIEW)
    principal = Principal(
        identity="perf-reviewer@example.com",
        display="Performance reviewer",
        kind=ActorKind.HUMAN,
        verified_by=IdentitySource.OIDC,
    )
    result = attestation.attest(
        item.id,
        principal,
        outcome,
        RecordDecision(
            finding_id=original.finding_id,
            severity="high",
            evidence_grade="E1",
            rationale="An explicit human judgement after reviewing the complete layer.",
        ),
    )
    assert result.resolved_by_decision_id is not None
    assert uow.events.find_by_decision(result.resolved_by_decision_id) is not None


@pytest.mark.parametrize("outcome", list(AttestationDecision))
def test_countersign_verifies_its_existing_layer_once_before_append(
    engine: Engine,
    report: list[tuple[str, Explained]],
    request: pytest.FixtureRequest,
    outcome: AttestationDecision,
) -> None:
    queries = profile(
        engine, lambda uow: countersign(uow, HOT_REPOSITORY, 1, outcome), reads_only=True
    )
    report.extend((request.node.name, query) for query in queries)
    histories = [
        query
        for query in queries
        if "event_payload" in query.sql
        and "ORDER BY" in query.sql
        and "events.layer_id =" in query.sql
        and "events.seq >" not in query.sql
    ]
    assert len(histories) == 1
    fast(histories[0], "events_layer_id_seq_key", 100)


@pytest.mark.parametrize("layer", LAYERS)
@pytest.mark.parametrize("outcome", list(AttestationDecision))
def test_human_countersign_includes_linear_integrity_admission_cost(
    clocked: Clocked, layer: str, outcome: AttestationDecision
) -> None:
    url, n = LAYERS[layer]
    elapsed = clocked(
        f"{layer}: {outcome} (full integrity admission + decision + review + frontier append)",
        lambda uow: countersign(uow, url, n, outcome),
    )
    assert elapsed < 2_000
