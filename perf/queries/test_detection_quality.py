"""Detection quality at a year's volume: the weekly rule-mining lane's two whole-ledger reads.

Mining reads every judged finding and every rule hit by design (the corpus is the ledger), so these
are one bounded scan each, not per-tick lookups; the budget pins that they stay a single statement.
"""

from __future__ import annotations

from perf.harness import Profile
from traust_core.v1.models.vocabulary import Validity


def test_findings_judged_a_validity_is_one_statement(explained: Profile) -> None:
    (statement,) = explained(
        lambda uow: uow.decisions.list_finding_ids_with_validity(Validity.FALSE_POSITIVE)
    )
    assert statement.execution_ms < 1_000, statement.plan


def test_confirmed_with_its_historical_spellings_is_one_statement(explained: Profile) -> None:
    (statement,) = explained(
        lambda uow: uow.decisions.list_finding_ids_with_validity(Validity.CONFIRMED)
    )
    assert statement.execution_ms < 1_000, statement.plan


def test_rule_hits_are_one_statement(explained: Profile) -> None:
    (statement,) = explained(lambda uow: uow.occurrences.list_with_rule())
    assert statement.execution_ms < 1_000, statement.plan
