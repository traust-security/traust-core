"""The family read doors at a year's volume — remediation work items, a repository's
verifications, PQC readiness and sites, the spend summary, the onboarding plan — in the
statement-bound style of test_insights: a scope read is a bounded batch of round trips,
never one per repository."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from time import perf_counter
from uuid import UUID

from perf.harness import _issued
from perf.seed import REPOSITORIES
from traust_core.v1.context import Context
from traust_core.v1.models.common import PageRequest, TimeWindow
from traust_core.v1.models.onboarding import OnboardingRequest, RepositorySpec
from traust_core.v1.models.operations import SpendDimension, SpendFilter
from traust_core.v1.models.pqc import PqcFilter
from traust_core.v1.models.remediation import VerificationFilter
from traust_core.v1.models.values import HttpsRepoUrl, ProductSlug

NOW = datetime.now(UTC)
MONTH = TimeWindow.month_of(NOW)
SPECS = 25  # a batch of onboarding specs: the plan's reads scale with the batch, not the fleet


def scoped(context: Context, call: Callable[[], object]) -> tuple[list, float]:
    with _issued(context.database) as statements:
        start = perf_counter()
        call()
    return statements, (perf_counter() - start) * 1000


def test_remediation_work_items_read_the_whole_scope_in_bounded_batches(
    context: Context, repository_ids: list[UUID]
) -> None:
    statements, _ = scoped(
        context, lambda: context.services().remediation.items_of_all(repository_ids)
    )
    assert len(statements) < REPOSITORIES, [sql for sql, _ in statements[:3]]


def test_a_repositorys_verifications_read_in_bounded_round_trips(
    context: Context, hot_repository: UUID
) -> None:
    statements, _ = scoped(
        context,
        lambda: context.services().verification.list(
            VerificationFilter(repository_id=hot_repository), PageRequest()
        ),
    )
    assert len(statements) <= 30, [sql for sql, _ in statements[:3]]


def test_pqc_readiness_and_sites_read_the_whole_scope_in_bounded_batches(context: Context) -> None:
    for call in (
        lambda: context.services().pqc.list_readiness(PqcFilter()),
        lambda: context.services().pqc.sites(PqcFilter()),
    ):
        statements, _ = scoped(context, call)
        assert len(statements) < REPOSITORIES, [sql for sql, _ in statements[:3]]


def test_the_spend_summary_reads_its_window_in_one_statement(context: Context) -> None:
    # the plan (its index, no spend-side scan) is gated in test_ops; here the door itself
    statements, _ = scoped(
        context,
        lambda: context.services().spend.summary(
            SpendFilter(window=MONTH), SpendDimension.REPOSITORY
        ),
    )
    assert len(statements) == 1, [sql for sql, _ in statements[:3]]


def test_an_onboarding_plan_reads_each_spec_in_bounded_round_trips(context: Context) -> None:
    request = OnboardingRequest(
        product=ProductSlug("product-1"),
        repositories=tuple(
            RepositorySpec(url=HttpsRepoUrl("forge.example", f"org/r{g}"))
            for g in range(2, SPECS + 2)
        ),
    )
    statements, _ = scoped(context, lambda: context.services().onboarding.plan(request))
    # each spec's lookups are bounded; a scan per spec (or per fleet repository) crosses this
    assert len(statements) <= 4 * SPECS + 20, [sql for sql, _ in statements[:3]]
