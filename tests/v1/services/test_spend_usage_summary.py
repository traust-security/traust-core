"""SpendService.usage_summary: a spend source's usage summed per day, skill and model, priced at
list rates, as traust-engine's `collect_spend.collect` and `attribute_spend.collect_attributed`
summed transcripts for traust's live spend view and its per-lane attribution."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa

from tests.v1.providers.test_model_catalog import REGISTRY
from tests.v1.providers.test_transcripts import PROJECTS, SKILLS, WORKSPACE
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.operations import (
    ModelUsage,
    SpendSource,
    TokenUsage,
    UsageDimension,
    UsageRollup,
)
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.transcripts import SessionTranscripts
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.operations import SpendService

OCT5 = datetime(2026, 10, 5, tzinfo=UTC)
DAY = timedelta(days=1)
DAY5 = TimeWindow(start=OCT5, end=OCT5 + DAY)
WEEK = TimeWindow(start=OCT5, end=OCT5 + 7 * DAY)
OPUS, HAIKU = "claude-opus-5-5", "claude-haiku-5-5"
D, S, M = UsageDimension.DAY, UsageDimension.SKILL, UsageDimension.MODEL


def spend(tmp_path: Path, priced: bool = True) -> SpendService:
    ctx = Context(Config(home=tmp_path))
    if priced:
        ctx.register_model_catalog(REGISTRY)
    uow = SqlTraustUnitOfWork(sa.create_engine("sqlite://"))
    return SpendService(uow, FixedClock(OCT5), (), ctx.model_catalog)


def transcripts() -> SpendSource:
    return SessionTranscripts(PROJECTS).source(WORKSPACE, SKILLS)


def usage(model: str, tokens_in: int, **kw: Any) -> ModelUsage:
    values: dict[str, Any] = {"tokens_out": 10, "session": "s1", "occurred_at": OCT5}
    return ModelUsage(provider="anthropic", model=model, tokens_in=tokens_in, **{**values, **kw})


def row(rollup: UsageRollup) -> tuple[Any, ...]:
    t = rollup.tokens
    return (
        rollup.day,
        rollup.skill,
        rollup.model,
        (t.tokens_in, t.tokens_out, t.cache_read, t.cache_creation),
        rollup.messages,
        rollup.sessions,
        rollup.cost_usd,
    )


def test_by_day_skill_and_model_each_request_lands_on_the_skill_running_then(
    tmp_path: Path,
) -> None:
    rows = spend(tmp_path).usage_summary(transcripts(), WEEK, (D, S, M))
    oct5, oct6 = date(2026, 10, 5), date(2026, 10, 6)
    assert [row(r) for r in rows] == [
        (oct5, None, OPUS, (150, 15, 0, 0), 2, 2, Decimal("0.0009")),
        (oct5, "secure-code-audit", OPUS, (10, 5, 0, 0), 1, 1, Decimal("0.00014")),
        # cache reads at opus's 0.05 multiplier, writes at 1.25x input
        (oct5, "triage", OPUS, (210, 25, 1000, 50), 2, 2, Decimal("0.00179")),
        (oct5, "validate-findings", OPUS, (70, 11, 0, 0), 2, 1, Decimal("0.0005")),
        (oct6, "secure-code-audit", HAIKU, (300, 30, 0, 0), 1, 1, Decimal("0.000045")),
    ]
    assert all(r.long_prompt is None and r.unpriced == () for r in rows)


def test_by_model_for_one_day_is_the_live_view(tmp_path: Path) -> None:
    [opus] = spend(tmp_path).usage_summary(transcripts(), DAY5, (M,))
    assert row(opus) == (None, None, OPUS, (440, 56, 1000, 50), 7, 2, Decimal("0.00333"))


def test_by_skill_counts_each_session_once_across_days_and_models(tmp_path: Path) -> None:
    rows = spend(tmp_path).usage_summary(transcripts(), WEEK, (S,))
    by_skill = {r.skill: (r.messages, r.sessions, r.cost_usd) for r in rows}
    assert by_skill == {
        None: (2, 2, Decimal("0.0009")),
        "secure-code-audit": (2, 1, Decimal("0.000185")),
        "triage": (2, 2, Decimal("0.00179")),
        "validate-findings": (2, 1, Decimal("0.0005")),
    }


def test_unpriced_models_are_named_never_counted_as_zero(tmp_path: Path) -> None:
    source = SpendSource(
        name="s",
        usages=(
            usage(HAIKU, 1000, skill="triage"),
            usage("claude-unpriced", 1000, skill="triage"),
            usage("not-in-the-registry", 1000, skill="triage"),
            usage("claude-unpriced", 1000),
        ),
    )
    unattributed, triage = spend(tmp_path).usage_summary(source, DAY5, (S,))
    assert (triage.cost_usd, triage.unpriced) == (
        Decimal("0.000105"),
        ("claude-unpriced", "not-in-the-registry"),
    )
    assert (unattributed.cost_usd, unattributed.unpriced) == (None, ("claude-unpriced",))


def test_requests_over_the_long_prompt_threshold_are_kept_apart_and_priced_long(
    tmp_path: Path,
) -> None:
    # haiku bills a prompt over 100,000 tokens (input, cache reads and writes) at its long rates
    long = usage(HAIKU, 90_000, cache_read=10_001, tokens_out=100)
    at_threshold = usage(HAIKU, 90_000, cache_read=10_000, tokens_out=100)
    [rollup] = spend(tmp_path).usage_summary(
        SpendSource(name="s", usages=(long, at_threshold)), DAY5, (M,)
    )
    assert rollup.long_prompt == TokenUsage(tokens_in=90_000, tokens_out=100, cache_read=10_001)
    # long: 90,000 x $0.5 + 100 x $2.5 + 10,001 x $0.5 x 0.1; at the threshold: base rates
    assert rollup.cost_usd == Decimal("0.04575005") + Decimal("0.00915")


def test_the_window_end_is_exclusive_and_todays_partial_day_counts(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    source = SpendSource(
        name="s",
        usages=(usage(HAIKU, 1, occurred_at=now), usage(HAIKU, 2, occurred_at=OCT5 + DAY)),
    )
    today = TimeWindow(start=now - timedelta(minutes=1), end=now + timedelta(minutes=1))
    assert [r.tokens.tokens_in for r in spend(tmp_path).usage_summary(source, today, (D,))] == [1]
    assert spend(tmp_path).usage_summary(source, DAY5, (D,)) == []


def test_without_a_model_registry_nothing_is_summarised(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"summarise s: pricing needs the model registry"):
        spend(tmp_path, priced=False).usage_summary(SpendSource(name="s"), DAY5, (M,))


def test_ctx_spend_views_never_opens_the_record_store(tmp_path: Path) -> None:
    home = tmp_path / "home"
    ctx = Context(Config(home=home))
    ctx.register_model_catalog(REGISTRY)
    rows = ctx.spend_views.usage_summary(transcripts(), WEEK, (D, S, M))
    assert "database" not in ctx.__dict__
    assert not home.exists()
    assert [row(r) for r in rows] == [
        row(r) for r in spend(tmp_path).usage_summary(transcripts(), WEEK, (D, S, M))
    ]


def test_registering_the_model_catalog_rebuilds_ctx_spend_views(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path / "home"))
    with pytest.raises(ConfigError, match="model registry"):
        ctx.spend_views.usage_summary(SpendSource(name="s"), DAY5, (M,))
    ctx.register_model_catalog(REGISTRY)
    assert ctx.spend_views.usage_summary(SpendSource(name="s"), DAY5, (M,)) == []
