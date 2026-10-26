"""The audit valve: a salted, deterministic 1-in-10 sample of auto-accepted false positives."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from traust_core.v1.models.findings import Decision
from traust_core.v1.services.findings.review import ReviewPolicy

KEYS = [f"statement-{i}" for i in range(1000)]


def auto_fp(key: str, **kw: object) -> Decision:
    values: dict[str, object] = {
        "finding_id": UUID(int=1),
        "statement_key": key,
        "validity": "false_positive",
        "auto_accept_tier": True,
        "occurred_at": datetime(2026, 10, 23, tzinfo=UTC),
    }
    return Decision(**{**values, **kw})  # type: ignore[arg-type]


def sampled(policy: ReviewPolicy) -> set[str]:
    return {k for k in KEYS if policy.needs_signoff(auto_fp(k)) is not None}


def test_a_salted_valve_samples_about_one_in_ten_and_the_same_keys_every_time() -> None:
    first = sampled(ReviewPolicy("s3cret"))
    assert len(first) == 108
    assert sampled(ReviewPolicy("s3cret")) == first


def test_the_salt_decides_which_keys_are_sampled() -> None:
    assert sampled(ReviewPolicy("other")) != sampled(ReviewPolicy("s3cret"))


def test_without_a_salt_every_auto_accepted_false_positive_is_audited() -> None:
    assert len(sampled(ReviewPolicy())) == len(KEYS)


def test_unsampled_machine_refutations_still_need_an_analyst() -> None:
    policy = ReviewPolicy()
    assert policy.needs_signoff(auto_fp("k", auto_accept_tier=False)) == "analyst_review"
    assert policy.needs_signoff(auto_fp("k", validity="confirmed")) is None
    assert policy.needs_signoff(auto_fp("k", actor="human:reviewer")) is None
