"""The rule-mining lane's delta, gate reachability and allowlist re-check, and their markdown.

Ported from traust-engine tests/test_run_rule_mining_lane.py (traust-engine 0b483d7).
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from traust_core.v1.models.detection_quality import (
    RuleCluster,
    RuleId,
    RuleMining,
    RulePack,
    RulePrecision,
    RuleRef,
    TruePositive,
)
from traust_core.v1.models.rule_mining import (
    Allowlist,
    LaneDelta,
    LaneStage,
    LanguageReach,
    PackReach,
    Reachability,
    ReachCrossing,
    ReachDirection,
    StageStatus,
)
from traust_core.v1.services.rule_mining import (
    allowlist_precision,
    lane_delta,
    reach_crossings,
    reachability,
    render_delta,
    render_mining,
)

NOW = datetime(2026, 10, 27, 12, tzinfo=UTC)
PACK = RulePack(name="traust", version="1")


def tp(**kw: object) -> TruePositive:
    values: dict[str, object] = {
        "finding_id": uuid4(),
        "repository_id": uuid4(),
        "repository_ref_id": uuid4(),
        "cwe": "CWE-78",
        "cwes": ("CWE-78",),
        "severity": "high",
        "language": "go",
        "paths": ("a.go",),
        "title": "t",
    }
    return TruePositive.model_validate({**values, **kw})


def cluster(cwe: str, language: str, count: int) -> RuleCluster:
    return RuleCluster(cwe=cwe, language=language, count=count, repositories=2, examples=(uuid4(),))


def prec(rule: str, promoted: int, dismissed: int) -> RulePrecision:
    return RulePrecision(rule=RuleId(rule), promoted=promoted, dismissed=dismissed)


def mining(
    confirmed: int = 100,
    uncovered: tuple[RuleCluster, ...] = (),
    precision: tuple[RulePrecision, ...] = (),
) -> RuleMining:
    return RuleMining(
        pack=PACK,
        corpus=tuple(tp() for _ in range(confirmed)),
        uncovered=uncovered,
        precision=precision,
    )


def test_a_baseline_run_flags_nothing() -> None:
    d = lane_delta(
        None, mining(uncovered=(cluster("CWE-78", "go", 5),), precision=(prec("r1", 1, 9),)), NOW
    )
    assert (d.baseline, d.new_uncovered_clusters, d.precision_gate_crossings) == (True, (), ())
    assert (d.attention.needed, d.tp_corpus.confirmed_tps, d.tp_corpus.growth) == (False, 100, None)


def test_identical_runs_produce_an_empty_delta() -> None:
    doc = mining(uncovered=(cluster("CWE-78", "go", 5),), precision=(prec("r1", 6, 4),))
    d = lane_delta(doc, doc, NOW)
    assert not d.baseline
    assert d.new_uncovered_clusters == d.resolved_uncovered_clusters == ()
    assert d.changed_uncovered_clusters == d.precision_gate_crossings == ()
    assert (d.tp_corpus.growth, d.attention.needed) == (0, False)


def test_new_resolved_and_changed_clusters_need_attention() -> None:
    prev = mining(uncovered=(cluster("CWE-78", "go", 5), cluster("CWE-89", "python", 3)))
    cur = mining(uncovered=(cluster("CWE-78", "go", 8), cluster("CWE-22", "go", 4)))
    d = lane_delta(prev, cur, NOW)
    assert [c.cluster for c in d.new_uncovered_clusters] == ["CWE-22/go"]
    assert [c.cluster for c in d.resolved_uncovered_clusters] == ["CWE-89/python"]
    assert [(c.cluster, c.previous_count, c.count) for c in d.changed_uncovered_clusters] == [
        ("CWE-78/go", 5, 8)
    ]
    reasons = " ".join(d.attention.reasons)
    assert d.attention.needed and "new" in reasons and "grew" in reasons


def test_a_shrunk_cluster_changes_but_needs_no_attention() -> None:
    d = lane_delta(
        mining(uncovered=(cluster("CWE-78", "go", 8),)),
        mining(uncovered=(cluster("CWE-78", "go", 3),)),
        NOW,
    )
    assert d.changed_uncovered_clusters[0].count == 3
    assert not d.attention.needed


def test_precision_gate_crossings_both_directions_and_new() -> None:
    prev = mining(precision=(prec("fell", 6, 4), prec("rose", 2, 8), prec("steady", 9, 1)))
    cur = mining(
        precision=(
            prec("fell", 2, 8),
            prec("rose", 7, 3),
            prec("steady", 9, 1),
            prec("entered", 1, 9),
            prec("unjudged", 0, 0),
        )
    )
    d = lane_delta(prev, cur, NOW)
    assert {x.rule: x.direction for x in d.precision_gate_crossings} == {
        "fell": "fell_below_gate",
        "rose": "rose_above_gate",
        "entered": "entered_below_gate",
    }
    assert d.attention.needed and any("precision gate" in r for r in d.attention.reasons)


def test_tp_corpus_growth_alone_is_not_attention() -> None:
    d = lane_delta(mining(confirmed=100), mining(confirmed=140), NOW)
    assert (d.tp_corpus.growth, d.attention.needed) == (40, False)


def test_the_delta_report_has_every_section() -> None:
    prev = mining(uncovered=(cluster("CWE-89", "python", 3),), precision=(prec("r1", 6, 4),))
    cur = mining(
        confirmed=110, uncovered=(cluster("CWE-22", "go", 4),), precision=(prec("r1", 2, 8),)
    )
    d = lane_delta(prev, cur, NOW).model_copy(
        update={"stages": (LaneStage(stage="mine", status=StageStatus.OK, summary="ok"),)}
    )
    md = render_delta(d)
    for section in (
        "New uncovered clusters",
        "CWE-22/go",
        "Resolved uncovered clusters",
        "fell_below_gate",
        "Stage results",
        "**Attention:** YES",
        "**+10** vs the previous mine",
    ):
        assert section in md


def reach(**langs: int) -> Reachability:
    return Reachability(
        available=True,
        packs={
            "p": PackReach(
                available=True,
                languages={
                    lang: LanguageReach(
                        repos=5, max_span=span, widest_covered_cwe="CWE-295", reachable=span >= 3
                    )
                    for lang, span in langs.items()
                },
            )
        },
    )


@pytest.mark.parametrize(
    ("prev", "cur", "expected"),
    [
        (reach(rust=1), reach(rust=3), [("rust", ReachDirection.OPENED)]),
        (reach(c=3), reach(c=2), [("c", ReachDirection.CLOSED)]),
        # a steady state is silent: a weekly complaint about a known-blocked language is noise
        (reach(cpp=0), reach(cpp=0), []),
        (reach(rust=3), reach(rust=4), []),
        # no prior state is not an opening, else it fires on every fresh install
        (None, reach(rust=3), []),
        (reach(rust=1), Reachability(available=False, reason="none"), []),
        # a pack not fetched must never read as "no ground truth"
        (
            reach(rust=1),
            Reachability(available=True, packs={"p": PackReach(available=False, reason="x")}),
            [],
        ),
    ],
)
def test_reach_crossings(
    prev: Reachability | None, cur: Reachability, expected: list[tuple[str, str]]
) -> None:
    assert [(c.language, c.direction) for c in reach_crossings(prev, cur)] == expected


def test_reachability_counts_repositories_sharing_a_covered_cwe() -> None:
    repos = [uuid4() for _ in range(4)]
    corpus = [
        *(
            tp(repository_id=r, language="rust", cwe="CWE-295", cwes=("CWE-295",))
            for r in repos[:3]
        ),
        tp(repository_id=repos[3], language="rust", cwe="CWE-89", cwes=("CWE-89",)),
        tp(repository_id=repos[0], language="c", cwe="CWE-295", cwes=("CWE-295",)),
        # no commit or no path: not a calibration target
        tp(repository_id=uuid4(), language="rust", cwe="CWE-295", repository_ref_id=None),
        tp(repository_id=uuid4(), language="rust", cwe="CWE-295", paths=()),
    ]
    covering = RulePack(
        name="p", version="1", rules=(RuleRef(id=RuleId("tls"), cwes=("CWE-295",)),)
    )
    got = reachability(corpus, {"p": covering, "uncached": None, "broken": "cache dirty"})
    rust, c = got.packs["p"].languages["rust"], got.packs["p"].languages["c"]
    assert (rust.repos, rust.max_span, rust.widest_covered_cwe, rust.reachable) == (
        4,
        3,
        "CWE-295",
        True,
    )
    assert (c.max_span, c.reachable) == (1, False)
    assert got.packs["p"].languages["cpp"].max_span == 0
    assert got.packs["uncached"] == PackReach(available=False, reason="pack not cached")
    assert got.packs["broken"] == PackReach(available=False, reason="cache dirty")


def test_reachability_without_a_corpus_is_unavailable() -> None:
    assert not reachability([], {"p": None}).available


def test_the_report_shows_reachability_and_a_crossing() -> None:
    d = lane_delta(None, mining(), NOW).model_copy(
        update={
            "reachability": reach(rust=1, cpp=0),
            "reachability_crossings": (
                ReachCrossing(
                    pack="p",
                    language="rust",
                    direction=ReachDirection.OPENED,
                    max_span=3,
                    widest_covered_cwe="CWE-295",
                    repos=12,
                ),
            ),
        }
    )
    body = render_delta(d)
    assert "Stage-A gate reachability" in body and "untestable" in body.lower()
    assert "Gate OPENED: rust vs p" in body


def judged(**precision: float) -> RuleMining:
    # promoted / (promoted + dismissed) == precision, over 10 judgements
    return mining(
        precision=tuple(prec(r, round(p * 10), 10 - round(p * 10)) for r, p in precision.items())
    )


@pytest.mark.parametrize(
    ("precision", "enabled", "below", "unmeasured"),
    [
        (
            {"go-tls-bypass": 0.2, "java-tls-bypass": 0.9},
            ("go-tls-bypass", "java-tls-bypass"),
            ["go-tls-bypass"],
            [],
        ),
        # a rule nobody has judged yet must not read as compliant
        ({"a": 0.9}, ("a", "b"), [], ["b"]),
        ({"a": 0.5}, ("a",), [], []),
    ],
)
def test_allowlisted_rules_are_rechecked_against_the_gate(
    precision: dict[str, float], enabled: tuple[str, ...], below: list[str], unmeasured: list[str]
) -> None:
    got = allowlist_precision(judged(**precision), Allowlist(rules=frozenset(enabled)))
    assert got.available and got.enabled == len(enabled)
    assert ([r.rule for r in got.below_gate], list(got.unmeasured)) == (below, unmeasured)


@pytest.mark.parametrize(
    ("allowlist", "reason"),
    [
        (None, "no rule-pack-allowlist.yaml"),
        (Allowlist(unreadable="no ids"), "allowlist unreadable: no ids"),
    ],
)
def test_a_missing_or_unreadable_allowlist_is_unavailable_not_empty(
    allowlist: Allowlist | None, reason: str
) -> None:
    got = allowlist_precision(mining(), allowlist)
    assert (got.available, got.reason) == (False, reason)


def test_the_report_marks_demotions() -> None:
    d = lane_delta(None, mining(), NOW).model_copy(
        update={
            "allowlist_precision": allowlist_precision(
                judged(**{"go-tls-bypass": 0.1}), Allowlist(rules=frozenset({"go-tls-bypass"}))
            )
        }
    )
    body = render_delta(d)
    assert "**DEMOTE**" in body and "silence is not a pass" in body


def test_the_delta_round_trips_as_the_next_runs_state() -> None:
    d = lane_delta(None, mining(), NOW).model_copy(update={"reachability": reach(rust=2)})
    assert LaneDelta.model_validate_json(d.model_dump_json()) == d


def test_the_mining_report_states_an_empty_corpus() -> None:
    body = render_mining(mining(confirmed=0))
    assert "**0 confirmed true positives**" in body
    assert "all rule-able clusters covered" in body and "empty corpus" in body
    assert "No structured opengrep judge decisions" in body


def test_the_mining_report_lists_backlog_and_precision() -> None:
    example = UUID(int=7)
    body = render_mining(
        RuleMining(
            pack=PACK,
            corpus=(tp(),),
            uncovered=(
                RuleCluster(
                    cwe="CWE-22", language="go", count=4, repositories=2, examples=(example,)
                ),
            ),
            precision=(prec("r1", 1, 3),),
        )
    )
    assert f"| CWE-22 | go | 4 | 2 | {example} |" in body
    assert "| r1 | 1 | 3 | 25% |" in body
