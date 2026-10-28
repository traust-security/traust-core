"""Sweep classification and clustering, ported from traust-engine tests/test_sweep_engine.py
(traust-engine 0b483d7)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from traust_core.v1.models.rule_mining import (
    Attention,
    LaneDelta,
    LaneStage,
    RuleLane,
    StageStatus,
    SweepCollection,
    SweepDraft,
    SweepFinding,
    TpCorpus,
    expressible,
    repo_slug,
)

NOW = datetime(2026, 10, 27, tzinfo=UTC)


@pytest.mark.parametrize(
    ("cwe", "file", "language", "ok", "reason"),
    [
        ("CWE-78", "a.go", "go", True, "syntactic"),
        ("CWE-532", "log.yaml", "yaml", True, "syntactic"),
        ("cwe-798", "a.py", "python", True, "syntactic"),
        ("CWE-306", "a.go", "go", False, "semantic_logic_class"),
        ("CWE-1395", "go.mod", "unknown", False, "dependency_version_class"),
        ("CWE-78", "a.tf", "unknown", False, "language_not_ruleable"),
        (None, "a.go", "go", False, "no_cwe"),
        ("not a cwe", "a.go", "go", False, "no_cwe"),
        ("CWE-78", None, "go", False, "no_location_anchor"),
        ("CWE-78", "", "go", False, "no_location_anchor"),
    ],
)
def test_expressible(
    cwe: str | None, file: str | None, language: str, ok: bool, reason: str
) -> None:
    got, why = expressible(cwe, file, language)
    assert got is ok and why.startswith(reason)


@pytest.mark.parametrize(
    ("url", "slug"),
    [
        ("https://github.com/org/repo-a", "repo-a"),
        ("https://github.com/org/repo-a.git", "repo-a"),
        ("https://github.com/org/repo-a/", "repo-a"),
        (None, "unknown"),
    ],
)
def test_repo_slug(url: str | None, slug: str) -> None:
    assert repo_slug(url) == slug


def found(
    title: str, cwe: str | None, file: str | None, url: str = "https://x/org/repoa", **kw: str
) -> SweepFinding:
    return SweepFinding.of(
        artifact="ref",
        url=url,
        finding_id=kw.get("finding_id", title),
        title=title,
        cwe=cwe,
        severity=kw.get("severity", "high"),
        file=file,
        kind=kw.get("kind"),  # type: ignore[arg-type]
    )


def test_a_finding_records_its_class_and_why() -> None:
    f = found("cmd injection", "cwe-78", "pkg/run.go")
    assert (f.repo, f.cwe, f.language, f.rule_expressible, f.source) == (
        "repoa",
        "CWE-78",
        "go",
        True,
        "ledger",
    )
    assert found("x" * 200, None, None).title == "x" * 160


def test_collection_dedups_classifies_and_clusters_largest_first() -> None:
    collection = SweepCollection.of(
        [
            found("cmd injection via sh -c", "CWE-78", "pkg/run.go"),
            found("cmd injection via sh -c (again)", "CWE-78", "pkg/run.go"),
            found("CMD INJECTION VIA SH -C", "CWE-78", "pkg/run.go"),  # same repo, file, cwe, title
            found("cmd injection", "CWE-78", "cmd/x.go", url="https://x/org/repob"),
            found("secret logged", "CWE-532", "collector/filter.py"),
            found("no authn", "CWE-306", "pkg/srv.go"),
            found("vulnerable pin", "CWE-1395", "go.mod"),
        ],
        NOW,
        "1.0",
    )
    assert collection.stats.model_dump() == {
        "confirmed_findings": 6,
        "by_source": {"ledger": 6},
        "rule_expressible": 4,
        "not_expressible": 2,
        "classes": 2,
    }
    assert [(c.class_id, c.count, c.repos) for c in collection.classes] == [
        ("CWE-78/go", 3, ("repoa", "repob")),
        ("CWE-532/python", 1, ("repoa",)),
    ]
    members = [collection.findings[i].file for i in collection.classes[0].member_indexes]
    assert members == ["pkg/run.go", "pkg/run.go", "cmd/x.go"]
    reasons = {f.reason.split(":")[0] for f in collection.findings if not f.rule_expressible}
    assert reasons == {"semantic_logic_class", "dependency_version_class"}


def test_an_empty_corpus_collects_nothing() -> None:
    collection = SweepCollection.of([], NOW, "1.0")
    assert (collection.stats.confirmed_findings, collection.classes) == (0, ())


@pytest.mark.parametrize(
    ("severity", "rule_severity"), [("critical", "ERROR"), ("medium", "WARNING")]
)
def test_a_draft_names_its_rule_and_cites_its_sources(severity: str, rule_severity: str) -> None:
    members = [found(f"t{i}", "CWE-798", f"f{i}.go", severity=severity) for i in range(10)]
    collection = SweepCollection.of(members, NOW, "1.0")
    draft = SweepDraft.of(collection.classes[0], list(collection.findings))
    assert (draft.slug, draft.rule_id, draft.severity) == (
        "sweep-go-cwe-798",
        "traust-go-sweep-cwe-798",
        rule_severity,
    )
    assert len(draft.sources) == 8 and draft.sources[0].artifact == "ledger:ref"


def stage(status: StageStatus) -> LaneStage:
    return LaneStage(stage="s", status=status)


def delta(attention: bool) -> LaneDelta:
    return LaneDelta(
        generated_at=NOW,
        baseline=False,
        tp_corpus=TpCorpus(),
        attention=Attention(needed=attention),
    )


@pytest.mark.parametrize(
    ("stages", "lane_delta", "code"),
    [
        ((stage(StageStatus.OK),), delta(False), 0),
        ((stage(StageStatus.SKIPPED),), delta(False), 0),
        ((stage(StageStatus.OK),), delta(True), 1),
        ((stage(StageStatus.FAILED),), delta(True), 2),
        ((stage(StageStatus.FAILED),), None, 2),
    ],
)
def test_the_lane_exits_quiet_attention_or_failed(
    stages: tuple[LaneStage, ...], lane_delta: LaneDelta | None, code: int
) -> None:
    assert RuleLane(stages=stages, delta=lane_delta).exit_code == code


def test_weaknesses_are_mined_as_their_own_classes() -> None:
    collection = SweepCollection.of(
        [
            found("cmd injection", "CWE-78", "pkg/run.go", kind="vulnerability"),
            found("cmd injection 2", "CWE-78", "pkg/x.go"),
            found("token logged", "CWE-532", "web/app.py", kind="weakness"),
            found("password logged", "CWE-532", "web/cfg.py", kind="weakness"),
            found("cmd injection hardening", "CWE-78", "pkg/y.go", kind="weakness"),
        ],
        NOW,
        "1.0",
    )
    assert {(c.class_id, c.kind, c.count) for c in collection.classes} == {
        ("CWE-78/go", "vulnerability", 2),
        ("CWE-532/python/weakness", "weakness", 2),
        ("CWE-78/go/weakness", "weakness", 1),
    }
    weakness = next(c for c in collection.classes if c.class_id == "CWE-78/go/weakness")
    draft = SweepDraft.of(weakness, [collection.findings[i] for i in weakness.member_indexes])
    assert (draft.slug, draft.rule_id, draft.kind) == (
        "sweep-go-cwe-78-weakness",
        "traust-go-sweep-cwe-78-weakness",
        "weakness",
    )
