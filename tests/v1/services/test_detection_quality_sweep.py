"""The sweep stages, the rule-mining lane and the validation benchmark on SQLite and Postgres.

Ported from traust-engine tests/test_sweep_engine.py and tests/test_run_rule_mining_lane.py
(traust-engine 0b483d7): the confirmed findings now come from core, the stage state from the
object store, the repositories from recorded secure-code audits.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, commit_all, contract_db, git
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.findings.test_reads import service as finding_service
from tests.v1.services.test_detection_quality_regression_pairs import (
    FIX,
    PRE,
    FakeCheckouts,
    Ledger,
    tree,
)
from traust_core.v1.context.documents import yaml_documents, yaml_text
from traust_core.v1.errors import ConfigError, NotFoundError, ValidationError
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.models.detection_quality import (
    RegressionPairFilter,
    RuleId,
    RulePack,
    RuleRef,
)
from traust_core.v1.models.rule_mining import (
    Allowlist,
    RepoSweep,
    RuleFile,
    RuleHit,
    RuleLaneRequest,
    RuleSweepRequest,
    StageStatus,
    SweepRepo,
)
from traust_core.v1.models.validation_benchmark import (
    BenchmarkVariant,
    ValidationBenchmark,
    ValidationRun,
)
from traust_core.v1.providers.base import Readiness
from traust_core.v1.providers.checkout import GitCheckout
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.rule_drafts import RuleDraftDirectory
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects.store import ObjectKey
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpecs
from traust_core.v1.services.detection_quality import DetectionQualityService

COVERING = "traust-go-cmd-injection"
PACK = RulePack(
    name="traust",
    version="1",
    rules=(RuleRef(id=RuleId(COVERING), languages=("go",), cwes=("CWE-78",)),),
)
AUTHORED = """rules:
  - id: traust-go-sweep-cwe-798
    languages: [go]
    severity: ERROR
    message: hardcoded credential
    metadata:
      cwe: ["CWE-798"]
      generalized_from:
        - source_finding: "FIND-001"
          repo: "repoa"
    pattern: $KEY = "AKIA..."
"""
RID = "traust-go-sweep-cwe-798"


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@dataclass
class Packs:
    pack: RulePack | None = PACK
    watched: RulePack | None = None
    name: str = "fake-packs"

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def packs(self) -> list[RulePack]:
        if self.pack is None:
            raise ConfigError("rule pack unreadable")
        return [self.pack]

    def cached(self, name: str, source: str) -> RulePack | None:
        return self.watched


@dataclass
class Sweeper:
    """Each repository's hits from a fixed table, recording what was scanned and at which pin."""

    hits: dict[str, int] = field(default_factory=dict)
    ready: bool = True
    scanned: list[str] = field(default_factory=list)
    pins: list[str | None] = field(default_factory=list)
    name: str = "fake-sweep"

    def check(self, binary: str) -> Readiness:
        return Readiness(ready=self.ready, detail=f"{binary} missing")

    def scan(self, repo: SweepRepo, rule: RuleFile, binary: str, timeout: int) -> RepoSweep:
        self.scanned.append(repo.slug)
        self.pins.append(repo.sha)
        if repo.slug not in self.hits:
            return RepoSweep(slug=repo.slug, url=repo.url, error="clone_failed")
        facts = tuple(
            RuleHit(
                rule_id=rule.ids[0],
                severity_hint="high",
                file=f"cmd/{i}.go",
                start_line=i + 1,
                end_line=i + 1,
                snippet=f"key{i}",
                test_path=i == 1,
            )
            for i in range(self.hits[repo.slug])
        )
        return RepoSweep(slug=repo.slug, url=repo.url, files_scanned=3, facts=facts)


@dataclass
class Bench:
    engine: Engine
    tmp: Path
    objects: InMemoryObjectStore = field(default_factory=InMemoryObjectStore)
    packs: Packs = field(default_factory=Packs)
    sweeper: Sweeper = field(default_factory=Sweeper)
    forge: FakeCheckouts | None = None

    @property
    def drafts(self) -> RuleDraftDirectory:
        return RuleDraftDirectory(
            self.tmp / "rule-drafts", self.tmp / "pack", yaml_documents, yaml_text
        )

    @property
    def service(self) -> DetectionQualityService:
        uow = SqlTraustUnitOfWork(self.engine)
        return DetectionQualityService(
            uow,
            finding_service(self.engine),
            ArtifactPublisher(PublishSpecs(), InMemoryObjectStore(), uow),
            clock=FixedClock(T0),
            rule_packs=self.packs,  # type: ignore[arg-type]
            checkouts=self.forge,  # type: ignore[arg-type]
            objects=self.objects,
            rule_drafts=self.drafts,
            sweeper=self.sweeper,
            git=GitCheckout(ProcessRunner(("git",))),
        )

    def confirmed(self) -> dict[str, UUID]:
        """repoa/repob of the legacy fixture: what the ledger and the Phase-0 files confirmed."""
        ids = {}
        with SqlTraustUnitOfWork(self.engine) as uow:
            seed = Seed(uow)
            cwes: dict[str, Any] = {}
            for repo_name, rows in (
                (
                    "repoa",
                    (
                        ("FIND-001", "CWE-78", "pkg/run.go", "confirmed", "high"),
                        ("FIND-002", "CWE-306", "pkg/srv.go", "confirmed", "critical"),
                        ("FIND-003", "CWE-89", "pkg/db.go", None, "high"),
                        ("FIND-004", "CWE-1395", "go.mod", "confirmed", "high"),
                        ("FIND-005", "CWE-532", "collector/filter.py", "confirmed", "high"),
                        ("FIND-006", "CWE-798", "cmd/main.go", "false_positive", "critical"),
                    ),
                ),
                (
                    "repob",
                    (
                        ("FIND-007", "CWE-798", "cmd/main.go", "confirmed", "critical"),
                        ("FIND-008", "CWE-295", "pkg/tls.go", "confirmed", "high"),
                    ),
                ),
            ):
                repo = seed.repository(url=f"https://github.com/org/{repo_name}")
                audit = seed.assessment(seed.repository_ref(repo))
                for label, cwe, path, validity, severity in rows:
                    if cwe not in cwes:
                        cwes[cwe] = seed.cwe(identifier=cwe)
                    f = seed.finding(repo, title=f"{label} {cwe} in {path}")
                    seed.finding_cwe(f, cwes[cwe])
                    seed.location(seed.occurrence(f, audit, severity=severity), path=path)
                    if validity:
                        seed.decision(f, validity=validity, actor="human:alice@example.com")
                    ids[label] = f.id
            uow.commit()
        return ids  # type: ignore[return-value]

    def pack_rule(self) -> None:
        (self.tmp / "pack").mkdir(exist_ok=True)
        (self.tmp / "pack" / "rules.yaml").write_text(
            f"rules:\n  - id: {COVERING}\n    languages: [go]\n    pattern: x\n"
        )

    def authored(self) -> None:
        draft = self.tmp / "rule-drafts" / "sweep-go-cwe-798"
        draft.mkdir(parents=True, exist_ok=True)
        (draft / "rule.skeleton.yaml").write_text(AUTHORED)


@pytest.fixture
def bench(engine: Engine, tmp_path: Path) -> Bench:
    return Bench(engine, tmp_path)


# --- collect ----------------------------------------------------------------------------------


def test_collect_classifies_every_confirmed_finding(bench: Bench) -> None:
    bench.confirmed()
    collected = bench.service.sweep_collect()
    assert (
        not collected.skipped and collected.state == "detection-quality/sweeps/state/collect.json"
    )
    assert collected.stats is not None
    # FIND-003 was never judged and FIND-006 is a false positive: neither is collected
    assert collected.stats.model_dump() == {
        "confirmed_findings": 6,
        "by_source": {"ledger": 6},
        "rule_expressible": 4,
        "not_expressible": 2,
        "classes": 4,
    }
    state = json.loads(bench.objects.get(bench.objects.stat(_key(collected.state))))
    assert {c["class_id"] for c in state["classes"]} == {
        "CWE-78/go",
        "CWE-532/python",
        "CWE-798/go",
        "CWE-295/go",
    }
    assert {f["repo"] for f in state["findings"]} == {"repoa", "repob"}
    reasons = {f["reason"].split(":")[0] for f in state["findings"] if not f["rule_expressible"]}
    assert reasons == {"semantic_logic_class", "dependency_version_class"}


def test_collect_resumes_unless_forced(bench: Bench) -> None:
    bench.confirmed()
    assert not bench.service.sweep_collect().skipped
    again = bench.service.sweep_collect()
    assert again.skipped and again.stats is None
    assert not bench.service.sweep_collect(force=True).skipped


def test_an_empty_ledger_collects_nothing(bench: Bench) -> None:
    stats = bench.service.sweep_collect().stats
    assert stats is not None and (stats.confirmed_findings, stats.classes) == (0, 0)


def _key(raw: str) -> ObjectKey:
    return ObjectKey.parse(raw)


# --- draft ------------------------------------------------------------------------------------


def test_drafts_need_a_collection_first(bench: Bench) -> None:
    with pytest.raises(NotFoundError, match="run `sweep collect` first"):
        bench.service.sweep_drafts()


def test_drafts_skip_classes_the_pack_or_a_held_draft_covers(bench: Bench) -> None:
    bench.confirmed()
    bench.service.sweep_collect()
    drafted = bench.service.sweep_drafts()
    assert set(drafted.emitted) == {"sweep-python-cwe-532", "sweep-go-cwe-798", "sweep-go-cwe-295"}
    (covered,) = [s for s in drafted.skipped if s.class_id == "CWE-78/go"]
    assert covered.reason == f"covered_by_pack: ['{COVERING}']"
    assert drafted.pack == "traust 1" and drafted.drafts_dir == str(bench.tmp / "rule-drafts")
    draft = bench.tmp / "rule-drafts" / "sweep-go-cwe-798"
    skeleton = (draft / "rule.skeleton.yaml").read_text()
    assert "id: traust-go-sweep-cwe-798" in skeleton and "generalized_from" in skeleton
    assert 'repo: "repob"' in skeleton and "severity: ERROR" in skeleton
    assert "cmd/main.go" in (draft / "DRAFT.md").read_text()
    assert bench.objects.exists(_key("detection-quality/sweeps/state/draft.json"))


def test_a_rerun_never_restages_a_held_draft(bench: Bench) -> None:
    bench.confirmed()
    bench.service.sweep_collect()
    bench.service.sweep_drafts()
    (bench.tmp / "rule-drafts" / "sweep-go-cwe-798" / "rule.skeleton.yaml").write_text(AUTHORED)
    again = bench.service.sweep_drafts()
    assert again.emitted == ()
    assert {s.reason for s in again.skipped if s.class_id != "CWE-78/go"} == {"draft_exists"}
    assert (
        "FIND-001"
        in (bench.tmp / "rule-drafts" / "sweep-go-cwe-798" / "rule.skeleton.yaml").read_text()
    )


def test_without_a_drafts_directory_drafting_is_refused(bench: Bench) -> None:
    uow = SqlTraustUnitOfWork(bench.engine)
    service = DetectionQualityService(
        uow,
        finding_service(bench.engine),
        ArtifactPublisher(PublishSpecs(), InMemoryObjectStore(), uow),
        objects=bench.objects,
    )
    with pytest.raises(ConfigError, match="no rule drafts directory configured"):
        service.sweep_drafts()


# --- sweep ------------------------------------------------------------------------------------


def repos(*slugs: str) -> tuple[SweepRepo, ...]:
    return tuple(SweepRepo(slug=s, url=f"https://github.com/org/{s}") for s in slugs)


def test_an_unauthored_skeleton_is_never_swept(bench: Bench) -> None:
    todo = bench.tmp / "todo.yaml"
    todo.write_text("rules:\n  - id: x-sweep\n    pattern: TODO\n")
    with pytest.raises(ValidationError, match="unauthored skeleton"):
        bench.service.sweep_rule(RuleSweepRequest(rule=str(todo), repos=repos("a")))
    assert bench.sweeper.scanned == []


def test_a_sweep_without_opengrep_is_refused(bench: Bench) -> None:
    bench.authored()
    bench.sweeper.ready = False
    with pytest.raises(ConfigError, match=r"opengrep not found on PATH \(og\)"):
        bench.service.sweep_rule(RuleSweepRequest(rule=RID, binary="og", repos=repos("a")))


def test_a_sweep_records_each_repository_and_resumes(bench: Bench) -> None:
    bench.authored()
    bench.sweeper.hits = {"hit-repo": 1, "clean-repo": 0}
    request = RuleSweepRequest(
        rule="sweep-go-cwe-798", repos=repos("hit-repo", "clean-repo", "gone")
    )
    swept = bench.service.sweep_rule(request)
    assert (swept.rule_id, swept.repos, swept.swept, swept.skipped) == (RID, 3, 3, 0)
    assert (swept.repo_errors, swept.hits) == (1, 1)
    assert swept.repo_results == f"detection-quality/sweeps/{RID}/repos"
    stored = RepoSweep.model_validate_json(
        bench.objects.get(bench.objects.stat(_key(f"{swept.repo_results}/hit-repo.json")))
    )
    assert (stored.rule_id, stored.facts[0].file) == (RID, "cmd/0.go")
    assert stored.rule_path.endswith("sweep-go-cwe-798/rule.skeleton.yaml")
    again = bench.service.sweep_rule(request)
    assert (again.swept, again.skipped) == (0, 3)
    assert bench.sweeper.scanned == ["hit-repo", "clean-repo", "gone"]


def test_the_sweep_limit_bounds_the_repositories(bench: Bench) -> None:
    bench.authored()
    swept = bench.service.sweep_rule(
        RuleSweepRequest(rule=RID, limit=2, repos=repos("a", "b", "c"))
    )
    assert (swept.repos, bench.sweeper.scanned) == (2, ["a", "b"])


def test_the_corpus_is_each_repository_audited_on_its_default_line(bench: Bench) -> None:
    with SqlTraustUnitOfWork(bench.engine) as uow:
        seed = Seed(uow)

        def audited(url: str, **audit: Any) -> None:
            repo = seed.repository(url=url)
            main = seed.repository_ref(repo, name="main", is_default=True, sha="a" * 40)
            branch = seed.repository_ref(repo, name="feature", sha="b" * 40)
            on = branch if audit.pop("branch", False) else main
            seed.assessment(on, **{"kind": "secure-code", **audit})

        audited("https://github.com/org/zeta")
        audited("https://github.com/org/alpha", kind="secure_code")
        audited("https://github.com/other/alpha")  # the same name: one URL per slug
        audited("https://github.com/org/beta")
        audited("https://github.com/org/branch-only", branch=True)
        audited("https://github.com/org/failed", status="failed")
        audited("https://github.com/org/threat-model", kind="threat-model")
        uow.commit()
    bench.authored()
    swept = bench.service.sweep_rule(RuleSweepRequest(rule=RID, limit=10))
    assert (swept.repos, bench.sweeper.scanned) == (3, ["alpha", "beta", "zeta"])
    # each repository is pinned to its audited commit, never the line's current head
    assert bench.sweeper.pins == ["a" * 40] * 3


def test_a_repository_with_several_audited_commits_pins_its_latest_audit(bench: Bench) -> None:
    with SqlTraustUnitOfWork(bench.engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url="https://github.com/org/twice")
        seed.assessment(
            seed.repository_ref(repo, name="main", is_default=True, sha="a" * 40),
            kind="secure-code",
            occurred_at=T0,
        )
        seed.assessment(
            seed.repository_ref(repo, name="main", is_default=True, sha="b" * 40),
            kind="secure-code",
            occurred_at=T0 + timedelta(hours=1),
        )
        uow.commit()
    bench.authored()
    swept = bench.service.sweep_rule(RuleSweepRequest(rule=RID, limit=10))
    assert (swept.repos, bench.sweeper.scanned) == (1, ["twice"])
    assert bench.sweeper.pins == ["b" * 40]


def test_an_unknown_rule_is_not_found(bench: Bench) -> None:
    with pytest.raises(NotFoundError, match="rule not found"):
        bench.service.sweep_rule(RuleSweepRequest(rule="no-such-rule", repos=repos("a")))


# --- emit -------------------------------------------------------------------------------------


def test_emit_writes_triage_candidates_and_resumes(bench: Bench) -> None:
    bench.authored()
    bench.sweeper.hits = {"hit-repo": 2}
    bench.service.sweep_rule(RuleSweepRequest(rule=RID, repos=repos("hit-repo", "err-repo")))
    emitted = bench.service.emit_sweep(RID)
    assert (
        not emitted.skipped
        and emitted.out == f"detection-quality/sweeps/{RID}/sweep-candidates.json"
    )
    report = json.loads(bench.objects.get(bench.objects.stat(_key(emitted.out))))
    assert report["artifact"] == "sweep-candidates"
    assert "never files findings" in report["purpose"] and "triage workflow" in report["purpose"]
    assert (report["rule_id"], report["repos_swept"], report["repos_with_hits"]) == (RID, 2, 1)
    assert report["repo_errors"] == 1
    first, second = report["candidates"]
    assert first == {
        "repo": "hit-repo",
        "url": "https://github.com/org/hit-repo",
        "file": "cmd/0.go",
        "line": 1,
        "end_line": 1,
        "location": "cmd/0.go:1",
        "excerpt": "key0",
        "rule_id": RID,
        "severity_hint": "high",
        "test_path": False,
        "source_finding_provenance": ["FIND-001"],
    }
    assert second["test_path"] is True
    assert report["source_findings"][0]["source_finding"] == "FIND-001"
    assert emitted.summary is not None
    assert (
        "never files findings" in emitted.summary
        and "| err-repo | 0 (clone_failed) |" in emitted.summary
    )
    assert "| hit-repo | 2 |" in emitted.summary
    assert bench.service.emit_sweep(RID).skipped
    assert not bench.service.emit_sweep(RID, force=True).skipped


def test_emit_needs_a_sweep_first(bench: Bench) -> None:
    bench.authored()
    with pytest.raises(NotFoundError, match="run `sweep sweep` first"):
        bench.service.emit_sweep(RID)


# --- regression drafts ------------------------------------------------------------------------


def test_regression_drafts_are_staged_and_held_ones_skipped(engine: Engine, tmp_path: Path) -> None:
    uow = SqlTraustUnitOfWork(engine)
    ledger = Ledger(engine, uow, Seed(uow))
    ledger.finding("cmd/run.go")
    forge = FakeCheckouts(
        tree({"cmd/run.go": ('exec.Command("sh", "-c", x)\n', "exec.Command(x)\n")})
    )
    bench = Bench(engine, tmp_path, forge=forge)
    found = bench.service.stage_regression_drafts(RegressionPairFilter(limit=6))
    (pair,) = found.pairs
    draft = tmp_path / "rule-drafts" / pair.id
    assert (draft / "before" / "cmd/run.go").read_text().startswith('exec.Command("sh"')
    assert (pair.pre_fix_sha, pair.fix_sha) == (PRE, FIX)
    again = bench.service.stage_regression_drafts(RegressionPairFilter(limit=6), skip_existing=True)
    assert (again.pairs, again.skipped_by_reason) == ((), {"staged": 1})


# --- the rule-mining lane ---------------------------------------------------------------------


def test_the_first_lane_run_is_a_baseline(bench: Bench) -> None:
    bench.confirmed()
    lane = bench.service.rule_lane(RuleLaneRequest())
    assert lane.exit_code == 0 and lane.delta is not None and lane.mining is not None
    assert lane.delta.baseline and not lane.delta.attention.needed
    assert lane.delta.drafts_staged == 3
    assert [(s.stage, s.status) for s in lane.stages] == [
        ("snapshot", StageStatus.OK),
        ("mine", StageStatus.OK),
        ("sweep-collect", StageStatus.OK),
        ("sweep-draft", StageStatus.OK),
        ("regression-drafts", StageStatus.SKIPPED),
    ]
    assert lane.stages[-1].summary == "repository checkouts not configured"
    assert lane.delta.stages == lane.stages
    assert lane.delta.reachability is not None
    assert lane.delta.reachability.packs["argus-observe-rules"].reason == "pack not cached"
    assert lane.delta.allowlist_precision is not None
    assert lane.delta.allowlist_precision.reason == "no rule-pack-allowlist.yaml"
    assert lane.delta_report is not None and "**Baseline run**" in lane.delta_report
    assert lane.mining_report is not None and "**6 confirmed true positives**" in lane.mining_report


def test_a_quiet_rerun_exits_zero_and_staged_drafts_need_attention(bench: Bench) -> None:
    bench.confirmed()
    bench.service.rule_lane(RuleLaneRequest(skip_sweep=True))
    quiet = bench.service.rule_lane(RuleLaneRequest(skip_sweep=True))
    assert quiet.exit_code == 0 and quiet.delta is not None and not quiet.delta.baseline
    assert quiet.stages[0].summary == "previous rule-mining.json loaded"
    assert [s.status for s in quiet.stages[2:4]] == [StageStatus.SKIPPED, StageStatus.SKIPPED]
    drafted = bench.service.rule_lane(RuleLaneRequest())
    assert drafted.exit_code == 1 and drafted.delta is not None
    assert drafted.delta.drafts_staged == 3
    assert any("awaiting authoring" in r for r in drafted.delta.attention.reasons)


def test_a_lane_whose_mine_fails_exits_two_with_no_delta(bench: Bench) -> None:
    bench.packs.pack = None
    lane = bench.service.rule_lane(RuleLaneRequest())
    assert (lane.exit_code, lane.delta, lane.stages[-1].stage) == (2, None, "mine")
    assert lane.stages[-1].status == StageStatus.FAILED
    assert not bench.objects.exists(_key("detection-quality/rule-lane/lane-delta.json"))


def test_a_failed_stage_is_recorded_and_the_lane_exits_two(bench: Bench) -> None:
    bench.confirmed()
    uow = SqlTraustUnitOfWork(bench.engine)
    service = DetectionQualityService(
        uow,
        finding_service(bench.engine),
        ArtifactPublisher(PublishSpecs(), InMemoryObjectStore(), uow),
        clock=FixedClock(T0),
        rule_packs=bench.packs,  # type: ignore[arg-type]
        objects=bench.objects,
    )
    lane = service.rule_lane(RuleLaneRequest(draft_limit=0))
    assert lane.exit_code == 2 and lane.delta is not None
    draft = next(s for s in lane.stages if s.stage == "sweep-draft")
    assert draft.status == StageStatus.FAILED and "rule drafts directory" in draft.summary
    assert lane.stages[-1].summary == "--draft-limit 0"


def test_an_allowlisted_rule_below_the_gate_needs_attention(bench: Bench) -> None:
    bench.confirmed()
    lane = bench.service.rule_lane(
        RuleLaneRequest(skip_sweep=True, allowlist=Allowlist(rules=frozenset({"argus-a"})))
    )
    assert lane.delta is not None and lane.delta.allowlist_precision is not None
    assert lane.delta.allowlist_precision.unmeasured == ("argus-a",)
    assert lane.exit_code == 0


def test_a_watched_pack_gate_opening_needs_attention(bench: Bench) -> None:
    with SqlTraustUnitOfWork(bench.engine) as uow:
        seed = Seed(uow)
        cwe = seed.cwe(identifier="CWE-295")
        for name in ("r1", "r2", "r3"):
            repo = seed.repository(url=f"https://github.com/org/{name}")
            f = seed.finding(repo, title="tls")
            seed.finding_cwe(f, cwe)
            audit = seed.assessment(seed.repository_ref(repo))
            seed.location(seed.occurrence(f, audit), path="src/tls.rs")
            seed.decision(f, validity="confirmed", actor="human:alice@example.com")
        uow.commit()

    def watching(cwe: str) -> RulePack:
        return RulePack(name="a", version="x", rules=(RuleRef(id=RuleId("r"), cwes=(cwe,)),))

    bench.packs.watched = watching("CWE-89")
    blocked = bench.service.rule_lane(RuleLaneRequest(skip_sweep=True))
    assert blocked.exit_code == 0 and blocked.delta is not None
    assert blocked.delta.reachability is not None
    rust = blocked.delta.reachability.packs["argus-observe-rules"].languages["rust"]
    assert (rust.repos, rust.max_span, rust.reachable) == (3, 0, False)
    bench.packs.watched = watching("CWE-295")
    opened = bench.service.rule_lane(RuleLaneRequest(skip_sweep=True))
    assert opened.exit_code == 1 and opened.delta is not None
    (crossing,) = opened.delta.reachability_crossings
    assert (crossing.language, crossing.direction, crossing.max_span) == ("rust", "opened", 3)
    assert any("Stage-A gate OPENED for rust" in r for r in opened.delta.attention.reasons)


# --- the validation benchmark -----------------------------------------------------------------

BENCHMARK = ValidationBenchmark.model_validate(
    {
        "namespace": "vb",
        "floors": {"confirm_recall": 0.9, "refute_precision": 0.9, "severity_within": 1.0},
        "fixtures": [
            {
                "id": "VB-1",
                "probe_class": "rbac",
                "controls_hint": "h",
                "vuln_manifest": "v.yaml",
                "claim": {
                    "title": "t",
                    "severity": "high",
                    "cvss": 8.0,
                    "cvss_vector": "CVSS:3.1/AV:N",
                    "category": "authorization",
                },
                "expected": {"vuln": "confirmed", "safe": "refuted"},
            }
        ],
    }
)


def test_scores_accumulate_on_the_scorecard(bench: Bench) -> None:
    assert bench.service.benchmark_scorecard().runs == ()
    run = ValidationRun.model_validate(
        {"validated_findings": [{"source_id": "b/VB-1", "verdict": "confirmed"}]}
    )
    score = bench.service.score_benchmark(BENCHMARK, run, BenchmarkVariant.VULN, "r1.json")
    assert (score.confirm_recall, score.scored_at, score.report) == (1.0, T0, "r1.json")
    bench.service.score_benchmark(BENCHMARK, ValidationRun(), BenchmarkVariant.SAFE, "r2.json")
    card = bench.service.benchmark_scorecard()
    assert [(r.variant, r.value) for r in card.runs] == [("vuln", 1.0), ("safe", 0.0)]


def test_the_worklist_is_stamped_by_the_clock(bench: Bench) -> None:
    worklist = bench.service.benchmark_worklist(BENCHMARK)
    assert worklist.metadata.generated_at == T0 and [c.id for c in worklist.findings] == ["VB-1"]


def test_the_trigger_reads_the_checkout_since_a_release(bench: Bench, tmp_path: Path) -> None:
    checkout = tmp_path / "mono"
    (checkout / "traust" / "src").mkdir(parents=True)
    (checkout / "README.md").write_text("x")
    git(checkout, "init", "-q")
    base = commit_all(checkout, "base")
    lane = checkout / "traust" / "harnessing" / "5-validate" / "validate-findings"
    lane.mkdir(parents=True)
    (lane / "SKILL.md").write_text("x")
    (checkout / "README.md").write_text("y")
    commit_all(checkout, "change")
    trigger = bench.service.benchmark_trigger(ToolRequest(workspace=checkout), base)
    assert trigger.paths == ("traust/harnessing/5-validate/validate-findings/SKILL.md",)
    assert bench.service.benchmark_trigger(ToolRequest(workspace=checkout), "HEAD").paths == ()
