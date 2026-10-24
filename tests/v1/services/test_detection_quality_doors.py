"""Detection quality doors on SQLite and Postgres: rule packs, canaries, calibration, critical
misses, compliance precision and scorecards.

Scenarios ported from traust-engine sweep/calibration.py, traust recall-benchmark
build_canaries.py, ops/build_critical_misses.py, ops/cve_replay_monitor.py and
ops/compliance_precision.py (traust fabdb13, traust-engine 435225b).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import timedelta
from functools import cached_property
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.findings.test_reads import service as finding_service
from tests.v1.services.test_detection_quality import (
    FP,
    PACK,
    REPO,
    TAINT,
    finding,
    provenance,
    report,
    target,
)
from traust_core.v1.errors import ConfigError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import (
    BenchmarkTargetArtifact,
    ComplianceAssessmentArtifact,
    SecurityAuditArtifact,
)
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import PageRequest, TimeWindow
from traust_core.v1.models.detection_quality import (
    BenchmarkFilter,
    CanaryInjection,
    CanaryKind,
    CanaryRepo,
    CanarySource,
    MissFilter,
    MissReason,
    RulePack,
    RuleRef,
    SeededFinding,
)
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import Repository, RepositoryRef
from traust_core.v1.providers.base import Readiness
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    AssessmentLog,
    PublishSpec,
    PublishSpecs,
)
from traust_core.v1.services.detection_quality import CANARY_ADMITTER, DetectionQualityService

SHA = "c" * 40


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@dataclass
class FakePacks:
    found: list[RulePack]
    name: str = "fake-packs"

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def packs(self) -> list[RulePack]:
        return self.found


@dataclass
class FakeCanaries:
    found: list[CanarySource]
    name: str = "fake-canaries"
    built: list[str] = field(default_factory=list)

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def sources(self) -> list[CanarySource]:
        return self.found

    def materialize(self, source: CanarySource) -> CanaryRepo:
        self.built.append(source.name)
        return CanaryRepo(repo_url=f"file:///cache/canaries/{source.name}", sha=SHA)


@dataclass
class World:
    engine: Engine
    uow: SqlTraustUnitOfWork
    publisher: ArtifactPublisher

    @cached_property
    def seed(self) -> Seed:
        """One seed per test, so generated fingerprints and CWEs never collide."""
        return Seed(self.uow)

    def cwe(self, identifier: str) -> Any:
        with self.uow as uow:
            return uow.cwes.find_by_identifier(identifier) or self.seed.cwe(identifier=identifier)

    def service(self, **kw: Any) -> DetectionQualityService:
        return DetectionQualityService(
            self.uow, finding_service(self.engine), self.publisher, clock=FixedClock(T0), **kw
        )

    def key(self, *targets: dict[str, Any], version: int = 1) -> UUID:
        doc = BenchmarkTargetArtifact.from_document(
            {"version": version, "updated": "2026-07-18", "targets": list(targets)}
        )
        return self.service().record(doc, provenance()).artifact_id

    def answer_key(self) -> dict[str, Any]:
        latest = self.publisher.latest_imported(BenchmarkTargetArtifact)
        assert latest is not None
        return json.loads(latest.document.payload)  # type: ignore[no-any-return]

    def attach(self, doc: Any, kind: str, version: str = "h-1", ref: RepositoryRef | None = None,
               **kw: Any) -> UUID:  # fmt: skip
        published = self.publisher.publish_artifact(doc)
        with self.uow as uow:
            seed = self.seed
            run = seed.assessment(
                ref or seed.repository_ref(), kind=kind, assessor_version=version, **kw
            )
            uow.commit()
        assert run.id is not None
        with self.uow as uow:
            AssessmentLog(uow).attach(run.id, published.artifact_id, sha256_hex(doc.payload))
            uow.commit()
        return run.id


@pytest.fixture
def world(engine: Engine) -> World:
    uow = SqlTraustUnitOfWork(engine)
    specs = PublishSpecs(
        PublishSpec(BenchmarkTargetArtifact),
        PublishSpec(SecurityAuditArtifact),
        PublishSpec(ComplianceAssessmentArtifact),
    )
    return World(engine, uow, ArtifactPublisher(specs, InMemoryObjectStore(), uow))


# --- rule_packs -------------------------------------------------------------------------------


def test_rule_packs_come_from_the_configured_source(world: World) -> None:
    assert world.service(rule_packs=FakePacks([PACK])).rule_packs() == [PACK]


@pytest.mark.parametrize(
    ("door", "need"),
    [
        (lambda s: s.rule_packs(), "rule-pack source"),
        (lambda s: s.build_canaries(provenance()), "canary materialiser"),
        (lambda s: s.drafts(None), "rule-draft artifact schema"),
        (lambda s: s.admit_rule(uuid4(), uuid4()), "rule-draft artifact schema"),
    ],
)
def test_doors_without_their_provider_or_storage_raise_config_errors(
    world: World, door: Any, need: str
) -> None:
    with pytest.raises(ConfigError, match=need):
        door(world.service())


# --- build_canaries ---------------------------------------------------------------------------


def source(name: str = "readme-x", kind: CanaryKind = CanaryKind.CANARY, **kw: Any) -> CanarySource:
    values: dict[str, Any] = {
        "name": name,
        "kind": kind,
        "recipe": f"canaries/{name}",
        "expected": (
            SeededFinding(cwes=("cwe-287",), paths=("pkg/a.go",), severity="high", title="no auth"),
        ),
        "tree": ("README.md", "pkg/a.go"),
        "injection": CanaryInjection(injection_class="readme_blatant", tokens=("CANARY-XX-1",))
        if kind == CanaryKind.CANARY
        else None,
    }
    return CanarySource(**{**values, **kw})


def test_canaries_become_seeded_targets_of_a_new_answer_key(world: World) -> None:
    world.key(target(), target(id="bt-canary-readme-x", provenance="seeded"), version=3)
    fake = FakeCanaries([source(), source("app", CanaryKind.SEEDED, language="go")])
    built = world.service(canaries=fake).build_canaries(provenance())
    assert [c.target_id for c in built] == ["bt-canary-readme-x", "bt-seeded-app"]
    key = world.answer_key()
    assert (key["version"], key["updated"]) == (4, "2026-10-05")
    assert [t["id"] for t in key["targets"]] == ["bt-x-001", "bt-canary-readme-x", "bt-seeded-app"]
    rebuilt, seeded = key["targets"][1:]
    assert rebuilt["repo_url"] == "file:///cache/canaries/readme-x"
    assert rebuilt["injection"] == {"class": "readme_blatant", "tokens": ["CANARY-XX-1"]}
    assert (rebuilt["pre_fix_sha"], rebuilt["admitted_by"], rebuilt["admitted_at"]) == (
        SHA,
        CANARY_ADMITTER,
        "2026-10-05",
    )
    assert (
        rebuilt["expected"][0]["cwes"] == ["CWE-287"]
        and rebuilt["expected"][0]["fingerprint"] is None
    )
    assert (seeded["provenance"], seeded["held_out"], seeded["language"]) == ("seeded", False, "go")
    assert "injection" not in seeded


def test_the_first_canaries_start_the_answer_key(world: World) -> None:
    world.service(canaries=FakeCanaries([source()])).build_canaries(provenance())
    assert world.answer_key()["version"] == 1


def test_a_materialised_canary_is_scored_at_the_path_cwe_tier(world: World) -> None:
    service = world.service(canaries=FakeCanaries([source()]))
    service.build_canaries(provenance())
    doc = report(finding(), repository="file:///cache/canaries/readme-x")
    run = service.run_benchmark(
        {"bt-canary-readme-x": [world.attach(doc, AssessmentKind.BENCHMARK_AUDIT)]}  # type: ignore[dict-item]
    )
    assert run.targets[0].matches[0].tier == "path_cwe" and run.targets[0].injection.passed  # type: ignore[union-attr]


@pytest.mark.parametrize("leak", ["canary.yaml", "docs/seed.yaml"])
def test_an_answer_key_inside_the_tree_is_refused(world: World, leak: str) -> None:
    fake = FakeCanaries([source(tree=("README.md", leak))])
    with pytest.raises(ValidationError, match="must never enter the materialised repository"):
        world.service(canaries=fake).build_canaries(provenance())
    assert fake.built == [] and world.publisher.latest(BenchmarkTargetArtifact) is None


def test_no_canary_sources_records_nothing(world: World) -> None:
    assert world.service(canaries=FakeCanaries([])).build_canaries(provenance()) == []
    assert world.publisher.latest(BenchmarkTargetArtifact) is None


# --- calibrate --------------------------------------------------------------------------------


@dataclass
class Corpus:
    world: World
    repos: list[tuple[Repository, RepositoryRef]] = field(default_factory=list)

    def repo(self, tp_path: str = "cmd/run.go", cwe: str = "CWE-78") -> RepositoryRef:
        """A repository with one confirmed TP at `tp_path`."""
        with self.world.uow as uow:
            seed = self.world.seed
            repo = seed.repository(url=f"https://github.com/org/r{len(self.repos)}")
            ref = seed.repository_ref(repo)
            f = seed.finding(repo)
            seed.finding_cwe(f, self.world.cwe(cwe))
            seed.location(seed.occurrence(f, seed.assessment(ref)), path=tp_path)
            seed.decision(
                f, validity="confirmed", actor="human:alice@example.com", rationale="x" * 12
            )
            uow.commit()
        self.repos.append((repo, ref))
        return ref

    def scan(self, ref: RepositoryRef, *hits: tuple[str | None, str], **kw: Any) -> UUID:
        with self.world.uow as uow:
            seed = self.world.seed
            scan = seed.assessment(ref, kind=kw.pop("kind", AssessmentKind.TOOL_SCAN), **kw)
            repo = uow.repositories.get(ref.repository_id)
            for rule, path in hits:
                seed.location(seed.occurrence(seed.finding(repo), scan, rule=rule), path=path)
            uow.commit()
        assert scan.id is not None
        return scan.id


def test_calibration_splits_hits_into_rediscoveries_and_novel(world: World) -> None:
    corpus = Corpus(world)
    ref = corpus.repo()
    hits = [(TAINT, "./cmd/run.go"), (TAINT, "cmd/other.go"), ("noisy", "a.go"), (None, "b.go")]
    scans = [corpus.scan(ref, *hits), corpus.scan(ref, (TAINT, "cmd/run.go"), status="failed")]
    cal = world.service().calibrate(PACK, scans)
    rules = {r.rule: (r.fires, r.rediscoveries, r.novel, r.repos_rediscovered) for r in cal.rules}
    assert rules == {TAINT: (2, 1, 1, 1), "noisy": (1, 0, 1, 0)}
    assert [r.rule for r in cal.rules] == [TAINT, "noisy"]
    assert [(f.assessment_id, f.reason) for f in cal.failed] == [(scans[1], "scan failed")]
    assert (cal.scans, cal.scanned, cal.findings, cal.rediscoveries, cal.tp_files) == (
        2,
        1,
        3,
        1,
        1,
    )
    assert cal.findings_per_repo == 3.0
    assert [(h.rule, h.path) for h in cal.novel_sample] == [
        ("noisy", "a.go"),
        (TAINT, "cmd/other.go"),
    ]
    assert (cal.reachability.repositories, cal.reachability.cwe, cal.reachability.reachable) == (
        1,
        "CWE-78",
        False,
    )


def test_a_rule_rediscovering_in_three_repositories_clears_the_gate(world: World) -> None:
    corpus = Corpus(world)
    scans = [corpus.scan(corpus.repo(), (TAINT, "cmd/run.go")) for _ in range(3)]
    scans.append(corpus.scan(corpus.repos[0][1], (TAINT, "cmd/run.go")))
    cal = world.service().calibrate(PACK, scans)
    (rule,) = cal.rules
    assert (rule.repos_rediscovered, rule.rediscoveries, rule.clears_gate) == (3, 4, True)
    assert cal.reachability.reachable and cal.novel_sample == ()


@pytest.mark.parametrize(
    ("covered", "reachable"),
    [(("CWE-78",), (1, "CWE-78")), (("CWE-327",), (0, None)), ((), (2, "CWE-306"))],
)
def test_gate_reachability_counts_only_cwes_the_pack_covers(
    world: World, covered: tuple[str, ...], reachable: tuple[int, str | None]
) -> None:
    corpus = Corpus(world)
    refs = [corpus.repo(), corpus.repo(cwe="CWE-306"), corpus.repo(cwe="CWE-306")]
    pack = RulePack(name="p", version="1", rules=(RuleRef(id=TAINT, cwes=covered),))  # type: ignore[arg-type]
    cal = world.service().calibrate(pack, [corpus.scan(r) for r in refs])
    assert (cal.reachability.repositories, cal.reachability.cwe) == reachable


def test_calibration_refuses_what_is_not_a_pack_scan(world: World) -> None:
    corpus = Corpus(world)
    audit = corpus.scan(corpus.repo(), kind=AssessmentKind.SECURE_CODE)
    with pytest.raises(ValidationError, match="not tool scans"):
        world.service().calibrate(PACK, [audit])
    with pytest.raises(NotFoundError):
        world.service().calibrate(PACK, [uuid4()])
    with pytest.raises(ValidationError, match="at least one scan"):
        world.service().calibrate(PACK, [])


# --- critical_misses / misses -----------------------------------------------------------------

DAY = timedelta(days=1)
WINDOW = TimeWindow(start=T0 + DAY, end=T0 + 3 * DAY)


@dataclass
class Campaign:
    world: World
    ids: dict[str, UUID] = field(default_factory=dict)

    def build(self) -> Campaign:
        with self.world.uow as uow:
            seed = self.world.seed
            repo = seed.repository(url="https://github.com/org/audited")
            ref = seed.repository_ref(repo)
            audit = seed.assessment(ref, kind=AssessmentKind.SECURE_CODE, occurred_at=T0)
            seed.location(seed.occurrence(seed.finding(repo), audit), path="pkg/a.go")
            later = seed.assessment(ref, kind=AssessmentKind.SCANNER, occurred_at=T0 + 2 * DAY)
            bench = seed.assessment(ref, kind=AssessmentKind.BENCHMARK_AUDIT, occurred_at=T0 + DAY)
            fresh = seed.repository(url="https://github.com/org/never-audited")
            fresh_run = seed.assessment(
                seed.repository_ref(fresh), kind=AssessmentKind.SCANNER, occurred_at=T0 + 2 * DAY
            )
            rows = {
                "area": (repo, [later], "critical", "pkg/a.go", None),
                "missed": (repo, [later], "critical", "pkg/z.go", None),
                "high": (repo, [later], "high", "pkg/h.go", None),
                "refuted": (repo, [later], "critical", "pkg/f.go", "false_positive"),
                "unaudited": (fresh, [fresh_run], "critical", "x.go", None),
                "already": (repo, [audit, later], "critical", "pkg/q.go", None),
                "benchmark-first": (repo, [bench, later], "critical", "pkg/b.go", None),
            }
            for label, (owner, runs, severity, path, validity) in rows.items():
                f = seed.finding(owner, title=label)
                for run in runs:
                    seed.location(seed.occurrence(f, run, severity=severity), path=path)
                if validity:
                    seed.decision(f, validity=validity, actor="human:alice@example.com",
                                  rationale="x" * 12)  # fmt: skip
                self.ids[label] = f.id  # type: ignore[assignment]
            self.ids |= {"audit": audit.id, "later": later.id}  # type: ignore[dict-item]
            uow.commit()
        return self


def test_critical_misses_are_new_criticals_an_earlier_audit_did_not_report(world: World) -> None:
    ids = Campaign(world).build().ids
    misses = world.service().critical_misses(WINDOW)
    assert {m.title: m.reason for m in misses} == {
        "area": MissReason.AREA_REPORTED,
        "missed": MissReason.MISSED,
        "benchmark-first": MissReason.MISSED,
    }
    assert {(m.found_by, m.missed_by, m.found_at) for m in misses} == {
        (ids["later"], ids["audit"], T0 + 2 * DAY)
    }


@pytest.mark.parametrize(
    "window", [TimeWindow(start=T0 + 3 * DAY, end=T0 + 9 * DAY), TimeWindow(start=T0, end=T0 + DAY)]
)
def test_critical_misses_outside_the_window_are_not_listed(
    world: World, window: TimeWindow
) -> None:
    Campaign(world).build()
    assert world.service().critical_misses(window) == []


def test_misses_are_filtered_and_paged(world: World) -> None:
    Campaign(world).build()
    service = world.service()
    first = service.misses(MissFilter(window=WINDOW), PageRequest(limit=2))
    rest = service.misses(MissFilter(window=WINDOW), PageRequest(limit=2, cursor=first.next))
    every = service.critical_misses(WINDOW)
    assert [*first.items, *rest.items] == every and rest.next is None and first.next
    only = service.misses(MissFilter(window=WINDOW, reason=MissReason.AREA_REPORTED), PageRequest())
    assert [m.title for m in only.items] == ["area"]
    nowhere = MissFilter(window=WINDOW, repository_id=uuid4())
    assert service.misses(nowhere, PageRequest()).items == ()


# --- calibrate_compliance ---------------------------------------------------------------------

NIST, PCI = "nist-800-53-rev5", "pci-dss-v4"


def compliance(
    *results: dict[str, Any], frameworks: tuple[str, ...] = (NIST,)
) -> ComplianceAssessmentArtifact:
    counts = dict.fromkeys(
        ("total_in_scope", "deterministic", "evidence_review", "organizational", "satisfied",
         "not_satisfied", "not_applicable", "not_assessed"), 0)  # fmt: skip
    return ComplianceAssessmentArtifact.from_document(
        {
            "metadata": {
                "artifact": "compliance-assessment",
                "harness_version": "h-1",
                "target": {"kind": "environment"},
                "frameworks": [{"id": f} for f in frameworks],
                "registry_hash": "0" * 64,
                "generated_at": "2026-10-05T00:00:00Z",
            },
            "coverage": {f: counts for f in frameworks},
            "results": list(results),
        }
    )


def check(
    check_id: str, verdict: str, source: str = "check", framework: str = NIST, **kw: Any
) -> dict[str, Any]:
    return {
        "framework": framework,
        "control_id": f"ctl-{check_id}",
        "classification": "deterministic",
        "verdict": verdict,
        "verdict_source": source,
        "check_id": check_id,
        "evidence": [{"sha256": "0" * 64, "kind": "iac_file", "locator": "main.tf:1"}],
        **kw,
    }


def overridden(check_id: str, framework: str = NIST) -> dict[str, Any]:
    override = {"by": "alice", "date": "2026-10-05", "rationale": "compensating control in place",
                "overridden_check_verdict": "not_satisfied"}  # fmt: skip
    return check(check_id, "satisfied", "human_override", framework, override=override)


def test_compliance_precision_counts_overrides_of_check_failures_as_dismissals(
    world: World,
) -> None:
    doc = compliance(
        check("tls", "not_satisfied"), overridden("tls"), check("mfa", "not_satisfied"),
        check("mfa", "satisfied"), check("logs", "not_satisfied", "agent"),
        check("pci-only", "not_satisfied", framework=PCI), frameworks=(NIST, PCI),
    )  # fmt: skip
    world.attach(doc, AssessmentKind.COMPLIANCE)
    world.attach(doc, AssessmentKind.COMPLIANCE)
    world.attach(
        compliance(check("tls", "not_satisfied"), frameworks=(PCI,)), AssessmentKind.COMPLIANCE
    )
    cal = world.service().calibrate_compliance(NIST)  # type: ignore[arg-type]
    assert cal.assessments == 1
    assert [(c.check_id, c.fired, c.dismissed, c.precision, c.flagged) for c in cal.checks] == [
        ("mfa", 1, 0, 1.0, False),
        ("tls", 2, 1, 0.5, True),
    ]


def test_compliance_precision_without_assessments_is_empty(world: World) -> None:
    cal = world.service().calibrate_compliance(NIST)  # type: ignore[arg-type]
    assert (cal.assessments, cal.checks) == (0, ())


# --- scorecards -------------------------------------------------------------------------------


def audited(
    *findings: dict[str, Any], repository: str = REPO, commit: str | None = None
) -> SecurityAuditArtifact:
    doc = json.loads(report(*findings, repository=repository).payload)
    if commit:
        doc["metadata"]["commit"] = commit
    return SecurityAuditArtifact.from_document(doc)


def test_scorecards_score_each_auditor_version_over_its_audits(world: World) -> None:
    world.key(target(), target(id="bt-y-001", repo_url="https://github.com/org/y"))
    hit, miss = audited(finding(fingerprint=FP)), audited()
    for doc, version, day in ((hit, "h-1", 0), (miss, "h-2", 1), (hit, "h-2", 2)):
        world.attach(doc, AssessmentKind.BENCHMARK_AUDIT, version, occurred_at=T0 + day * DAY)
    world.attach(
        audited(repository="https://github.com/org/unknown"), AssessmentKind.BENCHMARK_AUDIT
    )
    world.attach(hit, AssessmentKind.SECURE_CODE, "h-1")
    cards = world.service().scorecards(BenchmarkFilter())
    assert [(c.auditor_versions, c.overall.detected, c.mean_stability) for c in cards] == [
        (("h-1",), 1, None),
        (("h-2",), 0, 0.0),
    ]
    assert [c.targets_skipped for c in cards] == [1, 1]
    (only,) = world.service().scorecards(BenchmarkFilter(auditor_version="h-2"))
    assert only.auditor_versions == ("h-2",)


@pytest.mark.parametrize(("commit", "scored"), [("def5678" + "0" * 33, 1), ("1234567", 0)])
def test_scorecards_match_a_target_by_its_pinned_commit(
    world: World, commit: str, scored: int
) -> None:
    world.key(target(), target(id="bt-x-002", pre_fix_sha="1111111"))
    world.attach(audited(commit=commit), AssessmentKind.BENCHMARK_AUDIT)
    cards = world.service().scorecards(BenchmarkFilter())
    assert sum(c.targets_scored for c in cards) == scored


def test_scorecards_include_held_out_targets_only_at_release(world: World) -> None:
    world.key(target(held_out=True))
    world.attach(audited(), AssessmentKind.BENCHMARK_AUDIT)
    assert world.service().scorecards(BenchmarkFilter())[0].targets_scored == 0
    release = world.service().scorecards(BenchmarkFilter(include_held_out=True))
    assert release[0].by_split.keys() == {"held_out"}


def test_scorecards_need_an_answer_key(world: World) -> None:
    with pytest.raises(NotFoundError, match="no benchmark answer key"):
        world.service().scorecards(BenchmarkFilter())
