from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath

from pydantic import Field, JsonValue

from traust_core.v1.models.base import Dto, Model
from traust_core.v1.models.detection_quality import (
    EXT_LANG,
    REDISCOVERY_GATE,
    RULEABLE_LANGS,
    UNKNOWN_LANGUAGE,
    RuleId,
    RuleMining,
)

# Class-generalization sweep: confirmed findings with a syntactic signature, clustered by
# (CWE, language), drafted as candidate rules and run corpus-wide; hits are triage input, never
# findings, and rule promotion stays with the pack's test-and-calibrate gate.
DEFAULT_SWEEP_LIMIT = 40
LEDGER = "ledger"
# CWE families whose canonical manifestation is a shape an opengrep rule can pin: a sink call, a
# config key+value, an annotation or flag, a literal.
SYNTACTIC_CWES = frozenset(
    {
        *(22, 23, 36, 73, 77, 78, 79, 80, 88, 89, 90, 91, 93, 94, 95, 96, 116, 117, 643, 917, 943),
        *(15, 614, 1004, 1244),
        *(261, 295, 296, 319, 326, 327, 328, 330, 338, 347, 757, 759, 760, 916),
        *(259, 312, 313, 321, 532, 540, 798),
        *(502, 611, 776, 1321, 1333),
        *(601, 918),
        *(377, 379, 732),
    }
)
# Version facts (SCA territory), never an opengrep sweep class.
DEPENDENCY_CWES = frozenset({937, 1035, 1104, 1395})
SWEEP_LANGS = RULEABLE_LANGS | {"yaml"}
_CWE_NUMBER = re.compile(r"CWE-(\d+)", re.IGNORECASE)
SWEEP_PURPOSE = (
    "TRIAGE INPUT MATERIAL — corpus-wide sweep of one candidate/"
    "shipped rule generalized from confirmed findings (run-by-default "
    "policy). Every entry is a CANDIDATE, not a finding: the sweep "
    "engine never files findings and never routes externally — feed "
    "this file to the triage workflow for adjudication."
)


def cwe_number(cwe: str | None) -> int | None:
    m = _CWE_NUMBER.search(cwe or "")
    return int(m.group(1)) if m else None


def file_language(path: str | None) -> str:
    return EXT_LANG.get(PurePosixPath(path or "").suffix.lower(), UNKNOWN_LANGUAGE)


def expressible(cwe: str | None, file: str | None, language: str) -> tuple[bool, str]:
    """Whether the finding's evidence pins a syntactic pattern, and why: routes rule-authoring
    attention, never concludes anything about the finding."""
    num = cwe_number(cwe)
    if num is None:
        return False, "no_cwe: no CWE anchor to generalize from"
    if not file:
        return False, "no_location_anchor: evidence pins no file"
    if num in DEPENDENCY_CWES:
        return False, (
            f"dependency_version_class: CWE-{num} is a version fact (SCA/govulncheck "
            "territory), not a syntactic pattern"
        )
    if language not in SWEEP_LANGS:
        return False, f"language_not_ruleable: {language}"
    if num not in SYNTACTIC_CWES:
        return False, (
            f"semantic_logic_class: CWE-{num} evidence pins semantic logic "
            "(authn/authz/ordering/trust), not a concrete syntactic pattern"
        )
    return True, "syntactic: sink-call / config-key / annotation shape"


def repo_slug(url: str | None) -> str:
    if not url:
        return "unknown"
    return url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")


class SweepFinding(Model):
    """One confirmed finding as the sweep classifies it; `artifact` is the commit it was
    confirmed on."""

    source: str
    artifact: str
    repo: str
    url: str | None = None
    finding_id: str | None = None
    title: str
    cwe: str | None = None
    severity: str | None = None
    file: str | None = None
    line: int | None = None
    language: str
    rule_expressible: bool
    reason: str

    @classmethod
    def of(
        cls,
        *,
        artifact: str,
        url: str | None,
        finding_id: str,
        title: str,
        cwe: str | None,
        severity: str | None,
        file: str | None,
    ) -> SweepFinding:
        num = cwe_number(cwe)
        language = file_language(file)
        ok, reason = expressible(cwe, file, language)
        return cls(
            source=LEDGER,
            artifact=artifact,
            repo=repo_slug(url),
            url=url,
            finding_id=finding_id,
            title=title[:160],
            cwe=f"CWE-{num}" if num else None,
            severity=severity,
            file=file or None,
            language=language,
            rule_expressible=ok,
            reason=reason,
        )


class SweepClass(Model):
    class_id: str
    cwe: str
    language: str
    count: int
    repos: tuple[str, ...]
    member_indexes: tuple[int, ...]


class SweepStats(Model):
    confirmed_findings: int
    by_source: dict[str, int]
    rule_expressible: int
    not_expressible: int
    classes: int


class SweepCollection(Model):
    """The collect stage's state: every confirmed finding classified, the expressible ones
    clustered into (CWE, language) classes, largest first."""

    stage: str = "collect"
    generated: datetime
    harness_version: str
    stats: SweepStats
    classes: tuple[SweepClass, ...] = ()
    findings: tuple[SweepFinding, ...] = ()

    @classmethod
    def of(
        cls, found: Sequence[SweepFinding], generated: datetime, harness_version: str
    ) -> SweepCollection:
        findings: list[SweepFinding] = []
        seen: set[tuple[str, str | None, str | None, str]] = set()
        for f in found:
            key = (f.repo.lower(), f.file, f.cwe, f.title[:60].lower())
            if key not in seen:
                seen.add(key)
                findings.append(f)
        members: dict[tuple[str, str], list[int]] = {}
        for i, f in enumerate(findings):
            if f.rule_expressible and f.cwe:
                members.setdefault((f.cwe, f.language), []).append(i)
        classes = [
            SweepClass(
                class_id=f"{cwe}/{language}",
                cwe=cwe,
                language=language,
                count=len(idx),
                repos=tuple(sorted({findings[i].repo for i in idx})),
                member_indexes=tuple(idx),
            )
            for (cwe, language), idx in members.items()
        ]
        expressible_n = sum(f.rule_expressible for f in findings)
        by_source: dict[str, int] = {}
        for f in findings:
            by_source[f.source] = by_source.get(f.source, 0) + 1
        return cls(
            generated=generated,
            harness_version=harness_version,
            stats=SweepStats(
                confirmed_findings=len(findings),
                by_source=by_source,
                rule_expressible=expressible_n,
                not_expressible=len(findings) - expressible_n,
                classes=len(classes),
            ),
            classes=tuple(sorted(classes, key=lambda c: -c.count)),
            findings=tuple(findings),
        )


class SweepCollect(Model):
    """`skipped` when the state exists and the run wasn't forced; `state` names it."""

    skipped: bool
    state: str
    stats: SweepStats | None = None


class DraftSource(Model):
    source_finding: str
    repo: str
    url: str | None = None
    file: str | None = None
    line: int | None = None
    artifact: str


class SweepDraft(Model):
    """A candidate rule for one uncovered expressible class, citing its source findings."""

    cwe: str
    language: str
    count: int
    repos: int
    severity: str
    sources: tuple[DraftSource, ...]

    @property
    def slug(self) -> str:
        return f"sweep-{self.language}-{self.cwe.lower()}"

    @property
    def rule_id(self) -> str:
        return f"traust-{self.language}-sweep-{self.cwe.lower()}"

    @classmethod
    def of(cls, swept: SweepClass, members: Sequence[SweepFinding]) -> SweepDraft:
        return cls(
            cwe=swept.cwe,
            language=swept.language,
            count=swept.count,
            repos=len(swept.repos),
            severity="ERROR"
            if any(m.severity in ("critical", "high") for m in members)
            else "WARNING",
            sources=tuple(
                DraftSource(
                    source_finding=m.finding_id or "(unkeyed)",
                    repo=m.repo,
                    url=m.url,
                    file=m.file,
                    line=m.line,
                    artifact=f"{m.source}:{m.artifact}",
                )
                for m in members[:8]
            ),
        )


class DraftSkip(Model):
    class_id: str
    reason: str


class SweepDrafts(Model):
    """The draft stage's state: the drafts staged this run and each class skipped, with why."""

    stage: str = "draft"
    generated: datetime
    pack: str
    drafts_dir: str
    emitted: tuple[str, ...] = ()
    skipped: tuple[DraftSkip, ...] = ()


class RuleFile(Model):
    """A rule resolved from a `--rule` spec: its ids, whether it is still an unauthored skeleton,
    and the confirmed findings its metadata cites."""

    path: Path
    ids: tuple[str, ...]
    unauthored: bool
    provenance: tuple[JsonValue, ...] = ()

    def rule_id(self, spec: str) -> str:
        return spec if spec in self.ids else self.ids[0]


class SweepRepo(Dto):
    slug: str
    url: str


class RuleHit(Dto):
    """One opengrep match, as core's opengrep tool door normalises it."""

    rule_id: str
    severity_hint: str | None = None
    file: str
    start_line: int
    end_line: int
    message: str = ""
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    owasp_llm: tuple[str, ...] = ()
    confidence: JsonValue = None
    taint: bool = False
    snippet: str = ""
    test_path: bool = False
    nosem_marked: bool = False


class RepoSweep(Model):
    """One repository's sweep with one rule: hits, or the error that stopped it."""

    slug: str
    url: str | None = None
    rule_id: str = ""
    rule_path: str = ""
    error: str | None = None
    detail: str | None = None
    files_scanned: int | None = None
    engine_errors: int | None = None
    facts: tuple[RuleHit, ...] = ()


class RuleSweepRequest(Dto):
    """One rule (id, yaml path or draft name) over the corpus, or over `repos` when given."""

    rule: str
    limit: int = DEFAULT_SWEEP_LIMIT
    repos: tuple[SweepRepo, ...] | None = None
    work_dir: Path | None = None
    binary: str = "opengrep"
    timeout: int = 600


class RuleSweep(Model):
    rule_id: str
    rule_path: str
    repos: int
    swept: int
    skipped: int
    repo_errors: int
    hits: int
    repo_results: str


class RuleSweepCandidate(Model):
    """One sweep hit in the sweep-candidates shape /triage ingests: a candidate, never a finding."""

    repo: str
    url: str | None
    file: str
    line: int
    end_line: int
    location: str
    excerpt: str
    rule_id: str
    severity_hint: str | None
    test_path: bool
    source_finding_provenance: tuple[str, ...]


class RepoHits(Model):
    repo: str
    hits: int
    error: str | None = None


class SweepCandidates(Model):
    artifact: str = "sweep-candidates"
    purpose: str = SWEEP_PURPOSE
    generated: datetime
    harness_version: str
    rule_id: str
    rule_path: str
    source_findings: tuple[JsonValue, ...] = ()
    repos_swept: int
    repos_with_hits: int
    repo_errors: int
    candidates: tuple[RuleSweepCandidate, ...] = ()


class SweepEmit(Model):
    """`skipped` when the rule's candidates exist and the run wasn't forced; else the
    candidates file and its markdown summary."""

    rule_id: str
    skipped: bool
    out: str
    candidates: SweepCandidates | None = None
    summary: str | None = None


# Rule-mining lane: mine -> collect/draft -> regression drafts -> delta vs the previous mine.
# Deterministic stages only: authoring and calibration follow in the scheduled session.
PRECISION_GATE = 0.5  # the opengrep-ruleset plan's ~50% precision gate
DEFAULT_DRAFT_LIMIT = 6
# Languages whose Stage-A calibration is blocked on ground truth, and the candidate external packs
# tested against them (a pack enters when it is a promotion candidate, not when it is fetchable).
# PENDING(config: tool execution API follow-up — pins become config)
WATCHED_LANGS = ("rust", "c", "cpp", "csharp")
WATCHED_PACKS = {
    "argus-observe-rules": "https://github.com/smith-xyz/argus-observe-rules"
    "@2a94aebee9a26a7e0325582330c4eed232b984fb",
}


class StageStatus(StrEnum):
    OK = "ok"
    FAILED = "failed"
    SKIPPED = "skipped"


class LaneStage(Model):
    stage: str
    status: StageStatus
    returncode: int = 0
    summary: str = ""


class TpCorpus(Model):
    confirmed_tps: int | None = None
    ruleable_tps: int | None = None
    growth: int | None = None


class NewCluster(Model):
    cluster: str
    count: int
    repos: int
    example_findings: tuple[str, ...] = ()


class ResolvedCluster(Model):
    cluster: str
    previous_count: int


class ChangedCluster(Model):
    cluster: str
    previous_count: int
    count: int


class GateDirection(StrEnum):
    ENTERED_BELOW = "entered_below_gate"
    FELL_BELOW = "fell_below_gate"
    ROSE_ABOVE = "rose_above_gate"


class GateCrossing(Model):
    rule: RuleId
    previous_precision: float | None
    precision: float
    direction: GateDirection


class Attention(Model):
    needed: bool = False
    reasons: tuple[str, ...] = ()

    def plus(self, reason: str) -> Attention:
        return Attention(needed=True, reasons=(*self.reasons, reason))


class LanguageReach(Model):
    repos: int
    max_span: int
    widest_covered_cwe: str | None = None
    reachable: bool


class PackReach(Model):
    available: bool
    reason: str | None = None
    languages: dict[str, LanguageReach] = Field(default_factory=dict)


class Reachability(Model):
    """Per watched language and pack: can a rule clear the rediscovery gate yet?"""

    available: bool
    reason: str | None = None
    gate: int = REDISCOVERY_GATE
    packs: dict[str, PackReach] = Field(default_factory=dict)


class ReachDirection(StrEnum):
    OPENED = "opened"
    CLOSED = "closed"


class ReachCrossing(Model):
    pack: str
    language: str
    direction: ReachDirection
    max_span: int
    widest_covered_cwe: str | None = None
    repos: int


class Allowlist(Model):
    """The rules `rule-pack-allowlist.yaml` enables, or why it couldn't be read."""

    rules: frozenset[str] = frozenset()
    unreadable: str | None = None


class AllowlistRow(Model):
    rule: str
    precision: float
    below_gate: bool
    promoted: int
    dismissed: int


class AllowlistPrecision(Model):
    available: bool
    reason: str | None = None
    enabled: int = 0
    measured: tuple[AllowlistRow, ...] = ()
    unmeasured: tuple[str, ...] = ()
    below_gate: tuple[AllowlistRow, ...] = ()


class LaneDelta(Model):
    """This run's mine against the previous one; a run with no previous mine is a baseline:
    the picture is inventory, not news."""

    generated_at: datetime
    precision_gate: float = PRECISION_GATE
    baseline: bool
    tp_corpus: TpCorpus
    new_uncovered_clusters: tuple[NewCluster, ...] = ()
    resolved_uncovered_clusters: tuple[ResolvedCluster, ...] = ()
    changed_uncovered_clusters: tuple[ChangedCluster, ...] = ()
    precision_gate_crossings: tuple[GateCrossing, ...] = ()
    attention: Attention = Attention()
    drafts_staged: int = 0
    reachability: Reachability | None = None
    reachability_crossings: tuple[ReachCrossing, ...] = ()
    allowlist_precision: AllowlistPrecision | None = None
    stages: tuple[LaneStage, ...] = ()


class RuleLaneRequest(Dto):
    draft_limit: int = Field(default=DEFAULT_DRAFT_LIMIT, ge=0)
    skip_sweep: bool = False
    allowlist: Allowlist | None = None  # None: no rule-pack-allowlist.yaml


class RuleLane(Model):
    """The lane's stages, this run's mine and its delta (both None when the mine failed)."""

    stages: tuple[LaneStage, ...]
    mining: RuleMining | None = None
    delta: LaneDelta | None = None
    mining_report: str | None = None  # rule-mining.md
    delta_report: str | None = None  # lane-delta.md

    @property
    def failed(self) -> bool:
        return any(s.status == StageStatus.FAILED for s in self.stages)

    @property
    def exit_code(self) -> int:
        """0 quiet, 1 attention needed, 2 a stage failed."""
        if self.failed or self.delta is None:
            return 2
        return 1 if self.delta.attention.needed else 0
