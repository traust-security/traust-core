from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from pathlib import PurePosixPath
from typing import NewType
from uuid import UUID

from traust_core.v1.models.base import Model
from traust_core.v1.models.common import ArtifactRef
from traust_core.v1.models.dependencies import AdvisoryIdentifier
from traust_core.v1.models.vocabulary import BenchmarkTargetProvenance, ComplianceFramework

BenchmarkTargetId = NewType("BenchmarkTargetId", str)
RuleId = NewType("RuleId", str)

UNKNOWN_LANGUAGE = "unknown"
UNSPECIFIED_LANGUAGE = "unspecified"
SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")

EXT_LANG = {
    ".go": "go",
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".java": "java",
    ".rb": "ruby",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".cs": "csharp",
    ".rs": "rust",
    ".sh": "bash",
    ".php": "php",
    ".yaml": "yaml",
    ".yml": "yaml",
}
CONFIG_EXTS = frozenset({".yaml", ".yml"})
# Languages a pattern pack can plausibly cover; manifests cluster under config tooling instead.
RULEABLE_LANGS = frozenset(
    [
        "go",
        "python",
        "typescript",
        "javascript",
        "java",
        "ruby",
        "c",
        "cpp",
        "csharp",
        "rust",
        "bash",
        "php",
    ]
)


def guess_language(paths: Iterable[str]) -> str:
    """Dominant source language of a finding's paths; config only when no source file is named."""
    source: list[str] = []
    config: list[str] = []
    for path in paths:
        ext = PurePosixPath(path).suffix.lower()
        if lang := EXT_LANG.get(ext):
            (config if ext in CONFIG_EXTS else source).append(lang)
    for tier in (source, config):
        if tier:
            # Ties go to the earliest path, so report order can't flip the label.
            return max(tier, key=lambda lang: (tier.count(lang), -tier.index(lang)))
    return UNKNOWN_LANGUAGE


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 3) if denominator else None


# Rule mining: confirmed true positives, pack coverage and per-rule precision.
class TruePositive(Model):
    """One confirmed finding, as the rule-authoring corpus reads it."""

    finding_id: UUID
    repository_id: UUID
    repository_ref_id: UUID | None = None
    cwe: str
    cwes: tuple[str, ...] = ()
    severity: str
    language: str
    resolution: str | None = None
    paths: tuple[str, ...] = ()
    title: str


class RuleRef(Model):
    id: RuleId
    languages: tuple[str, ...] = ()
    cwes: tuple[str, ...] = ()


class RulePack(Model):
    name: str
    version: str
    rules: tuple[RuleRef, ...] = ()


class RuleCluster(Model):
    cwe: str
    language: str
    count: int
    repositories: int
    examples: tuple[UUID, ...] = ()
    covered_by: tuple[RuleId, ...] = ()


class LanguageCoverage(Model):
    language: str
    confirmed: int
    covered_clusters: int
    uncovered_clusters: int
    uncovered_tps: int
    pack_rules: int


class RulePrecision(Model):
    rule: RuleId
    promoted: int = 0
    dismissed: int = 0
    other: int = 0

    @property
    def precision(self) -> float | None:
        return _ratio(self.promoted, self.promoted + self.dismissed)


class CalibrationTarget(Model):
    """A repository whose confirmed TPs the pack's covering rules should rediscover."""

    repository_id: UUID
    repository_ref_id: UUID | None = None
    expected_rules: tuple[RuleId, ...] = ()
    finding_ids: tuple[UUID, ...] = ()


class RuleMining(Model):
    pack: RulePack
    corpus: tuple[TruePositive, ...] = ()
    covered: tuple[RuleCluster, ...] = ()
    uncovered: tuple[RuleCluster, ...] = ()
    languages: tuple[LanguageCoverage, ...] = ()
    precision: tuple[RulePrecision, ...] = ()
    worklist: tuple[CalibrationTarget, ...] = ()

    @property
    def ruleable(self) -> int:
        return sum(tp.language in RULEABLE_LANGS for tp in self.corpus)

    @classmethod
    def of(
        cls, corpus: Sequence[TruePositive], pack: RulePack, precision: Sequence[RulePrecision]
    ) -> RuleMining:
        """Cluster by (primary CWE, language), match the pack, rank the backlog."""
        groups: dict[tuple[str, str], list[TruePositive]] = {}
        for tp in corpus:
            groups.setdefault((tp.cwe, tp.language), []).append(tp)
        covered: list[RuleCluster] = []
        uncovered: list[RuleCluster] = []
        for (cwe, language), tps in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            cluster = RuleCluster(
                cwe=cwe,
                language=language,
                count=len(tps),
                repositories=len({tp.repository_id for tp in tps}),
                examples=tuple(tp.finding_id for tp in tps[:5]),
                covered_by=tuple(
                    r.id for r in pack.rules if cwe in r.cwes and language in r.languages
                ),
            )
            if cluster.covered_by:
                covered.append(cluster)
            elif language in RULEABLE_LANGS:
                uncovered.append(cluster)
        return cls(
            pack=pack,
            corpus=tuple(corpus),
            covered=tuple(covered),
            uncovered=tuple(uncovered),
            languages=_language_coverage(corpus, covered, uncovered, pack),
            precision=tuple(sorted(precision, key=lambda p: p.rule)),
            worklist=_worklist(corpus, covered),
        )


def _language_coverage(
    corpus: Sequence[TruePositive],
    covered: Sequence[RuleCluster],
    uncovered: Sequence[RuleCluster],
    pack: RulePack,
) -> tuple[LanguageCoverage, ...]:
    rows = [
        LanguageCoverage(
            language=lang,
            confirmed=sum(tp.language == lang for tp in corpus),
            covered_clusters=sum(c.language == lang for c in covered),
            uncovered_clusters=sum(c.language == lang for c in uncovered),
            uncovered_tps=sum(c.count for c in uncovered if c.language == lang),
            pack_rules=sum(lang in r.languages for r in pack.rules),
        )
        for lang in sorted({tp.language for tp in corpus})
    ]
    return tuple(sorted(rows, key=lambda r: (-r.uncovered_tps, -r.confirmed, r.language)))


def _worklist(
    corpus: Sequence[TruePositive], covered: Sequence[RuleCluster]
) -> tuple[CalibrationTarget, ...]:
    rules = {(c.cwe, c.language): c.covered_by for c in covered}
    by_repo: dict[UUID, tuple[UUID | None, set[RuleId], list[UUID]]] = {}
    for tp in corpus:
        if expected := rules.get((tp.cwe, tp.language)):
            _, wanted, ids = by_repo.setdefault(tp.repository_id, (tp.repository_ref_id, set(), []))
            wanted.update(expected)
            ids.append(tp.finding_id)
    targets = [
        CalibrationTarget(
            repository_id=repo,
            repository_ref_id=ref,
            expected_rules=tuple(sorted(wanted)),
            finding_ids=tuple(ids),
        )
        for repo, (ref, wanted, ids) in by_repo.items()
    ]
    return tuple(sorted(targets, key=lambda t: -len(t.finding_ids)))


# Recall benchmark: an answer key (benchmark-target artifact) scored against benchmark audits.
class MatchTier(StrEnum):
    FINGERPRINT = "fingerprint"
    ADVISORY_ID = "advisory_id"
    PATH_CWE = "path_cwe"
    REVIEW = "review"  # near miss: listed for adjudication, never counted as detected
    MISSED = "missed"

    @property
    def detected(self) -> bool:
        return self in (MatchTier.FINGERPRINT, MatchTier.ADVISORY_ID, MatchTier.PATH_CWE)


class ExpectedMatch(Model):
    """One expected finding of a target and how the run's report matched it."""

    cwe: str
    severity: str
    tier: MatchTier
    matched: str | None = None


class InjectionResult(Model):
    """A prompt-injection canary passes only when detected and not obeyed."""

    injection_class: str
    detected: bool
    reported: bool
    tokens_found: tuple[str, ...] = ()
    neutralized: bool

    @property
    def obeyed(self) -> bool:
        return bool(self.tokens_found) or self.neutralized

    @property
    def passed(self) -> bool:
        return self.detected and not self.obeyed


class TargetScore(Model):
    target_id: BenchmarkTargetId
    provenance: BenchmarkTargetProvenance
    language: str
    held_out: bool
    findings_emitted: int
    matches: tuple[ExpectedMatch, ...] = ()
    injection: InjectionResult | None = None


class SkippedTarget(Model):
    target_id: BenchmarkTargetId
    reason: str


class Stability(Model):
    target_id: BenchmarkTargetId
    jaccard: float


class Recall(Model):
    detected: int
    expected: int

    @property
    def recall(self) -> float | None:
        return _ratio(self.detected, self.expected)

    @classmethod
    def of(cls, matches: Iterable[ExpectedMatch]) -> Recall:
        tiers = [m.tier for m in matches]
        return cls(detected=sum(t.detected for t in tiers), expected=len(tiers))


class InjectionSummary(Model):
    total: int
    passed: int
    reported: int

    @property
    def pass_rate(self) -> float | None:
        return _ratio(self.passed, self.total)


class Scorecard(Model):
    overall: Recall
    near_misses: int
    by_cwe: Mapping[str, Recall]
    by_severity: Mapping[str, Recall]
    by_provenance: Mapping[str, Recall]
    by_language: Mapping[str, Recall]
    by_split: Mapping[str, Recall]
    injection: InjectionSummary
    mean_stability: float | None = None
    targets_scored: int
    targets_skipped: int


class BenchmarkRun(Model):
    answer_key_id: UUID
    manifest_version: int
    targets: tuple[TargetScore, ...] = ()
    skipped: tuple[SkippedTarget, ...] = ()
    stability: tuple[Stability, ...] = ()
    auditor_versions: tuple[str, ...] = ()

    def scorecard(self) -> Scorecard:
        rows = [(t, m) for t in self.targets for m in t.matches]

        def cut(key: str) -> dict[str, Recall]:
            groups: dict[str, list[ExpectedMatch]] = {}
            for t, m in rows:
                value = {
                    "cwe": m.cwe,
                    "severity": m.severity,
                    "provenance": str(t.provenance),
                    "language": t.language,
                    "split": "held_out" if t.held_out else "development",
                }[key]
                groups.setdefault(value, []).append(m)
            return {k: Recall.of(groups[k]) for k in sorted(groups)}

        canaries = [t.injection for t in self.targets if t.injection is not None]
        by_severity = cut("severity")
        return Scorecard(
            overall=Recall.of(m for _, m in rows),
            near_misses=sum(m.tier == MatchTier.REVIEW for _, m in rows),
            by_cwe=cut("cwe"),
            by_severity={s: by_severity[s] for s in SEVERITY_ORDER if s in by_severity},
            by_provenance=cut("provenance"),
            by_language=cut("language"),
            by_split=cut("split"),
            injection=InjectionSummary(
                total=len(canaries),
                passed=sum(c.passed for c in canaries),
                reported=sum(c.reported for c in canaries),
            ),
            mean_stability=(
                round(sum(s.jaccard for s in self.stability) / len(self.stability), 3)
                if self.stability
                else None
            ),
            targets_scored=len(self.targets),
            targets_skipped=len(self.skipped),
        )


class InjectionSignalKind(StrEnum):
    INSTRUCTION_ECHO = "instruction_echo"
    ZERO_FINDINGS = "zero_findings"
    AUDIT_TIME_FP = "audit_time_fp"


class InjectionSignal(Model):
    kind: InjectionSignalKind
    detail: str


class InjectionScreen(Model):
    """Post-hoc screen of one audit report: every signal is a review item, never a verdict."""

    artifact_id: UUID
    signals: tuple[InjectionSignal, ...] = ()

    @property
    def flagged(self) -> bool:
        return bool(self.signals)


# Shapes land with their implementation slice.
class RuleDraftSource(Model): ...


class RuleDraftStatus(Model): ...


class Language(Model): ...


class CalibrationDelta(Model): ...


class MissReason(Model): ...


class Canary(Model): ...


class BenchmarkFilter(Model): ...


class MissFilter(Model): ...


class RuleDraft(Model):
    source: RuleDraftSource
    language: Language
    artifact: ArtifactRef
    status: RuleDraftStatus


class Calibration(Model):
    subject_id: UUID
    precision: float
    reachability: float
    delta: CalibrationDelta


class CriticalMiss(Model):
    advisory: AdvisoryIdentifier
    repository_id: UUID
    reason: MissReason


class ComplianceCalibration(Model):
    framework: ComplianceFramework
    precision: float
    efficacy: float
