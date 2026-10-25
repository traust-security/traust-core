from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import NewType, get_args
from uuid import UUID

from pydantic import AliasChoices, BaseModel, Field, JsonValue
from pydantic import ValidationError as PydanticValidationError

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import Dto, Model
from traust_core.v1.models.code_facts import ConfigTriple, RouteGuardRow, SanitizerFact, SymbolFact
from traust_core.v1.models.common import ArtifactRef, TimeWindow
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
    auditor_versions: tuple[str, ...] = ()


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
            auditor_versions=self.auditor_versions,
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


# Rule-pack calibration: a pack's scans scored against confirmed true positives, path-level.
# >= 3 repositories rediscovered is the economics gate (opengrep-ruleset plan), not correctness.
REDISCOVERY_GATE = 3


class RuleCalibration(Model):
    rule: RuleId
    fires: int = 0
    rediscoveries: int = 0
    novel: int = 0
    repos_fired: int = 0
    repos_rediscovered: int = 0

    @property
    def clears_gate(self) -> bool:
        return self.repos_rediscovered >= REDISCOVERY_GATE


class GateReachability(Model):
    """The widest CWE the pack has rules for, by repositories holding its confirmed TPs."""

    repositories: int
    cwe: str | None = None

    @property
    def reachable(self) -> bool:
        return self.repositories >= REDISCOVERY_GATE


class ScanFailure(Model):
    """A pack scan that can't be scored: never read as a clean scan."""

    assessment_id: UUID
    reason: str


class NovelHit(Model):
    repository_id: UUID
    rule: RuleId
    path: str


class Calibration(Model):
    """Rediscovery and volume of a pack's scans; precision accrues from audits (`mine_rules`)."""

    pack: RulePack
    scans: int
    tp_files: int
    rules: tuple[RuleCalibration, ...] = ()
    failed: tuple[ScanFailure, ...] = ()
    reachability: GateReachability
    novel_sample: tuple[NovelHit, ...] = ()

    @property
    def scanned(self) -> int:
        return self.scans - len(self.failed)

    @property
    def findings(self) -> int:
        return sum(r.fires for r in self.rules)

    @property
    def rediscoveries(self) -> int:
        return sum(r.rediscoveries for r in self.rules)

    @property
    def findings_per_repo(self) -> float | None:
        return round(self.findings / self.scanned, 1) if self.scanned else None


# Rule drafts: no contracts schema or table holds them yet (see DetectionQualityService.drafts).
class RuleDraftSource(Model): ...


class RuleDraftStatus(Model): ...


class Language(Model): ...


class RuleDraft(Model):
    source: RuleDraftSource
    language: Language
    artifact: ArtifactRef
    status: RuleDraftStatus


# Canaries: seeded benchmark targets materialised as local repositories.
class CanaryKind(StrEnum):
    CANARY = "canary"  # prompt-injection canary: an injection block, one expected finding
    SEEDED = "seeded"  # synthetic app: one expected finding per planted defect

    @property
    def answer_key(self) -> str:
        """The file holding the answers: never committed into the materialised repository."""
        return "seed.yaml" if self == CanaryKind.SEEDED else "canary.yaml"


class SeededFinding(Model):
    cwes: tuple[str, ...]
    paths: tuple[str, ...]
    severity: str
    title: str = ""


class CanaryInjection(Model):
    injection_class: str
    tokens: tuple[str, ...]


class CanarySource(Model):
    """A canary or seeded fixture: its answer key and the files of the tree that gets committed."""

    name: str
    kind: CanaryKind
    recipe: str
    expected: tuple[SeededFinding, ...]
    tree: tuple[str, ...]
    language: str | None = None
    injection: CanaryInjection | None = None


class CanaryRepo(Model):
    """A materialised canary: a local repository whose HEAD is deterministic per content."""

    repo_url: str
    sha: str


class Canary(Model):
    target_id: BenchmarkTargetId
    repo: CanaryRepo
    source: CanarySource


class BenchmarkFilter(Model):
    """Which benchmark audits to score: by auditor version, held-out targets only at release."""

    auditor_version: str | None = None
    include_held_out: bool = False


# Critical misses: a critical finding first reported after an audit of its repository missed it.
class MissReason(StrEnum):
    MISSED = "missed"  # the audit reported nothing at any of the finding's paths
    AREA_REPORTED = "area_reported"  # it reported something there: for adjudication, not a hit


class CriticalMiss(Model):
    finding_id: UUID
    repository_id: UUID
    title: str
    found_by: UUID
    found_at: datetime
    missed_by: UUID
    reason: MissReason
    validity: str | None = None


class MissFilter(Model):
    window: TimeWindow
    repository_id: UUID | None = None
    reason: MissReason | None = None


# Compliance field precision: a human override reversing a check's not_satisfied is a dismissal.
COMPLIANCE_PRECISION_GATE = 0.5


class CheckPrecision(Model):
    check_id: str
    fired: int
    dismissed: int

    @property
    def precision(self) -> float | None:
        return _ratio(self.fired - self.dismissed, self.fired)

    @property
    def flagged(self) -> bool:
        """At or under the gate: a candidate for demotion to evidence_review (a reviewed change)."""
        return self.precision is not None and self.precision <= COMPLIANCE_PRECISION_GATE


class ComplianceCalibration(Model):
    framework: ComplianceFramework
    assessments: int
    checks: tuple[CheckPrecision, ...] = ()


# Semantic precedent cards: a confirmed finding generalised into a code-facts enumerator, a
# predicate over its rows and the one question a judge answers per matched row.
class CardEnumerator(StrEnum):
    CONFIG_MATRIX = "config-matrix"
    ROUTE_GUARDS = "route-guards"
    SANITIZER_PROBES = "sanitizer-probes"
    SYMBOL_INDEX = "symbol-index"


class PredicateOp(StrEnum):
    EQ = "eq"
    NE = "ne"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    MATCHES = "matches"
    GTE = "gte"
    LTE = "lte"
    EMPTY = "empty"
    NOT_EMPTY = "not_empty"
    TRUTHY = "truthy"
    FALSY = "falsy"


_VALUE_FREE_OPS = frozenset(
    {PredicateOp.EMPTY, PredicateOp.NOT_EMPTY, PredicateOp.TRUTHY, PredicateOp.FALSY}
)


def _blank(value: object) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _number(value: object) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _at(row: Mapping[str, JsonValue], dotted: str) -> JsonValue:
    value: JsonValue = row  # type: ignore[assignment]
    for part in dotted.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


class Predicate(Model):
    """A filter over one enumerator row: a leaf (`field` `op` `value`) or one of all/any/not."""

    all_of: tuple[Predicate, ...] = Field(default=(), alias="all")
    any_of: tuple[Predicate, ...] = Field(default=(), alias="any")
    negated: Predicate | None = Field(default=None, alias="not")
    field: str | None = None
    op: PredicateOp | None = None
    value: JsonValue = None

    def matches(self, row: Mapping[str, JsonValue]) -> bool:
        if self.all_of:
            return all(p.matches(row) for p in self.all_of)
        if self.any_of:
            return any(p.matches(row) for p in self.any_of)
        if self.negated is not None:
            return not self.negated.matches(row)
        assert self.field is not None and self.op is not None
        got, want = _at(row, self.field), self.value
        if self.op in (PredicateOp.GTE, PredicateOp.LTE):
            a, b = _number(got), _number(want)
            if got is None or a is None or b is None:
                return False
            return a >= b if self.op is PredicateOp.GTE else a <= b
        if self.op in (PredicateOp.CONTAINS, PredicateOp.NOT_CONTAINS):
            hit = want in got if isinstance(got, list) else str(want) in str(got or "")
            return hit == (self.op is PredicateOp.CONTAINS)
        return {
            PredicateOp.EQ: lambda: got == want,
            PredicateOp.NE: lambda: got != want,
            PredicateOp.IN: lambda: got in (want or []),  # type: ignore[operator]
            PredicateOp.NOT_IN: lambda: got not in (want or []),  # type: ignore[operator]
            PredicateOp.MATCHES: lambda: bool(re.search(str(want), str(got or ""), re.IGNORECASE)),
            PredicateOp.EMPTY: lambda: _blank(got),
            PredicateOp.NOT_EMPTY: lambda: not _blank(got),
            PredicateOp.TRUTHY: lambda: bool(got),
            PredicateOp.FALSY: lambda: not got,
        }[self.op]()


class SymbolMode(StrEnum):
    DEFS = "defs"
    REFS = "refs"


class SymbolLookup(Model):
    mode: SymbolMode
    name: str


class CardOptions(Dto):
    """`run` acknowledges that probing executes the checkout's code; `query` names the symbol."""

    run: bool = False
    query: SymbolLookup | None = None


class CardSource(Dto):
    finding_id: str = Field(validation_alias=AliasChoices("finding_id", "id"))


class PrecedentCard(Dto):
    id: str
    source_findings: tuple[CardSource, ...]
    weakness_shape: str
    enumerator: CardEnumerator
    enumerator_options: CardOptions = CardOptions()
    predicate: Predicate
    judge_question: str
    expected_fp_sources: tuple[str, ...]
    severity_hint: str = "medium"


class RejectedCard(Model):
    """A card that is not a recipe, with every reason; `expect_reject` pins a deliberate reject."""

    id: str
    expect_reject: bool
    reasons: tuple[str, ...]


def fact_fields(model: type[BaseModel], prefix: str = "") -> frozenset[str]:
    """The dotted field paths a model's JSON carries, by serialised name."""
    paths: set[str] = set()
    for name, info in model.model_fields.items():
        key = prefix + (info.serialization_alias or name)
        nested = next(
            (a for a in get_args(info.annotation) or (info.annotation,) if _is_model(a)), None
        )
        paths |= fact_fields(nested, f"{key}.") if nested else {key}
    return frozenset(paths)


def _is_model(annotation: object) -> bool:
    return isinstance(annotation, type) and issubclass(annotation, BaseModel)


_PROBE_RUN_FIELDS = frozenset({"outcome", "survived", "errors", "reason", "transcript"})
_SYMBOL_REF_FIELDS = frozenset({"path", "line", "is_def", "text"})
_CARD_ROWS: dict[CardEnumerator, type[BaseModel]] = {
    CardEnumerator.CONFIG_MATRIX: ConfigTriple,
    CardEnumerator.ROUTE_GUARDS: RouteGuardRow,
    CardEnumerator.SANITIZER_PROBES: SanitizerFact,
    CardEnumerator.SYMBOL_INDEX: SymbolFact,
}
_REQUIRED_CARD_FIELDS = (
    "id",
    "source_findings",
    "weakness_shape",
    "enumerator",
    "judge_question",
    "expected_fp_sources",
)
# A card carrying any of these is a checklist wearing a card's clothes: rejected, not ignored.
_PROSE_FIELDS = frozenset(
    {"checklist", "instructions", "steps", "prompt", "review_guidance", "things_to_look_for"}
)
_SEVERITY_HINTS = ("critical", "high", "medium", "low", "info")


def _card_fields(card: Mapping[str, object]) -> tuple[frozenset[str] | None, list[str]]:
    name = card.get("enumerator")
    if name not in set(CardEnumerator):
        return None, [
            f"unknown_enumerator: {name!r} is not a shipped deterministic enumerator "
            f"({', '.join(sorted(CardEnumerator))})"
        ]
    enumerator = CardEnumerator(str(name))
    options = card.get("enumerator_options")
    options = options if isinstance(options, Mapping) else {}
    fields = fact_fields(_CARD_ROWS[enumerator])
    if enumerator is CardEnumerator.SANITIZER_PROBES and options.get("run") is True:
        return fields | _PROBE_RUN_FIELDS, []
    if enumerator is CardEnumerator.SYMBOL_INDEX:
        query = options.get("query") or {}
        mode = query.get("mode") if isinstance(query, Mapping) else None
        if mode not in set(SymbolMode) or not query.get("name"):  # type: ignore[union-attr]
            return None, [
                "symbol_index_query_missing: symbol-index cards must declare "
                "enumerator_options.query = {mode: defs|refs, name: <symbol>}"
            ]
        return (_SYMBOL_REF_FIELDS if mode == SymbolMode.REFS else fields), []
    return fields, []


def _predicate_errors(node: object, fields: frozenset[str], path: str = "predicate") -> list[str]:
    if not isinstance(node, Mapping) or not node:
        return [f"{path}: predicate node must be a non-empty mapping"]
    if combos := [k for k in ("all", "any", "not") if k in node]:
        if len(node) != 1:
            return [f"{path}: combinator node must contain exactly one of all/any/not"]
        key = combos[0]
        if key == "not":
            return _predicate_errors(node["not"], fields, f"{path}.not")
        kids = node[key]
        if not isinstance(kids, list) or not kids:
            return [f"{path}.{key}: must be a non-empty list"]
        return [
            e
            for i, kid in enumerate(kids)
            for e in _predicate_errors(kid, fields, f"{path}.{key}[{i}]")
        ]
    errors: list[str] = []
    field, op = node.get("field"), node.get("op")
    if not isinstance(field, str) or not field:
        errors.append(f"{path}: leaf needs a `field`")
    elif field not in fields:
        errors.append(
            f"{path}: field {field!r} is not in the enumerator's output schema — a predicate "
            f"over fields the enumerator never emits is prose, not a recipe (known fields: "
            f"{', '.join(sorted(fields))})"
        )
    if op not in set(PredicateOp):
        errors.append(f"{path}: unknown op {op!r} (ops: {', '.join(sorted(PredicateOp))})")
    elif op not in _VALUE_FREE_OPS and "value" not in node:
        errors.append(f"{path}: op {op!r} requires a `value`")
    elif op in _VALUE_FREE_OPS and "value" in node:
        errors.append(f"{path}: op {op!r} takes no `value`")
    if op == PredicateOp.MATCHES and "value" in node:
        try:
            re.compile(str(node["value"]))
        except re.error as e:
            errors.append(f"{path}: bad regex for `matches`: {e}")
    if extra := sorted(set(node) - {"field", "op", "value"}):
        errors.append(f"{path}: unknown leaf keys {extra}")
    return errors


def _card_errors(card: Mapping[str, object]) -> list[str]:
    errors = [f"missing_required: `{f}`" for f in _REQUIRED_CARD_FIELDS if not card.get(f)]
    if prose := sorted(_PROSE_FIELDS & set(card)):
        errors.append(
            f"prose_checklist_fields: {prose} — cards compile to worklist generators, never to "
            "review prose"
        )
    sources = card.get("source_findings")
    if sources is not None and not (
        isinstance(sources, list)
        and all(isinstance(s, Mapping) and (s.get("finding_id") or s.get("id")) for s in sources)
    ):
        errors.append(
            "source_findings: must be a list of mappings each carrying a finding_id/id "
            "(provenance is part of the recipe)"
        )
    if (hint := card.get("severity_hint")) is not None and hint not in _SEVERITY_HINTS:
        errors.append(f"severity_hint: {hint!r} not in {sorted(_SEVERITY_HINTS)}")
    fields, field_errors = _card_fields(card)
    errors += field_errors
    if not (predicate := card.get("predicate")):
        errors.append(
            "no_predicate: card has no filter predicate over an enumerator's output — that is "
            "a prose checklist, rejected"
        )
    elif fields is not None:
        errors += _predicate_errors(predicate, fields)
    return errors


class CardDeck(Model):
    """A card file parsed: the valid cards and the rejected ones, each with all its reasons."""

    cards: tuple[PrecedentCard, ...] = ()
    rejected: tuple[RejectedCard, ...] = ()

    @property
    def unexpected(self) -> tuple[RejectedCard, ...]:
        return tuple(r for r in self.rejected if not r.expect_reject)

    @classmethod
    def parse(cls, document: object) -> CardDeck:
        raw = document.get("cards") if isinstance(document, Mapping) else None
        if not isinstance(raw, list):
            raise ValidationError("precedent cards: expected a top-level `cards:` list")
        cards: list[PrecedentCard] = []
        rejected: list[RejectedCard] = []
        for card in raw:
            if not isinstance(card, Mapping):
                rejected.append(
                    RejectedCard(
                        id="(unnamed)", expect_reject=False, reasons=("card must be a mapping",)
                    )
                )
                continue
            errors = _card_errors(card)
            if not errors:
                try:
                    cards.append(PrecedentCard.model_validate(card))
                    continue
                except PydanticValidationError as e:
                    errors = [f"{'.'.join(map(str, x['loc']))}: {x['msg']}" for x in e.errors()]
            rejected.append(
                RejectedCard(
                    id=str(card.get("id") or "(unnamed)"),
                    expect_reject=bool(card.get("expect_reject")),
                    reasons=tuple(errors),
                )
            )
        return cls(cards=tuple(cards), rejected=tuple(rejected))


class CardStatus(StrEnum):
    COMPILED = "compiled"
    NOT_RUN = "not_run"  # the card's rows need a door core doesn't have; `reason` names it


class CardRun(Model):
    id: str
    enumerator: CardEnumerator
    status: CardStatus
    rows_enumerated: int = 0
    matched: int = 0
    reason: str | None = None


class SweepCandidate(Model):
    """One matched row in the sweep-candidates shape /triage ingests: a candidate, never a
    finding; the card's judge question rides along for the verifier."""

    repo: str
    url: str
    file: str | None
    line: int | None
    end_line: int | None
    location: str
    excerpt: str
    rule_id: str
    severity_hint: str
    test_path: bool
    source_finding_provenance: tuple[str, ...]
    origin: str = "semantic-sweep"
    card_id: str
    enumerator: CardEnumerator
    judge_question: str
    expected_fp_sources: tuple[str, ...]

    @classmethod
    def of(cls, card: PrecedentCard, row: BaseModel, repo: str, url: str) -> SweepCandidate:
        file, line, excerpt = _site(row)
        return cls(
            repo=repo,
            url=url,
            file=file,
            line=line,
            end_line=line,
            location=f"{file}:{line}" if line else str(file),
            excerpt=excerpt[:400],
            rule_id=card.id,
            severity_hint=card.severity_hint,
            test_path=bool(file and _TEST_PATH.search(file)),
            source_finding_provenance=tuple(s.finding_id for s in card.source_findings),
            card_id=card.id,
            enumerator=card.enumerator,
            judge_question=card.judge_question,
            expected_fp_sources=card.expected_fp_sources,
        )


_TEST_PATH = re.compile(r"(^|/)(tests?|testdata|fixtures?|mocks?|examples?)(/|$)|_test\.")


def _site(row: BaseModel) -> tuple[str | None, int | None, str]:
    """Where a matched row points and the excerpt a verifier reads."""
    match row:
        case ConfigTriple(source=src, sink=sink):
            return (
                src.path,
                src.line,
                (
                    f"{row.key}={row.effective_default} [system={src.system} "
                    f"class={row.config_class} sink={sink.status}]"
                ),
            )
        case RouteGuardRow(registration=reg, handler=handler):
            return (
                reg.path,
                reg.line,
                (
                    f"{row.method} {row.pattern} -> {handler.expr} [guards={list(row.guards)} "
                    f"scope_guards={list(row.scope_guards)} unguards={list(row.unguard_markers)}"
                    f"{' ASYMMETRY' if row.asymmetry else ''}]"
                ),
            )
        case SanitizerFact():
            return row.path, row.line, f"{row.function}({row.arg}) outcome=discovered survived=n/a"
        case SymbolFact(location=loc):
            return loc.path, loc.line, f"{row.kind} {row.name} ({row.language})"
    raise ValidationError(f"no candidate shape for a {type(row).__name__} row")


class CardSweep(Model):
    repo: str
    cards: tuple[CardRun, ...] = ()
    candidates: tuple[SweepCandidate, ...] = ()
