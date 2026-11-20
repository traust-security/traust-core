"""Semantic pattern and taint candidates from opengrep over a checkout, reduced to normalized facts
for the audit skills to judge. A candidate generator, never a verdict.

Rule packs are a swappable input passed by path, never vendored: the deployment's pack
(`Context.register_rule_pack`), its supplemental packs enabled per rule by the allowlist, or the
sources a caller names (a tested local path or an HTTPS git URL pinned `@<sha>`). Registry
shorthands are refused because they provide no local behavioral fixtures. A pinned git source
is a workspace from the checkout service, never a clone of our own."""

from __future__ import annotations

import json
import logging
import re
import shutil
from collections import Counter, defaultdict
from collections.abc import Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass, field
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from traust_core.v1.errors import (
    ScannerError,
    ScannerFailure,
    ServiceError,
    TraustError,
    ValidationError,
)
from traust_core.v1.models import rule_checks
from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.models.rule_mining import ProposalCheck, RuleHit
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.config_matrix import YamlLoader
from traust_core.v1.providers.process import ProcessRunner, ProcessTimeout
from traust_core.v1.providers.sources import CheckoutRequest, Checkouts, Workspace
from traust_core.v1.providers.tools.adapter import adapter_result
from traust_core.v1.providers.tools.opengrep_additions import (
    RuleBatch,
    RuleReceipt,
    protected_ids,
    vet_rules,
)
from traust_core.v1.providers.tools.opengrep_quality import (
    OPENGREP_ENV,
    RuleQualityError,
    checked_rules,
)

log = logging.getLogger(__name__)

SCAN_TIMEOUT = 900
_ADDITIVE_OUTPUT_LIMIT = 4 << 20

TRAUST_PACK_LICENSE = (
    "traust-authored pack: our IP, licensed with the engine, no external restrictions"
)
# Optional internal-run supplement (never the default).
FORK_RULES_REPO = "https://github.com/opengrep/opengrep-rules"
FORK_RULES_SHA = "f1d2b562b414783763fd02a6ed2736eaed622efa"  # 2026-07 pin
FORK_RULES_LICENSE = (
    "LGPL-2.1 + Commons Clause (no-Sell): internal use "
    "OK, commercial redistribution restricted — see "
    "docs/external-dependencies.md"
)
# Optional internal-run supplement, uncalibrated against our ground truth: enable a calibrated
# subset per rule through the allowlist, never wholesale.
ARGUS_RULES_REPO = "https://github.com/smith-xyz/argus-observe-rules"
ARGUS_RULES_SHA = "2a94aebee9a26a7e0325582330c4eed232b984fb"  # 2026-08-05 pin
ARGUS_RULES_LICENSE = (
    "MIT (c) 2026 Argus Observe Rules Contributors: "
    "internal use, redistribution and commercial use "
    "permitted with attribution — see "
    "docs/external-dependencies.md"
)

TEST_PATH_RE = re.compile(r"(^|/)(tests?|e2e|examples?|testdata|hack)(/|$)")
EXCLUDES = ("vendor", "node_modules", "third_party", "_output", ".git")
SEVERITY_HINT = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
_CWE_ID = re.compile(r"^CWE-\d{1,5}")

# target file extensions -> rule pack language directory names
LANG_DIRS = {
    ".go": "go",
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".rb": "ruby",
    ".c": "c",
    ".h": "c",
    ".rs": "rust",
    ".php": "php",
    ".cs": "csharp",
    ".scala": "scala",
    ".kt": "kotlin",
    ".swift": "swift",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".tf": "terraform",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".sh": "bash",
    ".html": "html",
    ".sol": "solidity",
}

# The traust pack keeps its JavaScript rules in typescript/ (each rule declares both languages).
PACK_DIRS = {"javascript": "typescript"}
_LANGUAGE_ALIASES = {
    "bash": ("sh", "shell"),
    "cpp": ("c++",),
    "csharp": ("c#",),
    "go": ("golang",),
    "header": ("c", "c++", "cpp"),
    "javascript": ("js",),
    "kotlin": ("kt",),
    "python": ("py", "python2", "python3"),
    "ruby": ("rb",),
    "rust": ("rs",),
    "solidity": ("sol",),
    "terraform": ("hcl",),
    "typescript": ("ts",),
    "yaml": ("yml",),
}

# Below this many pack rules for a detected language the pre-scan can't seed the review, and the
# audit skills switch that language's manual lanes to the assertive posture. 8 = two-thirds of
# the Go baseline (12); tune only alongside the language-coverage plan.
THIN_RULE_THRESHOLD = 8

# The target's own suppression comments (`# nosemgrep`, `// nosem: rule-id`) are repository
# content, not exemptions: the scan runs with --disable-nosem and flags such facts nosem_marked.
NOSEM_RE = re.compile(r"\bnosem(?:grep)?\b", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class SupplementalPack:
    """An external pack the allowlist enables, and the only rule ids of it that may report."""

    name: str
    source: str
    rules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RuleAllowlist:
    """The only bare rule ids a scan may report, and where they came from."""

    rules: frozenset[str]
    source: str


def resolve_rule_pack_dir(pack: Path) -> Path:
    if not pack.is_dir():
        raise ValueError(f"opengrep rule pack is not a directory: {pack}")
    return pack


def _detect_languages(
    target: Path, extensions: Mapping[str, str], *, additive: bool = False
) -> set[str]:
    dirs: set[str] = set()
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        parts = path.relative_to(target).parts
        if any(part in EXCLUDES for part in (parts[:-1] if additive else parts[:1])):
            continue
        key = path.suffix.lower() if additive else path.suffix
        if lang := extensions.get(key) or extensions.get(path.name):
            dirs.add(lang)
    return dirs


def detect_language_dirs(target: Path) -> set[str]:
    return _detect_languages(target, LANG_DIRS)


def _additive_languages(target: Path) -> set[str]:
    detected = _detect_languages(
        target,
        LANG_DIRS
        | {
            ".ex": "elixir",
            ".exs": "elixir",
            ".h": "header",
            ".hcl": "terraform",
            ".json": "json",
            ".kts": "kotlin",
            ".lua": "lua",
            ".vue": "vue",
            "Dockerfile": "dockerfile",
        },
        additive=True,
    )
    return {
        "generic",
        "regex",
        *detected,
        *(alias for language in detected for alias in _LANGUAGE_ALIASES.get(language, ())),
    }


def _rule_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip().startswith("- id:")
    ]


def pack_rule_counts(pack: Path) -> dict[str, int]:
    """'- id:' rule count per pack language directory."""
    return {
        d.name: sum(len(_rule_lines(y)) for y in [*d.glob("*.yaml"), *d.glob("*.yml")])
        for d in sorted(resolve_rule_pack_dir(pack).iterdir())
        if d.is_dir()
    }


def coverage_block(target: Path, pack: Path) -> dict[str, Any]:
    """Which languages the checkout holds against how many pack rules each has; the audit skills
    decide the posture from it."""
    # Manifest and IaC languages have their own scanners, so they never read as gaps here.
    non_code = {"yaml", "html", "terraform"}
    detected = sorted(detect_language_dirs(target) - non_code)
    counts = pack_rule_counts(pack)
    per_lang = {lang: counts.get(PACK_DIRS.get(lang, lang), 0) for lang in detected}
    return {
        "detected_languages": detected,
        "traust_rules_by_language": per_lang,
        "thin_threshold": THIN_RULE_THRESHOLD,
        "thin_languages": sorted(
            lang for lang, n in per_lang.items() if 0 < n < THIN_RULE_THRESHOLD
        ),
        "uncovered_languages": sorted(lang for lang, n in per_lang.items() if n == 0),
    }


def resolve_rules(
    sources: Sequence[str], target: Path, pack: Path, checkouts: Checkouts
) -> tuple[list[dict[str, Any]], list[Workspace]]:
    """Each rules source as {source, config, sha, license_note}, with the workspaces to release
    when the scan is done; no sources means the pack, filtered to the target's languages."""
    pack = resolve_rule_pack_dir(pack)
    if not sources:
        dirs = {PACK_DIRS.get(lang, lang) for lang in detect_language_dirs(target)}
        lang_paths = [str(pack / d) for d in sorted(dirs) if (pack / d).is_dir()]
        return (
            [
                {
                    "source": "traust rule pack",
                    "config": lang_paths or [str(pack)],
                    "sha": None,
                    "license_note": TRAUST_PACK_LICENSE,
                }
            ],
            [],
        )
    resolved, held = [], []
    try:
        for src in sources:
            if src.strip() == "auto":
                raise ValidationError(
                    "refusing '--rules auto': registry auto-fetch has no "
                    "per-pack license accounting (see "
                    "docs/external-dependencies.md)"
                )
            if re.match(r"^[pr]/[\w./-]+$", src):
                raise ValidationError(
                    "registry-only rules have no local test fixtures; use a tested local "
                    "pack or a pinned HTTPS checkout"
                )
            elif src.startswith(("http://", "https://", "git@")):
                rules, workspace = _git_rules(src, checkouts)
                resolved.append(rules)
                held.append(workspace)
            else:
                path = Path(src).expanduser().resolve()
                if not path.exists():
                    raise ValidationError(f"rules source not found: {src}")
                resolved.append(
                    {
                        "source": src,
                        "config": [str(path)],
                        "sha": None,
                        "license_note": "local rules — license per author",
                    }
                )
    except BaseException:
        for workspace in held:
            checkouts.release(workspace)
        raise
    return resolved, held


def _git_rules(src: str, checkouts: Checkouts) -> tuple[dict[str, Any], Workspace]:
    url, ref = pinned_rules_source(src)
    workspace = checkouts.checkout(
        CheckoutRequest(
            repo=HttpsRepoUrl.parse(url, [urlsplit(url).hostname or ""]), ref=GitSha.parse(ref)
        )
    ).data
    root = rules_root(url, workspace.path)
    configs = [str(root)]
    return {
        "source": src,
        "config": configs,
        "sha": ref,
        "license_note": ARGUS_RULES_LICENSE
        if src.startswith(ARGUS_RULES_REPO)
        else FORK_RULES_LICENSE
        if url.rstrip("/").endswith("opengrep-rules")
        else "verify upstream license before redistribution",
    }, workspace


def pinned_rules_source(src: str) -> tuple[str, str]:
    """A git rules source `URL[@SHA]` as (https URL, 40-hex SHA)."""
    # split only on a trailing ref, never on the git@ host
    m = re.match(
        r"^(?P<url>.+?)@(?P<ref>[A-Za-z0-9._/-]+)$",
        src.replace("://", "\x00", 1).replace("git@", "\x01", 1),
    )
    if m and "/" not in m.group("ref"):
        url = m.group("url").replace("\x00", "://", 1).replace("\x01", "git@", 1)
        ref = m.group("ref")
    else:
        url, ref = (src, (FORK_RULES_SHA if src.rstrip("/") == FORK_RULES_REPO else "HEAD"))
    # a movable ref would change what the scan reports while the report still names the source
    if not re.fullmatch(r"[0-9a-f]{40}", ref):
        raise ValidationError(
            f"rules source {src!r}: ref must be a 40-hex commit "
            "SHA (movable refs change scan results silently)"
        )
    if not url.startswith("https://"):
        raise ValidationError(f"rules source {src!r}: https:// URLs only")
    return url, ref


def rules_root(url: str, dest: Path) -> Path:
    """The rules subtree of a checked-out pack: argus nests its rules under rules/languages/."""
    if not url.rstrip("/").endswith("argus-observe-rules"):
        return dest
    nested = dest / "rules" / "languages"
    return nested if nested.is_dir() else dest / "rules"


def bare_rule_id(check_id: str) -> str:
    """opengrep prefixes a check_id with the rules path, dotted; rule ids never hold a dot, so the
    bare id is the last segment and precision doesn't fragment across path prefixes."""
    return check_id.rsplit(".", 1)[-1] if check_id else check_id


def supplemental_packs(
    packs: Mapping[str, Any], *, base: Path | None = None
) -> list[SupplementalPack]:
    """Enabled, explicitly selected packs; local paths resolve beside the allowlist."""
    out = []
    for name, cfg in packs.items():
        if not isinstance(cfg, dict) or not cfg.get("enabled"):
            continue
        rules = cfg.get("rules")
        source = cfg.get("source")
        if (
            not isinstance(rules, list)
            or not rules
            or any(not isinstance(rule, str) or not rule.strip() for rule in rules)
            or len(set(rules)) != len(rules)
            or not isinstance(source, str)
            or not source.strip()
        ):
            raise ValidationError(f"enabled rule pack {name} needs a source and unique rule ids")
        if not source.startswith(("https://", "http://", "git@")):
            path = Path(source).expanduser()
            if not path.is_absolute():
                if base is None:
                    raise ValidationError(f"relative rule pack {name} needs an allowlist directory")
                path = base / path
            source = str(path.resolve())
        out.append(SupplementalPack(name, source, tuple(rules)))
    return out


def harness_pack_rule_ids(pack: Path) -> set[str]:
    """Every rule id in the pack, so a supplement's allowlist never suppresses our own rules."""
    pack = resolve_rule_pack_dir(pack)
    return {
        line.split(":", 1)[1].strip().strip("\"'")
        for y in [*pack.rglob("*.yaml"), *pack.rglob("*.yml")]
        for line in _rule_lines(y)
    }


def _nosem_marked(extra: dict[str, Any], target: Path, path: str, start: int, end: int) -> bool:
    """Whether the match, or the line above it, carries a nosem comment."""
    if NOSEM_RE.search(extra.get("lines") or ""):
        return True
    if not path or start < 1:
        return False
    file = Path(path) if Path(path).is_absolute() else target / path
    first, last = max(1, start - 1), max(start, end)
    try:
        with file.open(encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                if lineno > last:
                    break
                if lineno >= first and NOSEM_RE.search(line):
                    return True
    except OSError:
        return False
    return False


def _strings(value: Any) -> list[str]:
    return [str(v) for v in ([value] if isinstance(value, str) else value or [])]


def normalize(
    raw: dict[str, Any], target: Path, rule_ids: frozenset[str] = frozenset()
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """opengrep's JSON as (facts, engine errors)."""
    facts = []
    for r in raw.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        path = r.get("path", "")
        try:
            rel = str(Path(path).resolve().relative_to(target))
        except ValueError:
            rel = path
        start = (r.get("start") or {}).get("line", 0)
        end = (r.get("end") or {}).get("line", 0)
        stated = r.get("check_id", "?")
        matching = [rule for rule in rule_ids if stated == rule or stated.endswith("." + rule)]
        rule_id = max(matching, key=len) if matching else bare_rule_id(stated)
        facts.append(
            {
                "rule_id": rule_id,
                "severity_hint": SEVERITY_HINT.get(extra.get("severity", ""), "low"),
                "file": rel,
                "start_line": start,
                "end_line": end,
                "message": (extra.get("message") or "")[:400],
                "cwe": _strings(meta.get("cwe")),
                "owasp": _strings(meta.get("owasp")),
                # OWASP Top 10 for LLM Applications ids; the audit copies them to a finding
                "owasp_llm": _strings(meta.get("owasp_llm")),
                "confidence": meta.get("confidence"),
                # a weakness-kind rule's hits are hardening candidates, never vulnerabilities
                "kind": meta.get("kind"),
                "taint": "dataflow_trace" in extra,
                "snippet": (extra.get("lines") or "")[:200],
                "test_path": bool(TEST_PATH_RE.search(rel)),
                "nosem_marked": _nosem_marked(extra, target, path, start, end),
            }
        )
    errors = [
        {
            "level": e.get("level") if e.get("level") in {"warn", "warning", "error"} else "error",
            "type": (
                e.get("type")
                if e.get("type") in {"ParseError", "PartialParsing", "Timeout", "RuleParseError"}
                else "ScannerError"
            ),
            "message": "native scanner reported an error",
        }
        for e in raw.get("errors", [])
    ]
    return facts, errors


def _core_version() -> str:
    try:
        return package_version("traust-core")
    except PackageNotFoundError:
        return "0.0.0"


@dataclass(frozen=True, slots=True)
class _AdditionGate:
    pack: Path
    runner: ProcessRunner
    checkouts: Checkouts
    load: YamlLoader
    binary: str
    timeout: int

    def reserve(self, supplements: Sequence[SupplementalPack]) -> dict[str, str]:
        ids = dict.fromkeys(protected_ids(self.pack, self.load), "traust rule pack")
        with ExitStack() as held:
            for supplement in supplements:
                rules, workspaces = resolve_rules(
                    (supplement.source,), self.pack, self.pack, self.checkouts
                )
                for workspace in workspaces:
                    held.callback(self.checkouts.release, workspace)
                ids.update(dict.fromkeys(supplement.rules, supplement.name))
                for source in rules:
                    for config in source["config"]:
                        ids.update(
                            dict.fromkeys(protected_ids(Path(config), self.load), supplement.name)
                        )
        return ids

    @contextmanager
    def vet(
        self, source: str, protected: Mapping[str, str], languages: set[str] | None
    ) -> Iterator[tuple[list[dict[str, Any]], RuleBatch]]:
        with ExitStack() as held:
            try:
                resolved, workspaces = resolve_rules(
                    (source,), self.pack, self.pack, self.checkouts
                )
                for workspace in workspaces:
                    held.callback(self.checkouts.release, workspace)
                batch = held.enter_context(
                    vet_rules(
                        source,
                        tuple(Path(path) for entry in resolved for path in entry["config"]),
                        self.runner,
                        load=self.load,
                        binary=self.binary,
                        timeout=self.timeout,
                        protected=protected,
                        languages=languages,
                    )
                )
            except (TraustError, OSError, RecursionError) as error:
                detail = (
                    str(error) if isinstance(error, ValidationError) else "cannot open rule source"
                )
                yield [], RuleBatch((), (), (RuleReceipt(source).refuse("source", detail),))
            else:
                yield resolved, batch


def _degraded(refused: Sequence[RuleReceipt]) -> dict[str, int]:
    return dict(Counter(receipt.source for receipt in refused))


def intake_rules(
    sources: Sequence[str],
    *,
    pack: Path,
    supplements: Sequence[SupplementalPack],
    runner: ProcessRunner,
    checkouts: Checkouts,
    load: YamlLoader,
    timeout: int,
    binary: str,
) -> dict[str, Any]:
    """Vet additions without a target, without changing checked-in or enabled rules."""
    gate = _AdditionGate(pack, runner, checkouts, load, binary, timeout)
    protected = gate.reserve(supplements)
    applied: list[RuleReceipt] = []
    refused: list[RuleReceipt] = []
    for source in dict.fromkeys(sources):
        with gate.vet(source, protected, None) as (_, batch):
            applied.extend(batch.applied)
            refused.extend(batch.refused)
            protected.update({r.rule_id: r.source for r in batch.applied if r.rule_id is not None})
    return _additive_report(applied, refused)


def _additive_report(
    applied: Sequence[RuleReceipt], refused: Sequence[RuleReceipt]
) -> dict[str, Any]:
    return {
        "applied": [asdict(receipt) for receipt in applied],
        "refused": [asdict(receipt) for receipt in refused],
        "degraded": _degraded(refused),
    }


def _filter_additive_hits(
    batch: RuleBatch, facts: list[dict[str, Any]], scanned: int
) -> tuple[list[dict[str, Any]], list[RuleReceipt], list[RuleReceipt]]:
    hits: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for fact in facts:
        hits[fact["rule_id"]].append(fact)
    kept, applied, refused = [], [], []
    for receipt in batch.applied:
        matched = hits.get(receipt.rule_id or "", [])
        check = rule_checks.explosion(len(matched), len({f["file"] for f in matched}), scanned)
        if not check.passed:
            refused.append(receipt.refuse(check.name.value, check.detail))
        else:
            applied.append(receipt)
            kept.extend(f | {"origin": f"additive:{receipt.source}"} for f in matched)
    return kept, applied, refused


def _run_addition(
    gate: _AdditionGate, batch: RuleBatch, target: Path
) -> tuple[list[dict[str, Any]], list[RuleReceipt], list[RuleReceipt]]:
    ids = frozenset(r.rule_id for r in batch.applied if r.rule_id is not None)
    try:
        raw, facts, errors = _scan_snapshot(
            target,
            batch.configs,
            ids,
            gate.runner,
            gate.binary,
            gate.timeout,
            output_limit=_ADDITIVE_OUTPUT_LIMIT,
        )
    except ScannerError as error:
        reason = f"optional scan failed: {error.reason.value}"
    else:
        skipped = raw.get("skipped_rules", [])
        if not errors and not skipped and all(fact["rule_id"] in ids for fact in facts):
            return _filter_additive_hits(batch, facts, len(raw.get("paths", {}).get("scanned", [])))
        reason = "optional scan returned errors, skipped rules, or unrecognized results"
    return [], [], [r.refuse("scan", reason) for r in batch.applied]


@dataclass(slots=True)
class _AdditiveScan:
    facts: list[dict[str, Any]] = field(default_factory=list)
    sources: list[dict[str, Any]] = field(default_factory=list)
    applied: list[RuleReceipt] = field(default_factory=list)
    refused: list[RuleReceipt] = field(default_factory=list)


def _scan_additions(
    gate: _AdditionGate, sources: Sequence[str], target: Path, origins: Mapping[str, str]
) -> _AdditiveScan:
    result = _AdditiveScan()
    if not sources:
        return result
    try:
        protected = gate.reserve(())
    except (ValidationError, OSError, RecursionError):
        result.refused.extend(
            RuleReceipt(source).refuse("collision", "unable to verify the full baseline ID set")
            for source in dict.fromkeys(sources)
        )
        return result
    protected.update(
        {
            rule: "traust rule pack" if origin == "traust" else origin.removeprefix("supplement:")
            for rule, origin in origins.items()
        }
    )
    languages = _additive_languages(target)
    for source in dict.fromkeys(sources):
        with gate.vet(source, protected, languages) as (resolved, batch):
            result.refused.extend(batch.refused)
            if not batch.applied:
                continue
            protected.update({r.rule_id: r.source for r in batch.applied if r.rule_id is not None})
            matched, accepted, failed = _run_addition(gate, batch, target)
            result.applied.extend(accepted)
            result.refused.extend(failed)
            if accepted:
                result.sources.extend(resolved)
                result.facts.extend(matched)
    return result


def execute_scan(
    target: Path,
    rule_sources: Sequence[str],
    *,
    pack: Path,
    runner: ProcessRunner,
    checkouts: Checkouts,
    load: YamlLoader,
    supplements: Sequence[SupplementalPack] = (),
    rule_allow: RuleAllowlist | None = None,
    additive: Sequence[str] = (),
    timeout: int = SCAN_TIMEOUT,
    opengrep_bin: str = "opengrep",
) -> dict[str, Any]:
    """Scan only rule snapshots that passed native validation and strict fixture tests."""
    if rule_sources and additive:
        raise ValidationError("--rules replaces the pack and cannot be combined with --add-rules")
    rules, held = resolve_rules(rule_sources, target, pack, checkouts)
    applied: list[str] = []
    supp_allow: set[str] = set()
    quality_inputs = ExitStack()
    quality_checks: list[ProposalCheck] = []
    active_configs: list[Path] = []
    active_ids: set[str] = set()
    enabled: dict[int, tuple[str, ...]] = {}
    origins: dict[str, str] = {}
    supplement_names: dict[int, str] = {}
    try:
        if not rule_sources:
            for supp in supplements:
                if (
                    not supp.source.startswith(("https://", "http://", "git@"))
                    and not Path(supp.source).is_dir()
                ):
                    raise ValidationError(
                        f"local rule pack {supp.name} must be an existing directory: {supp.source}"
                    )
                supp_rules, supp_held = resolve_rules([supp.source], target, pack, checkouts)
                held += supp_held
                for source in supp_rules:
                    enabled[len(rules)] = supp.rules
                    supplement_names[len(rules)] = supp.name
                    rules.append(source)
                applied.append(supp.name)
                supp_allow.update(supp.rules)
        for index, source in enumerate(rules):
            checked = quality_inputs.enter_context(
                checked_rules(
                    [Path(path) for path in source["config"]],
                    runner,
                    load=load,
                    binary=opengrep_bin,
                    timeout=timeout,
                )
            )
            quality_checks.extend(checked.report.checks)
            if not checked.report.passed:
                raise RuleQualityError(checked.report)
            ids = set(checked.report.rules)
            if duplicate := active_ids & ids:
                raise ValidationError(f"duplicate rule ids across packs: {sorted(duplicate)}")
            if missing := set(enabled.get(index, ())) - ids:
                raise ValidationError(f"enabled rules not found in pack: {sorted(missing)}")
            active_ids.update(ids)
            active_configs.extend(checked.configs)
            origin = (
                f"supplement:{supplement_names[index]}"
                if index in supplement_names
                else f"override:{source['source']}"
                if rule_sources
                else "traust"
            )
            origins.update(dict.fromkeys(ids, origin))
        raw, facts, errors = _scan_snapshot(
            target, active_configs, frozenset(active_ids), runner, opengrep_bin, timeout
        )
        for fact in facts:
            if origin := origins.get(fact["rule_id"]):
                fact["origin"] = origin

        gate = _AdditionGate(pack, runner, checkouts, load, opengrep_bin, timeout)
        extra = _scan_additions(gate, additive, target, origins)
        facts.extend(extra.facts)
        rules.extend(extra.sources)
        allow = rule_allow
        if allow is None and supp_allow:
            traust_ids = harness_pack_rule_ids(pack) | {
                rule_id for rule_id, origin in origins.items() if origin == "traust"
            }
            additive_ids = {r.rule_id for r in extra.applied if r.rule_id is not None}
            allow = RuleAllowlist(
                frozenset(supp_allow | traust_ids | additive_ids),
                "rule-pack-allowlist.yaml "
                f"({len(supp_allow)} supplemental + "
                f"{len(traust_ids)} traust rule pack rules"
                + (f" + {len(additive_ids)} additive rules)" if additive_ids else ")"),
            )
        suppressed = 0
        if allow is not None:
            kept = [f for f in facts if f["rule_id"] in allow.rules]
            suppressed = len(facts) - len(kept)
            facts = kept

        try:
            version = runner.run(
                [opengrep_bin, "--version"], check=False, timeout_seconds=timeout, env=OPENGREP_ENV
            )
        except ProcessTimeout as error:
            raise ScannerError(
                f"opengrep version probe timed out after {timeout}s",
                reason=ScannerFailure.TIMEOUT,
                timeout_seconds=timeout,
            ) from error
        except ServiceError as error:
            raise ScannerError(
                "opengrep version probe could not complete", reason=ScannerFailure.EXIT
            ) from error
        if version.returncode != 0:
            raise ScannerError(
                f"opengrep version probe exited {version.returncode}",
                reason=ScannerFailure.EXIT,
                exit_code=version.returncode,
            )
        version_lines = re.findall(
            rb"(?m)^(?:opengrep )?[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}"
            rb"(?:[-+][A-Za-z0-9.-]{1,40})?\r?$",
            version.stdout,
        )
        if not version_lines:
            raise ScannerError(
                "opengrep returned invalid version output",
                reason=ScannerFailure.OUTPUT,
                exit_code=version.returncode,
            )
        og_version = version_lines[-1].decode().strip()
        return {
            "tool": "run_opengrep",
            "version": _core_version(),
            "opengrep_version": og_version,
            "target": str(target),
            "rules": [
                {k: v for k, v in r.items() if k != "config"} | {"config_paths": r["config"]}
                for r in rules
            ],
            "supplemental_packs": {"applied": applied},
            "additive_rules": _additive_report(extra.applied, extra.refused),
            "outcome": "degraded" if extra.refused or errors else "succeeded",
            "rule_allowlist": (
                {
                    "source": allow.source,
                    "rules": sorted(allow.rules),
                    "suppressed_facts": suppressed,
                }
                if allow is not None
                else None
            ),
            "stats": {
                "facts": len(facts),
                "files_scanned": len((raw.get("paths") or {}).get("scanned", [])),
                "errors": len(errors),
                "skipped_rules": len(raw.get("skipped_rules", [])),
                "suppressed_by_allowlist": suppressed,
            },
            "coverage": coverage_block(target, pack),
            "facts": facts,
            "quality_checks": [check.model_dump(mode="json") for check in quality_checks],
            "errors": errors,
        }
    finally:
        try:
            quality_inputs.close()
        finally:
            for workspace in held:
                checkouts.release(workspace)


def _scan_snapshot(
    target: Path,
    configs: Sequence[Path],
    rule_ids: frozenset[str],
    runner: ProcessRunner,
    binary: str,
    timeout: int,
    *,
    output_limit: int | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    cmd = [binary, "scan", "--json", "--quiet", "--disable-nosem"]
    for config in configs:
        cmd += ["--config", str(config)]
    for excluded in EXCLUDES:
        cmd += ["--exclude", excluded]
    cmd += ["--", str(target)]
    try:
        proc = runner.run(
            cmd,
            check=False,
            timeout_seconds=timeout,
            env=OPENGREP_ENV,
            max_output_bytes=output_limit,
        )
    except ProcessTimeout as error:
        raise ScannerError(
            f"opengrep timed out after {timeout}s",
            reason=ScannerFailure.TIMEOUT,
            timeout_seconds=timeout,
        ) from error
    except ServiceError as error:
        raise ScannerError(
            "opengrep scan process could not complete", reason=ScannerFailure.EXIT
        ) from error
    if proc.returncode not in (0, 1):
        raise ScannerError(
            f"opengrep scan exited {proc.returncode}",
            reason=ScannerFailure.EXIT,
            exit_code=proc.returncode,
        )
    try:
        raw = json.loads(proc.stdout)
        if not isinstance(raw, dict) or not isinstance(raw.get("results"), list):
            raise ValueError("invalid scanner report")
        if not isinstance(raw.get("errors", []), list):
            raise ValueError("invalid scanner errors")
        if not isinstance(raw.get("paths", {}), dict):
            raise ValueError("invalid scanner paths")
        if not isinstance(raw.get("skipped_rules", []), list):
            raise ValueError("invalid skipped rules")
        scanned = raw.get("paths", {}).get("scanned", [])
        if not isinstance(scanned, list) or any(not isinstance(path, str) for path in scanned):
            raise ValueError("invalid scanned paths")
        facts, errors = normalize(raw, target, rule_ids)
        for fact in facts:
            RuleHit.model_validate(fact)
    except (ValueError, TypeError, AttributeError, KeyError) as error:
        raise ScannerError(
            "opengrep produced invalid JSON scan output",
            reason=ScannerFailure.OUTPUT,
            exit_code=proc.returncode,
        ) from error
    return raw, facts, errors


def format_lines(start: int | None, end: int | None) -> str:
    if not start:
        return ""
    return f"{start}-{end}" if end and end != start else str(start)


def _describe(fact: dict[str, Any]) -> str:
    text = fact.get("message") or ""
    if fact.get("nosem_marked"):
        note = (
            "The target marks this line with a nosem comment; a suppression "
            "shipped by the audited repo is not an exemption, judge the fact."
        )
        text = f"{text} ({note})" if text else note
    return text


def _findings(facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    unidentified = 0
    for fact in facts:
        cwes = [m.group(0) for c in fact.get("cwe", []) if (m := _CWE_ID.match(c))]
        unidentified += len(fact.get("cwe", [])) - len(cwes)
        findings.append(
            {
                "id": f"opengrep/{fact['rule_id']}",
                "title": fact["message"] or fact["rule_id"],
                "severity": fact.get("severity_hint", "low"),
                "cwes": cwes,
                "locations": [
                    {
                        "path": fact["file"],
                        "lines": format_lines(fact.get("start_line"), fact.get("end_line")),
                    }
                ],
                "description": _describe(fact),
                "evidence": [{"code": fact["snippet"]}] if fact.get("snippet") else [],
                "category": fact["rule_id"],
                **({"kind": fact["kind"]} if fact.get("kind") else {}),
            }
        )
    if unidentified:
        log.warning(
            "opengrep: %d CWE value(s) with no CWE-<n> id left off the findings", unidentified
        )
    return findings


def scan(
    target: Path,
    pack: Path,
    *,
    runner: ProcessRunner,
    clock: Clock,
    checkouts: Checkouts,
    load: YamlLoader,
    supplements: Sequence[SupplementalPack] = (),
    rules: Sequence[str] = (),
    rule_allow: RuleAllowlist | None = None,
    timeout: int = SCAN_TIMEOUT,
    opengrep_bin: str = "opengrep",
) -> AdapterResultArtifact:
    """opengrep's facts over `target` as an adapter result."""
    target = target.resolve()
    pack = resolve_rule_pack_dir(pack)
    if not target.is_dir():
        raise ValueError(f"not a directory: {target}")
    if not shutil.which(opengrep_bin):
        raise FileNotFoundError(f"opengrep not found on PATH ({opengrep_bin})")
    report = execute_scan(
        target,
        rules,
        pack=pack,
        runner=runner,
        checkouts=checkouts,
        load=load,
        supplements=supplements,
        rule_allow=rule_allow,
        timeout=timeout,
        opengrep_bin=opengrep_bin,
    )
    return adapter_result(
        str(target),
        "opengrep",
        _findings(report["facts"]),
        scanned_at=clock.now(),
        scanner_version=report.get("opengrep_version", ""),
    )
