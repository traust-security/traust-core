"""Semantic pattern and taint candidates from opengrep over a checkout, reduced to normalized facts
for the audit skills to judge. A candidate generator, never a verdict.

Rule packs are a swappable input passed by path, never vendored: the deployment's pack
(`Context.register_rule_pack`), its supplemental packs enabled per rule by the allowlist, or the
sources a caller names (a local path, a git URL pinned `@<sha>`, a registry `p/<pack>`). The
registry's `auto` is refused: it fetches rules with no per-pack license accounting."""

from __future__ import annotations

import json
import logging
import re
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Any

from traust_core.v1.errors import IntegrityError, ValidationError
from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner, ProcessTimeout
from traust_core.v1.providers.tools.adapter import adapter_result

log = logging.getLogger(__name__)

CACHE_ROOT = Path.home() / ".cache" / "traust-engine"
SCAN_TIMEOUT = 900

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
REGISTRY_LICENSE = (
    "Semgrep registry pack: license varies per pack; "
    "Semgrep-maintained packs are restrictively licensed — "
    "see docs/external-dependencies.md"
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


def detect_language_dirs(target: Path) -> set[str]:
    dirs: set[str] = set()
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        parts = path.relative_to(target).parts
        if parts and parts[0] in EXCLUDES:
            continue
        if lang := LANG_DIRS.get(path.suffix):
            dirs.add(lang)
    return dirs


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
    per_lang = {lang: counts.get(lang, 0) for lang in detected}
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
    sources: Sequence[str], target: Path, pack: Path, runner: ProcessRunner
) -> list[dict[str, Any]]:
    """Each rules source as {source, config, sha, license_note}; no sources means the pack,
    filtered to the target's languages."""
    pack = resolve_rule_pack_dir(pack)
    if not sources:
        langs = detect_language_dirs(target)
        lang_paths = [str(pack / d) for d in sorted(langs) if (pack / d).is_dir()]
        return [
            {
                "source": "traust rule pack",
                "config": lang_paths or [str(pack)],
                "sha": None,
                "license_note": TRAUST_PACK_LICENSE,
            }
        ]
    resolved = []
    for src in sources:
        if src.strip() == "auto":
            raise ValidationError(
                "refusing '--rules auto': registry auto-fetch has no "
                "per-pack license accounting (see "
                "docs/external-dependencies.md)"
            )
        if re.match(r"^[pr]/[\w./-]+$", src):
            resolved.append(
                {"source": src, "config": [src], "sha": None, "license_note": REGISTRY_LICENSE}
            )
        elif src.startswith(("http://", "https://", "git@")):
            resolved.append(_git_rules(src, target, runner))
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
    return resolved


def _git_rules(src: str, target: Path, runner: ProcessRunner) -> dict[str, Any]:
    url, ref = pinned_rules_source(src)
    dest = rules_cache_dir(url, ref)
    if not dest.is_dir():
        _clone(runner, url, ref, dest)
    elif not _cache_ok(runner, dest, ref):
        log.warning("rule cache failed pin/cleanliness check — discarding and re-cloning")
        shutil.rmtree(dest)
        _clone(runner, url, ref, dest)
    if not _cache_ok(runner, dest, ref):
        raise IntegrityError(
            f"rules source {src!r}: freshly cloned cache still "
            "fails pin/cleanliness verification — refusing to "
            "scan with unverifiable rules"
        )
    sha = _git(runner, dest, "rev-parse", "HEAD").stdout.decode().strip()
    # argus nests its rules beside a tests/ tree of deliberately vulnerable fixtures: scope the
    # config to the rules subtree, then filter to the target's languages.
    root = rules_root(url, dest)
    configs = [str(root)]
    if url.rstrip("/").endswith(("opengrep-rules", "argus-observe-rules")):
        langs = detect_language_dirs(target)
        configs = [str(root / d) for d in sorted(langs) if (root / d).is_dir()] or configs
    return {
        "source": src,
        "config": configs,
        "sha": sha,
        "license_note": ARGUS_RULES_LICENSE
        if src.startswith(ARGUS_RULES_REPO)
        else FORK_RULES_LICENSE
        if url.rstrip("/").endswith("opengrep-rules")
        else "verify upstream license before redistribution",
    }


def _git(runner: ProcessRunner, dest: Path, *args: str, check: bool = True) -> Any:
    return runner.run(["git", "-C", str(dest), *args], check=check)


def _clone(runner: ProcessRunner, url: str, ref: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    runner.run(
        ["git", "clone", "--quiet", "--", url, str(dest)], env={"GIT_ALLOW_PROTOCOL": "https"}
    )
    if ref != "HEAD":
        _git(runner, dest, "checkout", "--quiet", ref)


def _cache_ok(runner: ProcessRunner, dest: Path, ref: str) -> bool:
    """A cached rule dir is trusted only at the pinned ref with a pristine worktree: otherwise an
    earlier hostile-repo scan or a local edit could have changed the rules the report pins."""
    head = _git(runner, dest, "rev-parse", "HEAD", check=False)
    if head.returncode != 0:
        return False
    if ref != "HEAD" and head.stdout.decode().strip() != ref:
        return False
    dirty = _git(runner, dest, "status", "--porcelain", check=False)
    return dirty.returncode == 0 and not dirty.stdout.decode().strip()


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


def rules_cache_dir(url: str, ref: str) -> Path:
    """Where a pinned git rules source is cloned."""
    return CACHE_ROOT / f"{Path(url).name}-{ref[:12]}"


def rules_root(url: str, dest: Path) -> Path:
    """The rules subtree of a cloned pack: argus nests its rules under rules/languages/."""
    if not url.rstrip("/").endswith("argus-observe-rules"):
        return dest
    nested = dest / "rules" / "languages"
    return nested if nested.is_dir() else dest / "rules"


def bare_rule_id(check_id: str) -> str:
    """opengrep prefixes a check_id with the rules path, dotted; rule ids never hold a dot, so the
    bare id is the last segment and precision doesn't fragment across path prefixes."""
    return check_id.rsplit(".", 1)[-1] if check_id else check_id


def supplemental_packs(packs: Mapping[str, Any]) -> list[SupplementalPack]:
    """The allowlist's enabled packs that name a source and at least one rule: an enabled pack
    with no rules would mean every rule, the wholesale enablement this forbids."""
    out = []
    for name, cfg in packs.items():
        if not isinstance(cfg, dict) or not cfg.get("enabled"):
            continue
        rules = tuple(str(r) for r in (cfg.get("rules") or []) if r)
        if rules and (src := cfg.get("source")):
            out.append(SupplementalPack(name, str(src), rules))
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
    raw: dict[str, Any], target: Path
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
        facts.append(
            {
                "rule_id": bare_rule_id(r.get("check_id", "?")),
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
            "level": e.get("level"),
            "type": e.get("type"),
            "message": str(e.get("message", ""))[:300],
            "path": e.get("path"),
        }
        for e in raw.get("errors", [])
    ]
    return facts, errors


def _core_version() -> str:
    try:
        return package_version("traust-core")
    except PackageNotFoundError:
        return "0.0.0"


def execute_scan(
    target: Path,
    rule_sources: Sequence[str],
    *,
    pack: Path,
    runner: ProcessRunner,
    supplements: Sequence[SupplementalPack] = (),
    rule_allow: RuleAllowlist | None = None,
    timeout: int = SCAN_TIMEOUT,
    opengrep_bin: str = "opengrep",
) -> dict[str, Any]:
    """Run opengrep over `target` and return its full facts report. Supplements apply only to a
    default (pack) run; a supplement whose source won't resolve is skipped with its reason."""
    rules = resolve_rules(rule_sources, target, pack, runner)
    applied: list[str] = []
    skipped: list[dict[str, str]] = []
    supp_allow: set[str] = set()
    if not rule_sources:
        for supp in supplements:
            try:
                rules += resolve_rules([supp.source], target, pack, runner)
            except (ValidationError, IntegrityError) as e:
                skipped.append({"pack": supp.name, "reason": str(e)})
                continue
            applied.append(supp.name)
            supp_allow.update(supp.rules)

    cmd = [opengrep_bin, "scan", "--json", "--quiet", "--disable-nosem"]
    for r in rules:
        for c in r["config"]:
            cmd += ["--config", c]
    for e in EXCLUDES:
        cmd += ["--exclude", e]
    cmd.append(str(target))
    try:
        proc = runner.run(cmd, check=False, timeout_seconds=timeout)
    except ProcessTimeout as e:
        raise TimeoutError(f"opengrep timed out after {timeout}s") from e
    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError("opengrep produced no JSON") from e

    facts, errors = normalize(raw, target)
    allow = rule_allow
    if allow is None and supp_allow:
        traust_ids = harness_pack_rule_ids(pack)
        allow = RuleAllowlist(
            frozenset(supp_allow | traust_ids),
            "rule-pack-allowlist.yaml "
            f"({len(supp_allow)} supplemental + "
            f"{len(traust_ids)} traust rule pack rules)",
        )
    suppressed = 0
    if allow is not None:
        kept = [f for f in facts if f["rule_id"] in allow.rules]
        suppressed = len(facts) - len(kept)
        facts = kept

    og_version = (
        runner.run([opengrep_bin, "--version"], check=False)
        .stdout.decode(errors="replace")
        .strip()
        .splitlines()[-1]
    )
    return {
        "tool": "run_opengrep",
        "version": _core_version(),
        "opengrep_version": og_version,
        "target": str(target),
        "rules": [
            {k: v for k, v in r.items() if k != "config"} | {"config_paths": r["config"]}
            for r in rules
        ],
        "supplemental_packs": {"applied": applied, "skipped": skipped},
        "rule_allowlist": (
            {"source": allow.source, "rules": sorted(allow.rules), "suppressed_facts": suppressed}
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
        "errors": errors,
    }


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
