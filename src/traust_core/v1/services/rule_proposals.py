"""The rule-proposal gate's checks. A proposed rule is admitted only when it is one well-formed
rule with no catch-all pattern, path glob or unsafe regex, its examples fire exactly, and it
stays quiet on the repository it was proposed for."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from traust_core.v1.models.rule_mining import ProposalCheck, ProposalCheckName
from traust_core.v1.models.vocabulary import FindingKind

MAX_HITS = 25
MAX_HIT_FILE_SHARE = 0.05  # of the files the checkout scan covered
MIN_HIT_FILES = 3
_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{2,}$")
_CWE = re.compile(r"^CWE-\d+$")
_SEVERITIES = {"ERROR", "WARNING", "INFO"}
_POSITIVE = {"pattern", "pattern-inside"}
_MATCHERS = ("pattern", "patterns", "pattern-either", "pattern-regex")
_REGEX_KEYS = {"pattern-regex", "pattern-not-regex", "regex"}
_METAVARIABLE = re.compile(r"\$[A-Z_][A-Z0-9_]*|\.\.\.")
_BACKREFERENCE = re.compile(r"\\[1-9]|\(\?P=|\\k<")
_LOOKBEHIND = re.compile(r"\(\?<[=!]")
# a group holding a quantifier, itself quantified: (a+)+, (\w+\s?)*, (.*){2,}
_NESTED = re.compile(r"\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)(?:[+*]|\{\d*,)")
_CATCH_ALL_GLOBS = {"*", "**", "**/*", "/**", "./**"}


def _strings(node: Any, key: str = "") -> Iterator[tuple[str, str]]:
    """(key, string) for every string under `node`, keyed by the nearest mapping key."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _strings(v, str(k))
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v, key)
    elif isinstance(node, str):
        yield key, node


def _check(name: ProposalCheckName, problems: list[str]) -> ProposalCheck:
    return ProposalCheck(name=name, passed=not problems, detail="; ".join(problems[:5]))


def structure(doc: Any) -> tuple[ProposalCheck, dict[str, Any] | None]:
    """One rule with an id, message, languages, severity and CWE; the rule when there is one."""
    rules = doc.get("rules") if isinstance(doc, dict) else None
    if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict):
        return _check(ProposalCheckName.STRUCTURE, ["the file must hold exactly one rule"]), None
    rule = rules[0]
    meta = rule.get("metadata") if isinstance(rule.get("metadata"), dict) else {}
    cwes = meta.get("cwe")
    languages = rule.get("languages")
    problems = []
    if not _ID.match(str(rule.get("id", ""))):
        problems.append("id must be lowercase letters, digits, dots and dashes")
    if not str(rule.get("message", "")).strip():
        problems.append("message is required")
    if not isinstance(languages, list) or not languages:
        problems.append("languages must be a non-empty list")
    if rule.get("severity") not in _SEVERITIES:
        problems.append(f"severity must be one of {sorted(_SEVERITIES)}")
    if not isinstance(cwes, list) or not all(_CWE.match(str(c).split(":")[0]) for c in cwes or [0]):
        problems.append("metadata.cwe must list CWE ids")
    if "kind" in meta and meta["kind"] not in {str(k) for k in FindingKind}:
        problems.append("metadata.kind must be a finding kind")
    taint = rule.get("mode") == "taint" and "pattern-sources" in rule and "pattern-sinks" in rule
    if not taint and not any(k in rule for k in _MATCHERS):
        problems.append("the rule needs patterns (or taint sources and sinks)")
    return _check(ProposalCheckName.STRUCTURE, problems), rule


def catch_all(rule: dict[str, Any]) -> ProposalCheck:
    """No matching pattern made only of metavariables and ellipses (`$X`, `$F(...)`, `...`), and
    no regex with no literal text."""
    problems = []
    matching = {k: v for k, v in rule.items() if k not in ("metadata", "message", "paths")}
    for key, text in _strings(matching):
        if key in _POSITIVE and not re.search(r"[A-Za-z]", _METAVARIABLE.sub("", text)):
            problems.append(f"{key}: {text.strip()[:60]!r} matches anything")
        elif key == "pattern-regex" and not re.search(r"[A-Za-z0-9]{2}", re.sub(r"\\.", "", text)):
            problems.append(f"{key}: {text[:60]!r} has no literal text")
    return _check(ProposalCheckName.CATCH_ALL, problems)


def paths(rule: dict[str, Any]) -> ProposalCheck:
    """`paths` never leaves the tree, and `include` never selects every file."""
    spec = rule.get("paths") if isinstance(rule.get("paths"), dict) else {}
    problems = []
    for key in ("include", "exclude"):
        for glob in spec.get(key) or []:
            g = str(glob)
            if ".." in g.split("/") or g.startswith(("/", "~")):
                problems.append(f"{key}: {g!r} leaves the tree")
            elif key == "include" and g.strip() in _CATCH_ALL_GLOBS:
                problems.append(f"include: {g!r} selects every file")
    return _check(ProposalCheckName.PATHS, problems)


def regexes(rule: dict[str, Any]) -> ProposalCheck:
    """Every regex compiles, with no backreference, lookbehind or nested quantifier."""
    problems = []
    for key, text in _strings(rule):
        if key not in _REGEX_KEYS:
            continue
        try:
            re.compile(text)
        except re.error as e:
            problems.append(f"{key}: {text[:40]!r} doesn't compile ({e})")
            continue
        for what, rx in (
            ("a backreference", _BACKREFERENCE),
            ("lookbehind", _LOOKBEHIND),
            ("a nested quantifier", _NESTED),
        ):
            if rx.search(text):
                problems.append(f"{key}: {text[:40]!r} has {what}")
    return _check(ProposalCheckName.REGEX, problems)


def example_lines(rule_id: str, example: str) -> tuple[set[int], set[int]]:
    """(lines a `ruleid:` comment says must match, lines an `ok:` comment says must not): each
    marker names the line after it, as `opengrep --test` reads them."""
    fire: set[int] = set()
    quiet: set[int] = set()
    for number, line in enumerate(example.splitlines(), start=1):
        m = re.search(r"\b(ruleid|ok):\s*([\w.,-]+)", line)
        if m and rule_id in m.group(2).split(","):
            (fire if m.group(1) == "ruleid" else quiet).add(number + 1)
    return fire, quiet


def examples(rule_id: str, example: str, hit_lines: set[int]) -> ProposalCheck:
    fire, quiet = example_lines(rule_id, example)
    problems = []
    if not fire or not quiet:
        problems.append("the example needs at least one `ruleid:` and one `ok:` line")
    if missed := sorted(fire - hit_lines):
        problems.append(f"no match on ruleid line(s) {missed}")
    if wrong := sorted(quiet & hit_lines):
        problems.append(f"matches ok line(s) {wrong}")
    return _check(ProposalCheckName.EXAMPLES, problems)


def explosion(hits: int, hit_files: int, files_scanned: int) -> ProposalCheck:
    """At most MAX_HITS matches, in at most MAX_HIT_FILE_SHARE of the files (MIN_HIT_FILES)."""
    cap = max(MIN_HIT_FILES, int(files_scanned * MAX_HIT_FILE_SHARE))
    problems = []
    if hits > MAX_HITS:
        problems.append(f"{hits} matches on the checkout (cap {MAX_HITS})")
    if hit_files > cap:
        problems.append(f"matches in {hit_files} of {files_scanned} files (cap {cap})")
    return _check(ProposalCheckName.EXPLOSION, problems)
