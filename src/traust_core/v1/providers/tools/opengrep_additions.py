"""Optional Opengrep rule admission over private rule and fixture snapshots."""

from __future__ import annotations

import json
import re
import tempfile
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, ExitStack, contextmanager
from dataclasses import dataclass, replace
from pathlib import Path

from traust_core.v1.errors import ValidationError
from traust_core.v1.models import rule_checks
from traust_core.v1.providers.config_matrix import YamlLoader
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.tools.opengrep_quality import (
    CheckedRules,
    checked_rules,
    fixture_files,
    read_rule_text,
    rule_files,
)

_MARKER = re.compile(
    r"(?m)^([ \t]*(?://+|#+|--|/\*+|<!--|;+|\*+)[ \t]*)(ruleid|ok):[ \t]*([\w.,-]+)"
)


@dataclass(frozen=True, slots=True)
class RuleReceipt:
    source: str
    file: str | None = None
    rule_id: str | None = None
    check: str | None = None
    reason: str | None = None

    def refuse(self, check: str, reason: str) -> RuleReceipt:
        return replace(self, check=check, reason=reason)


@dataclass(frozen=True, slots=True)
class RuleBatch:
    configs: tuple[Path, ...]
    applied: tuple[RuleReceipt, ...]
    refused: tuple[RuleReceipt, ...]


def _fixture_for_rule(text: str, rule_id: str, siblings: set[str]) -> str:
    def marker(match: re.Match[str]) -> str:
        names = [name for name in match[3].split(",") if name not in siblings or name == rule_id]
        return f"{match[1]}{match[2]}: {','.join(names)}" if names else match[1]

    return _MARKER.sub(marker, text)


def _read_rules(path: Path, root: Path, load: YamlLoader) -> list[object]:
    docs = load(read_rule_text(path, root))
    if path != root and not any(isinstance(d, dict) and "rules" in d for d in docs):
        return []
    if (
        len(docs) != 1
        or not isinstance(doc := docs[0], dict)
        or not isinstance(doc.get("rules"), list)
        or not doc["rules"]
    ):
        raise ValidationError("expected one non-empty rule document")
    return doc["rules"]


def _id(rule: object) -> str | None:
    return rule["id"] if isinstance(rule, dict) and isinstance(rule.get("id"), str) else None


def protected_ids(root: Path, load: YamlLoader) -> set[str]:
    """Reserve all baseline IDs, including languages inactive on this checkout."""
    return {
        name
        for path in rule_files(root)
        for rule in _read_rules(path, root, load)
        if (name := _id(rule)) is not None
    }


def _stage(
    rule: object,
    receipt: RuleReceipt,
    dest: Path,
    fixtures: Mapping[str, str],
    siblings: set[str],
    protected: Mapping[str, str],
    languages: set[str] | None,
) -> RuleReceipt:
    try:
        text = json.dumps({"rules": [rule]}, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        return receipt.refuse(
            "structure", "rule contains values that cannot be represented as JSON"
        )
    check, rule = rule_checks.structure({"rules": [rule]})
    if not check.passed or rule is None or receipt.rule_id is None:
        return receipt.refuse("structure", check.detail or "rule requires a string ID")
    for check in (rule_checks.catch_all(rule), rule_checks.paths(rule), rule_checks.regexes(rule)):
        if not check.passed:
            return receipt.refuse(check.name.value, check.detail)
    if owner := protected.get(receipt.rule_id):
        return receipt.refuse(
            "collision", f"{receipt.rule_id} conflicts between {owner} and {receipt.source}"
        )
    declared = rule["languages"]
    if not all(isinstance(language, str) and language for language in declared):
        return receipt.refuse("structure", "languages must name one or more Opengrep languages")
    if languages is not None and languages.isdisjoint(declared):
        return receipt.refuse(
            "skipped-for-language", "none of the rule's languages match the checkout"
        )
    dest.parent.mkdir()
    dest.write_text(text, encoding="utf-8")
    for suffix, fixture in fixtures.items():
        dest.with_name("rule" + suffix).write_text(
            _fixture_for_rule(fixture, receipt.rule_id, siblings) if siblings else fixture,
            encoding="utf-8",
        )
    return receipt


def _candidates(
    source: str,
    path: Path,
    stage: Path,
    load: YamlLoader,
    protected: Mapping[str, str],
    languages: set[str] | None,
) -> tuple[dict[Path, RuleReceipt], list[RuleReceipt]]:
    proposed: list[tuple[object, RuleReceipt, Mapping[str, str], set[str]]] = []
    refused: list[RuleReceipt] = []
    boundary = path if path.is_dir() else path.parent
    for rule_file in rule_files(path):
        receipt = RuleReceipt(source=source, file=rule_file.relative_to(boundary).as_posix())
        try:
            rules = _read_rules(rule_file, path, load)
            if not rules:
                continue
            fixtures = {
                fixture.name[len(rule_file.stem) :]: read_rule_text(fixture, boundary)
                for fixture in fixture_files(rule_file)
            }
        except (ValidationError, RecursionError) as error:
            reason = (
                str(error)
                if isinstance(error, ValidationError)
                else "rule document is too deeply nested"
            )
            refused.append(receipt.refuse("parse", reason))
            continue
        ids = {name for rule in rules if (name := _id(rule)) is not None}
        proposed.extend(
            (rule, replace(receipt, rule_id=_id(rule)), fixtures, ids - {_id(rule)})
            for rule in rules
        )
    counts = Counter(
        receipt.rule_id for _, receipt, _, _ in proposed if receipt.rule_id is not None
    )
    candidates: dict[Path, RuleReceipt] = {}
    for i, (rule, receipt, fixtures, siblings) in enumerate(proposed):
        if counts[receipt.rule_id] > 1:
            refused.append(
                receipt.refuse("collision", f"{receipt.rule_id} is repeated in {source}")
            )
            continue
        dest = stage / str(i) / "rule.yaml"
        result = _stage(rule, receipt, dest, fixtures, siblings, protected, languages)
        if result.check is not None:
            refused.append(result)
        else:
            candidates[dest] = result
    if not proposed and not refused:
        refused.append(RuleReceipt(source).refuse("structure", "no authored rules found"))
    return candidates, refused


@contextmanager
def vet_rules(
    source: str,
    paths: Sequence[Path],
    runner: ProcessRunner,
    *,
    load: YamlLoader,
    binary: str,
    timeout: int,
    protected: Mapping[str, str],
    languages: set[str] | None,
) -> Iterator[RuleBatch]:
    """Test a source as a batch, then isolate native failures by individual rule."""
    with tempfile.TemporaryDirectory(prefix="opengrep-additive-") as tmp, ExitStack() as held:
        candidates: dict[Path, RuleReceipt] = {}
        refused: list[RuleReceipt] = []
        for i, path in enumerate(paths):
            stage = Path(tmp) / str(i)
            stage.mkdir()
            good, bad = _candidates(source, path, stage, load, protected, languages)
            candidates.update(good)
            refused.extend(bad)
        if not candidates:
            yield RuleBatch((), (), tuple(refused))
            return

        def checked(files: Sequence[Path]) -> AbstractContextManager[CheckedRules]:
            return checked_rules(files, runner, load=load, binary=binary, timeout=timeout)

        with checked(tuple(candidates)) as batch:
            if batch.report.passed:
                yield RuleBatch(batch.configs, tuple(candidates.values()), tuple(refused))
                return
            failed = next(check for check in batch.report.checks if not check.passed)
        if len(candidates) == 1:
            only = next(iter(candidates.values()))
            yield RuleBatch((), (), (*refused, only.refuse(failed.name.value, failed.detail)))
            return
        configs: list[Path] = []
        applied: list[RuleReceipt] = []
        for path, receipt in candidates.items():
            rule = held.enter_context(checked((path,)))
            if rule.report.passed:
                configs.extend(rule.configs)
                applied.append(receipt)
            else:
                failed = next(check for check in rule.report.checks if not check.passed)
                refused.append(receipt.refuse(failed.name.value, failed.detail))
        yield RuleBatch(tuple(configs), tuple(applied), tuple(refused))
