"""Optional Opengrep rule admission over private rule and fixture snapshots."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path

from traust_core.v1.errors import ValidationError
from traust_core.v1.models import rule_checks
from traust_core.v1.models.rule_mining import ProposalCheckName
from traust_core.v1.providers.config_matrix import YamlLoader
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.tools.opengrep_quality import (
    NativeBudget,
    NativeBudgetError,
    SourceBudget,
    SourceBudgetError,
    SourceLimits,
    checked_rules,
    fixture_files,
    fixture_target,
    native_calls,
    read_rule_text,
    rule_files,
)

_MARKER = re.compile(
    r"(?m)^([ \t]*(?://+|#+|--|/\*+|<!--|;+|\*+)[ \t]*)(ruleid|ok):[ \t]*([\w.,-]+)"
)


class AdditionCheck(StrEnum):
    PARSE = "parse"
    COLLISION = "collision"
    SOURCE = "source"
    SCAN = "scan"
    LANGUAGE = "skipped-for-language"
    ADMISSION = "admission"
    BUDGET = "budget"


@dataclass(frozen=True, slots=True)
class RuleReceipt:
    source: str
    file: str | None = None
    rule_id: str | None = None
    check: ProposalCheckName | AdditionCheck | None = None
    reason: str | None = None

    def refuse(self, check: ProposalCheckName | AdditionCheck, reason: str) -> RuleReceipt:
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


def _read_rules(path: Path, root: Path, load: YamlLoader, budget: SourceBudget) -> list[object]:
    docs = load(read_rule_text(path, root, budget=budget))
    if path != root and not any(isinstance(d, dict) and "rules" in d for d in docs):
        return []
    if (
        len(docs) != 1
        or not isinstance(doc := docs[0], dict)
        or not isinstance(doc.get("rules"), list)
        or not doc["rules"]
    ):
        raise ValidationError("expected one non-empty rule document")
    budget.charge("rules", len(doc["rules"]))
    return doc["rules"]


def _id(rule: object) -> str | None:
    return rule["id"] if isinstance(rule, dict) and isinstance(rule.get("id"), str) else None


def protected_ids(root: Path, load: YamlLoader) -> set[str]:
    """Reserve all baseline IDs, including languages inactive on this checkout."""
    budget = SourceBudget()
    return {
        name
        for path in rule_files(root, budget=budget)
        for rule in _read_rules(path, root, load, budget)
        if (name := _id(rule)) is not None
    }


def _stage(
    rule: object,
    receipt: RuleReceipt,
    dest: Path | None,
    fixtures: Mapping[str, str],
    siblings: set[str],
    protected: Mapping[str, str],
    languages: set[str] | None,
    budget: SourceBudget,
) -> RuleReceipt:
    try:
        budget.charge("staged_files")
        chunks = []
        for chunk in json.JSONEncoder(allow_nan=False).iterencode({"rules": [rule]}):
            budget.charge("staged_bytes", len(chunk.encode("utf-8")))
            chunks.append(chunk)
        text = "".join(chunks)
    except SourceBudgetError:
        raise
    except (TypeError, ValueError, RecursionError):
        return receipt.refuse(
            ProposalCheckName.STRUCTURE, "rule contains values that cannot be represented as JSON"
        )
    check, rule = rule_checks.structure({"rules": [rule]})
    if not check.passed or rule is None or receipt.rule_id is None:
        return receipt.refuse(
            ProposalCheckName.STRUCTURE, check.detail or "rule requires a string ID"
        )
    for check in (rule_checks.catch_all(rule), rule_checks.paths(rule), rule_checks.regexes(rule)):
        if not check.passed:
            return receipt.refuse(check.name, check.detail)
    if receipt.rule_id in protected:
        return receipt.refuse(
            AdditionCheck.COLLISION,
            f"{receipt.rule_id} conflicts between "
            f"{protected[receipt.rule_id]} and {receipt.source}",
        )
    declared = rule["languages"]
    if not all(isinstance(language, str) and language for language in declared):
        return receipt.refuse(
            ProposalCheckName.STRUCTURE, "languages must name one or more Opengrep languages"
        )
    if languages is not None and languages.isdisjoint(declared):
        return receipt.refuse(
            AdditionCheck.LANGUAGE, "none of the rule's languages match the checkout"
        )
    if dest is not None:
        for fixture in fixtures.values():
            budget.stage(len(fixture.encode("utf-8")))
        dest.parent.mkdir()
        dest.write_text(text, encoding="utf-8")
        for name, fixture in fixtures.items():
            target = dest.parent / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                _fixture_for_rule(fixture, receipt.rule_id, siblings) if siblings else fixture,
                encoding="utf-8",
            )
    return receipt


def _candidates(
    source: str,
    path: Path,
    stage: Path | None,
    load: YamlLoader,
    protected: Mapping[str, str],
    languages: set[str] | None,
    budget: SourceBudget,
    native: NativeBudget | None = None,
) -> tuple[dict[Path, RuleReceipt], list[RuleReceipt]]:
    proposed: list[tuple[object, RuleReceipt, Mapping[str, str], set[str]]] = []
    refused: list[RuleReceipt] = []
    boundary = path if path.is_dir() else path.parent
    staged_rule = Path("rule.yaml")
    for rule_file in rule_files(path, budget=budget):
        if native is not None:
            native.remaining()
        receipt = RuleReceipt(source=source, file=rule_file.relative_to(boundary).as_posix())
        try:
            rules = _read_rules(rule_file, path, load, budget)
            if not rules:
                continue
            fixtures = (
                {
                    fixture_target(rule_file, fixture, staged_rule).as_posix(): read_rule_text(
                        fixture, boundary, budget=budget
                    )
                    for fixture in fixture_files(rule_file, budget=budget)
                }
                if stage is not None
                else {}
            )
        except SourceBudgetError:
            raise
        except (ValidationError, RecursionError) as error:
            reason = (
                str(error)
                if isinstance(error, ValidationError)
                else "rule document is too deeply nested"
            )
            refused.append(receipt.refuse(AdditionCheck.PARSE, reason))
            continue
        ids = {name for rule in rules if (name := _id(rule)) is not None}
        proposed.extend(
            (rule, replace(receipt, rule_id=_id(rule)), fixtures, ids) for rule in rules
        )
    counts = Counter(
        receipt.rule_id for _, receipt, _, _ in proposed if receipt.rule_id is not None
    )
    candidates: dict[Path, RuleReceipt] = {}
    for i, (rule, receipt, fixtures, siblings) in enumerate(proposed):
        if native is not None:
            native.remaining()
        if counts[receipt.rule_id] > 1:
            refused.append(
                receipt.refuse(
                    AdditionCheck.COLLISION, f"{receipt.rule_id} is repeated in {source}"
                )
            )
            continue
        dest = stage / str(i) / "rule.yaml" if stage is not None else None
        result = _stage(rule, receipt, dest, fixtures, siblings, protected, languages, budget)
        if result.check is not None:
            refused.append(result)
        else:
            candidates[dest if dest is not None else Path(str(i))] = result
    if not proposed and not refused:
        refused.append(
            RuleReceipt(source).refuse(ProposalCheckName.STRUCTURE, "no authored rules found")
        )
    return candidates, refused


def inspect_rules(
    source: str,
    path: Path,
    load: YamlLoader,
    protected: Mapping[str, str],
    *,
    limits: SourceLimits | None = None,
) -> tuple[tuple[RuleReceipt, ...], tuple[RuleReceipt, ...]]:
    try:
        candidates, refused = _candidates(
            source, path, None, load, protected, None, SourceBudget(limits)
        )
    except SourceBudgetError as error:
        return (), (RuleReceipt(source).refuse(AdditionCheck.SOURCE, str(error)),)
    return tuple(candidates.values()), tuple(refused)


_VCS = frozenset({".git", ".hg", ".svn", ".bzr"})
_CREDITS = ("license", "licence", "notice", "copying", "authors", "copyright", "attribution")


def _open_directory(path: Path) -> int:
    path = path.parent.resolve(strict=True) / path.name
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            nested = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = nested
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _copy_pack(
    source: int,
    destination: Path,
    budget: SourceBudget,
    names: Sequence[str] | None = None,
    depth: int = 0,
    regular_only: Sequence[str] = (),
) -> None:
    if depth > budget.limits.depth:
        raise SourceBudgetError("rule source exceeds depth budget")
    if names is None:
        selected = []
        with os.scandir(source) as entries:
            for entry in entries:
                if entry.name not in _VCS:
                    budget.entry(destination / entry.name)
                    selected.append(entry.name)
        names = selected
    for name in sorted(names):
        if name in _VCS:
            continue
        budget.entry(destination / name)
        mode = os.stat(name, dir_fd=source, follow_symlinks=False).st_mode
        if name in regular_only and not stat.S_ISREG(mode):
            raise ValidationError(f"rule pack credit is not a regular file: {name}")
        target = destination / name
        if stat.S_ISDIR(mode):
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source)
            try:
                target.mkdir()
                _copy_pack(descriptor, target, budget, depth=depth + 1)
            finally:
                os.close(descriptor)
        elif stat.S_ISREG(mode):
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source)
            with os.fdopen(descriptor, "rb") as original:
                metadata = os.fstat(original.fileno())
                if not stat.S_ISREG(metadata.st_mode):
                    raise ValidationError(f"rule pack input is a link or special file: {name}")
                budget.file(target, metadata.st_size)
                with target.open("xb") as copied:
                    remaining = metadata.st_size
                    while block := original.read(min(64 << 10, remaining + 1)):
                        if len(block) > remaining:
                            raise SourceBudgetError("rule input grew while capturing its snapshot")
                        copied.write(block)
                        remaining -= len(block)
                    os.fchmod(copied.fileno(), stat.S_IMODE(metadata.st_mode) & 0o777)
        else:
            raise ValidationError(f"rule pack input is a link or special file: {name}")


def _copy_attribution(root: Path, source: Path, target: Path, budget: SourceBudget) -> None:
    if root.resolve().is_relative_to(source.resolve()) or (
        source.is_file() and root.resolve() == source.parent.resolve()
    ):
        return
    descriptor = _open_directory(root)
    try:
        names = []
        with os.scandir(descriptor) as entries:
            for entry in entries:
                budget.entry(root / entry.name)
                if entry.name.lower().startswith(_CREDITS):
                    mode = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False).st_mode
                    if stat.S_ISDIR(mode):
                        continue
                    if not stat.S_ISREG(mode):
                        raise ValidationError(
                            f"rule pack attribution is a link or special file: {entry.name}"
                        )
                    names.append(entry.name)
        if any((target / name).exists() for name in names):
            stem = ".repository-attribution"
            suffix = 0
            attribution = target / stem
            while attribution.exists():
                suffix += 1
                budget.charge("entries")
                attribution = target / f"{stem}-{suffix}"
            budget.entry(attribution)
            attribution.mkdir()
            target = attribution
        _copy_pack(descriptor, target, budget, names, regular_only=names)
    finally:
        os.close(descriptor)


@contextmanager
def capture_rules(
    sources: Sequence[Path],
    destination: Path,
    *,
    limits: SourceLimits | None = None,
    attribution_roots: Sequence[Path | None] | None = None,
) -> Iterator[tuple[Path, tuple[Path, ...], Path]]:
    """Capture full inputs privately; no accepted path exists until publication."""
    budget = SourceBudget(limits)
    if attribution_roots is not None and len(attribution_roots) != len(sources):
        raise ValidationError("rule pack attribution roots must match source inputs")
    try:
        destination = destination.expanduser()
        destination = destination.parent.resolve(strict=True) / destination.name
        if destination.exists() or destination.is_symlink():
            raise ValidationError(f"rule pack destination already exists: {destination}")
        boundaries = [source.resolve(strict=True) for source in sources]
        for index, boundary in enumerate(boundaries):
            if destination.is_relative_to(boundary) or boundary.is_relative_to(destination):
                raise ValidationError("rule pack source and destination must not overlap")
            if any(
                boundary.is_relative_to(other) or other.is_relative_to(boundary)
                for other in boundaries[:index]
            ):
                raise ValidationError("rule pack sources must not overlap")
        with tempfile.TemporaryDirectory(
            prefix=".opengrep-intake-", dir=destination.parent
        ) as temporary:
            snapshot = Path(temporary) / "pack"
            snapshot.mkdir()
            inputs = []
            for index, source in enumerate(sources):
                source = source.parent.resolve(strict=True) / source.name
                target = snapshot if len(sources) == 1 else snapshot / f"source-{index}"
                target.mkdir(exist_ok=True)
                mode = source.lstat().st_mode
                if stat.S_ISDIR(mode):
                    descriptor = _open_directory(source)
                    try:
                        _copy_pack(descriptor, target, budget)
                    finally:
                        os.close(descriptor)
                    inputs.append(target)
                elif stat.S_ISREG(mode):
                    descriptor = _open_directory(source.parent)
                    try:
                        names = []
                        credits = []
                        with os.scandir(descriptor) as entries:
                            for entry in entries:
                                budget.entry(source.parent / entry.name)
                                paired = entry.name in (source.name, source.stem) or (
                                    entry.name.startswith(source.stem + ".")
                                    and (
                                        Path(entry.name).suffix not in (".yaml", ".yml")
                                        or ".test." in entry.name
                                    )
                                )
                                if paired:
                                    names.append(entry.name)
                                elif entry.name.lower().startswith(_CREDITS) and stat.S_ISREG(
                                    entry.stat(follow_symlinks=False).st_mode
                                ):
                                    names.append(entry.name)
                                    credits.append(entry.name)
                        _copy_pack(descriptor, target, budget, names, regular_only=credits)
                    finally:
                        os.close(descriptor)
                    inputs.append(target / source.name)
                else:
                    raise ValidationError(f"rule pack input is a link or special file: {source}")
                if attribution_roots is not None and (root := attribution_roots[index]) is not None:
                    _copy_attribution(root, source, target, budget)
            yield snapshot, tuple(inputs), destination
    except OSError as error:
        raise ValidationError(f"cannot admit rule pack into {destination}") from error


def pack_digest(snapshot: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(snapshot.rglob("*")):
        if path.is_file():
            digest.update(path.relative_to(snapshot).as_posix().encode() + b"\0")
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def publish_rules(snapshot: Path, destination: Path) -> None:
    if sys.platform == "darwin":
        name, flag = "renameatx_np", 0x00000004  # RENAME_EXCL
    elif sys.platform == "linux":
        name, flag = "renameat2", 1  # RENAME_NOREPLACE
    else:
        raise ValidationError("atomic no-overwrite rule admission is unavailable on this platform")
    rename = getattr(ctypes.CDLL(None, use_errno=True), name, None)
    if rename is None:
        raise ValidationError("atomic no-overwrite rule admission is unavailable on this platform")
    rename.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    with ExitStack() as descriptors:
        source = _open_directory(snapshot.parent)
        descriptors.callback(os.close, source)
        target = _open_directory(destination.parent)
        descriptors.callback(os.close, target)
        if (
            rename(source, os.fsencode(snapshot.name), target, os.fsencode(destination.name), flag)
            != 0
        ):
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code), str(destination))


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
    limits: SourceLimits | None = None,
    budget: NativeBudget,
) -> Iterator[RuleBatch]:
    """Isolate native failures by bounded bisection, retaining accepted snapshots."""
    native_budget = budget
    source_budget = SourceBudget(limits)
    with tempfile.TemporaryDirectory(prefix="opengrep-additive-") as tmp, ExitStack() as held:
        candidates: dict[Path, RuleReceipt] = {}
        refused: list[RuleReceipt] = []
        try:
            native_budget.remaining()
            for i, path in enumerate(paths):
                stage = Path(tmp) / str(i)
                stage.mkdir()
                good, bad = _candidates(
                    source, path, stage, load, protected, languages, source_budget, native_budget
                )
                candidates.update(good)
                refused.extend(bad)
            native_budget.plan(native_calls(tuple(candidates)) + 128, extend=True)
        except (SourceBudgetError, NativeBudgetError) as error:
            check = (
                AdditionCheck.BUDGET
                if isinstance(error, NativeBudgetError)
                else AdditionCheck.SOURCE
            )
            yield RuleBatch((), (), (RuleReceipt(source).refuse(check, str(error)),))
            return
        configs: list[Path] = []
        applied: list[RuleReceipt] = []
        pending = [tuple(candidates)] if candidates else []
        while pending:
            files = pending.pop()
            context = ExitStack()
            try:
                batch = context.enter_context(
                    checked_rules(
                        files,
                        runner,
                        load=load,
                        binary=binary,
                        timeout=timeout,
                        limits=limits,
                        budget=native_budget,
                    )
                )
            except (NativeBudgetError, SourceBudgetError) as error:
                context.close()
                check = (
                    AdditionCheck.BUDGET
                    if isinstance(error, NativeBudgetError)
                    else AdditionCheck.SOURCE
                )
                remaining = (*files, *(path for group in reversed(pending) for path in group))
                refused.extend(candidates[path].refuse(check, str(error)) for path in remaining)
                break
            if batch.report.passed:
                held.enter_context(context)
                configs.extend(batch.configs)
                applied.extend(candidates[path] for path in files)
                continue
            failed = next(check for check in batch.report.checks if not check.passed)
            context.close()
            if len(files) == 1:
                refused.append(candidates[files[0]].refuse(failed.name, failed.detail))
            else:
                middle = len(files) // 2
                pending.extend((files[middle:], files[:middle]))
        yield RuleBatch(tuple(configs), tuple(applied), tuple(refused))
