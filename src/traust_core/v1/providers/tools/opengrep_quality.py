"""Native Opengrep quality checks over the same rule snapshot a scan consumes."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from pydantic import JsonValue, StrictBool, StrictInt, StrictStr
from pydantic import ValidationError as ModelValidationError

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.base import Dto
from traust_core.v1.models.rule_mining import (
    ProposalCheck,
    ProposalCheckName,
    RuleQualityReport,
    example_lines,
)
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.config_matrix import YamlLoader
from traust_core.v1.providers.process import ProcessResult, ProcessRunner, ProcessTimeout

# The bundled scanner Python uses the process locale, not PYTHONUTF8.
OPENGREP_ENV = {
    "LC_ALL": "en_US.UTF-8" if sys.platform == "darwin" else "C.UTF-8",
    "SEMGREP_SEND_METRICS": "off",
}

_OUTPUT_LIMIT = 4 << 20
_SKIPPABLE_ERRORS = re.compile(r"\b[1-9]\d*\s+(?:fatal|skippable)\s+errors?\b", re.I)


@dataclass(frozen=True, slots=True)
class SourceLimits:
    files: int = 50_000
    bytes: int = 256 << 20
    rules: int = 25_000
    fixtures: int = 50_000
    entries: int = 100_000
    depth: int = 64
    staged_files: int = 50_000
    staged_bytes: int = 256 << 20


class SourceBudgetError(ValidationError):
    """An optional source exceeds its bounded discovery or snapshot allowance."""


class SourceBudget:
    def __init__(self, limits: SourceLimits | None = None) -> None:
        self.limits = limits if limits is not None else SourceLimits()
        self._counts: dict[str, int] = {}
        self._entries: set[Path] = set()
        self._files: dict[Path, int] = {}
        self._fixtures: set[Path] = set()

    def charge(self, kind: str, amount: int = 1) -> None:
        count = self._counts.get(kind, 0) + amount
        if count > getattr(self.limits, kind):
            raise SourceBudgetError(f"rule source exceeds {kind} budget")
        self._counts[kind] = count

    def entry(self, path: Path) -> None:
        if path not in self._entries:
            self.charge("entries")
            self._entries.add(path)

    def file(self, path: Path, size: int) -> None:
        self.entry(path)
        if path not in self._files:
            self.charge("files")
        self.charge("bytes", max(0, size - self._files.get(path, 0)))
        self._files[path] = max(size, self._files.get(path, 0))

    def fixture(self, path: Path) -> None:
        if path not in self._fixtures:
            self.charge("fixtures")
            self._fixtures.add(path)

    def stage(self, size: int) -> None:
        self.charge("staged_files")
        self.charge("staged_bytes", size)


class NativeBudgetError(ValidationError):
    """Optional native vetting exhausted its shared deadline or process allowance."""


@dataclass(slots=True)
class NativeBudget:
    clock: Clock
    seconds: float = 300
    calls: int | None = None
    _started: datetime = field(init=False, repr=False)
    _automatic: bool = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._started = self.clock.now()
        self._automatic = self.calls is None

    def plan(self, calls: int, *, extend: bool = False) -> None:
        if self.calls is None:
            self.calls = calls
        elif extend and self._automatic:
            self.calls += calls

    def remaining(self) -> float:
        remaining = self.seconds - (self.clock.now() - self._started).total_seconds()
        if (self.calls is not None and self.calls <= 0) or remaining <= 0:
            raise NativeBudgetError("optional rule vetting budget exhausted")
        return remaining

    def timeout(self, requested: float) -> float:
        remaining = self.remaining()
        if self.calls is None:
            raise NativeBudgetError("optional rule vetting work was not planned")
        self.calls -= 1
        return min(requested, remaining)


_VCS = frozenset({".git", ".hg", ".svn", ".bzr"})


def _source_files(source: Path, budget: SourceBudget) -> list[Path]:
    files: list[Path] = []
    pending = [(source, 0)]
    while pending:
        path, depth = pending.pop()
        if depth > budget.limits.depth:
            raise SourceBudgetError("rule source exceeds depth budget")
        budget.entry(path)
        metadata = path.lstat()
        if stat.S_ISREG(metadata.st_mode):
            budget.file(path, metadata.st_size)
            files.append(path)
        elif stat.S_ISDIR(metadata.st_mode):
            with os.scandir(path) as entries:
                for entry in entries:
                    if entry.name not in _VCS:
                        child = path / entry.name
                        budget.entry(child)
                        pending.append((child, depth + 1))
        else:
            raise ValidationError(f"rule input is a link or special file: {path.name}")
    return sorted(files)


class _Matches(Dto):
    expected_lines: tuple[StrictInt, ...]
    reported_lines: tuple[StrictInt, ...]


class _Check(Dto):
    passed: StrictBool
    matches: dict[str, _Matches]
    errors: tuple[JsonValue, ...]


class _Config(Dto):
    checks: dict[str, _Check]


class _Tests(Dto):
    results: dict[str, _Config]
    config_missing_tests: tuple[StrictStr, ...]
    config_missing_fixtests: tuple[StrictStr, ...]
    config_with_errors: tuple[JsonValue, ...]
    fixtest_results: dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class CheckedRules:
    configs: tuple[Path, ...]
    digest: str
    report: RuleQualityReport


class RuleQualityError(ValidationError):
    def __init__(self, report: RuleQualityReport) -> None:
        self.report = report
        failed = "; ".join(f"{c.name}: {c.detail}" for c in report.checks if not c.passed)
        super().__init__(f"Opengrep rule quality failed: {failed or 'no tested rules'}")


def fixture_name(rule: Path, example: str) -> str:
    if Path(example).name != example or not Path(example).suffix:
        raise ValidationError("example must be a bare file name with an extension")
    name = rule.stem + "." + example
    if Path(example).suffix in (".yaml", ".yml") and ".test." not in name:
        name = str(Path(name).with_suffix(".test" + Path(example).suffix))
    return name


def read_rule_text(source: Path, boundary: Path, *, budget: SourceBudget | None = None) -> str:
    if not source.resolve().is_relative_to(boundary.resolve()):
        raise ValidationError(f"rule fixture leaves its source directory: {source}")
    usage = budget if budget is not None else SourceBudget()
    try:
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValidationError(f"rule input is a link or special file: {source.name}")
            usage.file(source, metadata.st_size)
            content = stream.read(metadata.st_size + 1)
            if len(content) > metadata.st_size:
                raise SourceBudgetError("rule input grew while capturing its bounded snapshot")
            return content.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise ValidationError(f"cannot read rule input {source.name}") from error


def rule_files(source: Path, *, budget: SourceBudget | None = None) -> Iterator[Path]:
    usage = budget if budget is not None else SourceBudget()
    root = source if source.is_dir() else source.parent
    paths = [
        path
        for path in _source_files(source, usage)
        if path.suffix in (".yaml", ".yml") or path == source
    ]
    fixture_roots = {
        path.with_suffix("")
        for path in paths
        if ".test." not in path.name and path.with_suffix("").is_dir()
    }
    for path in paths:
        if (
            ".test." not in path.name
            and not any(path.is_relative_to(folder) for folder in fixture_roots)
            and not any(
                part.startswith(".") or part == "tests"
                for part in path.relative_to(root).parts[:-1]
            )
        ):
            yield path


def fixture_files(rule: Path, *, budget: SourceBudget | None = None) -> Iterator[Path]:
    usage = budget if budget is not None else SourceBudget()
    matches = []
    with os.scandir(rule.parent) as entries:
        for entry in entries:
            path = rule.parent / entry.name
            usage.entry(path)
            if (
                path != rule
                and entry.name.startswith(rule.stem + ".")
                and (path.suffix not in (".yaml", ".yml") or ".test." in path.name)
            ):
                matches.extend(_source_files(path, usage))
    directory = rule.with_suffix("")
    if directory.exists() or directory.is_symlink():
        matches.extend(_source_files(directory, usage))
    for path in sorted(matches):
        usage.fixture(path)
        yield path


def fixture_target(rule: Path, fixture: Path, staged_rule: Path) -> Path:
    directory = rule.with_suffix("")
    if fixture.is_relative_to(directory):
        return staged_rule.with_suffix("") / fixture.relative_to(directory)
    return staged_rule.with_name(staged_rule.stem + fixture.name[len(rule.stem) :])


def _snapshot(
    sources: Sequence[Path],
    root: Path,
    examples: Mapping[str, str] | None,
    load: YamlLoader,
    budget: SourceBudget,
) -> tuple[tuple[Path, ...], tuple[str, ...], dict[Path, str], list[str]]:
    configs, rules, problems = [], [], []
    fixtures: dict[Path, str] = {}
    seen: set[Path] = set()
    for index, source in enumerate(sources):
        source = source.expanduser().absolute()
        source = source.parent.resolve() / source.name
        if not source.exists():
            raise ValidationError(f"rule source not found: {source}")
        boundary = source if source.is_dir() else source.parent
        for path in rule_files(source, budget=budget):
            if path in seen:
                continue
            relative = path.relative_to(boundary)
            seen.add(path)
            text = read_rule_text(path, boundary, budget=budget)
            # Native pairing ignores dotted config basenames such as rule.skeleton.yaml.
            destination = (
                root
                / ("directory-fixtures" if path.with_suffix("").is_dir() else "ordinary")
                / f"source-{index}"
                / relative.parent
                / (relative.name + ".rules")
                / "rule.yaml"
            )
            try:
                documents = load(text)
            except (OSError, UnicodeError, ValidationError) as error:
                if path == source or "rule" in path.name:
                    problems.append(f"cannot parse rule input {path.name}")
                    documents = []
                else:
                    raise ValidationError(f"cannot parse rule input {path.name}") from error
            authored = [d for d in documents if isinstance(d, dict) and "rules" in d]
            if not authored and path != source:
                continue
            budget.stage(len(text.encode("utf-8")))
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text, encoding="utf-8", newline="")
            configs.append(destination)
            if len(documents) != 1 or not authored or not isinstance(authored[0]["rules"], list):
                problems.append(f"{path.name} must contain one rule document")
                continue
            budget.charge("rules", len(authored[0]["rules"]))
            for rule in authored[0]["rules"]:
                if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
                    problems.append(f"{path.name} contains a rule without a string id")
                    continue
                rule_id = rule["id"]
                if rule_id in rules:
                    problems.append(f"duplicate rule id: {rule_id}")
                rules.append(rule_id)
                if str(rule.get("pattern", "")).strip().startswith("TODO"):
                    problems.append(f"{rule_id} is an unauthored skeleton")
            for fixture in fixture_files(path, budget=budget):
                staged = fixture_target(path, fixture, destination)
                text = read_rule_text(fixture, boundary, budget=budget)
                budget.stage(len(text.encode("utf-8")))
                staged.parent.mkdir(parents=True, exist_ok=True)
                fixtures[staged.resolve()] = text
                staged.write_text(text, encoding="utf-8", newline="")
    if examples is not None:
        if len(configs) != 1:
            raise ValidationError("proposal examples require exactly one rule file")
        for name, text in examples.items():
            destination = configs[0].with_name(fixture_name(configs[0], name))
            budget.fixture(destination)
            budget.stage(len(text.encode("utf-8")))
            destination.write_text(text, encoding="utf-8", newline="")
            fixtures[destination.resolve()] = text
    if not rules:
        problems.append("no authored rules found")
    return tuple(configs), tuple(rules), fixtures, problems


def _run(
    runner: ProcessRunner, argv: Sequence[str], timeout: int, budget: NativeBudget | None
) -> ProcessResult:
    return runner.run(
        argv,
        check=False,
        timeout_seconds=budget.timeout(timeout) if budget is not None else timeout,
        max_output_bytes=_OUTPUT_LIMIT,
        env=OPENGREP_ENV,
    )


def _process_failure(error: ServiceError | ValidationError) -> str:
    if isinstance(error, ProcessTimeout):
        return "native process timed out"
    return "native process could not complete"


def _validate(
    root: Path,
    runner: ProcessRunner,
    binary: str,
    timeout: int,
    problems: Sequence[str],
    budget: NativeBudget | None,
) -> ProposalCheck:
    issues = list(problems)
    try:
        result = _run(runner, [binary, "validate", str(root)], timeout, budget)
        output = (result.stdout + result.stderr).decode(errors="replace")
        if result.returncode != 0 or _SKIPPABLE_ERRORS.search(output):
            issues.append(f"native validate exited {result.returncode} or reported errors")
    except NativeBudgetError:
        raise
    except (ServiceError, ValidationError) as error:
        issues.append(_process_failure(error))
    return ProposalCheck(
        name=ProposalCheckName.VALIDATE, passed=not issues, detail="; ".join(issues)[:3000]
    )


def _test_targets(root: Path, configs: Sequence[Path]) -> Iterator[tuple[str, ...]]:
    directories, ordinary = [], []
    for config in configs:
        (directories if config.with_suffix("").is_dir() else ordinary).append(config)
    if ordinary or not directories:
        yield (str(root / "ordinary"),)
    for config in directories:
        # Explicit files avoid older native runners opening paired directories as files.
        for target in fixture_files(config):
            if not target.stem.endswith(".fixed"):
                yield ("--config", str(config), str(target))


def native_calls(configs: Sequence[Path]) -> int:
    return 1 + sum(1 for _ in _test_targets(Path(), configs))


def _test_runs(
    root: Path,
    configs: Sequence[Path],
    runner: ProcessRunner,
    binary: str,
    timeout: int,
    budget: NativeBudget | None,
) -> Iterator[ProcessResult]:
    for target in _test_targets(root, configs):
        yield _run(runner, [binary, "test", "--json", "--strict", *target], timeout, budget)


def _tests(
    root: Path,
    configs: Sequence[Path],
    rules: Sequence[str],
    fixtures: Mapping[Path, str],
    runner: ProcessRunner,
    binary: str,
    timeout: int,
    budget: NativeBudget | None,
) -> ProposalCheck:
    issues = []
    try:
        reports = []
        for result in _test_runs(root, configs, runner, binary, timeout, budget):
            if result.returncode != 0:
                issues.append(f"native test exited {result.returncode}")
            native = _Tests.model_validate_json(result.stdout)
            if (
                native.config_missing_tests
                or native.config_missing_fixtests
                or native.config_with_errors
            ):
                issues.append("native test reported missing fixtures or configuration errors")
            reports.append(native)
        combined: dict[str, dict[str, _Check]] = {}
        for report in reports:
            if not any(config.checks for config in report.results.values()):
                issues.append("native test returned no check receipts")
            for name, config in report.results.items():
                checks = combined.setdefault(name, {})
                for rule_id, check in config.checks.items():
                    previous = checks.get(rule_id)
                    if previous is None:
                        checks[rule_id] = check
                    elif previous.matches.keys() & check.matches.keys():
                        issues.append(f"native test returned duplicate fixtures for {rule_id}")
                    else:
                        checks[rule_id] = _Check(
                            passed=previous.passed and check.passed,
                            matches={**previous.matches, **check.matches},
                            errors=(*previous.errors, *check.errors),
                        )
        tested = set()
        for checks in combined.values():
            config = _Config(checks=checks)
            for rule_id, check in config.checks.items():
                if rule_id not in rules:
                    issues.append("native test returned an unrecognized rule id")
                    continue
                if rule_id in tested:
                    issues.append(f"native test returned duplicate receipts for {rule_id}")
                tested.add(rule_id)
                annotations = [
                    example_lines(rule_id, fixtures[path])
                    for name in check.matches
                    if (path := Path(name).resolve()) in fixtures
                ]
                if not any(fire for fire, _ in annotations) or not any(
                    quiet for _, quiet in annotations
                ):
                    issues.append(
                        f"{rule_id} needs both ruleid: and ok: examples in native matching fixtures"
                    )
                if (
                    not check.passed
                    or check.errors
                    or not any(match.expected_lines for match in check.matches.values())
                ):
                    issues.append(f"native test did not pass {rule_id}")
                for name, match in check.matches.items():
                    path = Path(name).resolve()
                    if path not in fixtures:
                        issues.append(f"native test returned an unknown fixture for {rule_id}")
                        continue
                    fire, _ = example_lines(rule_id, fixtures[path])
                    if set(match.expected_lines) != fire or set(match.expected_lines) != set(
                        match.reported_lines
                    ):
                        issues.append(f"unexpected or missing matches for {rule_id}")
        if tested != set(rules):
            issues.append("native test did not exercise exactly the supplied rule ids")
        if any(_failed_fix(report.fixtest_results) for report in reports):
            issues.append("native autofix test did not pass")
    except NativeBudgetError:
        raise
    except ModelValidationError:
        issues.append("native test returned invalid output")
    except (ServiceError, ValidationError) as error:
        issues.append(_process_failure(error))
    return ProposalCheck(
        name=ProposalCheckName.TEST, passed=not issues, detail="; ".join(issues)[:3000]
    )


def _failed_fix(value: JsonValue) -> bool:
    if isinstance(value, dict):
        return value.get("passed") is False or any(_failed_fix(v) for v in value.values())
    if isinstance(value, list):
        return any(_failed_fix(v) for v in value)
    return False


@contextmanager
def checked_rules(
    sources: Sequence[Path],
    runner: ProcessRunner,
    *,
    load: YamlLoader,
    binary: str = "opengrep",
    timeout: int = 300,
    examples: Mapping[str, str] | None = None,
    limits: SourceLimits | None = None,
    budget: NativeBudget | None = None,
) -> Iterator[CheckedRules]:
    """Validate and test a private snapshot; only that snapshot may be scanned."""
    with tempfile.TemporaryDirectory(prefix="opengrep-quality-") as temporary:
        root = Path(temporary).resolve()
        configs, rules, fixtures, problems = _snapshot(
            sources, root, examples, load, SourceBudget(limits)
        )
        if budget is not None:
            budget.plan(native_calls(configs))
        validation = _validate(root, runner, binary, timeout, problems, budget)
        testing = (
            _tests(root, configs, rules, fixtures, runner, binary, timeout, budget)
            if validation.passed
            else ProposalCheck(
                name=ProposalCheckName.TEST,
                passed=False,
                detail="not run because native validation failed",
            )
        )
        digest = hashlib.sha256()
        for path in sorted({*configs, *fixtures}):
            digest.update(path.relative_to(root).as_posix().encode() + b"\0")
            digest.update(hashlib.sha256(path.read_bytes()).digest())
        yield CheckedRules(
            configs=configs,
            digest=digest.hexdigest(),
            report=RuleQualityReport(rules=rules, checks=(validation, testing)),
        )
