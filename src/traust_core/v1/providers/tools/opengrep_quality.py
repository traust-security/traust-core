"""Native Opengrep quality checks over the same rule snapshot a scan consumes."""

from __future__ import annotations

import hashlib
import re
import sys
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
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
from traust_core.v1.providers.config_matrix import YamlLoader
from traust_core.v1.providers.process import ProcessResult, ProcessRunner, ProcessTimeout

# The bundled scanner Python uses the process locale, not PYTHONUTF8.
OPENGREP_ENV = {
    "LC_ALL": "en_US.UTF-8" if sys.platform == "darwin" else "C.UTF-8",
    "SEMGREP_SEND_METRICS": "off",
}

_OUTPUT_LIMIT = 4 << 20
_SKIPPABLE_ERRORS = re.compile(r"\b[1-9]\d*\s+(?:fatal|skippable)\s+errors?\b", re.I)


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


def _fixture(path: Path, rule: Path) -> bool:
    return (
        path.is_file()
        and path != rule
        and path.name.startswith(rule.stem + ".")
        and (path.suffix not in (".yaml", ".yml") or ".test." in path.name)
    )


def fixture_name(rule: Path, example: str) -> str:
    if Path(example).name != example or not Path(example).suffix:
        raise ValidationError("example must be a bare file name with an extension")
    name = rule.stem + "." + example
    if Path(example).suffix in (".yaml", ".yml") and ".test." not in name:
        name = str(Path(name).with_suffix(".test" + Path(example).suffix))
    return name


def read_rule_text(source: Path, boundary: Path) -> str:
    if not source.resolve().is_relative_to(boundary.resolve()):
        raise ValidationError(f"rule fixture leaves its source directory: {source}")
    try:
        text = source.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValidationError(f"cannot read rule input {source.name}") from error
    return text


def rule_files(source: Path) -> Iterator[Path]:
    root = source if source.is_dir() else source.parent
    paths = (
        sorted({*source.rglob("*.yaml"), *source.rglob("*.yml")}) if source.is_dir() else [source]
    )
    for path in paths:
        if ".test." not in path.name and not any(
            part.startswith(".") or part == "tests" for part in path.relative_to(root).parts[:-1]
        ):
            yield path


def fixture_files(rule: Path) -> Iterator[Path]:
    return (path for path in sorted(rule.parent.glob(rule.stem + ".*")) if _fixture(path, rule))


def _snapshot(
    sources: Sequence[Path], root: Path, examples: Mapping[str, str] | None, load: YamlLoader
) -> tuple[tuple[Path, ...], tuple[str, ...], dict[Path, str], list[str]]:
    configs, rules, problems = [], [], []
    fixtures: dict[Path, str] = {}
    seen: set[Path] = set()
    for index, source in enumerate(sources):
        source = source.expanduser().resolve()
        if not source.exists():
            raise ValidationError(f"rule source not found: {source}")
        boundary = source if source.is_dir() else source.parent
        for path in rule_files(source):
            if path in seen:
                continue
            relative = path.relative_to(boundary)
            seen.add(path)
            text = read_rule_text(path, boundary)
            # Native pairing ignores dotted config basenames such as rule.skeleton.yaml.
            destination = (
                root
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
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text, encoding="utf-8")
            configs.append(destination)
            if len(documents) != 1 or not authored or not isinstance(authored[0]["rules"], list):
                problems.append(f"{path.name} must contain one rule document")
                continue
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
            for fixture in fixture_files(path):
                staged = destination.with_name("rule" + fixture.name[len(path.stem) :])
                fixtures[staged.resolve()] = read_rule_text(fixture, boundary)
                staged.write_text(fixtures[staged.resolve()], encoding="utf-8")
    if examples is not None:
        if len(configs) != 1:
            raise ValidationError("proposal examples require exactly one rule file")
        for name, text in examples.items():
            destination = configs[0].with_name(fixture_name(configs[0], name))
            destination.write_text(text, encoding="utf-8")
            fixtures[destination.resolve()] = text
    if not rules:
        problems.append("no authored rules found")
    return tuple(configs), tuple(rules), fixtures, problems


def _run(runner: ProcessRunner, argv: Sequence[str], timeout: int) -> ProcessResult:
    return runner.run(
        argv,
        check=False,
        timeout_seconds=timeout,
        max_output_bytes=_OUTPUT_LIMIT,
        env=OPENGREP_ENV,
    )


def _process_failure(error: ServiceError | ValidationError) -> str:
    if isinstance(error, ProcessTimeout):
        return "native process timed out"
    return "native process could not complete"


def _validate(
    root: Path, runner: ProcessRunner, binary: str, timeout: int, problems: Sequence[str]
) -> ProposalCheck:
    issues = list(problems)
    try:
        result = _run(runner, [binary, "validate", str(root)], timeout)
        output = (result.stdout + result.stderr).decode(errors="replace")
        if result.returncode != 0 or _SKIPPABLE_ERRORS.search(output):
            issues.append(f"native validate exited {result.returncode} or reported errors")
    except (ServiceError, ValidationError) as error:
        issues.append(_process_failure(error))
    return ProposalCheck(
        name=ProposalCheckName.VALIDATE, passed=not issues, detail="; ".join(issues)[:3000]
    )


def _tests(
    root: Path,
    rules: Sequence[str],
    fixtures: Mapping[Path, str],
    runner: ProcessRunner,
    binary: str,
    timeout: int,
) -> ProposalCheck:
    issues = []
    try:
        result = _run(runner, [binary, "test", "--json", "--strict", str(root)], timeout)
        if result.returncode != 0:
            issues.append(f"native test exited {result.returncode}")
        native = _Tests.model_validate_json(result.stdout)
        if (
            native.config_missing_tests
            or native.config_missing_fixtests
            or native.config_with_errors
        ):
            issues.append("native test reported missing fixtures or configuration errors")
        tested = set()
        for config in native.results.values():
            for rule_id, check in config.checks.items():
                if rule_id not in rules:
                    issues.append("native test returned an unrecognized rule id")
                    continue
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
                for match in check.matches.values():
                    if set(match.expected_lines) != set(match.reported_lines):
                        issues.append(f"unexpected or missing matches for {rule_id}")
        if tested != set(rules):
            issues.append("native test did not exercise exactly the supplied rule ids")
        if _failed_fix(native.fixtest_results):
            issues.append("native autofix test did not pass")
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
) -> Iterator[CheckedRules]:
    """Validate and test a private snapshot; only that snapshot may be scanned."""
    with tempfile.TemporaryDirectory(prefix="opengrep-quality-") as temporary:
        root = Path(temporary).resolve()
        configs, rules, fixtures, problems = _snapshot(sources, root, examples, load)
        validation = _validate(root, runner, binary, timeout, problems)
        testing = (
            _tests(root, rules, fixtures, runner, binary, timeout)
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
