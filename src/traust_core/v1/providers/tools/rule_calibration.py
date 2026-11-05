from __future__ import annotations

import re
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from traust_core.v1.errors import ConfigError, NotFoundError, ServiceError, ValidationError
from traust_core.v1.models.detection_quality import RuleId, RulePack
from traust_core.v1.models.rule_calibration import (
    CalibrationHit,
    FixtureSanity,
    PackScan,
    RuleCalibrationRequest,
)
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.providers.base import Readiness, on_path
from traust_core.v1.providers.config_matrix import YamlLoader
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.sources import CheckoutRequest, Checkouts, Workspace
from traust_core.v1.providers.tools.detection_quality import rule_refs
from traust_core.v1.providers.tools.opengrep import (
    LANG_DIRS,
    RuleAllowlist,
    SupplementalPack,
    execute_scan,
    pinned_rules_source,
    rules_root,
)

_ANNOTATION = re.compile(r"\b(?:ruleid|ok):\s*\S+")


@dataclass(frozen=True, slots=True)
class PreparedCalibrationPack:
    pack: RulePack
    root: Path
    rules: Path


class OpengrepCalibration:
    name = "opengrep-calibration"

    def __init__(
        self,
        pack: Path,
        supplements: Callable[[], Sequence[SupplementalPack]],
        checkouts: Checkouts,
        runner: ProcessRunner,
        load: YamlLoader,
    ) -> None:
        self._pack, self._supplements = pack, supplements
        self._checkouts, self._runner, self._load = checkouts, runner, load

    def check(self, binary: str = "opengrep") -> Readiness:
        return on_path(binary)

    @contextmanager
    def prepare(self, request: RuleCalibrationRequest) -> Iterator[PreparedCalibrationPack]:
        if not (ready := self.check(request.binary)).ready:
            raise ConfigError(f"calibration scanner unavailable: {ready.detail}")
        source = request.rules
        allowed: tuple[str, ...] | None = None
        if source is None and request.pack != "traust":
            supplement = next((s for s in self._supplements() if s.name == request.pack), None)
            if supplement is None:
                raise NotFoundError(f"rule pack {request.pack!r} is not registered")
            source, allowed = supplement.source, supplement.rules
        workspace: Workspace | None = None
        try:
            if source and source.startswith(("https://", "http://", "git@")):
                url, sha = pinned_rules_source(source)
                workspace = self._checkouts.checkout(
                    CheckoutRequest(
                        repo=HttpsRepoUrl.parse(url, [urlsplit(url).hostname or ""]),
                        ref=GitSha.parse(sha),
                    )
                ).data
                root, rules = workspace.path, rules_root(url, workspace.path)
                version = sha
            else:
                if source and (source == "auto" or re.match(r"^[pr]/[\w./-]+$", source)):
                    raise ValidationError("calibration needs a local or commit-pinned rules tree")
                rules = Path(source).expanduser().resolve() if source else self._pack.resolve()
                root = rules if rules.is_dir() else rules.parent
                version = source or "registered"
            if not rules.exists():
                raise NotFoundError(f"calibration rules tree unavailable: {rules}")
            refs = rule_refs(rules, self._load)
            if allowed is not None:
                if missing := sorted(set(allowed) - set(refs)):
                    raise ValidationError(f"calibration allowlisted rules missing: {missing}")
                refs = {r: refs[r] for r in allowed}
            if not refs:
                raise ValidationError(f"calibration source {rules} contains no rules")
            yield PreparedCalibrationPack(
                pack=RulePack(name=request.pack, version=version, rules=tuple(refs.values())),
                root=root,
                rules=rules,
            )
        finally:
            if workspace is not None:
                self._checkouts.release(workspace)

    def scan(
        self,
        prepared: PreparedCalibrationPack,
        target: Path,
        request: RuleCalibrationRequest,
        *,
        files: Sequence[Path] = (),
    ) -> PackScan:
        if not target.is_dir():
            raise NotFoundError(f"calibration target unavailable: {target}")
        try:
            report = execute_scan(
                target,
                [str(prepared.rules)],
                pack=prepared.rules if prepared.rules.is_dir() else prepared.rules.parent,
                runner=self._runner,
                checkouts=self._checkouts,
                rule_allow=RuleAllowlist(
                    frozenset(r.id for r in prepared.pack.rules), "calibration pack"
                ),
                timeout=request.timeout,
                files=files,
                opengrep_bin=request.binary,
            )
        except (RuntimeError, TimeoutError, IndexError, TypeError, AttributeError, ValueError) as e:
            raise ServiceError(f"calibration scan {target}: {e}") from e
        stats = report["stats"]
        return PackScan(
            files_scanned=stats["files_scanned"],
            engine_errors=stats["errors"],
            skipped_rules=stats["skipped_rules"],
            returncode=report["returncode"],
            hits=tuple(
                CalibrationHit(
                    rule=RuleId(f["rule_id"]),
                    path=f["file"],
                    line=f.get("start_line"),
                    snippet=f.get("snippet") or "",
                )
                for f in report["facts"]
            ),
        )

    def fixtures(
        self, prepared: PreparedCalibrationPack, request: RuleCalibrationRequest
    ) -> FixtureSanity:
        tests = prepared.root / "tests"
        if tests.is_symlink() and not tests.resolve().is_relative_to(prepared.root.resolve()):
            raise ValidationError(f"fixture tree leaves the rules checkout: {tests}")
        target = tests if tests.is_dir() else prepared.root
        annotated = False
        files: list[Path] = []
        for path in target.rglob("*"):
            if (
                path.is_file()
                and not path.is_symlink()
                and path.suffix in LANG_DIRS
                and not any(p.startswith(".") for p in path.relative_to(target).parts)
            ):
                files.append(path)
                try:
                    annotated |= bool(
                        _ANNOTATION.search(path.read_text(encoding="utf-8", errors="replace"))
                    )
                except OSError as e:
                    raise ServiceError(f"reading calibration fixture {path}: {e}") from e
        if not annotated and not tests.is_dir():
            raise NotFoundError(f"no tests/ tree or annotated fixtures in {prepared.root}")
        if not files:
            raise NotFoundError(f"calibration fixture tree has no supported source files: {target}")
        # Explicit files bypass opengrep's built-in tests/ and *_test.go exclusions.
        return FixtureSanity(
            target=target, scan=self.scan(prepared, target, request, files=sorted(files))
        )
