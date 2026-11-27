"""propose_rule: the gate's order (a rule that fails a static check never runs), staging an
admitted proposal as a draft, and one real opengrep run."""

from __future__ import annotations

import json
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import NoCheckouts
from tests.v1.providers.tools.test_opengrep_quality import NativeRunner
from tests.v1.services.test_detection_quality_sweep import COVERING, Bench, Sweeper, engine
from traust_core.v1.context.documents import yaml_documents
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.rule_mining import (
    ProposalCheck,
    ProposalCheckName,
    RepoSweep,
    RuleHit,
    RuleProposal,
    SweepRepo,
)
from traust_core.v1.providers.process import ProcessResult
from traust_core.v1.providers.rule_drafts import NOTES, SKELETON
from traust_core.v1.providers.tools import detection_quality as sweep_provider
from traust_core.v1.providers.tools.detection_quality import OpengrepRuleSweep

__all__ = ["engine"]  # the fixture, shared with the sweep tests

RID = "traust-proposed-py-shell"
RULE = f"""rules:
  - id: {RID}
    languages: [python]
    severity: ERROR
    message: a shell runs a built command
    metadata:
      cwe: ["CWE-78"]
    pattern: os.system($CMD)
"""
EXAMPLE = f"""import os
import subprocess
# ruleid: {RID}
os.system(cmd)
# ok: {RID}
subprocess.run(["ls"])
"""


@dataclass
class Trials(Sweeper):
    """Fixed trial results: hit lines on the examples, then hits on the checkout."""

    example_lines: tuple[int, ...] = (4,)
    checkout_hits: int = 2
    checkout_files: int = 40
    error: str | None = None
    engine_errors: int | None = 0
    quality_checks: tuple[ProposalCheck, ...] = (
        ProposalCheck(name=ProposalCheckName.VALIDATE, passed=True),
        ProposalCheck(name=ProposalCheckName.TEST, passed=True),
    )
    trials: list[str] = field(default_factory=list)

    def trial(
        self,
        rule: str,
        target: Path | Mapping[str, str],
        binary: str,
        timeout: int,
        *,
        examples: Mapping[str, str],
    ) -> RepoSweep:
        on_examples = not isinstance(target, Path)
        self.trials.append("examples" if on_examples else "checkout")
        if self.error:
            return RepoSweep(
                slug="trial",
                error=self.error,
                quality_checks=self.quality_checks,
                engine_errors=self.engine_errors,
            )
        lines = self.example_lines if on_examples else range(1, self.checkout_hits + 1)
        files = ("example.py",) if on_examples else tuple(f"src/m{i}.py" for i in lines)
        facts = tuple(
            RuleHit(rule_id=RID, file=f, start_line=n, end_line=n)
            for n, f in zip(lines, files * len(lines), strict=False)
        )
        return RepoSweep(
            slug="trial",
            files_scanned=1 if on_examples else self.checkout_files,
            facts=facts,
            quality_checks=self.quality_checks,
            engine_errors=self.engine_errors,
        )


def proposal(tmp_path: Path, **kw: object) -> RuleProposal:
    checkout = tmp_path / "checkout"
    checkout.mkdir(exist_ok=True)
    values: dict[str, object] = {
        "rule": RULE,
        "example": EXAMPLE,
        "example_name": "example.py",
        "shape": "a built command reaches os.system (route-guards gap: none)",
        "checkout": checkout,
    }
    return RuleProposal.model_validate(values | kw)


def bench(engine: Engine, tmp_path: Path, sweeper: Sweeper) -> Bench:
    return Bench(engine, tmp_path, sweeper=sweeper)


def test_an_admitted_proposal_is_staged_as_a_draft(engine: Engine, tmp_path: Path) -> None:
    sweeper = Trials()
    b = bench(engine, tmp_path, sweeper)
    verdict = b.service.propose_rule(proposal(tmp_path))
    assert verdict.admitted and verdict.draft == RID
    assert [c.name for c in verdict.checks] == [
        "structure",
        "catch-all",
        "paths",
        "regex",
        "validate",
        "test",
        "examples",
        "explosion",
    ]
    assert (verdict.hits, verdict.files_scanned) == (2, 40)
    assert sweeper.trials == ["examples", "checkout"]
    draft = tmp_path / "rule-drafts" / RID
    assert (draft / SKELETON).read_text() == RULE
    assert (draft / "rule.skeleton.example.py").read_text() == EXAMPLE
    assert "a built command reaches os.system" in (draft / NOTES).read_text()
    # the staged draft is authored, so the mine-ledger sweep takes it as it is
    assert not b.drafts.resolve(RID).unauthored


def test_a_rule_failing_a_static_check_never_runs(engine: Engine, tmp_path: Path) -> None:
    sweeper = Trials()
    unsafe = RULE.replace("pattern: os.system($CMD)", 'pattern-regex: "(a+)+b"')
    verdict = bench(engine, tmp_path, sweeper).service.propose_rule(proposal(tmp_path, rule=unsafe))
    assert not verdict.admitted and verdict.draft is None
    assert {c.name: c.passed for c in verdict.checks}["regex"] is False
    assert sweeper.trials == []
    assert not (tmp_path / "rule-drafts").exists()


def test_examples_that_dont_fire_stop_before_the_checkout_scan(
    engine: Engine, tmp_path: Path
) -> None:
    sweeper = Trials(example_lines=(4, 6))
    verdict = bench(engine, tmp_path, sweeper).service.propose_rule(proposal(tmp_path))
    assert not verdict.admitted
    assert verdict.checks[-1].name == "examples" and "ok line(s) [6]" in verdict.checks[-1].detail
    assert sweeper.trials == ["examples"]


def test_an_exploding_rule_is_refused_and_not_staged(engine: Engine, tmp_path: Path) -> None:
    sweeper = Trials(checkout_hits=30)
    verdict = bench(engine, tmp_path, sweeper).service.propose_rule(proposal(tmp_path))
    assert not verdict.admitted and verdict.hits == 30
    assert verdict.checks[-1].name == "explosion" and not verdict.checks[-1].passed
    assert not (tmp_path / "rule-drafts" / RID).exists()


def test_a_failed_trial_scan_is_a_failed_check(engine: Engine, tmp_path: Path) -> None:
    verdict = bench(engine, tmp_path, Trials(error="scan_timeout")).service.propose_rule(
        proposal(tmp_path)
    )
    assert not verdict.admitted and verdict.checks[-1].detail == "scan failed: scan_timeout"


@pytest.mark.parametrize("taken", [COVERING, "held"])
def test_an_id_the_pack_or_a_draft_already_has_is_refused(
    engine: Engine, tmp_path: Path, taken: str
) -> None:
    b = bench(engine, tmp_path, Trials())
    if taken == "held":
        b.service.propose_rule(proposal(tmp_path))
        taken = RID
    verdict = b.service.propose_rule(proposal(tmp_path, rule=RULE.replace(RID, taken)))
    assert not verdict.admitted and "already exists" in verdict.checks[0].detail


def test_missing_opengrep_bad_yaml_and_a_missing_checkout_are_errors(
    engine: Engine, tmp_path: Path
) -> None:
    with pytest.raises(ConfigError):
        bench(engine, tmp_path, Trials(ready=False)).service.propose_rule(proposal(tmp_path))
    service = bench(engine, tmp_path, Trials()).service
    with pytest.raises(ValidationError):
        service.propose_rule(proposal(tmp_path, rule="rules: [unclosed"))
    with pytest.raises(ValidationError):
        service.propose_rule(proposal(tmp_path, checkout=tmp_path / "missing"))


@pytest.mark.skipif(not shutil.which("opengrep"), reason="opengrep not on PATH")
def test_the_gate_end_to_end_through_opengrep(engine: Engine, tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    (checkout / "app").mkdir(parents=True)
    (checkout / "app" / "run.py").write_text("import os\nos.system(user_cmd)\n")
    (checkout / "app" / "safe.py").write_text("print('ok')\n")
    (tmp_path / "pack").mkdir()
    real = OpengrepRuleSweep(
        tmp_path / "pack", ("PATH", "HOME"), NoCheckouts(), load=yaml_documents
    )
    verdict = Bench(engine, tmp_path, sweeper=real).service.propose_rule(  # type: ignore[arg-type]
        proposal(tmp_path, checkout=checkout)
    )
    assert verdict.admitted, verdict.checks
    assert verdict.hits == 1


@pytest.mark.parametrize("errors", [None, 1])
def test_partial_or_unmeasured_engine_results_cannot_admit_a_rule(
    engine: Engine, tmp_path: Path, errors: int | None
) -> None:
    verdict = bench(engine, tmp_path, Trials(engine_errors=errors)).service.propose_rule(
        proposal(tmp_path)
    )
    assert not verdict.admitted and verdict.draft is None


def test_missing_native_quality_receipts_cannot_admit_a_rule(
    engine: Engine, tmp_path: Path
) -> None:
    verdict = bench(engine, tmp_path, Trials(quality_checks=())).service.propose_rule(
        proposal(tmp_path)
    )
    assert not verdict.admitted and verdict.draft is None
    assert {c.name for c in verdict.checks if not c.passed} == {"examples"}


def test_a_failed_native_test_cannot_be_overridden_by_matching_examples(
    engine: Engine, tmp_path: Path
) -> None:
    checks = (
        ProposalCheck(name=ProposalCheckName.VALIDATE, passed=True),
        ProposalCheck(name=ProposalCheckName.TEST, passed=False, detail="fixture mismatch"),
    )
    verdict = bench(engine, tmp_path, Trials(quality_checks=checks)).service.propose_rule(
        proposal(tmp_path)
    )
    assert not verdict.admitted and verdict.draft is None


def test_unannotated_example_matches_do_not_admit_a_rule(engine: Engine, tmp_path: Path) -> None:
    verdict = bench(engine, tmp_path, Trials(example_lines=(4, 7))).service.propose_rule(
        proposal(tmp_path)
    )
    assert not verdict.admitted and "unannotated" in verdict.checks[-1].detail


@pytest.mark.parametrize("stage", ["examples", "explosion"])
@pytest.mark.parametrize(
    ("failure", "category"),
    [
        ("scan-timeout", "scan_timeout"),
        ("scan-exit", "opengrep_failed"),
        ("scan-malformed", "invalid_output"),
    ],
)
def test_real_trial_transport_failures_keep_passed_quality_and_the_actual_failed_stage(
    engine: Engine,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    failure: str,
    category: str,
) -> None:
    class FailingScanRunner(NativeRunner):
        def run(self, argv: Sequence[str], **kwargs: Any) -> ProcessResult:
            if argv[1] == "scan" and Path(argv[-1]).name == "tree" and stage == "explosion":
                target = Path(argv[-1])
                return ProcessResult(
                    tuple(argv),
                    0,
                    json.dumps(
                        {
                            "results": [
                                {
                                    "check_id": RID,
                                    "path": str(target / "example.py"),
                                    "start": {"line": 4},
                                    "end": {"line": 4},
                                }
                            ],
                            "errors": [],
                            "paths": {"scanned": [str(target / "example.py")]},
                        }
                    ).encode(),
                    b"",
                    0.01,
                )
            return super().run(argv, **kwargs)

    runner = FailingScanRunner(failure)
    monkeypatch.setattr(sweep_provider, "ProcessRunner", lambda *args, **kwargs: runner)
    real = OpengrepRuleSweep(tmp_path / "pack", (), NoCheckouts(), load=yaml_documents)
    monkeypatch.setattr(real, "check", lambda binary: Trials().check(binary))
    verdict = Bench(engine, tmp_path, sweeper=real).service.propose_rule(  # type: ignore[arg-type]
        proposal(tmp_path)
    )
    assert not verdict.admitted and verdict.draft is None
    native = [check for check in verdict.checks if check.name in {"validate", "test"}]
    assert len(native) == 2 and all(check.passed for check in native)
    assert verdict.checks[-1].name == stage and not verdict.checks[-1].passed
    assert category in verdict.checks[-1].detail
    assert "PRIVATE_NATIVE_SENTINEL" not in verdict.model_dump_json()
    if failure == "scan-timeout":
        assert "300s" in verdict.checks[-1].detail


@pytest.mark.skipif(not shutil.which("opengrep"), reason="real Opengrep integration")
@pytest.mark.parametrize("extension", ["yaml", "yml"])
def test_yaml_proposal_and_staged_skeleton_use_native_matching_fixtures(
    engine: Engine, tmp_path: Path, extension: str
) -> None:
    rule_id = "acme-yaml-privileged"
    rule = f"""rules:
  - id: {rule_id}
    languages: [yaml]
    severity: ERROR
    message: privileged workload
    metadata:
      cwe: [CWE-250]
    pattern: "privileged: true"
"""
    example = f"# ruleid: {rule_id}\nprivileged: true\n---\n# ok: {rule_id}\nprivileged: false\n"
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / f"app.{extension}").write_text("privileged: true\n")
    real = OpengrepRuleSweep(
        tmp_path / "pack", ("PATH", "HOME"), NoCheckouts(), load=yaml_documents
    )
    b = Bench(engine, tmp_path, sweeper=real)  # type: ignore[arg-type]
    verdict = b.service.propose_rule(
        proposal(
            tmp_path,
            rule=rule,
            example=example,
            example_name=f"example.{extension}",
            checkout=checkout,
        )
    )
    assert verdict.admitted, verdict.checks
    assert verdict.hits == 1
    staged = tmp_path / "rule-drafts" / rule_id
    assert (staged / SKELETON).read_text() == rule
    assert (staged / f"rule.skeleton.example.test.{extension}").read_text() == example
    found = real.scan(
        SweepRepo(slug="staged", url=f"dir:{checkout}"),
        b.drafts.resolve(rule_id),
        "opengrep",
        120,
    )
    assert found.error is None and len(found.facts) == 1
    assert all(check.passed for check in found.quality_checks)


@pytest.mark.parametrize("error", ["scan_timeout", "opengrep_failed", "invalid_rules"])
def test_missing_receipts_report_the_actual_scan_failure_not_invented_native_failures(
    engine: Engine, tmp_path: Path, error: str
) -> None:
    verdict = bench(engine, tmp_path, Trials(error=error, quality_checks=())).service.propose_rule(
        proposal(tmp_path)
    )
    assert not verdict.admitted and verdict.draft is None
    assert verdict.checks[-1].name == "examples"
    assert error in verdict.checks[-1].detail
    assert not any(check.name in {"validate", "test"} for check in verdict.checks)
