"""Gitleaks: ported from traust-engine tests/test_run_gitleaks.py, the gitleaks cases of
test_adapter_contract_boundary.py, test_native_adapter_artifact.py and
test_adapter_observation_publication.py."""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from tests.v1.conftest import git
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ServiceError
from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.findings import FindingFilter
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import (
    ProcessError,
    ProcessResult,
    ProcessRunner,
    ProcessTimeout,
)
from traust_core.v1.providers.tools.gitleaks import (
    Gitleaks,
    candidates_to_findings,
    parse_report,
)
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs

RULES = Path(__file__).parents[3] / "fixtures" / "tools" / "gitleaks-rules.toml"
WHEN = datetime(2026, 10, 24, 12, tzinfo=UTC)
FAKE_TOKEN = "sha256~" + "B" * 43
HAVE_GITLEAKS = shutil.which("gitleaks") is not None
needs_gitleaks = pytest.mark.skipif(not HAVE_GITLEAKS, reason="gitleaks not on PATH")


def real() -> Gitleaks:
    return Gitleaks(ProcessRunner(["gitleaks", "git"], timeout_seconds=900), FixedClock(WHEN))


def candidates(repo: Path, mode: str = "dir") -> list[dict[str, Any]]:
    gitleaks = real()
    return parse_report(gitleaks.run(repo, mode, RULES, 900), repo, mode)


def target_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "target"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "config.py").write_text(f'token = "{FAKE_TOKEN}"\n')
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "add")
    return repo


def test_parse_report_is_secret_free() -> None:
    findings = [
        {
            "RuleID": "traust-openshift-sha256-token",
            "Description": "OpenShift OAuth access token",
            "File": "config.py",
            "StartLine": 1,
            "EndLine": 1,
            "Secret": FAKE_TOKEN,
            "Match": f'token = "{FAKE_TOKEN}"',
            "Entropy": 4.2,
            "Fingerprint": "config.py:traust:1",
        }
    ]
    (c,) = parse_report(findings, Path("/nonexistent"), "dir")
    assert c["liveness_class"] == "openshift"
    assert c["evidence"] == "secret_pattern_match"
    assert FAKE_TOKEN not in json.dumps([c])
    assert "commit" not in c


def test_history_mode_keeps_author_not_message() -> None:
    findings = [
        {
            "RuleID": "aws-access-token",
            "File": "x",
            "Commit": "abc123",
            "Email": "dev@example.com",
            "Date": "2026-01-01T00:00:00Z",
            "Message": "add creds INJECTION-MARKER",
            "Secret": "AKIA" + "X" * 16,
        }
    ]
    c = parse_report(findings, Path("/nonexistent"), "history")[0]
    assert c["commit"] == "abc123"
    assert c["author_email"] == "dev@example.com"
    assert "INJECTION-MARKER" not in json.dumps(c)
    assert c["liveness_class"] == "aws"


def test_inline_allow_from_redacted_line_is_flagged() -> None:
    findings = [
        {
            "RuleID": "generic-api-key",
            "File": "x",
            "StartLine": 1,
            "Line": 'KEY = "REDACTED"  # gitleaks:allow',
        }
    ]
    c = parse_report(findings, Path("/nonexistent"), "dir")[0]
    assert c["inline_allow"] is True
    assert "gitleaks:allow" in candidates_to_findings([c])[0]["description"]


def test_inline_allow_read_from_checkout_without_leaking_line(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text(f'TOKEN = "{FAKE_TOKEN}"  # gitleaks:allow\nOTHER = 1\n')
    findings = [{"RuleID": "traust-openshift-sha256-token", "File": "settings.py", "StartLine": 1}]
    c = parse_report(findings, tmp_path, "dir")[0]
    assert c["inline_allow"] is True
    assert FAKE_TOKEN not in json.dumps(c)


@pytest.mark.parametrize(
    ("text", "finding", "mode"),
    [
        (f'TOKEN = "{FAKE_TOKEN}"\n', {"StartLine": 1}, "dir"),
        ("x = 1\nTOKEN = 2  # gitleaks:allow\n", {"StartLine": 1, "EndLine": 1}, "dir"),
        ("TOKEN = 1  # gitleaks:allow\n", {"StartLine": 1}, "history"),
        ("TOKEN = 1  # gitleaks:allow\n", {"StartLine": 0}, "dir"),
        ("TOKEN = 1  # gitleaks:allow\n", {"StartLine": "1"}, "dir"),
        (None, {"StartLine": 1}, "dir"),
    ],
)
def test_no_marker_on_the_matched_lines_is_not_inline_allow(
    tmp_path: Path, text: str | None, finding: dict[str, Any], mode: str
) -> None:
    if text is not None:
        (tmp_path / "settings.py").write_text(text)
    native = {"RuleID": "traust-openshift-sha256-token", "File": "settings.py", **finding}
    c = parse_report([native], tmp_path, mode)[0]
    assert c["inline_allow"] is False
    assert "gitleaks:allow" not in candidates_to_findings([c])[0]["description"]


def test_unmapped_rule_is_untestable() -> None:
    c = parse_report([{"RuleID": "generic-api-key", "File": "x"}], Path("/nonexistent"), "dir")[0]
    assert c["liveness_class"] is None


def test_candidates_are_checkout_relative_and_sorted_by_location(tmp_path: Path) -> None:
    findings = [
        {"RuleID": "b", "File": str(tmp_path / "z.py"), "StartLine": 1},
        {"RuleID": "a", "File": str(tmp_path / "a.py"), "StartLine": 9},
        {"RuleID": "a", "File": str(tmp_path / "a.py"), "StartLine": 2},
        {"RuleID": "c", "File": "/elsewhere/x.py"},
    ]
    got = [(c["path"], c["start_line"]) for c in parse_report(findings, tmp_path, "history")]
    assert got == [("/elsewhere/x.py", None), ("a.py", 2), ("a.py", 9), ("z.py", 1)]


def test_native_secret_scanner_identity_is_not_a_domain_fingerprint(tmp_path: Path) -> None:
    native = {
        "RuleID": "fixture-secret-rule",
        "Description": "Synthetic scanner observation without a real credential.",
        "File": "fixture.env",
        "StartLine": 3,
        "EndLine": 4,
        "Fingerprint": "fixture.env:fixture-secret-rule:3",
    }
    candidates = parse_report([native], tmp_path, "dir")
    assert candidates[0]["fingerprint"] == native["Fingerprint"]
    (finding,) = candidates_to_findings(candidates)
    assert finding["id"] == "gitleaks/fixture-secret-rule"
    assert finding["locations"] == [{"path": "fixture.env", "lines": "3-4"}]
    assert "fingerprint" not in finding and "origin" not in finding


class Scripted(ProcessRunner):
    """Answers gitleaks' runs: writes `report` where it was told, then exits `rc`."""

    def __init__(self, report: object = (), rc: int = 0, version: bytes = b"8.30.1\n") -> None:
        super().__init__(["gitleaks", "git"])
        self.report, self.rc, self.version = report, rc, version
        self.calls: list[list[str]] = []

    def run(self, argv: Sequence[str], **kw: Any) -> ProcessResult:
        args = list(argv)
        self.calls.append(args)
        if args[1:] == ["version"]:
            return ProcessResult(tuple(args), 0, self.version, b"", 0.0)
        if isinstance(self.report, BaseException):
            raise self.report
        Path(args[args.index("--report-path") + 1]).write_text(json.dumps(self.report))
        return ProcessResult(tuple(args), self.rc, b"", b"boom", 0.0)


def test_the_scan_argv_redacts_ignores_the_targets_allow_comments_and_never_fails_on_hits(
    tmp_path: Path,
) -> None:
    runner = Scripted([{"RuleID": "aws-access-token", "File": "x", "StartLine": 1}])
    result = Gitleaks(runner, FixedClock(WHEN)).scan(tmp_path, RULES, mode="history")
    argv = runner.calls[0]
    assert argv[:3] == ["gitleaks", "git", str(tmp_path.resolve())]
    assert argv[3:] == [
        "--config",
        str(RULES),
        "--report-format",
        "json",
        "--report-path",
        argv[8],
        "--redact=100",
        "--ignore-gitleaks-allow",
        "--exit-code",
        "0",
        "--no-banner",
        "--log-level",
        "error",
    ]
    assert not Path(argv[8]).exists()
    assert result.metadata.tool == "gitleaks" and result.metadata.scanner_version == "8.30.1"
    assert result.scanned_at == "2026-10-24T12:00:00Z"
    assert [f.id for f in result.findings] == ["gitleaks/aws-access-token"]
    assert result.findings[0].severity == "high"


def test_dir_mode_scans_the_working_tree_and_an_empty_report_is_no_candidates(
    tmp_path: Path,
) -> None:
    runner = Scripted(None)
    result = Gitleaks(runner, FixedClock(WHEN)).scan(tmp_path, RULES)
    assert runner.calls[0][1] == "dir"
    assert result.findings == () and result.summary.total == 0


def test_a_failed_gitleaks_run_is_a_runtime_error_with_its_stderr(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match=r"gitleaks failed \(exit 2\): boom"):
        Gitleaks(Scripted([], rc=2), FixedClock(WHEN)).scan(tmp_path, RULES)


def test_a_timed_out_gitleaks_run_is_a_typed_error(tmp_path: Path) -> None:
    timeout = ProcessTimeout(("gitleaks",), subprocess.TimeoutExpired("gitleaks", 900))
    with pytest.raises(ServiceError, match="gitleaks failed to run"):
        Gitleaks(Scripted(timeout), FixedClock(WHEN)).scan(tmp_path, RULES)


def test_a_missing_config_or_target_never_runs_gitleaks(tmp_path: Path) -> None:
    runner = Scripted([])
    gitleaks = Gitleaks(runner, FixedClock(WHEN))
    with pytest.raises(ValueError, match="gitleaks config is not a file"):
        gitleaks.scan(tmp_path, tmp_path / "absent.toml")
    with pytest.raises(ValueError, match="not a directory"):
        gitleaks.scan(tmp_path / "absent", RULES)
    assert runner.calls == []


class Probe(ProcessRunner):
    def __init__(self, answer: ProcessResult | BaseException) -> None:
        super().__init__(["gitleaks", "git"])
        self.answer = answer

    def run(self, argv: Sequence[str], **kw: Any) -> ProcessResult:
        if isinstance(self.answer, BaseException):
            raise self.answer
        if kw.get("check", True) and self.answer.returncode:
            raise ProcessError(self.answer)
        return self.answer


@pytest.mark.parametrize(
    ("answer", "version", "head"),
    [
        (ProcessResult(("x",), 0, b"v8.30.1\nextra\n", b"", 0.0), "v8.30.1", "v8.30.1\nextra"),
        (ProcessResult(("x",), 0, b"  \n", b"", 0.0), None, ""),
        (ProcessResult(("x",), 128, b"", b"fatal", 0.0), None, None),
        (ServiceError("gitleaks failed to run"), None, None),
    ],
)
def test_version_and_head_are_none_when_they_cannot_be_read(
    tmp_path: Path, answer: ProcessResult | BaseException, version: str | None, head: str | None
) -> None:
    gitleaks = Gitleaks(Probe(answer), FixedClock(WHEN))
    assert gitleaks.version() == version
    assert gitleaks.repo_head(tmp_path) == head


@needs_gitleaks
def test_dir_scan_end_to_end(tmp_path: Path) -> None:
    repo = target_repo(tmp_path)
    found = candidates(repo)
    assert "traust-openshift-sha256-token" in [c["rule_id"] for c in found]
    assert FAKE_TOKEN not in json.dumps(found)
    assert real().repo_head(repo) == git(repo, "rev-parse", "HEAD")
    assert real().version()


@needs_gitleaks
def test_dir_scan_ignores_target_inline_allow(tmp_path: Path) -> None:
    repo = target_repo(tmp_path)
    (repo / "config.py").write_text(f'token = "{FAKE_TOKEN}"  # gitleaks:allow\n')
    hits = [c for c in candidates(repo) if c["rule_id"] == "traust-openshift-sha256-token"]
    assert hits, "a target-supplied gitleaks:allow comment must not suppress the candidate"
    assert all(c["inline_allow"] for c in hits)
    assert FAKE_TOKEN not in json.dumps(hits)


@needs_gitleaks
def test_history_scan_finds_wiped_secret(tmp_path: Path) -> None:
    repo = target_repo(tmp_path)
    (repo / "config.py").write_text("clean = True\n")
    git(repo, "commit", "-aqm", "wipe")
    hits = [
        c for c in candidates(repo, "history") if c["rule_id"] == "traust-openshift-sha256-token"
    ]
    assert hits and hits[0]["commit"]
    assert not [c for c in candidates(repo) if c["rule_id"] == "traust-openshift-sha256-token"]


@needs_gitleaks
def test_real_gitleaks_output_is_an_admissible_adapter_artifact(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text(f'TOKEN = "{FAKE_TOKEN}"\n', encoding="utf-8")
    result = real().scan(tmp_path, RULES, timeout=30)
    assert any(
        finding.id == "gitleaks/traust-openshift-sha256-token"
        and any(location.path == "settings.py" for location in finding.locations)
        for finding in result.findings
    )
    assert all(f.cwes == () and f.remediation == "" for f in result.findings)
    assert FAKE_TOKEN.encode() not in result.payload


@needs_gitleaks
def test_real_observations_publish_without_promoting_findings(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "observations.txt").write_text(f"token: {FAKE_TOKEN}\n")
    artifact = real().scan(target, RULES, timeout=30)
    assert all(f.validation_status is None and f.disposition is None for f in artifact.findings)
    context = Context(Config(home=tmp_path / "store"))
    repository = context.services().portfolio.register_repository(
        HttpsRepoUrl.parse("https://github.com/example/scanner-observations", ("github.com",)),
        False,
    )
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(AdapterResultArtifact)))
    restored = publisher.get(publisher.publish_artifact(artifact).artifact_id)
    assert restored.payload == artifact.payload
    page = context.services().findings.list(
        FindingFilter(repository_id=repository.id), PageRequest(limit=10)
    )
    assert page.items == ()
