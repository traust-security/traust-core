"""CheckovProvider: ported from traust-engine tests/test_cloud_config_provider.py (itself from
traust test_cloud_config_audit.py, test_run_checkov_coverage.py and
test_run_checkov_bicep_fallback.py). Checkov, bicep and git are never invoked: a scripted
ProcessRunner answers for them."""

from __future__ import annotations

import inspect
import json
import shutil
import subprocess
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from traust_core.v1.context import Config, Context
from traust_core.v1.context.tools import bicep_candidates, checkov_tool
from traust_core.v1.errors import ConfigError, ServiceError, ValidationError
from traust_core.v1.models.cloud_config import CheckovScan, CloudConfigFacts
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import ProcessResult, ProcessRunner, ProcessTimeout
from traust_core.v1.providers.tools import NoDatabase, ToolRequest, cloud_config
from traust_core.v1.providers.tools.cloud_config import (
    CheckovProvider,
    _bicep_parse_failures,
    _containerfiles,
    _first_party,
    _scan_tree,
)

FIXTURES = Path(__file__).parents[3] / "fixtures" / "cloud_config"
RECORDED = (FIXTURES / "checkov-3.3.6.json").read_text()
RECORDED_ROOT = "/work/clone-a/myrepo"
LEGACY_SNAPSHOT = "68045f8c22717898437d7e35ce61990aa0685350b9fd118fab27fecdc85f0dea"
WHEN = datetime(2026, 10, 23, 9, tzinfo=UTC)
HEAD = "0123456789abcdef0123456789abcdef01234567"
HEAD_OUT = (HEAD + "\n").encode()

Answer = bytes | ProcessResult | BaseException


def result(
    argv: Sequence[str], stdout: bytes = b"", rc: int = 0, stderr: bytes = b""
) -> ProcessResult:
    return ProcessResult(tuple(argv), rc, stdout, stderr, 0.0)


def failed_to_run(cause: BaseException) -> ServiceError:
    """What core's ProcessRunner raises when the binary is missing."""
    err = ServiceError(f"failed to run: {cause}")
    err.__cause__ = cause
    return err


def timed_out(binary: str, seconds: float) -> ProcessTimeout:
    """What core's ProcessRunner raises when the binary overruns its budget."""
    return ProcessTimeout((binary,), subprocess.TimeoutExpired(binary, seconds))


class Tools(ProcessRunner):
    """Answers for checkov, bicep and git; `scan` gets the directory checkov was pointed at."""

    def __init__(
        self,
        scan: Callable[[Path], Answer] = lambda d: b"[]",
        *,
        version: Answer = b"3.3.6\n",
        head: Answer = HEAD_OUT,
        bicep: Answer = b"Bicep CLI version 0.45.15 (abc)\n",
        build: Callable[[Path], bool | BaseException] = lambda dst: (
            dst.write_text("{}") is not None
        ),
        arm: Callable[[Path], Answer] = lambda d: b"[]",
    ) -> None:
        super().__init__(())
        self.scan, self.version, self.head, self.bicep = scan, version, head, bicep
        self.build, self.arm = build, arm
        self.calls: list[list[str]] = []

    def run(self, argv: Sequence[str], **_: Any) -> ProcessResult:
        argv = list(argv)
        self.calls.append(argv)
        answer: Answer
        if argv[0] == "git":
            answer = self.head
        elif argv[1:] == ["--version"]:
            answer = self.version if argv[0] == "checkov" else self.bicep
        elif argv[1] == "build":
            built = self.build(Path(argv[argv.index("--outfile") + 1]))
            answer = (
                built
                if isinstance(built, BaseException)
                else (b"" if built else result(argv, rc=1))
            )
        else:
            directory = Path(argv[argv.index("--directory") + 1])
            answer = (self.arm if "arm" in argv else self.scan)(directory)
        if isinstance(answer, BaseException):
            raise answer
        return answer if isinstance(answer, ProcessResult) else result(argv, answer)

    def scans(self) -> list[list[str]]:
        return [c for c in self.calls if "--directory" in c]


def recorded(directory: Path) -> bytes:
    """The recorded output as checkov would print it scanning `directory`."""
    return RECORDED.replace(RECORDED_ROOT, str(directory)).encode()


def provider(tools: Tools, bicep: Sequence[Path] = ()) -> CheckovProvider:
    return CheckovProvider(tools, tools, FixedClock(WHEN), bicep)


def checkout(root: Path, name: str = "myrepo") -> Path:
    target = root / name
    shutil.copytree(FIXTURES / "source", target)
    return target


def acquire(tools: Tools, workspace: Path, bicep: Sequence[Path] = ()) -> CloudConfigFacts:
    return provider(tools, bicep).acquire(ToolRequest(workspace=workspace)).data


def listing(root: Path) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))


# readiness: checkov present at the pinned version


@pytest.mark.parametrize(
    ("version", "ready", "detail"),
    [
        (b"3.3.6\n", True, ""),
        (result(["checkov"], stderr=b"3.3.6\n"), True, ""),
        (b"3.3.5\n", False, "checkov version mismatch: pinned 3.3.6, found: 3.3.5"),
        (
            failed_to_run(FileNotFoundError("checkov")),
            False,
            "checkov not on PATH (pip install checkov==3.3.6)",
        ),
        (
            timed_out("checkov", 60),
            False,
            "checkov --version timed out",
        ),
    ],
)
def test_ready_only_at_the_pinned_version(version: Answer, ready: bool, detail: str) -> None:
    readiness = provider(Tools(version=version)).check()
    assert (readiness.ready, readiness.detail) == (ready, detail)


def test_acquire_refuses_another_version_and_a_missing_workspace(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"pinned 3\.3\.6, found: 3\.4\.0"):
        acquire(Tools(version=b"3.4.0\n"), checkout(tmp_path))
    with pytest.raises(ValidationError, match="workspace is not a directory"):
        acquire(Tools(), tmp_path / "absent")


# the offline guarantee is structural, so test it structurally


def test_the_scan_argv_is_fixed_and_offline(tmp_path: Path) -> None:
    tools = Tools()
    target = checkout(tmp_path)
    acquire(tools, target)
    assert tools.scans() == [
        [
            "checkov",
            "--directory",
            str(target.resolve()),
            "--output",
            "json",
            "--skip-download",
            "--compact",
            "--skip-framework",
            "secrets",
        ]
    ]


def test_the_runner_source_never_reaches_the_network_or_a_platform_key() -> None:
    src = inspect.getsource(cloud_config)
    for token in ("urllib", "requests", "http", "bc-api-key", "api-key"):
        assert token not in src


def test_the_toolchain_registers_checkov_on_its_own_runners(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    ctx.register_toolchain(tmp_path / "absent-tools.yaml", tmp_path / "absent-profiles.yaml")
    built = ctx.tools.get("checkov")
    assert isinstance(built, CheckovProvider)
    assert (built._checkov._timeout, built._probe._timeout) == (1800.0, 60.0)


def test_bicep_is_looked_for_in_the_override_then_path_then_the_pinned_install_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCA_BICEP", str(tmp_path / "my-bicep"))
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/local/bin/{name}")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert bicep_candidates() == [
        tmp_path / "my-bicep",
        Path("/usr/local/bin/bicep"),
        tmp_path / ".cache" / "cca-tools" / "bicep-0.45.15" / "bicep",
    ]
    monkeypatch.delenv("CCA_BICEP")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert bicep_candidates() == [tmp_path / ".cache" / "cca-tools" / "bicep-0.45.15" / "bicep"]


# the recorded scan, end to end


def test_recorded_checkov_output_matches_the_legacy_runner(tmp_path: Path) -> None:
    target = checkout(tmp_path)
    got = provider(Tools(recorded)).acquire(ToolRequest(workspace=target))
    facts = got.data
    assert (facts.target, len(facts.facts), facts.counts.failed) == ("myrepo", 33, 33)
    assert facts.snapshot_id == LEGACY_SNAPSHOT
    assert facts.target_head == HEAD
    assert [g.split(" file(s)")[0] for g in facts.gaps] == [
        "myrepo: 1 .tekton/ PipelineRun",
        "myrepo: 1 OpenShift Template",
    ]
    assert facts.notes == {}
    acq = got.acquisition
    assert (acq.provider, acq.version, acq.source, acq.acquired_at) == (
        "checkov",
        "3.3.6",
        str(target.resolve()),
        WHEN,
    )


def test_a_hidden_path_is_scanned_through_a_non_hidden_temp_path(tmp_path: Path) -> None:
    target = checkout(tmp_path / ".cache-clones")
    seen: list[Path] = []

    def scan(directory: Path) -> bytes:
        seen.append(directory)
        assert directory.is_symlink() and directory.resolve() == target.resolve()
        return recorded(directory)

    facts = acquire(Tools(scan), target)
    assert not any(p.startswith(".") for p in seen[0].parts[1:])
    assert facts.snapshot_id == LEGACY_SNAPSHOT  # temp-path facts keep their ids
    assert "suppresses checkov's kubernetes framework" in facts.notes["hidden_path_workaround"]
    assert not seen[0].exists()


def test_a_containerfile_is_scanned_through_its_alias_and_cited_by_its_real_path(
    tmp_path: Path,
) -> None:
    target = checkout(tmp_path)
    (target / "img" / "Dockerfile").rename(target / "img" / "Containerfile")
    before = listing(target)
    seen: list[Path] = []

    def scan(directory: Path) -> bytes:
        seen.append(directory)
        assert (directory / "img" / "Dockerfile").resolve() == (
            target / "img" / "Containerfile"
        ).resolve()
        return recorded(directory)

    facts = acquire(Tools(scan), target)
    docker = [f for f in facts.facts if f.framework == "dockerfile"]
    assert {f.file_path for f in docker} == {"/img/Containerfile"}
    assert all(f.resource.startswith("/img/Containerfile") for f in docker if f.resource)
    native = CloudConfigFacts.of(
        CheckovScan(
            target="myrepo",
            version="3.3.6",
            outputs=(RECORDED.replace("/img/Dockerfile", "/img/Containerfile").encode(),),
            roots=(RECORDED_ROOT,),
        )
    )
    assert {f.fact_id for f in docker} <= {f.fact_id for f in native.facts}
    assert "1 Containerfile(s) aliased" in facts.notes["containerfile_alias_workaround"]
    assert seen[0] != target.resolve() and not seen[0].exists()
    assert listing(target) == before  # read-only toward the checkout


# a failed scan is a gap, never a clean target


@pytest.mark.parametrize(
    ("answer", "gap"),
    [
        (failed_to_run(FileNotFoundError("checkov")), "checkov not on PATH"),
        (timed_out("checkov", 1800), "timeout after 1800s"),
        (result(["checkov"], rc=2, stderr=b"warming up\nboom: bad flag\n"), "boom: bad flag"),
        (result(["checkov"], rc=2), "exit 2, no output"),
        (b"not json", "unparseable checkov JSON output"),
    ],
)
def test_a_scan_that_produced_nothing_is_the_only_gap(
    tmp_path: Path, answer: Answer, gap: str
) -> None:
    facts = acquire(Tools(lambda d: answer), checkout(tmp_path))
    assert (facts.facts, facts.gaps) == ((), (f"myrepo: {gap}",))
    assert facts.target_head == HEAD


@pytest.mark.parametrize(
    "head",
    [
        result(["git"], rc=128, stderr=b"fatal: not a git repository"),
        failed_to_run(FileNotFoundError("git")),
        b"\n",
    ],
)
def test_an_unknown_head_is_recorded_as_none(tmp_path: Path, head: Answer) -> None:
    assert acquire(Tools(head=head), checkout(tmp_path)).target_head is None


# the Containerfile alias tree


def tree(tmp_path: Path) -> Path:
    """Containerfiles top-level and nested, plus third-party and hidden copies to skip."""
    root = tmp_path / "myrepo"
    files = {
        "Containerfile": "FROM scratch\n",
        "vllm-bootc/Containerfile": "FROM quay.io/base\nUSER root\n",
        "vllm-bootc/Containerfile.ostree": "FROM quay.io/ostree\n",
        "vendor/x/Containerfile": "FROM x\n",
        ".git/Containerfile": "FROM x\n",
        ".tekton/Containerfile": "FROM x\n",
        "main.tf": 'resource "rhoas_kafka" "k" {}\n',
        "template.yaml": "apiVersion: template.openshift.io/v1\nkind: Template\n",
    }
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def containerfiles(root: Path) -> list[PurePosixPath]:
    return _containerfiles(list(_first_party(root)))


def test_only_first_party_containerfiles_are_aliased(tmp_path: Path) -> None:
    assert [p.as_posix() for p in containerfiles(tree(tmp_path))] == [
        "Containerfile",
        "vllm-bootc/Containerfile",
        "vllm-bootc/Containerfile.ostree",
    ]


def test_the_scan_tree_aliases_each_containerfile_and_leaves_the_checkout_alone(
    tmp_path: Path,
) -> None:
    root = tree(tmp_path)
    (tmp_path / "scan").mkdir()
    scan_dir, aliases, notes = _scan_tree(root, tmp_path / "scan", containerfiles(root))
    assert aliases == {
        "/Dockerfile": "/Containerfile",
        "/vllm-bootc/Dockerfile": "/vllm-bootc/Containerfile",
        "/vllm-bootc/Dockerfile.ostree": "/vllm-bootc/Containerfile.ostree",
    }
    for alias, real in aliases.items():
        link = scan_dir / alias.lstrip("/")
        assert link.is_symlink() and link.resolve() == (root / real.lstrip("/")).resolve()
    assert not (root / "Dockerfile").exists() and not (root / "vllm-bootc" / "Dockerfile").exists()
    assert (scan_dir / "template.yaml").resolve() == (root / "template.yaml").resolve()
    assert "not aliased" not in notes["containerfile_alias_workaround"]
    assert "hidden_path_workaround" not in notes


def test_the_scan_tree_mirrors_every_directory_as_a_real_directory(tmp_path: Path) -> None:
    # checkov never descends a directory symlink: a partial mirror dropped 32 facts live
    root = tree(tmp_path)
    (root / "infra").mkdir()
    (root / "infra" / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    (root / "loop").symlink_to(root)
    (tmp_path / "scan").mkdir()
    scan_dir, _, _ = _scan_tree(root, tmp_path / "scan", containerfiles(root))
    for rel in ("infra", "vllm-bootc", "vendor", ".tekton"):
        assert (scan_dir / rel).is_dir() and not (scan_dir / rel).is_symlink(), rel
    assert (scan_dir / "infra" / "main.tf").is_symlink()
    assert (scan_dir / "loop").is_symlink()  # a symlinked dir stays a symlink: no loop


def test_a_containerfile_with_a_real_dockerfile_twin_is_not_aliased(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "Containerfile").write_text("FROM a\n")
    (root / "Dockerfile").write_text("FROM b\n")
    (tmp_path / "scan").mkdir()
    scan_dir, aliases, notes = _scan_tree(root, tmp_path / "scan", containerfiles(root))
    assert aliases == {}
    assert notes["containerfile_alias_workaround"].endswith(
        "not aliased (Dockerfile-name twin already exists): Containerfile"
    )
    assert (scan_dir / "Dockerfile").resolve() == (root / "Dockerfile").resolve()


def test_a_plain_checkout_is_scanned_in_place(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    assert _scan_tree(root, tmp_path, []) == (root, {}, {})


def test_the_inventory_walk_skips_symlinked_vendored_and_hidden_dirs_but_dot_tekton(
    tmp_path: Path,
) -> None:
    root = tree(tmp_path)
    (root / "linked").symlink_to(root / "vllm-bootc")
    (root / "node_modules").mkdir()
    (root / "node_modules" / "x.tf").write_text("")
    assert sorted(p.as_posix() for p in _first_party(root)) == [
        ".tekton/Containerfile",
        "Containerfile",
        "main.tf",
        "template.yaml",
        "vllm-bootc/Containerfile",
        "vllm-bootc/Containerfile.ostree",
    ]


# the bicep transpile fallback


def bicep_block(*failures: str) -> dict[str, Any]:
    return {
        "check_type": "bicep",
        "results": {"failed_checks": [], "parsing_errors": list(failures)},
        "summary": {"passed": 1, "failed": 0, "skipped": 0, "parsing_errors": len(failures)},
    }


def arm_output(directory: Path) -> bytes:
    check = {
        "check_id": "CKV_AZURE_189",
        "check_name": "kv public access",
        "file_path": f"{directory}/infra/kv.bicep.arm.json",
        "file_line_range": [1, 2],
        "resource": "Microsoft.KeyVault/vaults.kv",
    }
    summary = {"passed": 0, "failed": 1, "skipped": 0, "parsing_errors": 0}
    return json.dumps(
        {"check_type": "arm", "results": {"failed_checks": [check]}, "summary": summary}
    ).encode()


def bicep_checkout(tmp_path: Path) -> tuple[Path, Path]:
    target = tmp_path / "myrepo"
    (target / "infra").mkdir(parents=True)
    (target / "infra" / "kv.bicep").write_text("param x string\n")
    (target / "infra" / "broken.yaml").write_text("x: [\n")
    cli = tmp_path / "bin" / "bicep"
    cli.parent.mkdir()
    cli.write_text("")
    return target, cli


def bicep_scan(directory: Path) -> bytes:
    return json.dumps(
        [bicep_block(f"{directory}/infra/kv.bicep", f"{directory}/infra/broken.yaml")]
    ).encode()


def parse_gap(facts: CloudConfigFacts) -> str:
    return next(g for g in facts.gaps if "failed to parse" in g)


def test_a_rejected_bicep_is_transpiled_offline_rescanned_as_arm_and_cites_its_source(
    tmp_path: Path,
) -> None:
    target, cli = bicep_checkout(tmp_path)
    tools = Tools(bicep_scan, arm=arm_output)
    facts = acquire(tools, target, [cli])
    (fact,) = facts.facts
    assert (fact.framework, fact.file_path, fact.check_id) == (
        "arm",
        "/infra/kv.bicep",
        "CKV_AZURE_189",
    )
    assert "1/1 parse-failed .bicep" in facts.notes["bicep_transpile_fallback"]
    assert "(1 .bicep of them transpile-recovered" in parse_gap(facts)
    (build,) = [c for c in tools.calls if c[1:2] == ["build"]]
    assert build[:3] == [str(cli), "build", str(target.resolve() / "infra" / "kv.bicep")]
    assert "--no-restore" in build
    arm = tools.scans()[1]
    assert arm[arm.index("--framework") + 1] == "arm" and "--skip-download" in arm


@pytest.mark.parametrize(
    ("bicep", "build", "note"),
    [
        (None, True, "is not installed — transpile fallback unavailable"),
        (b"Bicep CLI version 0.30.0\n", True, "is not installed — transpile fallback unavailable"),
        (b"Bicep CLI version 0.45.15\n", False, "0/1 parse-failed .bicep file(s) transpiled"),
        (
            timed_out("bicep", 60),
            True,
            "is not installed — transpile fallback unavailable",
        ),
        (
            b"Bicep CLI version 0.45.15\n",
            timed_out("bicep", 60),
            "0/1 parse-failed .bicep file(s) transpiled",
        ),
        (
            b"Bicep CLI version 0.45.15\n",
            failed_to_run(FileNotFoundError("bicep")),
            "0/1 parse-failed .bicep file(s) transpiled",
        ),
    ],
)
def test_a_bicep_the_fallback_cannot_recover_stays_not_assessed(
    tmp_path: Path, bicep: Answer | None, build: bool | BaseException, note: str
) -> None:
    target, cli = bicep_checkout(tmp_path)
    tools = Tools(bicep_scan, bicep=bicep or b"", build=lambda dst: build)
    facts = acquire(tools, target, [cli] if bicep else [])
    assert note in facts.notes["bicep_transpile_fallback"]
    assert parse_gap(facts) == "myrepo: 2 file(s) failed to parse — those files are not assessed"
    assert len(tools.scans()) == 1  # no arm re-scan


def test_a_checkout_without_rejected_bicep_never_looks_for_the_cli(tmp_path: Path) -> None:
    tools = Tools(recorded)
    facts = acquire(tools, checkout(tmp_path), [tmp_path / "bicep"])
    assert "bicep_transpile_fallback" not in facts.notes
    assert not [c for c in tools.calls if "bicep" in c[0]]


@pytest.mark.parametrize(
    ("parsed", "strip", "want"),
    [
        (
            [bicep_block("/scan/root/a/b.bicep", "/scan/root/c.yaml")],
            ("/scan/root",),
            ["/a/b.bicep"],
        ),
        (bicep_block("/repo/x.bicep", "/repo/x.bicep"), ("", "/repo"), ["/x.bicep"]),
        ([bicep_block()], (), []),
        (bicep_block("/elsewhere/y.bicep"), ("/repo",), ["/elsewhere/y.bicep"]),
        (["not a block", {"results": None}], (), []),
    ],
)
def test_parse_failures_are_bicep_only_and_checkout_relative(
    parsed: Any, strip: tuple[str, ...], want: list[str]
) -> None:
    assert _bicep_parse_failures(parsed, strip) == want


# fix-forward (XWING-2440): pin before the scan, loud arm re-scan failures, bicep edges


def test_another_checkov_version_never_scans_the_checkout(tmp_path: Path) -> None:
    tools = Tools(version=b"3.4.0\n")
    with pytest.raises(ConfigError, match=r"pinned 3\.3\.6, found: 3\.4\.0"):
        acquire(tools, checkout(tmp_path))
    assert tools.scans() == []
    assert [c for c in tools.calls if c[0] != "checkov"] == []  # no git, no bicep either


@pytest.mark.parametrize(
    ("arm", "error"),
    [
        (timed_out("checkov", 1800), "timeout after 1800s"),
        (failed_to_run(FileNotFoundError("checkov")), "checkov not on PATH"),
        (result(["checkov"], rc=1, stderr=b"arm: kaput\n"), "arm: kaput"),
        (b"", "exit 0, no output"),
    ],
)
def test_a_failed_arm_rescan_is_a_visible_note_and_recovers_nothing(
    tmp_path: Path, arm: Answer, error: str
) -> None:
    target, cli = bicep_checkout(tmp_path)
    tools = Tools(bicep_scan, arm=lambda d: arm)
    facts = acquire(tools, target, [cli])
    assert facts.facts == ()
    assert facts.notes["bicep_transpile_fallback"] == (
        f"1/1 parse-failed .bicep file(s) transpiled but the arm re-scan failed: {error}; "
        "files stay NOT ASSESSED"
    )
    assert parse_gap(facts) == "myrepo: 2 file(s) failed to parse — those files are not assessed"
    assert len(tools.scans()) == 2  # the re-scan was attempted


def test_a_partial_transpile_names_what_stays_unparsed(tmp_path: Path) -> None:
    target, cli = bicep_checkout(tmp_path)

    def scan(directory: Path) -> bytes:
        # ghost.bicep is reported but is not a file in the checkout: never transpiled
        return json.dumps(
            [bicep_block(f"{directory}/infra/kv.bicep", f"{directory}/infra/ghost.bicep")]
        ).encode()

    tools = Tools(scan, arm=arm_output)
    facts = acquire(tools, target, [cli])
    note = facts.notes["bicep_transpile_fallback"]
    assert note.startswith("1/2 parse-failed .bicep")
    assert note.endswith("; still unparsed (stay NOT ASSESSED): /infra/ghost.bicep")
    assert [c[2] for c in tools.calls if c[1:2] == ["build"]] == [
        str(target.resolve() / "infra" / "kv.bicep")
    ]
    assert "(1 .bicep of them transpile-recovered" in parse_gap(facts)


class Versions(Tools):
    """Each bicep candidate answers `--version` for itself."""

    def __init__(self, versions: dict[str, Answer]) -> None:
        super().__init__()
        self.versions = versions

    def run(self, argv: Sequence[str], **kw: Any) -> ProcessResult:
        if list(argv[1:]) == ["--version"] and argv[0] in self.versions:
            self.bicep = self.versions[argv[0]]
        return super().run(argv, **kw)


def test_the_first_pinned_bicep_file_wins(tmp_path: Path) -> None:
    missing, old, pinned, later = (tmp_path / n for n in ("missing", "old", "pinned", "later"))
    (tmp_path / "missing").mkdir()  # a directory, not a file: skipped unprobed
    for cand in (old, pinned, later):
        cand.write_text("")
    tools = Versions(
        {
            str(old): b"Bicep CLI version 0.30.0\n",
            str(pinned): b"Bicep CLI version 0.45.15\n",
            str(later): b"Bicep CLI version 0.45.15\n",
        }
    )
    assert provider(tools, [missing, old, pinned, later])._find_bicep() == pinned
    assert [c[0] for c in tools.calls] == [str(old), str(pinned)]


def test_the_probe_runner_allows_checkov_git_bicep_and_each_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCA_BICEP", str(tmp_path / "my-bicep-0.45"))
    monkeypatch.setattr(shutil, "which", lambda name: None)
    built = checkov_tool(Context(Config(home=tmp_path)))
    assert built._probe._allowed >= {"checkov", "git", "bicep", "my-bicep-0.45"}
    assert built._checkov._allowed == {"checkov"}
    for cand in built._bicep:
        built._probe._validate([str(cand), "--version"])  # raises when not allowed


@pytest.mark.parametrize(
    ("answer", "expect"),
    [
        (b"3.3.6\n", "3.3.6"),
        (b"checkov 3.2.1 (pip)\n", "3.2.1"),
        (b"no version here\n", None),
        (failed_to_run(FileNotFoundError("checkov")), None),
    ],
)
def test_checkov_reports_its_own_version_and_keeps_no_database(
    answer: Answer, expect: str | None
) -> None:
    checkov = provider(Tools(version=answer))
    assert checkov.version() == expect
    assert checkov.database() is None
    with pytest.raises(NoDatabase, match="checkov keeps no vulnerability database"):
        checkov.update_database()


def test_checkov_refuses_a_target_that_is_not_a_checkout(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="runs over a checkout, not a sbom"):
        provider(Tools()).acquire(ToolRequest(sbom=tmp_path / "x.json"))
