from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.artifacts import FleetFixArtifact
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import ProcessResult, ProcessRunner
from traust_core.v1.providers.tools.fleet_fix import GitFleetFixApplier

FIXTURES = Path(__file__).parents[3] / "fixtures"
SPEC = json.loads((FIXTURES / "remediation" / "fleet-fix-konflux.json").read_text())
CATALOG = "https://github.com/example/konflux-build-catalog"
ORIGIN = "https://github.com/example/component"
PIN = "a" * 40
WHEN = datetime(2026, 7, 18, 9, tzinfo=UTC)
TEKTON = f"""\
apiVersion: tekton.dev/v1
kind: PipelineRun
spec:
  pipelineRef:
    resolver: git
    params:
      - name: url
        value: "{CATALOG}"
      - name: revision
        value: main
      - name: pathInRepo
        value: pipelines/docker-build.yaml
"""
PINNED = f"value: {PIN}  # fleet-fix(konflux-mutable-pipelineref): pinned from main 2026-07-18"
AST_GREP = {"kind": "ast_grep", "file_glob": ["**/*.go"], "pattern": "md5.New()", "lang": "go"}


def spec(**changes: Any) -> FleetFixArtifact:
    return FleetFixArtifact.from_document({**json.loads(json.dumps(SPEC)), **changes})


def origin(tmp_path: Path, files: Mapping[str, str], link: tuple[str, str] | None = None) -> str:
    """A local repository standing in for the https origin; returns its HEAD."""
    repo = tmp_path / "origin"
    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    if link:
        (repo / link[0]).parent.mkdir(parents=True, exist_ok=True)
        (repo / link[0]).symlink_to(link[1])
    # A clean env: under a git hook GIT_DIR / GIT_INDEX_FILE would point these at the caller's repo.
    env = {"PATH": os.environ["PATH"], "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
    run = lambda *a: subprocess.run(  # noqa: E731
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *a],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    run("init", "-q")
    run("add", "-A")
    run("commit", "-qm", "init")
    return run("rev-parse", "HEAD")


class Git(ProcessRunner):
    """Real git, except: a clone of ORIGIN reads the local origin, and ls-remote is answered."""

    def __init__(self, tmp_path: Path, remote: Callable[[str], bytes | BaseException]) -> None:
        super().__init__(["git"])
        self.origin = str(tmp_path / "origin")
        self.remote = remote
        self.calls: list[tuple[list[str], Mapping[str, str] | None]] = []
        self.after_checkout: Callable[[Path], object] = lambda repo: None

    def run(self, argv: Sequence[str], **kw: Any) -> ProcessResult:
        argv = list(argv)
        self.calls.append((list(argv), kw.get("env")))
        if "ls-remote" in argv:
            out = self.remote(argv[argv.index("--") + 1])
            if isinstance(out, BaseException):
                raise out
            return ProcessResult(tuple(argv), 0, out, b"", 0.0)
        if "clone" in argv:  # file:// is (rightly) refused under GIT_ALLOW_PROTOCOL=https
            argv[argv.index(ORIGIN)] = self.origin
            kw["env"] = {"GIT_TERMINAL_PROMPT": "0"}
        out = super().run(argv, **kw)
        if "checkout" in argv:
            self.after_checkout(Path(argv[2]))
        return out

    def argv(self, verb: str) -> list[list[str]]:
        return [a for a, _ in self.calls if verb in a]


class AstGrep(ProcessRunner):
    """Plays `ast-grep run --update-all`: replaces the pattern text in each path."""

    def __init__(self, rc: int = 0) -> None:
        super().__init__(["ast-grep"])
        self.rc = rc
        self.calls: list[tuple[list[str], Path | None]] = []

    def run(self, argv: Sequence[str], **kw: Any) -> ProcessResult:
        self.calls.append((list(argv), kw.get("cwd")))
        flags = dict(a[2:].split("=", 1) for a in argv if a.startswith("--") and "=" in a)
        for path in (Path(a) for a in argv if a.startswith("/")):
            text = path.read_text()
            if flags["pattern"] in text:
                path.write_text(text.replace(flags["pattern"], flags["rewrite"]))
        return ProcessResult(tuple(argv), self.rc, b"", b"boom", 0.0)


def applier(tmp_path: Path, remote: Callable[[str], bytes | BaseException], ast_grep=None):
    git = Git(tmp_path, remote)
    ast = ast_grep or AstGrep()
    return GitFleetFixApplier(git, ast, FixedClock(WHEN)), git, ast


def answer(url: str) -> bytes:
    return f"{PIN}\trefs/heads/main\n".encode()


# --- pinned_ref_line --------------------------------------------------------------------------


def test_a_fresh_clone_of_the_commit_gets_its_revisions_pinned(tmp_path: Path) -> None:
    sha = origin(
        tmp_path,
        {
            ".tekton/pr.yaml": TEKTON,
            ".tekton/push.yaml": TEKTON,
            "config/deploy.yaml": "params:\n  - name: revision\n    value: main\n",
        },
    )
    fixer, git, _ = applier(tmp_path, answer)
    diff = fixer.apply(spec(), ORIGIN, sha)
    assert diff.files_changed == (".tekton/pr.yaml", ".tekton/push.yaml")
    assert diff.unresolved == ()
    assert f"+        {PINNED}" in diff.diff and "-        value: main" in diff.diff
    assert "config/deploy.yaml" not in diff.diff  # outside file_glob
    clone, env = next((a, e) for a, e in git.calls if "clone" in a)
    assert clone[clone.index("--") + 1] == ORIGIN
    assert env == {"GIT_ALLOW_PROTOCOL": "https", "GIT_TERMINAL_PROMPT": "0"}
    assert git.argv("checkout")[0][-3:] == ["--quiet", "--detach", sha]
    (ls_remote,) = git.argv("ls-remote")  # one call per URL
    assert ls_remote[ls_remote.index("ls-remote") :] == [
        "ls-remote",
        "--",
        CATALOG,
        "refs/heads/main",
        "main",
    ]
    assert not git.argv("commit") and not git.argv("push")


def test_the_clone_is_https_only_with_option_injection_blocked(tmp_path: Path) -> None:
    sha = origin(tmp_path, {".tekton/pr.yaml": TEKTON})
    fixer, git, _ = applier(tmp_path, answer)
    fixer.apply(spec(), ORIGIN, sha)
    for argv, env in git.calls:
        assert {"core.fsmonitor=false", "core.hooksPath=/dev/null"} <= set(argv)
        assert env == {"GIT_ALLOW_PROTOCOL": "https", "GIT_TERMINAL_PROMPT": "0"}


@pytest.mark.parametrize(
    ("remote", "unresolved"),
    [
        (lambda url: b"", ".tekton/pr.yaml:10: no commit for " + CATALOG),
        (
            lambda url: b"not-a-sha\trefs/heads/main\n",
            ".tekton/pr.yaml:10: no commit for " + CATALOG,
        ),
        (lambda url: ServiceError("timed out"), ".tekton/pr.yaml:10: no commit for " + CATALOG),
    ],
)
def test_an_unresolvable_url_is_reported_and_left_alone(
    tmp_path: Path, remote: Callable[[str], bytes | BaseException], unresolved: str
) -> None:
    sha = origin(tmp_path, {".tekton/pr.yaml": TEKTON})
    fixer, _, _ = applier(tmp_path, remote)
    diff = fixer.apply(spec(), ORIGIN, sha)
    assert (diff.files_changed, diff.unresolved, diff.diff) == ((), (unresolved,), "")


def test_no_match_changes_nothing(tmp_path: Path) -> None:
    sha = origin(tmp_path, {".tekton/pr.yaml": "spec: {}\n"})
    fixer, git, _ = applier(tmp_path, answer)
    assert fixer.apply(spec(), ORIGIN, sha).files_changed == ()
    assert not git.argv("ls-remote")


def test_a_tracked_link_is_never_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside.yaml"
    outside.write_text(TEKTON)
    sha = origin(tmp_path, {"README": "x\n"}, link=(".tekton/pr.yaml", str(outside)))
    fixer, _, _ = applier(tmp_path, answer)
    assert fixer.apply(spec(), ORIGIN, sha).files_changed == ()
    assert outside.read_text() == TEKTON


@pytest.mark.parametrize(
    ("url", "sha"),
    [
        ("http://github.com/example/component", PIN),
        ("ext::sh -c touch% /tmp/pwned", PIN),
        ("--upload-pack=touch /tmp/pwned", PIN),
        ("file:///etc", PIN),
        ("https://github.com/example/component --upload-pack=x", PIN),
        (ORIGIN, "main"),
        (ORIGIN, "--orphan"),
    ],
)
def test_an_unsafe_target_is_refused_before_any_git(tmp_path: Path, url: str, sha: str) -> None:
    fixer, git, _ = applier(tmp_path, answer)
    with pytest.raises(ValidationError):
        fixer.apply(spec(), url, sha)
    assert git.calls == []


@pytest.mark.parametrize(
    ("url", "ref"),
    [
        ("http://example.com/r", "main"),
        ("ext::sh -c id", "main"),
        ("-oProxyCommand=id", "main"),
        ("https://example.com/r x", "main"),
        ("https://example.com/r'", "main"),
        ("https://example.com/r", "--upload-pack=id"),
        ("https://example.com/r", "-x"),
        ("https://example.com/r", ""),
    ],
)
def test_ls_remote_refuses_hostile_urls_and_refs_without_running(
    tmp_path: Path, url: str, ref: str
) -> None:
    fixer, git, _ = applier(tmp_path, answer)
    assert fixer.ls_remote(url, ref) is None
    assert git.calls == []


def test_a_dirty_checkout_is_refused(tmp_path: Path) -> None:
    sha = origin(tmp_path, {".tekton/pr.yaml": TEKTON})
    fixer, git, _ = applier(tmp_path, answer)
    git.after_checkout = lambda repo: (repo / "stray.txt").write_text("x")
    with pytest.raises(ValidationError, match="is not clean"):
        fixer.apply(spec(), ORIGIN, sha)
    allowed = spec(guards={"require_clean_tree": False})
    assert fixer.apply(allowed, ORIGIN, sha).files_changed == (".tekton/pr.yaml",)


def test_a_failed_clone_raises(tmp_path: Path) -> None:
    fixer, _, _ = applier(tmp_path, answer)  # no origin repository
    with pytest.raises(ServiceError):
        fixer.apply(spec(), ORIGIN, PIN)


# --- ast_grep ---------------------------------------------------------------------------------


def ast_spec() -> FleetFixArtifact:
    return spec(
        matcher=AST_GREP,
        rewrite={"template": "sha256.New()"},
        tests=[
            {
                "name": "swaps md5",
                "file": "pkg/a.go",
                "before": "package pkg\n\nvar h = md5.New()\n",
                "after_contains": ["sha256.New()"],
                "after_not_contains": ["md5.New()"],
            }
        ],
    )


def test_an_ast_grep_spec_runs_over_the_in_scope_files_only(tmp_path: Path) -> None:
    sha = origin(
        tmp_path,
        {"pkg/a.go": "var h = md5.New()\n", "pkg/b.py": "md5.New()\n", "pkg/c.go": "ok\n"},
    )
    fixer, _, ast = applier(tmp_path, answer)
    diff = fixer.apply(ast_spec(), ORIGIN, sha)
    assert diff.files_changed == ("pkg/a.go",) and "+var h = sha256.New()" in diff.diff
    ((argv, cwd),) = ast.calls
    assert argv[:6] == [
        "ast-grep",
        "run",
        "--pattern=md5.New()",
        "--rewrite=sha256.New()",
        "--lang=go",
        "--update-all",
    ]
    assert [Path(a).name for a in argv[6:]] == ["a.go", "c.go"]
    assert cwd is not None and not any(Path(a).is_relative_to(cwd) for a in argv[6:])


def test_ast_grep_failing_raises_and_no_files_skip_it(tmp_path: Path) -> None:
    sha = origin(tmp_path, {"pkg/a.go": "var h = md5.New()\n"})
    fixer, _, _ = applier(tmp_path, answer, AstGrep(rc=2))
    with pytest.raises(ServiceError, match="ast-grep exited 2: boom"):
        fixer.apply(ast_spec(), ORIGIN, sha)
    empty = origin(tmp_path / "e", {"README": "x\n"})
    fixer, _, ast = applier(tmp_path / "e", answer)
    assert fixer.apply(ast_spec(), ORIGIN, empty).files_changed == () and ast.calls == []


def test_a_golden_fixture_is_run_alone_in_a_scratch_dir(tmp_path: Path) -> None:
    fixer, git, ast = applier(tmp_path, answer)
    test = ast_spec().tests[0]
    assert (
        fixer.after(ast_spec(), test.file, test.before) == "package pkg\n\nvar h = sha256.New()\n"
    )
    assert git.calls == [] and len(ast.calls) == 1


@pytest.mark.parametrize("file", ["/etc/passwd", "../x.go", "pkg/../../x.go"])
def test_a_golden_fixture_cannot_escape_its_scratch_dir(tmp_path: Path, file: str) -> None:
    fixer, _, ast = applier(tmp_path, answer)
    with pytest.raises(ValidationError, match="escapes"):
        fixer.after(ast_spec(), file, "x")
    assert ast.calls == []


@pytest.mark.skipif(shutil.which("ast-grep") is None, reason="ast-grep not installed")
def test_real_ast_grep_proves_its_goldens_through_core(tmp_path: Path) -> None:
    from traust_core.v1.models.remediation import golden_failures

    fixer = GitFleetFixApplier(
        ProcessRunner(["git"]), ProcessRunner(["ast-grep"]), FixedClock(WHEN)
    )
    doc = ast_spec()
    assert golden_failures(doc, "2026-07-18", lambda t: fixer.after(doc, t.file, t.before)) == []


# --- wiring -----------------------------------------------------------------------------------


def test_without_registration_there_is_no_applier_or_golden_runner(tmp_path: Path) -> None:
    remediation = Context(Config(home=tmp_path)).services().remediation
    assert remediation._applier is None and remediation._goldens is None


def test_registration_sets_the_applier_and_golden_runner(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    ctx.register_fleet_fix()
    remediation = ctx.services().remediation
    assert isinstance(remediation._applier, GitFleetFixApplier)
    assert remediation._goldens is remediation._applier
