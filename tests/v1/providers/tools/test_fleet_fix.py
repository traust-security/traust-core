from __future__ import annotations

import json
import shutil
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from tests.v1.conftest import CheckoutForge, NoCheckouts
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import NotFoundError, ServiceError, ValidationError
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


def checkout(
    tmp_path: Path, files: Mapping[str, str], link: tuple[str, str] | None = None
) -> tuple[CheckoutForge, str]:
    """A local bare repository standing in for the https origin; returns (forge, HEAD)."""
    forge = CheckoutForge(tmp_path, ORIGIN)
    committed = dict(files)
    if link:
        committed[link[0]] = Path(link[1])
    return forge, str(forge.commit(committed))


class Git(ProcessRunner):
    """Real git, except ls-remote is answered by the test."""

    def __init__(self, remote: Callable[[str], bytes | BaseException]) -> None:
        super().__init__(["git"])
        self.remote = remote
        self.calls: list[tuple[list[str], Mapping[str, str] | None]] = []

    def run(self, argv: Sequence[str], **kw: Any) -> ProcessResult:
        argv = list(argv)
        self.calls.append((list(argv), kw.get("env")))
        if "ls-remote" in argv:
            out = self.remote(argv[argv.index("--") + 1])
            if isinstance(out, BaseException):
                raise out
            return ProcessResult(tuple(argv), 0, out, b"", 0.0)
        return super().run(argv, **kw)

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


class Dirtier:
    """The checkout seam, dirtying every workspace it hands out (a guard test)."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner

    def checkout(self, request: Any) -> Any:
        result = self.inner.checkout(request)
        (result.data.path / "stray.txt").write_text("x")
        return result

    def release(self, workspace: Any) -> None:
        self.inner.release(workspace)


def applier(checkouts: Any, remote: Callable[[str], bytes | BaseException], ast_grep=None):
    git = Git(remote)
    ast = ast_grep or AstGrep()
    return GitFleetFixApplier(git, ast, FixedClock(WHEN), checkouts), git, ast


def answer(url: str) -> bytes:
    return f"{PIN}\trefs/heads/main\n".encode()


# --- pinned_ref_line --------------------------------------------------------------------------


def test_a_writable_checkout_of_the_commit_gets_its_revisions_pinned(tmp_path: Path) -> None:
    forge, sha = checkout(
        tmp_path,
        {
            ".tekton/pr.yaml": TEKTON,
            ".tekton/push.yaml": TEKTON,
            "config/deploy.yaml": "params:\n  - name: revision\n    value: main\n",
        },
    )
    fixer, git, _ = applier(forge.service(), answer)
    diff = fixer.apply(spec(), ORIGIN, sha)
    assert diff.files_changed == (".tekton/pr.yaml", ".tekton/push.yaml")
    assert diff.unresolved == ()
    assert f"+        {PINNED}" in diff.diff and "-        value: main" in diff.diff
    assert "config/deploy.yaml" not in diff.diff  # outside file_glob
    assert not git.argv("clone") and not git.argv("fetch")
    (ls_remote,) = git.argv("ls-remote")  # one call per URL
    assert ls_remote[ls_remote.index("ls-remote") :] == [
        "ls-remote",
        "--",
        CATALOG,
        "refs/heads/main",
        "main",
    ]
    assert not git.argv("commit") and not git.argv("push")


def test_the_trees_git_is_hardened_and_never_a_clone(tmp_path: Path) -> None:
    forge, sha = checkout(tmp_path, {".tekton/pr.yaml": TEKTON})
    fixer, git, _ = applier(forge.service(), answer)
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
    forge, sha = checkout(tmp_path, {".tekton/pr.yaml": TEKTON})
    fixer, _, _ = applier(forge.service(), remote)
    diff = fixer.apply(spec(), ORIGIN, sha)
    assert (diff.files_changed, diff.unresolved, diff.diff) == ((), (unresolved,), "")


def test_no_match_changes_nothing(tmp_path: Path) -> None:
    forge, sha = checkout(tmp_path, {".tekton/pr.yaml": "spec: {}\n"})
    fixer, git, _ = applier(forge.service(), answer)
    assert fixer.apply(spec(), ORIGIN, sha).files_changed == ()
    assert not git.argv("ls-remote")


def test_a_tracked_link_is_never_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside.yaml"
    outside.write_text(TEKTON)
    forge, sha = checkout(tmp_path, {"README": "x\n"}, link=(".tekton/pr.yaml", str(outside)))
    fixer, _, _ = applier(forge.service(), answer)
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
        ("https://github.com:not-a-port/example/component", PIN),
        (ORIGIN, "main"),
        (ORIGIN, "--orphan"),
    ],
)
def test_an_unsafe_target_is_refused_before_any_git(tmp_path: Path, url: str, sha: str) -> None:
    fixer, git, _ = applier(NoCheckouts(), answer)
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
    fixer, git, _ = applier(NoCheckouts(), answer)
    assert fixer.ls_remote(url, ref) is None
    assert git.calls == []


def test_a_dirty_checkout_is_refused(tmp_path: Path) -> None:
    forge, sha = checkout(tmp_path, {".tekton/pr.yaml": TEKTON})
    fixer, _, _ = applier(Dirtier(forge.service()), answer)
    with pytest.raises(ValidationError, match="is not clean"):
        fixer.apply(spec(), ORIGIN, sha)
    allowed = spec(guards={"require_clean_tree": False})
    assert fixer.apply(allowed, ORIGIN, sha).files_changed == (".tekton/pr.yaml",)


def test_a_commit_the_forge_does_not_hold_is_refused(tmp_path: Path) -> None:
    forge, _ = checkout(tmp_path, {"README": "x\n"})
    fixer, _, _ = applier(forge.service(), answer)
    with pytest.raises(NotFoundError, match="is not in"):
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
    forge, sha = checkout(
        tmp_path,
        {"pkg/a.go": "var h = md5.New()\n", "pkg/b.py": "md5.New()\n", "pkg/c.go": "ok\n"},
    )
    fixer, _, ast = applier(forge.service(), answer)
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
    forge, sha = checkout(tmp_path, {"pkg/a.go": "var h = md5.New()\n"})
    fixer, _, _ = applier(forge.service(), answer, AstGrep(rc=2))
    with pytest.raises(ServiceError, match="ast-grep exited 2: boom"):
        fixer.apply(ast_spec(), ORIGIN, sha)
    empty_forge, empty = checkout(tmp_path / "e", {"README": "x\n"})
    fixer, _, ast = applier(empty_forge.service(), answer)
    assert fixer.apply(ast_spec(), ORIGIN, empty).files_changed == () and ast.calls == []


def test_a_golden_fixture_is_run_alone_in_a_scratch_dir(tmp_path: Path) -> None:
    fixer, git, ast = applier(NoCheckouts(), answer)
    test = ast_spec().tests[0]
    assert (
        fixer.after(ast_spec(), test.file, test.before) == "package pkg\n\nvar h = sha256.New()\n"
    )
    assert git.calls == [] and len(ast.calls) == 1


@pytest.mark.parametrize("file", ["/etc/passwd", "../x.go", "pkg/../../x.go"])
def test_a_golden_fixture_cannot_escape_its_scratch_dir(tmp_path: Path, file: str) -> None:
    fixer, _, ast = applier(NoCheckouts(), answer)
    with pytest.raises(ValidationError, match="escapes"):
        fixer.after(ast_spec(), file, "x")
    assert ast.calls == []


@pytest.mark.skipif(shutil.which("ast-grep") is None, reason="ast-grep not installed")
def test_real_ast_grep_proves_its_goldens_through_core(tmp_path: Path) -> None:
    from traust_core.v1.models.remediation import golden_failures

    fixer = GitFleetFixApplier(
        ProcessRunner(["git"]), ProcessRunner(["ast-grep"]), FixedClock(WHEN), NoCheckouts()
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
