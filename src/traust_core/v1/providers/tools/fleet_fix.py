"""The fleet-fix applier and ast-grep golden runner: clones, `git ls-remote`, ast-grep and diffs
for `RemediationService`; it never commits, forks or pushes."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.artifacts import FleetFixArtifact
from traust_core.v1.models.common import RepoPath
from traust_core.v1.models.remediation import FleetFixDiff, in_scope, rewrite_pinned_refs
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner

CLONE_TIMEOUT = 600.0
LS_REMOTE_TIMEOUT = 60.0
GIT_TIMEOUT = 120.0
AST_GREP_TIMEOUT = 600.0
# URLs come from target-repository files (the spec's url_regex): hostile by definition.
# https-only plus GIT_ALLOW_PROTOCOL blocks ext::/ssh helper execution; `--` and the leading
# character checks block option injection (audit A1, a confirmed RCE class).
_HTTPS_URL = re.compile(r"https://[^\s'\"]+")
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")
_SHA = re.compile(r"[0-9a-f]{40}")
_NETWORK_ENV = {"GIT_ALLOW_PROTOCOL": "https", "GIT_TERMINAL_PROMPT": "0"}
# Never a command the checkout's own config names (fsmonitor, hooks).
_HARDENED = ("-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null")


class GitFleetFixApplier:
    """A fleet-fix spec applied to a fresh https clone of one commit, as a diff; also runs an
    ast_grep spec over one golden fixture for core's golden tests."""

    def __init__(self, git: ProcessRunner, ast_grep: ProcessRunner, clock: Clock) -> None:
        self._git = git
        self._ast_grep = ast_grep
        self._clock = clock

    def apply(self, spec: FleetFixArtifact, repository_url: str, sha: str) -> FleetFixDiff:
        if not _HTTPS_URL.fullmatch(repository_url):
            raise ValidationError(f"fleet fix {spec.id}: {repository_url!r} is not an https URL")
        if not _SHA.fullmatch(sha):
            raise ValidationError(f"fleet fix {spec.id}: {sha!r} is not a 40-hex commit")
        with tempfile.TemporaryDirectory(prefix="fleetfix-") as tmp:
            repo = Path(tmp) / "repo"
            self._run_git(
                Path(tmp),
                "clone",
                "--quiet",
                "--no-checkout",
                "--",
                repository_url,
                str(repo),
                timeout=CLONE_TIMEOUT,
            )
            self._run_git(repo, "checkout", "--quiet", "--detach", sha)
            guards = spec.guards
            if guards.require_clean_tree is not False and self._run_git(
                repo, "status", "--porcelain"
            ):
                raise ValidationError(f"fleet fix {spec.id}: {repository_url}@{sha} is not clean")
            files = self._in_scope(spec, repo)
            if spec.matcher.kind == "pinned_ref_line":
                unresolved = self._rewrite(spec, repo, files)
            else:
                self._run_ast_grep(spec, [repo / f for f in files])
                unresolved = []
            changed = self._run_git(repo, "diff", "--name-only", "-z").split("\0")
            return FleetFixDiff(
                files_changed=tuple(RepoPath(f) for f in changed if f),
                unresolved=tuple(unresolved),
                diff=self._run_git(repo, "diff", "--no-ext-diff", "--no-textconv"),
            )

    def after(self, spec: FleetFixArtifact, file: str, before: str) -> str:
        path = PurePosixPath(file)
        if path.is_absolute() or ".." in path.parts:
            raise ValidationError(f"fleet fix {spec.id}: golden fixture path {file!r} escapes")
        with tempfile.TemporaryDirectory(prefix="fleetfix-golden-") as tmp:
            target = Path(tmp, *path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(before, encoding="utf-8")
            self._run_ast_grep(spec, [target])
            return target.read_text(encoding="utf-8")

    def _in_scope(self, spec: FleetFixArtifact, repo: Path) -> list[str]:
        """Tracked regular files the spec's file_glob allows; links are never followed."""
        tracked = self._run_git(repo, "ls-files", "-z").split("\0")
        return [
            f
            for f in tracked
            if f
            and in_scope(spec.matcher.file_glob, f)
            and (repo / f).is_file()
            and not (repo / f).is_symlink()
        ]

    def _rewrite(self, spec: FleetFixArtifact, repo: Path, files: list[str]) -> list[str]:
        date = self._clock.now().date().isoformat()
        ref = (spec.resolver.ref if spec.resolver else None) or "main"
        cache: dict[str, str | None] = {}

        def resolve(url: str) -> str | None:
            if url not in cache:
                cache[url] = self.ls_remote(url, ref)
            return cache[url]

        unresolved: list[str] = []
        for f in files:
            text = (repo / f).read_text(encoding="utf-8", errors="replace")
            new, missed = rewrite_pinned_refs(spec, f, text, date, resolve)
            unresolved += missed
            if new != text:
                (repo / f).write_text(new, encoding="utf-8")
        return unresolved

    def ls_remote(self, url: str, ref: str) -> str | None:
        """The commit `ref` names on an https remote; None (reported unresolved by core) when the
        URL or ref fails the guards or the remote doesn't answer."""
        if not (_HTTPS_URL.fullmatch(url) and _REF.fullmatch(ref)):
            return None
        argv = ["git", *_HARDENED, "ls-remote", "--", url, f"refs/heads/{ref}", ref]
        try:
            out = self._git.run(
                argv, env=_NETWORK_ENV, check=False, timeout_seconds=LS_REMOTE_TIMEOUT
            )
        except ServiceError:
            return None
        shas = (line.split("\t")[0].strip() for line in out.stdout.decode().splitlines())
        return next((s for s in shas if _SHA.fullmatch(s)), None)

    def _run_ast_grep(self, spec: FleetFixArtifact, paths: list[Path]) -> None:
        if not paths:
            return
        m: Any = spec.matcher
        argv = [
            "ast-grep",
            "run",
            f"--pattern={m.pattern}",
            f"--rewrite={spec.rewrite.template}",
            f"--lang={m.lang}",
            "--update-all",
            *map(str, paths),
        ]
        # An empty cwd: ast-grep looks for sgconfig.yml (custom languages load native libraries)
        # upward from it, and the target repository must not supply one.
        with tempfile.TemporaryDirectory(prefix="fleetfix-cwd-") as cwd:
            out = self._ast_grep.run(argv, cwd=Path(cwd), check=False)
        if out.returncode not in (0, 1):  # 1: no match
            tail = out.stderr.decode(errors="replace")[-400:]
            raise ServiceError(f"fleet fix {spec.id}: ast-grep exited {out.returncode}: {tail}")

    def _run_git(self, repo: Path, *args: str, timeout: float = GIT_TIMEOUT) -> str:
        argv = ["git", "-C", str(repo), *_HARDENED, *args]
        return self._git.run(argv, env=_NETWORK_ENV, timeout_seconds=timeout).stdout.decode()
