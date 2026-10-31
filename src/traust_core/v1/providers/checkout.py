"""A local checkout read through git: read-only, list argv, never a fetch, and never a command
the checkout's own config names (fsmonitor, external diff, textconv). Fetching a repository is
`RepoCheckoutService`'s job, not this reader's."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from traust_core.v1.errors import ValidationError
from traust_core.v1.providers.process import ProcessRunner

_SHA = re.compile(r"[0-9a-f]{7,40}")
HARDENED = ("-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null")
_RENAME_BRACE = re.compile(r"\{[^{}]*=> ?([^{}]*)\}")


_CHANGE = {"A": "added", "D": "deleted", "R": "renamed"}


@dataclass(frozen=True, slots=True)
class NumstatRow:
    path: str
    added: int
    deleted: int


def numstat_path(path: str) -> str:
    """A `git diff --numstat -M` rename (`a/{old => new}/b`, `old => new`) as its new path."""
    if "=>" not in path:
        return path
    path = _RENAME_BRACE.sub(lambda m: m.group(1), path)
    if "=>" in path:
        path = path.split("=>", 1)[1].strip()
    return path.replace("//", "/").lstrip("/")


def _since(anchor: str) -> str:
    if not _SHA.fullmatch(anchor):
        raise ValidationError(f"not a commit sha: {anchor!r}")
    return f"{anchor}..HEAD"


class GitCheckout:
    def __init__(self, runner: ProcessRunner) -> None:
        self._runner = runner

    def _git(self, checkout: Path, *args: str, check: bool = True) -> str:
        result = self._runner.run(["git", "-C", str(checkout), *HARDENED, *args], check=check)
        return result.stdout.decode(errors="replace") if result.returncode == 0 else ""

    def is_checkout(self, checkout: Path) -> bool:
        return checkout.is_dir() and bool(
            self._git(checkout, "rev-parse", "--git-dir", check=False)
        )

    def reachable(self, checkout: Path, sha: str) -> bool:
        return bool(_SHA.fullmatch(sha)) and (
            self._runner.run(
                ["git", "-C", str(checkout), *HARDENED, "cat-file", "-e", f"{sha}^{{commit}}"],
                check=False,
            ).returncode
            == 0
        )

    def numstat(self, checkout: Path, anchor: str) -> list[NumstatRow]:
        """Lines added and deleted per file, `anchor..HEAD`; binary files count 0."""
        rows = []
        for line in self._git(
            checkout,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--numstat",
            "-M",
            f"{anchor}..HEAD",
            "--",
        ).splitlines():
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            added, deleted, path = parts
            rows.append(
                NumstatRow(
                    numstat_path(path),
                    int(added) if added.isdigit() else 0,
                    int(deleted) if deleted.isdigit() else 0,
                )
            )
        return rows

    def tracked(self, checkout: Path) -> list[str]:
        return [p for p in self._git(checkout, "ls-files", "-z").split("\0") if p]

    def hunks(self, checkout: Path, anchor: str, path: str, context: int) -> str:
        return self._git(
            checkout,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            f"-U{context}",
            f"{anchor}..HEAD",
            "--",
            path,
        )

    def diff(self, checkout: Path, anchor: str) -> str:
        """The unified diff `anchor..HEAD`, renames detected."""
        return self._git(
            checkout, "diff", "--no-ext-diff", "--no-textconv", "-M", _since(anchor), "--"
        )

    def change_types(self, checkout: Path, anchor: str) -> dict[str, str]:
        """Each changed file's change, `anchor..HEAD`, by its new path: added, deleted,
        renamed or modified."""
        changes = {}
        for line in self._git(
            checkout, "diff", "--no-ext-diff", "--name-status", "-M", _since(anchor), "--"
        ).splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                changes[parts[-1]] = _CHANGE.get(parts[0][:1], "modified")
        return changes

    def head(self, checkout: Path) -> str:
        """The commit checked out (HEAD), in full."""
        return self._git(checkout, "rev-parse", "--verify", "HEAD^{commit}").strip()

    def changed_paths(self, checkout: Path, since: str) -> list[str]:
        """The files changed `since..HEAD`, for any ref `since` names."""
        if since.startswith("-"):
            raise ValidationError(f"not a ref: {since!r}")
        return self._git(checkout, "diff", "--name-only", f"{since}..HEAD", "--").splitlines()
