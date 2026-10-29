from __future__ import annotations

from pathlib import Path

import pytest

from tests.v1.conftest import commit_all, git
from traust_core.v1.errors import ValidationError
from traust_core.v1.providers.checkout import GitCheckout, NumstatRow, numstat_path
from traust_core.v1.providers.process import ProcessRunner

READER = GitCheckout(ProcessRunner(("git",)))


@pytest.fixture
def repo(tmp_path: Path) -> tuple[Path, str]:
    r = tmp_path / "widget"
    r.mkdir()
    git(r, "init", "-q")
    (r / "pkg").mkdir()
    (r / "pkg" / "a.go").write_text("package pkg\n")
    (r / "old.go").write_text("package main\n// " + "x" * 40 + "\n")
    (r / "logo.png").write_bytes(b"\x89PNG\x00\x01")
    base = commit_all(r, "base")
    (r / "pkg" / "a.go").write_text("package pkg\n\nfunc A() {}\n")
    git(r, "mv", "old.go", "new.go")
    (r / "logo.png").write_bytes(b"\x89PNG\x00\x02")
    commit_all(r, "change")
    return r, base


@pytest.mark.parametrize(
    ("raw", "path"),
    [
        ("pkg/{old => new}/f.go", "pkg/new/f.go"),
        ("old.go => new.go", "new.go"),
        ("{ => cmd}/main.go", "cmd/main.go"),
        ("plain/path.go", "plain/path.go"),
    ],
)
def test_a_numstat_rename_is_its_new_path(raw: str, path: str) -> None:
    assert numstat_path(raw) == path


def test_numstat_counts_lines_renames_by_new_path_and_binaries_as_zero(
    repo: tuple[Path, str],
) -> None:
    r, base = repo
    rows = {row.path: row for row in READER.numstat(r, base)}
    assert rows["pkg/a.go"] == NumstatRow("pkg/a.go", 2, 0)
    assert rows["new.go"] == NumstatRow("new.go", 0, 0)
    assert rows["logo.png"] == NumstatRow("logo.png", 0, 0)


def test_tracked_lists_the_files_at_head(repo: tuple[Path, str]) -> None:
    assert sorted(READER.tracked(repo[0])) == ["logo.png", "new.go", "pkg/a.go"]


def test_hunks_are_the_unified_diff_of_one_file(repo: tuple[Path, str]) -> None:
    r, base = repo
    hunks = READER.hunks(r, base, "pkg/a.go", 10)
    assert "+func A() {}" in hunks
    assert "new.go" not in hunks


@pytest.mark.parametrize(
    ("sha", "reachable"),
    [("deadbeef" * 5, False), ("not-a-sha", False), ("", False)],
)
def test_an_unknown_or_malformed_sha_is_unreachable(
    repo: tuple[Path, str], sha: str, reachable: bool
) -> None:
    assert READER.reachable(repo[0], sha) is reachable


def test_the_base_commit_is_reachable_full_or_short(repo: tuple[Path, str]) -> None:
    r, base = repo
    assert READER.reachable(r, base)
    assert READER.reachable(r, base[:7])


def test_a_plain_directory_or_missing_path_is_not_a_checkout(tmp_path: Path) -> None:
    assert not READER.is_checkout(tmp_path)
    assert not READER.is_checkout(tmp_path / "missing")


def test_a_repository_is_a_checkout(repo: tuple[Path, str]) -> None:
    assert READER.is_checkout(repo[0])


def test_the_checkouts_own_config_never_runs_a_command(
    repo: tuple[Path, str], tmp_path: Path
) -> None:
    r, base = repo
    marker = tmp_path / "ran"
    hook = tmp_path / "hook"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
    hook.chmod(0o755)
    for key in ("core.fsmonitor", "diff.external"):
        git(r, "config", key, str(hook))
    git(r, "config", "diff.go.textconv", str(hook))
    (r / ".gitattributes").write_text("*.go diff=go\n")
    READER.numstat(r, base)
    READER.hunks(r, base, "pkg/a.go", 3)
    READER.tracked(r)
    assert not marker.exists()


def test_diff_is_the_unified_diff_since_the_anchor(repo: tuple[Path, str]) -> None:
    r, base = repo
    diff = READER.diff(r, base)
    assert "+func A() {}" in diff and "rename to new.go" in diff


def test_change_types_name_each_file_by_its_new_path(repo: tuple[Path, str]) -> None:
    r, base = repo
    (r / "added.go").write_text("package main\n")
    (r / "logo.png").unlink()
    commit_all(r, "add and delete")
    assert READER.change_types(r, base) == {
        "pkg/a.go": "modified",
        "new.go": "renamed",
        "added.go": "added",
        "logo.png": "deleted",
    }


def test_head_is_the_full_sha_checked_out(repo: tuple[Path, str]) -> None:
    r, base = repo
    head = READER.head(r)
    assert len(head) == 40 and head != base and READER.reachable(r, head)


@pytest.mark.parametrize("anchor", ["--output=/tmp/x", "HEAD", "main", ""])
def test_a_diff_anchor_must_be_a_sha(repo: tuple[Path, str], anchor: str) -> None:
    for read in (READER.diff, READER.change_types):
        with pytest.raises(ValidationError, match="not a commit sha"):
            read(repo[0], anchor)


def test_changed_paths_are_every_file_changed_since_any_ref(repo: tuple[Path, str]) -> None:
    r, base = repo
    changed = ["logo.png", "new.go", "pkg/a.go"]
    assert sorted(READER.changed_paths(r, base)) == sorted(READER.changed_paths(r, "HEAD~1"))
    assert sorted(READER.changed_paths(r, "HEAD~1")) == changed
    assert READER.changed_paths(r, "HEAD") == []


def test_changed_paths_refuse_an_option_for_a_ref(repo: tuple[Path, str]) -> None:
    with pytest.raises(ValidationError, match="not a ref"):
        READER.changed_paths(repo[0], "--output=/tmp/x")


@pytest.mark.parametrize("url", ["http://example.invalid/r.git", "file:///tmp/r", "ext::sh -c x"])
def test_a_clone_is_https_only(tmp_path: Path, url: str) -> None:
    with pytest.raises(ValidationError, match="https URL"):
        READER.clone(url, tmp_path / "r", timeout_seconds=5)
