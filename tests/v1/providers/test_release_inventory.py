from __future__ import annotations

import csv
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.inventory import ReleaseBump
from traust_core.v1.models.release_inventory import ReleaseArtifactKind
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import ProcessResult, ProcessRunner
from traust_core.v1.providers.release_inventory import ReleaseInventoryFeed, parse_release_snapshot

CLOCK = FixedClock(datetime(2026, 10, 5, tzinfo=UTC))
REPO = "https://github.com/example/source"
DISTGIT = "https://gitlab.com/example/rpms/package"


def inventory(root: Path, version: str, images: str) -> None:
    path = root / f"payload-{version}-payload-repos.csv"
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(("GitHub URL", "Payload Image(s)"))
        writer.writerow((REPO, images))


class Git(ProcessRunner):
    def __init__(self) -> None:
        super().__init__(("git",))
        self.head = "a" * 40
        self.fail = False
        self.calls: list[tuple[list[str], dict[str, str]]] = []

    def run(self, argv: list[str], **kwargs: Any) -> ProcessResult:
        self.calls.append((argv, kwargs["env"]))
        if self.fail:
            raise ServiceError("forge offline")
        return ProcessResult(tuple(argv), 0, f"{self.head}\tHEAD\n".encode(), b"", 0)


def test_inventory_baseline_digest_movement_and_rerun(tmp_path: Path) -> None:
    inventory(tmp_path, "1.0", "quay.io/example/app@sha256:aaa;manager")
    provider = ReleaseInventoryFeed(tmp_path, Git(), CLOCK)
    baseline = provider.fetch().data
    assert parse_release_snapshot(baseline).observations == ()
    inventory(tmp_path, "1.0", "quay.io/example/app@sha256:bbb;manager;manager")
    changed = provider.fetch(lambda: baseline).data
    [event] = parse_release_snapshot(changed).observations
    assert (event.target, event.kind, event.repository, event.version, event.change) == (
        "quay.io/example/app@sha256:bbb",
        ReleaseArtifactKind.CONTAINER,
        REPO,
        "1.0.0",
        ReleaseBump.NONE,
    )
    assert provider.fetch(lambda: changed).data == changed


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("2.0", ReleaseBump.MAJOR),
        ("1.1", ReleaseBump.MINOR),
        ("1.0.1", ReleaseBump.PATCH),
        ("0.9", ReleaseBump.BACKFILL),
    ],
)
def test_inventory_path_not_image_tag_defines_version(
    tmp_path: Path, version: str, expected: ReleaseBump
) -> None:
    inventory(tmp_path, "1.0", "manager")
    provider = ReleaseInventoryFeed(tmp_path, Git(), CLOCK)
    baseline = provider.fetch().data
    inventory(tmp_path, version, "manager")
    snapshot = parse_release_snapshot(provider.fetch(lambda: baseline).data)
    [event] = snapshot.observations
    assert event.change == expected
    assert event.family == "payload-{V}-payload-repos.csv"
    assert event.target == "manager"
    if expected == ReleaseBump.BACKFILL:
        assert snapshot.versions[event.family] == "1.0.0"


def test_distgit_changes_are_pinned_unknown_not_versions_and_failures_keep_head(
    tmp_path: Path,
) -> None:
    git = Git()
    provider = ReleaseInventoryFeed(tmp_path, git, CLOCK, watched=(DISTGIT, "file:///tmp/repo"))
    baseline = provider.fetch().data
    old = parse_release_snapshot(baseline)
    assert old.observations == ()
    assert "file:///tmp/repo" in old.skipped
    git.fail = True
    failed = provider.fetch(lambda: baseline).data
    assert parse_release_snapshot(failed).distgit_heads[DISTGIT] == "a" * 40
    git.fail, git.head = False, "b" * 40
    changed = parse_release_snapshot(provider.fetch(lambda: failed).data)
    [event] = changed.observations
    assert (event.kind, event.target, event.head, event.change, event.version) == (
        ReleaseArtifactKind.RPM,
        DISTGIT,
        "b" * 40,
        ReleaseBump.UNKNOWN,
        None,
    )
    assert changed.releases == ()
    assert all(call[0] == ["git", "ls-remote", "--", DISTGIT, "HEAD"] for call in git.calls)
    assert all(call[1]["GIT_ALLOW_PROTOCOL"] == "https" for call in git.calls)


def test_corrupt_snapshot_is_not_reseeded(tmp_path: Path) -> None:
    provider = ReleaseInventoryFeed(tmp_path, Git(), CLOCK)
    with pytest.raises(ValidationError):
        provider.fetch(lambda: b'{"seen_images": 42}')


def test_missing_inputs_do_not_erase_snapshot(tmp_path: Path) -> None:
    provider = ReleaseInventoryFeed(tmp_path / "missing", Git(), CLOCK)
    assert not provider.check().ready
    snapshot = parse_release_snapshot(provider.fetch(lambda: b'{"seen_images":["known"]}').data)
    assert snapshot.seen_images == ("known",)
    assert snapshot.skipped == {"inventory": "release inventory inputs directory is missing"}


def test_missing_container_inventory_does_not_hide_a_distgit_head_change(tmp_path: Path) -> None:
    git = Git()
    provider = ReleaseInventoryFeed(tmp_path / "missing", git, CLOCK, watched=(DISTGIT,))
    baseline = provider.fetch().data
    git.head = "c" * 40
    snapshot = parse_release_snapshot(provider.fetch(lambda: baseline).data)
    [event] = snapshot.observations
    assert event.head == "c" * 40 and event.kind == ReleaseArtifactKind.RPM
    assert event.version is None and event.change == ReleaseBump.UNKNOWN
    assert snapshot.releases == ()
    assert "inventory" in snapshot.skipped
