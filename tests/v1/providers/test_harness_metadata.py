from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pydantic
import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.harness_metadata import HarnessMetadata
from traust_core.v1.providers.checkout import HARDENED
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.harness_metadata import HarnessMetadataProvider
from traust_core.v1.providers.process import ProcessError, ProcessRunner

AT = datetime(2026, 11, 3, 12, tzinfo=UTC)
TESTS = """import unavailable_test_dependency
raise RuntimeError("measuring must not import this module")
# def test_comment(): pass
TEXT = "def test_string(): pass"

def helper():
    pass

def test_plain():
    pass

async def test_async():
    pass

class TestWidget:
    def test_method(self):
        pass

    async def test_async_method(self):
        pass

    def helper(self):
        pass

@pytest.mark.parametrize("value", [1, 2, 3])
def test_parameterized(value):
    pass
"""


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _git(process: ProcessRunner, root: Path, *args: str) -> str:
    return (
        process.run(
            [
                "git",
                "-C",
                str(root),
                *HARDENED,
                "-c",
                "user.name=Harness Test",
                "-c",
                "user.email=harness@example.com",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "tag.gpgsign=false",
                *args,
            ]
        )
        .stdout.decode()
        .strip()
    )


def _commit(process: ProcessRunner, root: Path) -> str:
    _git(process, root, "add", "--all")
    _git(process, root, "commit", "-q", "-m", "fixture")
    return _git(process, root, "rev-parse", "HEAD")


def _shipped(root: Path) -> None:
    _write(root, "VERSION", "1.2.3\n")
    _write(root, "src/widget.py", "# harness\n\nVALUE = 1\n")
    _write(root, "src/no_newline.py", "VALUE = 2")
    _write(root, "src/widget/__init__.py", "")
    _write(root, "tests/test_widget.py", TESTS)
    for directory in ("vendor", "deps", "generated", "__pycache__", ".venv", "node_modules"):
        _write(root, f"{directory}/unexpected.py", "not valid Python!\n" * 20)
        _write(root, f"{directory}/tests/test_unexpected.py", "not valid Python!\n")


@pytest.fixture
def checkout(tmp_path: Path) -> tuple[Path, ProcessRunner, str]:
    root = tmp_path / "harness"
    root.mkdir()
    process = ProcessRunner(("git",))
    _git(process, root, "init", "-q")
    _shipped(root)
    _commit(process, root)
    _git(process, root, "tag", "v1.2.2")
    _write(root, "VERSION", "1.2.4\n")
    revision = _commit(process, root)
    _git(process, root, "tag", "-a", "v1.2.4", "-m", "fixture release")
    return root, process, revision


def test_measures_real_git_facts_physical_source_lines_and_syntactic_tests(
    checkout: tuple[Path, ProcessRunner, str],
) -> None:
    root, process, revision = checkout
    result = HarnessMetadataProvider(root, process, FixedClock(AT)).measure()

    assert result == HarnessMetadata(
        measured_at=AT,
        version="1.2.4",
        revision=revision,
        commits=2,
        releases=2,
        source_lines=4,
        test_count=5,
    )


def test_measurement_reads_current_checkout_not_historical_or_committed_file_contents(
    checkout: tuple[Path, ProcessRunner, str],
) -> None:
    root, process, revision = checkout
    _write(root, "VERSION", "1.2.5-dev\n")
    _write(root, "src/widget.py", "VALUE = 3\n")
    _write(root, "tests/test_widget.py", "async def test_changed(): pass\n")
    measured_at = datetime(2026, 11, 4, tzinfo=UTC)

    result = HarnessMetadataProvider(root, process, FixedClock(measured_at)).measure()

    assert result.measured_at == measured_at
    assert result.version == "1.2.5-dev"
    assert result.revision == revision
    assert result.source_lines == 2
    assert result.test_count == 1


def test_git_enumeration_ignores_untracked_python_and_does_not_mutate_the_checkout(
    checkout: tuple[Path, ProcessRunner, str],
) -> None:
    root, process, _ = checkout
    _write(root, "src/untracked.py", "not Python!\n" * 100)
    _write(root, "tests/test_untracked.py", "not Python!\n")
    before = _git(process, root, "status", "--porcelain=v1", "--untracked-files=all")
    index = (root / ".git/index").read_bytes()

    result = HarnessMetadataProvider(root, process, FixedClock(AT)).measure()

    assert result.source_lines == 4
    assert result.test_count == 5
    assert (root / ".git/index").read_bytes() == index
    assert _git(process, root, "status", "--porcelain=v1", "--untracked-files=all") == before


def test_commit_count_is_reachable_from_head_not_all_local_branches(
    checkout: tuple[Path, ProcessRunner, str],
) -> None:
    root, process, revision = checkout
    _git(process, root, "checkout", "-q", "-b", "another-branch")
    _write(root, "README", "another branch\n")
    _commit(process, root)
    _git(process, root, "checkout", "-q", "--detach", revision)

    result = HarnessMetadataProvider(root, process, FixedClock(AT)).measure()

    assert result.revision == revision
    assert result.commits == 2


def test_installed_sources_are_measured_without_git_or_executing_test_modules(
    tmp_path: Path,
) -> None:
    _shipped(tmp_path)
    result = HarnessMetadataProvider(tmp_path, ProcessRunner(()), FixedClock(AT)).measure()

    assert result.version == "1.2.3"
    assert result.revision is None
    assert result.commits is None
    assert result.releases is None
    assert result.source_lines == 4
    assert result.test_count == 5
    assert any("Git metadata is missing" in item for item in result.limitations)
    assert any("shipped files" in item for item in result.limitations)


def test_missing_version_and_test_tree_are_unknown_not_zero(tmp_path: Path) -> None:
    _write(tmp_path, "widget.py", "VALUE = 1\n")
    result = HarnessMetadataProvider(tmp_path, ProcessRunner(()), FixedClock(AT)).measure()

    assert result.version is None
    assert result.source_lines == 1
    assert result.test_count is None
    assert any("VERSION is missing" in item for item in result.limitations)
    assert any("Test tree is missing" in item for item in result.limitations)


def test_present_empty_source_and_test_trees_have_measured_zero_counts(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    result = HarnessMetadataProvider(tmp_path, ProcessRunner(()), FixedClock(AT)).measure()

    assert result.source_lines == 0
    assert result.test_count == 0
    assert not any("tree is missing" in item for item in result.limitations)


def test_test_modules_outside_a_conventional_test_tree_are_counted(tmp_path: Path) -> None:
    _write(tmp_path, "test_widget.py", "def test_top_level(): pass\n")
    _write(tmp_path, "widget_test.py", "async def test_other(): pass\n")
    result = HarnessMetadataProvider(tmp_path, ProcessRunner(()), FixedClock(AT)).measure()

    assert result.test_count == 2
    assert result.source_lines is None
    assert any("Python source tree is missing" in item for item in result.limitations)


def test_python_test_encoding_cookie_is_respected(tmp_path: Path) -> None:
    path = tmp_path / "tests/test_encoded.py"
    path.parent.mkdir()
    path.write_bytes(b"# coding: latin-1\nTEXT = '\xe9'\nasync def test_encoded(): pass\n")

    result = HarnessMetadataProvider(tmp_path, ProcessRunner(()), FixedClock(AT)).measure()

    assert result.test_count == 1


@pytest.mark.parametrize("text", ["def test_broken(:\n", "def test_null(): pass\x00"])
def test_malformed_test_python_raises_a_typed_error(tmp_path: Path, text: str) -> None:
    _write(tmp_path, "tests/test_broken.py", text)

    with pytest.raises(ValidationError, match="invalid harness Python test") as caught:
        HarnessMetadataProvider(tmp_path, ProcessRunner(()), FixedClock(AT)).measure()

    assert isinstance(caught.value.__cause__, (SyntaxError, ValueError))


@pytest.mark.parametrize("kind", ["missing", "file"])
def test_invalid_explicit_root_raises_a_typed_error(tmp_path: Path, kind: str) -> None:
    root = tmp_path / "invalid"
    if kind == "file":
        root.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ValidationError, match="harness root is not a directory"):
        HarnessMetadataProvider(root, ProcessRunner(()), FixedClock(AT)).measure()


def test_corrupt_explicit_git_metadata_is_not_treated_as_an_installed_distribution(
    tmp_path: Path,
) -> None:
    _write(tmp_path, ".git", "not a Git directory pointer\n")
    _write(tmp_path, "widget.py", "VALUE = 1\n")

    with pytest.raises(ProcessError):
        HarnessMetadataProvider(tmp_path, ProcessRunner(("git",)), FixedClock(AT)).measure()


def test_an_installed_directory_does_not_inherit_its_ancestors_git_facts(
    checkout: tuple[Path, ProcessRunner, str],
) -> None:
    root, process, _ = checkout
    installed = root / "installed"
    installed.mkdir()
    _write(installed, "widget.py", "VALUE = 1\n")

    result = HarnessMetadataProvider(installed, process, FixedClock(AT)).measure()

    assert result.revision is None
    assert result.commits is None
    assert result.releases is None
    assert result.version is None
    assert result.source_lines == 1


def test_missing_local_tags_measure_zero_releases(tmp_path: Path) -> None:
    process = ProcessRunner(("git",))
    _git(process, tmp_path, "init", "-q")
    _write(tmp_path, "widget.py", "VALUE = 1\n")
    _commit(process, tmp_path)

    result = HarnessMetadataProvider(tmp_path, process, FixedClock(AT)).measure()

    assert result.commits == 1
    assert result.releases == 0


def test_shallow_history_does_not_claim_a_complete_commit_count(
    checkout: tuple[Path, ProcessRunner, str], tmp_path: Path
) -> None:
    root, process, revision = checkout
    shallow = tmp_path / "shallow"
    _git(process, tmp_path, "clone", "-q", "--depth=1", root.as_uri(), str(shallow))

    result = HarnessMetadataProvider(shallow, process, FixedClock(AT)).measure()

    assert result.revision == revision
    assert result.commits is None
    assert any("history is shallow" in item for item in result.limitations)


def test_symlinked_python_cannot_read_outside_the_harness_root(tmp_path: Path) -> None:
    root = tmp_path / "harness"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("VALUE = 1\n", encoding="utf-8")
    (root / "widget.py").symlink_to(outside)

    with pytest.raises(ValidationError, match="harness file escapes root"):
        HarnessMetadataProvider(root, ProcessRunner(()), FixedClock(AT)).measure()


def test_an_empty_version_is_unknown_with_a_reason(tmp_path: Path) -> None:
    _write(tmp_path, "VERSION", " \n")
    result = HarnessMetadataProvider(tmp_path, ProcessRunner(()), FixedClock(AT)).measure()

    assert result.version is None
    assert any("VERSION is empty" in item for item in result.limitations)


def test_an_invalid_version_encoding_raises_a_typed_error(tmp_path: Path) -> None:
    (tmp_path / "VERSION").write_bytes(b"\xff")

    with pytest.raises(ValidationError, match="invalid harness VERSION"):
        HarnessMetadataProvider(tmp_path, ProcessRunner(()), FixedClock(AT)).measure()


def test_a_naive_measurement_clock_is_rejected(tmp_path: Path) -> None:
    clock = FixedClock(datetime(2026, 11, 3))

    with pytest.raises(
        ValidationError, match="harness measured_at must be a timezone-aware datetime"
    ):
        HarnessMetadataProvider(tmp_path, ProcessRunner(()), clock).measure()


def test_the_model_rejects_naive_measurement_timestamps() -> None:
    with pytest.raises(pydantic.ValidationError, match="timezone"):
        HarnessMetadata(measured_at=datetime(2026, 11, 3))


def test_disallowed_git_reports_unknown_metrics_but_still_measures_shipped_python(
    checkout: tuple[Path, ProcessRunner, str],
) -> None:
    root, _, _ = checkout

    result = HarnessMetadataProvider(root, ProcessRunner(()), FixedClock(AT)).measure()

    assert result.revision is None
    assert result.commits is None
    assert result.releases is None
    assert result.source_lines == 4
    assert result.test_count == 5
    assert any("Git not permitted" in item for item in result.limitations)
    assert any("shipped files" in item for item in result.limitations)


def test_git_paths_with_spaces_and_newlines_are_not_split_into_fake_files(
    checkout: tuple[Path, ProcessRunner, str],
) -> None:
    root, process, _ = checkout
    _write(root, "src/space and\nnewline.py", "VALUE = 3\n")
    _write(root, "tests/test_space and\nnewline.py", "async def test_path(): pass\n")
    _commit(process, root)

    result = HarnessMetadataProvider(root, process, FixedClock(AT)).measure()

    assert result.source_lines == 5
    assert result.test_count == 6


def test_a_tracked_placeholder_preserves_a_present_empty_test_tree(tmp_path: Path) -> None:
    process = ProcessRunner(("git",))
    _git(process, tmp_path, "init", "-q")
    _write(tmp_path, "widget.py", "VALUE = 1\n")
    _write(tmp_path, "tests/.keep", "")
    _commit(process, tmp_path)

    result = HarnessMetadataProvider(tmp_path, process, FixedClock(AT)).measure()

    assert result.test_count == 0


def test_a_version_directory_is_an_invalid_metadata_file(tmp_path: Path) -> None:
    (tmp_path / "VERSION").mkdir()

    with pytest.raises(ValidationError, match="cannot read harness metadata"):
        HarnessMetadataProvider(tmp_path, ProcessRunner(()), FixedClock(AT)).measure()
