"""ReportFiles: the report files a caller names on disk."""

from __future__ import annotations

from pathlib import Path

import pytest

from traust_core.v1.providers.report_files import ReportFiles


def _touch(root: Path, *names: str) -> None:
    for name in names:
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text("{}", encoding="utf-8")


def test_collect_sweeps_json_under_a_directory_in_path_order(tmp_path: Path) -> None:
    _touch(
        tmp_path,
        "b/x-security-audit.json",
        "a.json",
        "notes.md",
        "b/x-refuted-register.json",
        "b/.state/phase.json",
    )
    assert ReportFiles().collect(tmp_path) == [
        tmp_path / "a.json",
        tmp_path / "b/x-security-audit.json",
    ]


def test_collect_names_one_file_even_a_refuted_register(tmp_path: Path) -> None:
    _touch(tmp_path, "x-refuted-register.json")
    path = tmp_path / "x-refuted-register.json"
    assert ReportFiles().collect(path) == [path]


def test_collect_of_a_missing_path_is_empty(tmp_path: Path) -> None:
    assert ReportFiles().collect(tmp_path / "nope") == []


def test_read_raises_for_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        ReportFiles().read(tmp_path / "nope.json")


def test_exists_and_is_file(tmp_path: Path) -> None:
    _touch(tmp_path, "d/f.json")
    files = ReportFiles()
    assert files.exists(tmp_path / "d") and not files.is_file(tmp_path / "d")
    assert files.is_file(tmp_path / "d/f.json")
    assert not files.exists(tmp_path / "gone")
