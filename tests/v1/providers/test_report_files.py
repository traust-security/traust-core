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


def test_threat_models_finds_both_names_and_skips_symlinks_and_artifacts(tmp_path: Path) -> None:
    _touch(
        tmp_path,
        "a/THREAT_MODEL.md",
        "a/svc-threat-model.md",
        "a/notes.md",
        "a/artifacts/w1/THREAT_MODEL.md",
    )
    (tmp_path / "a/link-threat-model.md").symlink_to(tmp_path / "a/svc-threat-model.md")
    scratch = tmp_path / "a/artifacts/w1/THREAT_MODEL.md"
    files = ReportFiles()
    assert files.threat_models([tmp_path]) == [
        tmp_path / "a/THREAT_MODEL.md",
        tmp_path / "a/svc-threat-model.md",
    ]
    assert files.threat_models([scratch]) == [scratch]
    assert files.threat_models([tmp_path / "a/link-threat-model.md"]) == []


def test_sarif_reports_prefer_the_cumulative_and_skip_hidden_dirs(tmp_path: Path) -> None:
    _touch(
        tmp_path,
        "findings/prodA/repo1/repo1-security-audit.json",
        "findings/prodA/repo1/repo1-findings-current.json",
        "findings/prodA/repo1/repo1-container-audit.json",
        "findings/prodB/repo2/repo2-security-audit.json",
        "findings/prodB/repo2/repo2-security-audit-findings-current.json",
        "findings/prodC/repo3/repo3-cloud-config-audit.json",
        "findings/prodC/repo3/repo3-findings-current.json",
        "findings/prodD/repo4/repo4-security-audit.json",
        "findings/prodD/repo4/notes.json",
        ".verify-tmp/x-security-audit.json",
    )
    (tmp_path / "findings/linked").symlink_to(tmp_path / "findings/prodD")
    names = sorted(p.name for p in ReportFiles().sarif_reports(tmp_path))
    assert names == [
        "repo1-container-audit.json",
        "repo1-findings-current.json",
        "repo2-security-audit-findings-current.json",
        "repo3-findings-current.json",
        "repo4-security-audit.json",
    ]
