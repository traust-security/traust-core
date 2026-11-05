from __future__ import annotations

from pathlib import Path

import pytest

from traust_core.v1.context.documents import yaml_documents
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.input_segments import InputSegment, InputSegmentInventory
from traust_core.v1.providers.input_segments import InputSegments


def _file(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_declaration_order_precedes_undeclared_directories_without_excluding_ansible(
    tmp_path: Path,
) -> None:
    _file(
        tmp_path,
        "inventory.yaml",
        "segments:\n"
        "  services: {kind: services, label: Managed Services}\n"
        "  platform: release-payload\n"
        "  catalog: {kind: catalog, registries: [registry.example.org]}\n"
        "  empty:\n"
        "  absent: groups\n"
        "org_teams: {example: Platform}\n",
    )
    for name in ("z-extra", "platform", "ansible", "catalog", "services", "empty", "a-extra"):
        (tmp_path / name).mkdir()
    _file(tmp_path, "ansible/group/automation-repos.csv", "URL\nhttps://forge.example/org/run\n")

    inventory = InputSegments(tmp_path, yaml_documents).read()

    assert [segment.name for segment in inventory.segments] == [
        "services",
        "platform",
        "catalog",
        "empty",
        "a-extra",
        "ansible",
        "z-extra",
    ]
    assert inventory.segments[5].repository_urls == ("https://forge.example/org/run",)
    assert inventory.segments[3].repository_urls == ()


def test_missing_descriptor_orders_all_segments_alphabetically(tmp_path: Path) -> None:
    for name in ("zeta", "ansible", "alpha", ".git"):
        (tmp_path / name).mkdir()
    _file(tmp_path, "root-repos.csv", "URL\nhttps://forge.example/org/root\n")

    assert InputSegments(tmp_path, yaml_documents).read() == InputSegmentInventory(
        segments=tuple(
            InputSegment(name=name, repository_urls=()) for name in ("alpha", "ansible", "zeta")
        )
    )


def test_reads_every_nested_repository_csv_and_ignores_owner_and_other_files(
    tmp_path: Path,
) -> None:
    _file(
        tmp_path,
        "platform/platform-1.0-payload-repos.csv",
        "GitHub Repository,GitHub URL,Source Branch\n"
        "org/payload,https://forge.example/org/payload,release-1.0\n",
    )
    _file(
        tmp_path,
        "platform/product/1.0/group-repos.csv",
        "Repository,URL,App/Sub-Service,Resource Type\n"
        "org/nested,https://forge.example/org/nested,product,upstream\n",
    )
    _file(
        tmp_path, "platform/product/unversioned-repos.csv", "URL\nhttps://forge.example/org/base\n"
    )
    _file(tmp_path, "platform/product/owners-repos.csv", 'URL\n"malformed\n')
    _file(tmp_path, "platform/owners.csv", "URL\nnot a repository\n")
    _file(tmp_path, "platform/product/notes.csv", "URL\nnot a repository\n")
    _file(tmp_path, "platform/product/group-repos.md", "not a CSV")

    assert InputSegments(tmp_path, yaml_documents).read().segments == (
        InputSegment(
            name="platform",
            repository_urls=(
                "https://forge.example/org/base",
                "https://forge.example/org/nested",
                "https://forge.example/org/payload",
            ),
        ),
    )


def test_canonicalizes_through_structural_repo_urls_and_deduplicates_per_segment(
    tmp_path: Path,
) -> None:
    _file(
        tmp_path,
        "platform/group-repos.csv",
        "URL\n"
        "  https://FORGE.EXAMPLE/Org/Repo.git/  \n"
        "https://forge.example/Org/Repo\n"
        "https://git.example/group/subgroup/project.git\n",
    )
    _file(tmp_path, "platform/nested/more-repos.csv", "URL\nhttps://forge.example/Org/Repo/\n")
    _file(tmp_path, "services/group-repos.csv", "URL\nhttps://forge.example/Org/Repo.git\n")

    assert (
        InputSegments(tmp_path, yaml_documents).read().segments
        == InputSegmentInventory(
            segments=(
                InputSegment(
                    name="platform",
                    repository_urls=(
                        "https://forge.example/Org/Repo",
                        "https://git.example/group/subgroup/project",
                    ),
                ),
                InputSegment(name="services", repository_urls=("https://forge.example/Org/Repo",)),
            )
        ).segments
    )


def test_blank_url_cells_are_empty_and_legacy_url_column_priority_is_preserved(
    tmp_path: Path,
) -> None:
    _file(
        tmp_path,
        "platform/group-repos.csv",
        "GitHub URL,URL,Repository\n"
        ",,blank\n"
        "   ,  ,whitespace\n"
        "  ,https://forge.example/org/fallback,fallback\n"
        "https://forge.example/org/preferred,https://forge.example/org/other,preferred\n",
    )

    assert InputSegments(tmp_path, yaml_documents).read().segments[0].repository_urls == (
        "https://forge.example/org/fallback",
        "https://forge.example/org/preferred",
    )


@pytest.mark.parametrize("descriptor", ["", "# empty descriptor\n", "{}\n", "segments:\n"])
def test_empty_descriptors_and_empty_segment_files_are_represented(
    tmp_path: Path, descriptor: str
) -> None:
    _file(tmp_path, "inventory.yaml", descriptor)
    (tmp_path / "no-files").mkdir()
    _file(tmp_path, "empty-files/zero-repos.csv", "")
    _file(tmp_path, "empty-files/header-repos.csv", "Repository,URL\n")
    _file(tmp_path, "empty-files/blank-repos.csv", "\n\n")

    assert InputSegments(tmp_path, yaml_documents).read() == InputSegmentInventory(
        segments=(
            InputSegment(name="empty-files", repository_urls=()),
            InputSegment(name="no-files", repository_urls=()),
        )
    )


def test_existing_empty_inventory_is_not_a_missing_root(tmp_path: Path) -> None:
    assert InputSegments(tmp_path, yaml_documents).read() == InputSegmentInventory(segments=())


@pytest.mark.parametrize("is_file", [False, True], ids=["missing", "file"])
def test_missing_or_non_directory_configured_root_raises_config_error(
    tmp_path: Path, is_file: bool
) -> None:
    root = tmp_path / "configured-inputs"
    if is_file:
        root.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ConfigError, match="reading input segments") as error:
        InputSegments(root, yaml_documents).read()

    assert str(root) in str(error.value)


@pytest.mark.parametrize(
    "url",
    [
        "not a URL",
        "http://forge.example/org/repo",
        "git@forge.example:org/repo.git",
        "https://forge.example/only-owner",
        "https://forge.example/org/../repo",
        "https://forge.example/org/repo?ref=main",
        "https://forge.example/org/repo#fragment",
        "https://user:password@forge.example/org/repo",
        "https://forge.example:invalid/org/repo",
        "https://[invalid/org/repo",
    ],
)
def test_malformed_nonblank_repository_urls_have_file_and_row_context(
    tmp_path: Path, url: str
) -> None:
    path = _file(tmp_path, "platform/nested/group-repos.csv", f"URL\n\n{url}\n")

    with pytest.raises(ConfigError, match="invalid repository URL") as error:
        InputSegments(tmp_path, yaml_documents).read()

    assert f"{path}:3:" in str(error.value)
    assert error.value.__cause__ is not None


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('URL\n"https://forge.example/org/repo\n', "reading repository inventory"),
        ("URL\nhttps://forge.example/org/repo,extra\n", "too many CSV fields"),
        ("Repository\norg/repo\n", "expected a GitHub URL or URL column"),
    ],
)
def test_malformed_csv_raises_config_error_with_source_path(
    tmp_path: Path, text: str, message: str
) -> None:
    path = _file(tmp_path, "platform/group-repos.csv", text)

    with pytest.raises(ConfigError, match=message) as error:
        InputSegments(tmp_path, yaml_documents).read()

    assert str(path) in str(error.value)


def test_utf8_bom_does_not_hide_the_repository_url_column(tmp_path: Path) -> None:
    _file(tmp_path, "platform/group-repos.csv", "\ufeffURL\nhttps://forge.example/org/repo\n")

    assert InputSegments(tmp_path, yaml_documents).read().segments[0].repository_urls == (
        "https://forge.example/org/repo",
    )


def test_invalid_csv_encoding_is_a_chained_config_error(tmp_path: Path) -> None:
    path = _file(tmp_path, "platform/group-repos.csv", "")
    path.write_bytes(b"URL\n\xff\n")

    with pytest.raises(ConfigError, match="reading repository inventory") as error:
        InputSegments(tmp_path, yaml_documents).read()

    assert str(path) in str(error.value)
    assert isinstance(error.value.__cause__, UnicodeError)


@pytest.mark.parametrize(
    "descriptor",
    [
        "segments: [platform]\n",
        "- not a mapping\n",
        "false\n",
        "segments: {platform: 42}\n",
        "segments: {platform: {kind: unsupported}}\n",
        "segments: {42: groups}\n",
        "segments: {'': groups}\n",
        "segments: [\n",
        "segments: {}\n---\nsegments: {platform: groups}\n",
    ],
)
def test_malformed_nonblank_descriptor_is_not_silently_ignored(
    tmp_path: Path, descriptor: str
) -> None:
    path = _file(tmp_path, "inventory.yaml", descriptor)

    with pytest.raises(ConfigError) as error:
        InputSegments(tmp_path, yaml_documents).read()

    assert str(path) in str(error.value)


def test_unreadable_descriptor_is_not_treated_as_absent(tmp_path: Path) -> None:
    path = tmp_path / "inventory.yaml"
    path.mkdir()

    with pytest.raises(ConfigError, match="reading input segment descriptor") as error:
        InputSegments(tmp_path, yaml_documents).read()

    assert str(path) in str(error.value)
    assert isinstance(error.value.__cause__, OSError)
