import base64
import json
from pathlib import Path
from urllib.parse import quote

import pytest

from tests.v1.providers.test_forge_file import GITHUB, GITLAB, SHA
from tests.v1.providers.test_forge_inventory import Script, forge, ok
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.providers.sources import ForgeFiles, SourceError, WorkspaceFiles

FILES = {
    "pkg/auth.go": "first\nsecond\nthird\n",
    "components/a/pkg/scope.go": "first\n",
    "components/b/pkg/scope.go": "first\r\nsecond\rthird",
    "deploy/server-jwt-args-patch.yaml": "setting: value\n",
    "src/empty.c": "",
    "vendor/third.c": "vendored\n",
    "build/generated.c": "generated\n",
    "nested/.venv/hidden.py": "hidden\n",
}


def remote(files: dict[str, str], repo: HttpsRepoUrl = GITHUB) -> tuple[ForgeFiles, Script]:
    if repo == GITHUB:
        answers = {
            "git/trees/": ok(json.dumps({"truncated": False, "paths": list(files)})),
            **{
                f"contents/{path}?ref={SHA}": ok(
                    json.dumps(
                        {
                            "type": "file",
                            "encoding": "base64",
                            "content": base64.b64encode(text.encode()).decode(),
                        }
                    )
                )
                for path, text in files.items()
            },
        }
    else:
        answers = {
            "repository/tree?": ok(json.dumps([{"type": "blob", "path": path} for path in files])),
            **{
                f"files/{quote(path, safe='')}/raw?ref={SHA}": ok(text)
                for path, text in files.items()
            },
        }
    provider, script = forge(answers)
    return ForgeFiles(provider, repo, SHA), script


@pytest.mark.parametrize("repo", [GITHUB, GITLAB])
@pytest.mark.parametrize(
    "cited,expected",
    [
        ("pkg/auth.go", ["pkg/auth.go"]),
        ("./pkg/auth.go", ["pkg/auth.go"]),
        ("src/pkg/auth.go", ["pkg/auth.go"]),
        ("app/pkg/auth.go", ["pkg/auth.go"]),
        ("operator/pkg/auth.go", ["pkg/auth.go"]),
        ("auth.go", ["pkg/auth.go"]),
        (
            "pkg/scope.go",
            ["components/a/pkg/scope.go", "components/b/pkg/scope.go"],
        ),
        ("deploy/jwt-args-patch.yaml", ["deploy/server-jwt-args-patch.yaml"]),
        ("src/empty.c", ["src/empty.c"]),
        ("vendor/third.c", ["vendor/third.c"]),
        ("third.c", []),
        ("generated.c", []),
        ("hidden.py", []),
        ("other/pkg/auth.go", []),
        ("missing.go", []),
    ],
)
def test_local_and_forge_views_agree_on_matching_and_line_counts(
    tmp_path: Path, repo: HttpsRepoUrl, cited: str, expected: list[str]
) -> None:
    root = tmp_path / "operator"
    for name, text in FILES.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    local, (forged, _) = WorkspaceFiles(root), remote(FILES, repo)
    local_paths, forge_paths = local.matches(cited), forged.matches(cited)
    assert sorted(path.relative_to(root).as_posix() for path in local_paths) == expected
    assert sorted(path.as_posix() for path in forge_paths) == expected
    assert all(not path.is_absolute() for path in forge_paths)
    assert sorted(local.line_count(path) for path in local_paths) == sorted(
        forged.line_count(path) for path in forge_paths
    )
    resolved = local.resolve(cited)
    assert forged.resolve(cited) == (resolved.relative_to(root) if resolved else None)


@pytest.mark.parametrize("repo", [GITHUB, GITLAB])
def test_forge_reads_are_lazy_cached_and_bound_to_the_native_repo_and_sha(
    repo: HttpsRepoUrl,
) -> None:
    files, script = remote(FILES, repo)
    assert script.calls == []
    path = files.resolve("pkg/auth.go")
    assert path == Path("pkg/auth.go")
    assert len(script.calls) == 1
    assert files.matches("auth.go") == [path]
    assert files.line_count(path) == 3
    assert files.line_count(path) == 3
    assert len(script.calls) == 2
    tree_call, file_call = script.calls
    assert str(SHA) in " ".join(tree_call)
    assert str(SHA) in " ".join(file_call)
    assert repo.host in tree_call and repo.host in file_call
    project = repo.path if repo == GITHUB else quote(repo.path, safe="")
    assert any(project in arg for arg in tree_call)
    assert any(project in arg for arg in file_call)


@pytest.mark.parametrize(
    "cited",
    [
        "",
        ".",
        "..",
        "../pkg/auth.go",
        "pkg/../auth.go",
        "./../pkg/auth.go",
        "/etc/passwd",
        "//other-host/share/auth.go",
        "C:/Windows/auth.go",
        "C:\\Windows\\auth.go",
        "https://other.example/repo/auth.go",
        "pkg//auth.go",
        "%2e%2e/pkg/auth.go",
        "pkg/auth.go\x00",
    ],
)
def test_malformed_citations_never_read_the_forge_or_local_files(cited: str) -> None:
    files, script = remote(FILES)
    assert files.resolve(cited) is None
    assert files.matches(cited) == []
    assert script.calls == []


@pytest.mark.parametrize("path", [Path("/etc/passwd"), Path("../secret"), Path("a/../secret")])
def test_line_counts_refuse_forged_absolute_and_traversal_references(path: Path) -> None:
    files, script = remote(FILES)
    with pytest.raises(ValidationError, match="relative repository"):
        files.line_count(path)
    assert script.calls == []


def test_a_reference_outside_the_recorded_tree_is_not_read(tmp_path: Path) -> None:
    secret = tmp_path / "secret.c"
    secret.write_text("server-only\n", encoding="utf-8")
    files, script = remote({})
    assert files.matches(secret.as_posix()) == []
    assert files.line_count(Path("secret.c")) is None
    assert len(script.calls) == 1


def test_a_listed_but_missing_file_is_distinct_from_an_unreadable_file() -> None:
    files, script = remote({"pkg/auth.go": "first\n"})
    script.answers.pop(f"contents/pkg/auth.go?ref={SHA}")
    assert files.line_count(Path("pkg/auth.go")) is None
    assert files.line_count(Path("pkg/auth.go")) is None
    assert len(script.calls) == 2
    assert files.matches("pkg/auth.go") == [Path("pkg/auth.go")]


@pytest.mark.parametrize(
    "answer,status",
    [
        ((1, "", "HTTP 401 Unauthorized"), "no-credentials"),
        ((1, "", "dial tcp: i/o timeout"), "unreachable"),
        ((1, "", "HTTP 500 Internal Server Error"), "error"),
        (ok("not json"), "error"),
    ],
)
@pytest.mark.parametrize("stage", ["tree", "file"])
def test_remote_read_failures_are_errors_not_missing_citations(
    answer: tuple[int, str, str], status: str, stage: str
) -> None:
    files, script = remote(FILES)
    endpoint = "git/trees/" if stage == "tree" else f"contents/pkg/auth.go?ref={SHA}"
    script.answers[endpoint] = answer
    with pytest.raises(SourceError) as error:
        files.line_count(Path("pkg/auth.go"))
    assert error.value.observation_status == status


def test_a_truncated_tree_cannot_claim_a_present_or_missing_citation() -> None:
    files, script = remote(FILES)
    script.answers["git/trees/"] = ok(json.dumps({"truncated": True, "paths": ["pkg/auth.go"]}))
    for cited in ("pkg/auth.go", "missing.go"):
        with pytest.raises(SourceError, match="truncated"):
            files.matches(cited)


@pytest.mark.parametrize("path", ["/etc/passwd", "../secret.c", "a/../secret.c", "C:/secret.c"])
def test_unsafe_forge_tree_paths_fail_without_reading_a_file(path: str) -> None:
    files, script = remote({path: "secret\n"})
    with pytest.raises(SourceError, match="unsafe file path"):
        files.matches("secret.c")
    assert len(script.calls) == 1


@pytest.mark.parametrize(
    "repo,sha",
    [
        (str(GITHUB), SHA),
        (GITHUB, str(SHA)),
        (GITHUB, GitSha("main")),
        (HttpsRepoUrl("github.com", "../operator"), SHA),
    ],
)
def test_forge_views_reject_untyped_or_unsafe_repository_bindings(
    repo: HttpsRepoUrl | str, sha: GitSha | str
) -> None:
    provider, script = forge({})
    with pytest.raises(ValidationError):
        ForgeFiles(provider, repo, sha)
    assert script.calls == []


def test_workspace_line_counts_keep_empty_unreadable_and_replacement_semantics(
    tmp_path: Path,
) -> None:
    empty, invalid = tmp_path / "empty.c", tmp_path / "invalid.c"
    empty.write_text("", encoding="utf-8")
    invalid.write_bytes(b"first\n\xff\nlast")
    files = WorkspaceFiles(tmp_path)
    assert files.line_count(empty) == 0
    assert files.line_count(invalid) == 3
    assert files.line_count(tmp_path / "missing.c") is None
    assert files.line_count(tmp_path) is None


def test_workspace_resolution_never_follows_a_symlink_outside_its_root(tmp_path: Path) -> None:
    root = tmp_path / "operator"
    root.mkdir()
    secret = tmp_path / "secret.c"
    secret.write_text("server-only\n", encoding="utf-8")
    (root / "link.c").symlink_to(secret)
    files = WorkspaceFiles(root)
    assert files.resolve("../secret.c") is None
    assert files.resolve("link.c") is None


@pytest.mark.parametrize("directory", sorted(WorkspaceFiles.SKIP_DIRS))
def test_both_views_skip_build_and_vendor_directories_only_for_suffix_matching(
    tmp_path: Path, directory: str
) -> None:
    name = f"nested/{directory}/library.c"
    path = tmp_path / name
    path.parent.mkdir(parents=True)
    path.write_text("first\n", encoding="utf-8")
    forged, _ = remote({name: "first\n"})
    local = WorkspaceFiles(tmp_path)
    assert local.matches("library.c") == forged.matches("library.c") == []
    assert local.resolve(name) == path
    assert forged.resolve(name) == Path(name)


def test_unrelated_filenames_outside_the_file_read_contract_do_not_hide_valid_citations() -> None:
    files, _ = remote({"docs/Release Notes.md": "notes\n", "pkg/auth.go": "first\n"})
    assert files.matches("auth.go") == [Path("pkg/auth.go")]
    assert files.line_count(Path("pkg/auth.go")) == 1
