"""ArchiveCheckout: a commit's kept files from the forge's archive stream, safely, within a cap."""

from __future__ import annotations

import gzip
import io
import json
import shutil
import subprocess
import tarfile
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

import pydantic
import pytest

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.values import GitSha
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.forge_archive import ArchiveCheckout
from traust_core.v1.providers.sources import CheckoutRequest
from traust_core.v1.providers.syft import MANIFESTS

SHA = "a" * 40
REF = GitSha.parse(SHA)
KEEP_MANIFESTS = CheckoutRequest(repo="https://github.com/o/r", ref=REF, keep=MANIFESTS)  # type: ignore[arg-type]
HOSTS = {"github.com": "github", "ghe.example": "github", "gitlab.example": "gitlab"}
GO_MOD = b"module example.com/svc\n\ngo 1.22\n\nrequire google.golang.org/grpc v1.56.2\n"
PACKAGE_LOCK = json.dumps(
    {
        "name": "web",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "web", "dependencies": {"lodash": "4.17.20"}},
            "node_modules/lodash": {"version": "4.17.20"},
        },
    }
).encode()


def tarball(files: Mapping[str, bytes], links: Mapping[str, str] = {}) -> bytes:
    """A forge-style archive: everything under one top directory."""
    out = io.BytesIO()
    with (
        gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as gz,
        tarfile.open(fileobj=gz, mode="w") as tar,
    ):
        for name, data in files.items():
            info = tarfile.TarInfo(
                name if name.startswith(("/", "..")) else f"repo-{SHA[:7]}/{name}"
            )
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for name, target in links.items():
            info = tarfile.TarInfo(f"repo-{SHA[:7]}/{name}")
            info.type, info.linkname = tarfile.SYMTYPE, target
            tar.addfile(info)
    return out.getvalue()


class Fetcher:
    """HttpFetcher.stream over fixed bytes; `attempts` > 1 replays the stream like a retry."""

    def __init__(self, body: bytes, attempts: int = 1) -> None:
        self.body, self.attempts = body, attempts
        self.asked: list[tuple[str, Mapping[str, str]]] = []

    def stream(
        self, url: str, consume: Callable[[BinaryIO], Any], headers: Mapping[str, str] | None = None
    ) -> Any:
        self.asked.append((url, dict(headers or {})))
        for _ in range(self.attempts):
            got = consume(io.BytesIO(self.body))
        return got


def checkout(body: bytes, tokens: Mapping[str, str] = {}, cap: int = 1 << 20, attempts: int = 1):
    fetcher = Fetcher(body, attempts)
    clock = FixedClock(datetime(2026, 10, 28, tzinfo=UTC))
    return fetcher, ArchiveCheckout(fetcher, clock, HOSTS, tokens, cap)  # type: ignore[arg-type]


def files(root: Path) -> set[str]:
    return {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()}


def test_only_the_kept_files_land_and_release_removes_them() -> None:
    body = tarball(
        {
            "go.mod": GO_MOD,
            "web/package-lock.json": PACKAGE_LOCK,
            ".github/workflows/ci.yml": b"on: push\n",
            "docs/ci.yml": b"not a workflow\n",
            "main.go": b"package main\n",
            "assets/logo.png": b"\x89PNG",
        }
    )
    _, archive = checkout(body)
    workspace = archive.checkout(
        CheckoutRequest(repo="https://github.com/o/r", ref=REF, keep=MANIFESTS)
    ).data
    assert workspace.sha == REF
    assert files(workspace.path) == {"go.mod", "web/package-lock.json", ".github/workflows/ci.yml"}
    archive.release(workspace)
    assert not workspace.path.exists()


def test_keep_none_is_the_whole_tree_and_links_never_land() -> None:
    body = tarball({"a.txt": b"a", "pkg/b.go": b"b"}, links={"escape": "/etc/passwd"})
    _, archive = checkout(body)
    workspace = archive.checkout(CheckoutRequest(repo="https://github.com/o/r", ref=REF)).data
    assert files(workspace.path) == {"a.txt", "pkg/b.go"}
    archive.release(workspace)


@pytest.mark.parametrize(
    ("repo", "tokens", "url", "headers"),
    [
        ("https://github.com/o/r", {}, f"https://api.github.com/repos/o/r/tarball/{SHA}", {}),
        (
            "https://github.com/o/r",
            {"github.com": "t1"},
            f"https://api.github.com/repos/o/r/tarball/{SHA}",
            {"Authorization": "Bearer t1"},
        ),
        ("https://ghe.example/o/r", {}, f"https://ghe.example/api/v3/repos/o/r/tarball/{SHA}", {}),
        (
            "https://gitlab.example/group/sub/r",
            {"gitlab.example": "t2"},
            f"https://gitlab.example/api/v4/projects/group%2Fsub%2Fr/repository/archive.tar.gz?sha={SHA}",
            {"PRIVATE-TOKEN": "t2"},
        ),
    ],
)
def test_each_forge_is_asked_for_its_archive_with_its_token_in_a_header(
    repo: str, tokens: dict[str, str], url: str, headers: dict[str, str]
) -> None:
    fetcher, archive = checkout(tarball({"go.mod": GO_MOD}), tokens)
    result = archive.checkout(CheckoutRequest(repo=repo, ref=REF, keep=MANIFESTS))
    archive.release(result.data)
    assert fetcher.asked == [(url, headers)]
    assert result.acquisition.source == url
    assert all(token not in result.acquisition.model_dump_json() for token in tokens.values())


@pytest.mark.parametrize(
    ("repo", "match"),
    [("https://unknown.example/o/r", "not a known forge")],
)
def test_bad_requests_are_refused_before_any_fetch(repo: str, match: str) -> None:
    fetcher, archive = checkout(tarball({"go.mod": GO_MOD}))
    with pytest.raises(ValidationError, match=match):
        archive.checkout(CheckoutRequest(repo=repo, ref=REF))
    assert fetcher.asked == []


def test_a_request_without_a_commit_is_refused_before_any_fetch() -> None:
    fetcher, _ = checkout(tarball({"go.mod": GO_MOD}))
    with pytest.raises(pydantic.ValidationError, match="ref"):
        CheckoutRequest(repo="https://github.com/o/r")  # type: ignore[call-arg]
    assert fetcher.asked == []


def leftovers() -> set[str]:
    import tempfile

    return {p.name for p in Path(tempfile.gettempdir()).glob("checkout-*")}


@pytest.mark.parametrize(
    ("body", "error", "match"),
    [
        (tarball({"/etc/cron.d/x": b"x"}), ValidationError, "unsafe archive member"),
        (tarball({"../outside/go.mod": GO_MOD}), ValidationError, "unsafe archive member"),
        (tarball({"go.mod": GO_MOD * 64}), ServiceError, "workspace cap"),
    ],
    ids=["absolute", "parent", "over-cap"],
)
def test_an_unsafe_or_oversized_archive_fails_and_leaves_nothing(
    body: bytes, error: type[Exception], match: str
) -> None:
    before = leftovers()
    _, archive = checkout(body, cap=len(GO_MOD) * 8)
    with pytest.raises(error, match=match):
        archive.checkout(KEEP_MANIFESTS)
    assert leftovers() == before


def test_a_retried_stream_starts_from_a_clean_workspace() -> None:
    _, archive = checkout(tarball({"go.mod": GO_MOD, "a/go.mod": GO_MOD}), attempts=2)
    workspace = archive.checkout(CheckoutRequest(repo="https://github.com/o/r", ref=REF)).data
    assert files(workspace.path) == {"go.mod", "a/go.mod"}
    archive.release(workspace)


@pytest.mark.skipif(shutil.which("syft") is None, reason="syft not on PATH")
def test_syft_reads_the_same_packages_from_the_kept_manifests(tmp_path: Path) -> None:
    body = tarball(
        {
            "go.mod": GO_MOD,
            "web/package-lock.json": PACKAGE_LOCK,
            "web/src/index.js": b"console.log(1)\n",
            "svc/requirements.txt": b"django==4.2.0\n",
            "svc/app.py": b"print(1)\n",
            "README.md": b"# r\n",
        }
    )
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tar:
        tar.extractall(tmp_path / "full", filter="data")
    _, archive = checkout(body)
    kept = archive.checkout(
        CheckoutRequest(repo="https://github.com/o/r", ref=REF, keep=MANIFESTS)
    ).data

    def purls(root: Path) -> set[str]:
        out = subprocess.run(
            ["syft", "-q", f"dir:{root}", "-o", "cyclonedx-json"], capture_output=True, check=True
        )
        return {c["purl"] for c in json.loads(out.stdout)["components"] if c.get("purl")}

    try:
        assert purls(kept.path) == purls(tmp_path / "full") != set()
    finally:
        archive.release(kept)
