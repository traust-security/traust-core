"""Allow-listed fetches of fix patches and package source, safe extraction, and reading the
extracted tree. Ported from traust-engine main's tests/test_applicability.py."""

from __future__ import annotations

import io
import tarfile
import zipfile
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from traust_core.v1.errors import ServiceError
from traust_core.v1.models.below_range import FileChange, Hunk, HunkPresence
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.package_source import (
    FetchRefused,
    PackageSources,
    SourceHosts,
    anchor,
    archive_url,
    extract,
    go_requires,
    importers,
    nuget_version,
    presence,
    root_of,
)

FORGES = frozenset({"github.com", "gitlab.com"})
REGISTRIES = frozenset(
    {
        "proxy.golang.org",
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "repo1.maven.org",
        "static.crates.io",
        "rubygems.org",
        "api.nuget.org",
        "github.com",
    }
)
REDIRECTS = {
    "github.com": frozenset({"patch-diff.githubusercontent.com", "codeload.github.com"}),
    "proxy.golang.org": frozenset({"storage.googleapis.com"}),
}
HOSTS = SourceHosts(FORGES, REGISTRIES, REDIRECTS, ("github-patches", "go-module-proxy"))


class FakeHttp:
    """Serves `pages` (url -> body, or (body, final url)); anything else is a 404."""

    def __init__(
        self, pages: Mapping[str, bytes | tuple[bytes, str]] | Callable[[str], tuple[bytes, str]]
    ) -> None:
        self.pages = pages
        self.calls: list[str] = []

    def fetch(self, url: str, limit: int) -> tuple[bytes, str]:
        self.calls.append(url)
        if callable(self.pages):
            return self.pages(url)
        if url not in self.pages:
            raise ServiceError(f"{url}: HTTP 404", status=404)
        page = self.pages[url]
        return page if isinstance(page, tuple) else (page, url)


def sources(pages: object = (), hosts: SourceHosts = HOSTS) -> PackageSources:
    http = pages if isinstance(pages, FakeHttp) else FakeHttp(dict(pages))  # type: ignore[arg-type]
    return PackageSources(hosts, http=http)  # type: ignore[arg-type]


def tarball(files: Mapping[str, bytes], mode: str = "w:gz") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:  # type: ignore[call-overload]
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def gem(files: Mapping[str, bytes]) -> bytes:
    return tarball({"metadata.gz": b"x", "data.tar.gz": tarball(files)}, mode="w")


def test_hosts_off_the_list_plain_http_and_redirects_off_the_list_are_refused(
    tmp_path: Path,
) -> None:
    with pytest.raises(FetchRefused):
        sources().patch("https://evil.example/o/r/commit/abc.patch")
    with pytest.raises(FetchRefused):
        sources().patch("http://github.com/o/r/commit/abc.patch")
    bounced = FakeHttp(lambda u: (b"x", "https://evil.example/x"))
    with pytest.raises(FetchRefused, match="redirected off the allow-list"):
        sources(bounced).patch("https://github.com/o/r/commit/abc.patch")
    proxied = FakeHttp(lambda u: (_module_zip(), "https://storage.googleapis.com/blob"))
    assert sources(proxied).source(Ecosystem.GO, "example.com/lib", "1.4.0", tmp_path).files == 2


def test_redirects_are_whatever_the_hosts_allow(tmp_path: Path) -> None:
    mirror = FakeHttp(lambda u: (b"x", "https://mirror.example/blob"))
    allowed = SourceHosts(FORGES, REGISTRIES, {"github.com": frozenset({"mirror.example"})})
    assert sources(mirror, allowed).patch("https://github.com/o/r/pull/1.patch") == "x"
    with pytest.raises(FetchRefused):
        sources(mirror).patch("https://github.com/o/r/pull/1.patch")


def test_a_body_over_the_cap_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("traust_core.v1.providers.package_source.MAX_BYTES", 3)
    with pytest.raises(FetchRefused, match="size cap"):
        sources({"https://github.com/o/r/pull/1.patch": b"four"}).patch(
            "https://github.com/o/r/pull/1.patch"
        )


def test_readiness_needs_both_roles() -> None:
    assert sources().check().ready
    assert "github-patches" in sources().check().detail
    assert not sources(hosts=SourceHosts(FORGES, frozenset())).check().ready


def test_extract_skips_escapes_and_links(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in (("pkg-1.0/ok.py", b"ok"), ("../escape.py", b"bad"), ("/abs.py", b"bad")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("pkg-1.0/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)
    assert extract(buf.getvalue(), "tar", tmp_path / "out") == 1
    assert (tmp_path / "out" / "pkg-1.0" / "ok.py").read_text() == "ok"
    assert not (tmp_path / "escape.py").exists()


def test_a_zip_skips_symlinks_and_escapes(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("m@v1/ok.go", "package m")
        z.writestr("../escape.go", "bad")
        link = zipfile.ZipInfo("m@v1/link")
        link.external_attr = 0o120777 << 16
        z.writestr(link, "/etc/passwd")
    assert extract(buf.getvalue(), "zip", tmp_path / "out") == 1


def test_an_unreadable_archive_is_refused(tmp_path: Path) -> None:
    with pytest.raises(FetchRefused, match="unreadable zip"):
        extract(b"not a zip", "zip", tmp_path)
    with pytest.raises(FetchRefused, match=r"no data\.tar\.gz"):
        extract(tarball({"metadata.gz": b"x"}, mode="w"), "gem", tmp_path)


def test_a_gem_extracts_its_data_archive(tmp_path: Path) -> None:
    blob = gem({"lib/rack/utils.rb": b"module Rack; end\n", "../escape.rb": b"x"})
    assert extract(blob, "gem", tmp_path) == 1
    assert (tmp_path / "lib/rack/utils.rb").is_file()


@pytest.mark.parametrize(
    ("ecosystem", "name", "version", "url"),
    [
        (
            Ecosystem.NPM,
            "@scope/pkg",
            "1.2.3",
            "https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz",
        ),
        (
            Ecosystem.CARGO,
            "tokio",
            "1.38.0",
            "https://static.crates.io/crates/tokio/tokio-1.38.0.crate",
        ),
        (
            Ecosystem.MAVEN,
            "com.fasterxml.jackson.core:jackson-databind",
            "2.13.4",
            "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.13.4/"
            "jackson-databind-2.13.4-sources.jar",
        ),
        (Ecosystem.RUBY, "rack", "2.2.8", "https://rubygems.org/downloads/rack-2.2.8.gem"),
        (
            Ecosystem.GO,
            "github.com/Foo/bar",
            "v1.0.0",
            "https://proxy.golang.org/github.com/!foo/bar/@v/v1.0.0.zip",
        ),
    ],
)
def test_registry_urls(
    ecosystem: Ecosystem, name: str, version: str, url: str, tmp_path: Path
) -> None:
    http = FakeHttp(lambda u: (b"", u))
    with pytest.raises(FetchRefused):  # the empty body isn't an archive: only the URL matters
        sources(http).source(ecosystem, name, version, tmp_path)
    assert http.calls == [url]


def test_maven_needs_a_group_and_unsupported_ecosystems_are_refused(tmp_path: Path) -> None:
    with pytest.raises(FetchRefused, match="group:artifact"):
        sources().source(Ecosystem.MAVEN, "no-group", "1.0", tmp_path)
    with pytest.raises(FetchRefused, match="no package source"):
        sources().source(Ecosystem.ACTIONS, "actions/checkout", "4.0.0", tmp_path)


def test_pypi_takes_the_sdist_else_the_wheel(tmp_path: Path) -> None:
    sdist = b'{"urls":[{"packagetype":"bdist_wheel","filename":"p.whl","url":"https://files.pythonhosted.org/p.whl"},{"packagetype":"sdist","filename":"p-1.0.tar.gz","url":"https://files.pythonhosted.org/p.tgz"}]}'
    got = sources(
        {
            "https://pypi.org/pypi/p/1.0/json": sdist,
            "https://files.pythonhosted.org/p.tgz": tarball(
                {"p-1.0/p/__init__.py": b"", "p-1.0/setup.py": b""}
            ),
        }
    ).source(Ecosystem.PYPI, "p", "1.0", tmp_path / "s")
    assert (got.url, got.files, got.tree.name) == (
        "https://files.pythonhosted.org/p.tgz",
        2,
        "p-1.0",
    )
    with pytest.raises(FetchRefused, match="no sdist or wheel"):
        sources({"https://pypi.org/pypi/p/1.0/json": b'{"urls":[]}'}).source(
            Ecosystem.PYPI, "p", "1.0", tmp_path / "t"
        )


def _module_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("example.com/lib@v1.4.0/go.mod", "module example.com/lib\n")
        z.writestr("example.com/lib@v1.4.0/parse.go", "package lib\n")
    return buf.getvalue()


def test_release_times_come_from_the_registries() -> None:
    pages = {
        "https://proxy.golang.org/example.com/lib/@v/v1.4.0.info": (
            b'{"Version":"v1.4.0","Time":"2024-02-01T00:12:23Z"}'
        ),
        "https://pypi.org/pypi/pkg/1.0/json": (
            b'{"urls":[{"upload_time_iso_8601":"2023-11-01T06:59:10Z"}]}'
        ),
        "https://registry.npmjs.org/lib": b'{"time":{"1.2.3":"2022-01-02T03:04:05.000Z"}}',
    }
    s = sources(pages)
    assert s.release_time(Ecosystem.GO, "example.com/lib", "1.4.0") == "2024-02-01T00:12:23Z"
    assert s.release_time(Ecosystem.PYPI, "pkg", "1.0") == "2023-11-01T06:59:10Z"
    assert s.release_time(Ecosystem.NPM, "lib", "1.2.3") == "2022-01-02T03:04:05.000Z"
    assert s.release_time(Ecosystem.NPM, "lib", "9.9.9") is None
    assert s.release_time(Ecosystem.MAVEN, "g:a", "1.0") is None
    assert s.release_time(Ecosystem.PYPI, "absent", "1.0") is None  # didn't answer: no date


def test_rubygems_release_time_skips_platform_builds() -> None:
    rows = (
        b'[{"number":"2.2.8","platform":"java","created_at":"2023-01-01T00:00:00Z"},'
        b'{"number":"2.2.8","platform":"ruby","created_at":"2023-07-31T01:02:03Z"}]'
    )
    s = sources({"https://rubygems.org/api/v1/versions/rack.json": rows})
    assert s.release_time(Ecosystem.RUBY, "rack", "2.2.8") == "2023-07-31T01:02:03Z"
    assert s.release_time(Ecosystem.NUGET, "Newtonsoft.Json", "13.0.1") is None


def test_nuget_versions_normalize_as_the_flat_container_names_them() -> None:
    assert nuget_version("1.23.0") == "1.23.0"
    assert nuget_version("1.0.0.0") == "1.0.0"
    assert nuget_version("1.01.2+build.5") == "1.1.2"
    assert nuget_version("2.0.0-Preview.1") == "2.0.0-preview.1"


def test_archive_urls_for_declared_repositories() -> None:
    c = "e" * 40
    assert archive_url("https://github.com/microsoft/kiota", c) == (
        f"https://github.com/microsoft/kiota/archive/{c}.tar.gz"
    )
    assert archive_url("https://github.com/dotnet/runtime.git", c) == (
        f"https://github.com/dotnet/runtime/archive/{c}.tar.gz"
    )
    assert archive_url("https://gitlab.com/grp/sub/proj", c) == (
        f"https://gitlab.com/grp/sub/proj/-/archive/{c}/proj-{c}.tar.gz"
    )
    for bad in (
        "https://dev.azure.com/org/proj",
        "https://github.com/a/../b",
        "https://github.com/a",
    ):
        with pytest.raises(FetchRefused):
            archive_url(bad, c)
    with pytest.raises(FetchRefused):
        archive_url("https://github.com/a/b", "not-a-commit")


NUSPEC = (
    '<?xml version="1.0"?><package><metadata><id>Microsoft.OpenApi.Kiota.Builder</id>'
    "<version>1.23.0</version>"
    '<repository type="git" url="https://github.com/microsoft/kiota" commit="' + "e" * 40 + '" />'
    "</metadata></package>"
)
NUSPEC_URL = (
    "https://api.nuget.org/v3-flatcontainer/microsoft.openapi.kiota.builder/1.23.0/"
    "microsoft.openapi.kiota.builder.nuspec"
)


def test_nuget_source_is_the_archive_at_the_declared_commit(tmp_path: Path) -> None:
    archive = "https://github.com/microsoft/kiota/archive/" + "e" * 40 + ".tar.gz"
    final = "https://codeload.github.com/microsoft/kiota/tar.gz/" + "e" * 40
    http = FakeHttp(
        {
            NUSPEC_URL: NUSPEC.encode(),
            archive: (tarball({"kiota-" + "e" * 40 + "/src/A.cs": b"class A {}\n"}), final),
        }
    )
    s = sources(http)
    assert (
        s.nuget_id("microsoft.openapi.kiota.builder", "1.23.0") == "Microsoft.OpenApi.Kiota.Builder"
    )
    src = s.source(Ecosystem.NUGET, "Microsoft.OpenApi.Kiota.Builder", "1.23.0", tmp_path / "s")
    assert (src.files, src.url) == (1, archive)
    assert src.declared_by is not None
    assert src.declared_by.model_dump() == {
        "nuspec": NUSPEC_URL,
        "repository": "https://github.com/microsoft/kiota",
        "commit": "e" * 40,
    }
    assert http.calls.count(NUSPEC_URL) == 1  # fetched once, reused


def test_a_nuspec_without_a_commit_or_with_another_id_is_refused() -> None:
    no_commit = NUSPEC.replace(' commit="' + "e" * 40 + '"', "")
    with pytest.raises(FetchRefused, match="no source repository"):
        sources({NUSPEC_URL: no_commit.encode()}).nuget_declared(
            "Microsoft.OpenApi.Kiota.Builder", "1.23.0"
        )
    other = NUSPEC.replace("<id>Microsoft.OpenApi.Kiota.Builder</id>", "<id>Other</id>")
    with pytest.raises(FetchRefused, match="does not match"):
        sources({NUSPEC_URL: other.encode()}).nuget_id("microsoft.openapi.kiota.builder", "1.23.0")


REGISTRATION = "https://api.nuget.org/v3/registration5-semver1/newtonsoft.json/index.json"


def test_nuget_published_casing_comes_from_the_registration_index() -> None:
    inline = b'{"items":[{"items":[{"catalogEntry":{"id":"Newtonsoft.Json"}}]}]}'
    assert sources({REGISTRATION: inline}).nuget_published("newtonsoft.json") == "Newtonsoft.Json"
    page = "https://api.nuget.org/v3/registration5-semver1/newtonsoft.json/page/1.json"
    linked = {
        REGISTRATION: ('{"items":[{"@id":"' + page + '"}]}').encode(),
        page: b'{"items":[{"catalogEntry":{"id":"Newtonsoft.Json"}}]}',
    }
    assert sources(linked).nuget_published("newtonsoft.json") == "Newtonsoft.Json"
    assert sources().nuget_published("newtonsoft.json") is None  # unknown to nuget.org
    assert sources({REGISTRATION: b'{"items":[]}'}).nuget_published("newtonsoft.json") is None


def test_nuget_published_refuses_pages_off_nuget_org_and_raises_when_unreachable() -> None:
    off = {REGISTRATION: b'{"items":[{"@id":"https://evil.example/page.json"}]}'}
    with pytest.raises(FetchRefused, match=r"off nuget\.org"):
        sources(off).nuget_published("newtonsoft.json")

    def down(url: str) -> tuple[bytes, str]:
        raise ServiceError(f"{url}: gave up after 4 attempts")

    with pytest.raises(ServiceError):
        sources(FakeHttp(down)).nuget_published("newtonsoft.json")


def test_root_of_descends_single_directories(tmp_path: Path) -> None:
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "b" / "x.go").write_text("x")
    assert root_of(tmp_path) == tmp_path / "a" / "b"


def test_anchor_strips_a_consistent_prefix_and_never_matches_by_base_name(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "parse.go").write_text("x")
    (tmp_path / "lib" / "web" / "cache").mkdir(parents=True)
    (tmp_path / "lib" / "web" / "cache" / "cache.js").write_text("unrelated")
    files = [FileChange(path="sub/pkg/parse.go"), FileChange(path="lib/util/cache.js")]
    assert set(anchor(files, tmp_path)) == {"sub/pkg/parse.go"}


def test_maven_sources_anchor_below_the_module_source_root(tmp_path: Path) -> None:
    (tmp_path / "com" / "ex").mkdir(parents=True)
    (tmp_path / "com" / "ex" / "Parser.java").write_text("x")
    files = [FileChange(path="core/src/main/java/com/ex/Parser.java")]
    assert set(anchor(files, tmp_path)) == {"core/src/main/java/com/ex/Parser.java"}


def test_presence_counts_removed_and_added_lines(tmp_path: Path) -> None:
    (tmp_path / "parse.go").write_text("func f() {\n\treturn parse(s)\n}\n")
    rows = presence(
        [
            FileChange(
                path="parse.go",
                hunks=(
                    Hunk(removed=("\treturn parse(s)", "   "), added=("\treturn parseBounded(s)",)),
                ),
            ),
            FileChange(path="absent.go", hunks=(Hunk(removed=("x",)),)),
        ],
        tmp_path,
    )
    assert rows[0].installed_path == "parse.go"
    assert rows[0].hunks == (
        HunkPresence(removed_lines=1, removed_present=1, added_lines=1, added_present=0),
    )
    assert (rows[1].installed_path, rows[1].hunks) == (None, ())


def test_go_requires_are_read_from_go_mod(tmp_path: Path) -> None:
    assert go_requires(tmp_path) == []
    (tmp_path / "go.mod").write_text(
        "module example.com/lib\n\nrequire example.com/one v1.2.0\n\n"
        "require (\n\texample.com/two v0.3.1 // indirect\n)\n"
    )
    assert sorted(go_requires(tmp_path)) == [
        ("example.com/one", "1.2.0"),
        ("example.com/two", "0.3.1"),
    ]


@pytest.mark.parametrize(
    ("eco", "dep", "text", "expect"),
    [
        (Ecosystem.NPM, "busboy", "var Busboy = require('busboy')", True),
        (Ecosystem.NPM, "busboy", "import Busboy from 'busboy/lib/x'", True),
        (Ecosystem.NPM, "busboy", "var b = require('busboyish')", False),
        (Ecosystem.PYPI, "Python-Jose", "from python_jose import jwt", True),
        (
            Ecosystem.MAVEN,
            "org.bouncycastle:bcutil-jdk18on",
            "import org.bouncycastle.util.Arrays;",
            True,
        ),
        (Ecosystem.CARGO, "rustls-pki-types", "use rustls_pki_types::CertificateDer;", True),
        (Ecosystem.GO, "golang.org/x/net", 'import "golang.org/x/net/http2"', True),
        (Ecosystem.RUBY, "rack", "require 'rack'", False),
    ],
)
def test_importers(eco: Ecosystem, dep: str, text: str, expect: bool, tmp_path: Path) -> None:
    (tmp_path / "src.txt").write_text(text)
    assert importers(eco, dep, [tmp_path / "src.txt"], tmp_path) == (["src.txt"] if expect else [])


def test_an_unparseable_registry_answer_is_refused(tmp_path: Path) -> None:
    with pytest.raises(FetchRefused, match="unparseable JSON"):
        sources({REGISTRATION: b"<html>"}).nuget_published("newtonsoft.json")
    with pytest.raises(FetchRefused, match="expected a JSON object"):
        sources({"https://pypi.org/pypi/p/1.0/json": b"[]"}).source(
            Ecosystem.PYPI, "p", "1.0", tmp_path
        )
