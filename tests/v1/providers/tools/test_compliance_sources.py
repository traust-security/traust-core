from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError, NotFoundError, ServiceError, ValidationError
from traust_core.v1.models.common import ArtifactRef
from traust_core.v1.models.compliance import doc_text, parse_adr
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.http import HttpFetcher
from traust_core.v1.providers.process import ProcessResult, ProcessRunner
from traust_core.v1.providers.tools.compliance_sources import (
    DocsTarget,
    GithubAdrSource,
    RedHatDocSource,
    github_slug,
)

WHEN = datetime(2026, 10, 24, 9, tzinfo=UTC)
PIN = "a" * 40
REPO = "https://github.com/o/r"
DOCS = "https://docs.redhat.com/en/documentation/p/1"
HTML = """<html><head><script>junk()</script><style>x{}</style></head>
<body><nav>menu</nav>
<h1 id="top">Managing clusters</h1><p>Intro &amp; text.</p>
<h2 id="sec-2fa">Two-factor authentication</h2>
<p>For greater security, use 2FA.</p>
<h2>Untitled anchorless</h2><p>tail</p>
<footer>foot</footer></body></html>"""


class Runner(ProcessRunner):
    """Answers each argv with `answer(argv)`: bytes for stdout, or an exception to raise."""

    def __init__(self, answer: Callable[[list[str]], bytes | BaseException]) -> None:
        super().__init__(())
        self.answer = answer
        self.calls: list[list[str]] = []

    def run(self, argv: Sequence[str], **_: Any) -> ProcessResult:
        self.calls.append(list(argv))
        out = self.answer(list(argv))
        if isinstance(out, BaseException):
            raise out
        return ProcessResult(tuple(argv), 0, out, b"", 0.0)


class Raw(HttpFetcher):
    def __init__(self, files: dict[str, bytes | BaseException]) -> None:
        super().__init__("test")
        self.files = files
        self.urls: list[str] = []

    def get(self, url: str) -> bytes:
        self.urls.append(url)
        out = self.files[url]
        if isinstance(out, BaseException):
            raise out
        return out


def tree(*paths: str, truncated: bool = False) -> bytes:
    entries = [{"path": p, "type": "tree" if p.endswith("/") else "blob"} for p in paths]
    return json.dumps({"tree": entries, "truncated": truncated}).encode()


def raw(path: str) -> str:
    return f"https://raw.githubusercontent.com/o/r/{PIN}/{path}"


def adr_source(listing: bytes | BaseException, files: dict[str, bytes | BaseException]):
    gh = Runner(lambda argv: listing)
    http = Raw(files)
    return GithubAdrSource(gh, http, FixedClock(WHEN)), gh, http


# --- ADR registers ----------------------------------------------------------------------------


def test_only_decision_records_under_the_register_paths_are_read_at_the_pin() -> None:
    listing = tree(
        "docs/adr/",
        "docs/adr/ADR-021-opa.md",
        "docs/adr/archives/SD-ADR-0040.adoc",
        "docs/adr/template.md",
        "docs/adr/README.md",
        "docs/adr/diagram.png",
        "docs/other/ADR-1.md",
    )
    files = {
        raw("docs/adr/ADR-021-opa.md"): b"# Use OPA\n\n## Status\n\nAccepted\n",
        raw("docs/adr/archives/SD-ADR-0040.adoc"): b"# Old\nStatus: accepted\n",
    }
    source, gh, http = adr_source(listing, files)
    got = source.files(REPO, PIN, ["docs/adr"])
    assert gh.calls == [["gh", "api", f"repos/o/r/git/trees/{PIN}?recursive=1"]]
    assert [f.path for f in got.data] == [
        "docs/adr/ADR-021-opa.md",
        "docs/adr/archives/SD-ADR-0040.adoc",
    ]
    assert http.urls == list(files)
    assert got.data[0].url == f"https://github.com/o/r/blob/{PIN}/docs/adr/ADR-021-opa.md"
    assert (got.acquisition.provider, got.acquisition.version, got.acquisition.source) == (
        "github-adr",
        PIN,
        REPO,
    )
    register = {"name": "arch", "paths": ["docs/adr"]}
    ref = ArtifactRef(id=uuid4(), name="adr-registry", digest="0" * 64)
    statuses = [parse_adr(register, f.path, f.text, f.url, ref).status for f in got.data]
    assert statuses == ["accepted", "archived"]


def test_a_register_file_is_read_up_to_the_legacy_cap() -> None:
    files = {raw("d/x.md"): b"# t\n" + b"a" * 300_000}
    source, _, _ = adr_source(tree("d/x.md"), files)
    assert len(source.files(REPO, PIN, ["d"]).data[0].text) == 262_144


def test_paths_are_quoted_into_the_raw_url() -> None:
    source, _, http = adr_source(tree("d/a b.md"), {raw("d/a%20b.md"): b"# t\n"})
    assert source.files(REPO, PIN, ["d"]).data[0].path == "d/a b.md"
    assert http.urls == [raw("d/a%20b.md")]


@pytest.mark.parametrize(
    ("repo", "pin", "listing", "files", "error", "match"),
    [
        ("https://gitlab.com/o/r", PIN, tree(), {}, ValidationError, "not a GitHub repository"),
        (REPO, "main", tree(), {}, ValidationError, "not a 40-hex commit"),
        (REPO, PIN[:12], tree(), {}, ValidationError, "not a 40-hex commit"),
        (REPO, PIN, ServiceError("gh exited 1"), {}, ServiceError, "tree unreadable"),
        (REPO, PIN, b"not json", {}, ServiceError, "tree unreadable"),
        (REPO, PIN, tree("d/x.md", truncated=True), {}, ServiceError, "truncated"),
        # legacy recorded `unknown` for an unreadable body; core#119 fails closed instead
        (
            REPO,
            PIN,
            tree("d/x.md"),
            {raw("d/x.md"): ServiceError("HTTP 404")},
            ServiceError,
            "d/x.md unreadable",
        ),
    ],
)
def test_an_unreadable_register_raises(
    repo: str,
    pin: str,
    listing: bytes | BaseException,
    files: dict[str, bytes | BaseException],
    error: type[Exception],
    match: str,
) -> None:
    source, _, _ = adr_source(listing, files)
    with pytest.raises(error, match=match):
        source.files(repo, pin, ["d"])


@pytest.mark.parametrize(
    ("url", "slug"),
    [
        ("https://github.com/o/r", "o/r"),
        ("https://github.com/o/r.git", "o/r"),
        ("git@github.com:o/r.git", "o/r"),
        ("https://github.com/o/r/tree/main/docs", "o/r"),
    ],
)
def test_github_slug(url: str, slug: str) -> None:
    assert github_slug(url) == slug


# --- official docs ----------------------------------------------------------------------------


ALL_GUIDES = DocsTarget("p", "1")


def docs_source(answer: Callable[[str], bytes | BaseException], target: DocsTarget = ALL_GUIDES):
    curl = Runner(lambda argv: answer(argv[-1]))
    product = uuid4()
    return RedHatDocSource(curl, FixedClock(WHEN), {product: target}), curl, product


LANDING = (
    b'<a href="/en/documentation/p/1/html/guide_b">b</a>'
    b'<a href="/en/documentation/p/1/html/guide_a">a</a>'
    b'<a href="/en/documentation/p/1/html/guide_a">again</a>'
    b'<a href="/en/documentation/q/1/html/other">other product</a>'
)


def test_every_listed_guide_is_fetched_single_page_with_stock_curl() -> None:
    source, curl, product = docs_source(lambda url: LANDING if url == DOCS else HTML.encode())
    got = source.fetch(product)
    assert curl.calls[0] == [
        "curl",
        "-sSL",
        "--fail",
        "--proto",
        "=https",
        "--max-time",
        "60",
        DOCS,
    ]
    assert [d.url for d in got.data] == [
        f"{DOCS}/html-single/guide_a/index",
        f"{DOCS}/html-single/guide_b/index",
    ]
    assert {(d.product_slug, d.version) for d in got.data} == {("p", "1")}
    assert (got.acquisition.provider, got.acquisition.source) == ("docs.redhat.com", DOCS)
    text = doc_text(got.data[0].html, got.data[0].url)
    anchor = f"{DOCS}/html-single/guide_a/index"
    assert f"## Two-factor authentication [{anchor}#sec-2fa]" in text
    assert "junk()" not in text and "menu" not in text


def test_named_guides_skip_the_landing_page() -> None:
    source, curl, product = docs_source(lambda url: HTML.encode(), DocsTarget("p", "1", ("g",)))
    assert [d.guide for d in source.fetch(product).data] == ["g"]
    assert [c[-1] for c in curl.calls] == [f"{DOCS}/html-single/g/index"]


@pytest.mark.parametrize(
    ("answer", "target", "match"),
    [
        (lambda url: b"<html>nothing</html>", DocsTarget("p", "1"), "no guides found"),
        (lambda url: ServiceError("curl exited 22"), DocsTarget("p", "1"), "fetch failed"),
        (
            lambda url: ServiceError("403") if url.endswith("/g2/index") else b"",
            DocsTarget("p", "1", ("g1", "g2")),
            "fetch failed for .*/g2/index",
        ),
        (lambda url: b"", DocsTarget("p/../x", "1"), "not a plain slug"),
        (lambda url: b"", DocsTarget("p", "1", ("g?x=1",)), "not a plain slug"),
    ],
)
def test_a_failed_or_unsafe_fetch_is_loud_never_partial(
    answer: Callable[[str], bytes | BaseException], target: DocsTarget, match: str
) -> None:
    source, _, product = docs_source(answer, target)
    with pytest.raises((ServiceError, NotFoundError, ValidationError), match=match):
        source.fetch(product)


def test_a_product_without_declared_docs_is_not_found() -> None:
    source, curl, _ = docs_source(lambda url: b"")
    with pytest.raises(NotFoundError, match=r"no docs\.redhat\.com slug/version declared"):
        source.fetch(uuid4())
    assert curl.calls == []


# --- wiring -----------------------------------------------------------------------------------


def test_registered_sources_reach_the_compliance_doors(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    ctx.register_compliance_sources()
    compliance = ctx.services().compliance
    assert isinstance(compliance._adr_source, GithubAdrSource)
    assert isinstance(compliance._docs, RedHatDocSource)
    with pytest.raises(NotFoundError, match=r"no docs\.redhat\.com slug/version declared"):
        compliance._docs.fetch(uuid4())


def test_without_registered_sources_the_compliance_doors_refuse(tmp_path: Path) -> None:
    compliance = Context(Config(home=tmp_path)).services().compliance
    assert compliance._adr_source is None
    with pytest.raises(ConfigError, match="needs a DocSource"):
        compliance.collect_product_docs(uuid4())
