import gzip
import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from traust_core.v1.errors import ConfigError, ServiceError, ValidationError
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.feeds import (
    MAX_PAGES,
    FeedSource,
    HttpFileFeed,
    PagedJsonFeed,
    Paging,
    Probe,
    epss_scores,
    fill_template,
    kev_entries,
    validate_payload,
)

AT = datetime(2026, 10, 22, tzinfo=UTC)


@pytest.mark.parametrize(
    ("raw", "filename"),
    [
        (gzip.compress(b"cve,epss\n", mtime=0), "epss_scores-current.csv.gz"),
        (b'{"a": 1}', "known_exploited_vulnerabilities.json"),
        (gzip.compress(b"[]", mtime=0), "index.json.gz"),
        (b"anything", "archive_latest.txt"),
    ],
)
def test_well_formed_payload_passes(raw: bytes, filename: str) -> None:
    validate_payload(raw, filename)


@pytest.mark.parametrize(
    ("raw", "filename"),
    [
        (b"", "kev.json"),
        (b"not a gzip payload", "epss.csv.gz"),
        (b"{broken", "kev.json"),
        (b"\xff\xfe", "rh-cve.csv"),
        (gzip.compress(b"", mtime=0), "epss_scores-current.csv.gz"),
        (gzip.compress(b"cve,epss\n", mtime=0)[:10] + b"\xff\xff", "epss_scores-current.csv.gz"),
    ],
)
def test_corrupt_payload_raises(raw: bytes, filename: str) -> None:
    with pytest.raises(ValidationError):
        validate_payload(raw, filename)


class _Fetcher:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.urls: list[str] = []

    def get(self, url: str) -> bytes:
        self.urls.append(url)
        return self.body


def test_http_file_feed_fetches_its_url_with_provenance() -> None:
    fetcher = _Fetcher(b"payload")
    url = "https://feeds.test/epss_scores-current.csv.gz"
    feed = HttpFileFeed(
        "epss",
        url,
        "epss_scores-current.csv.gz",
        timedelta(hours=24),
        http=fetcher,  # type: ignore[arg-type]
        clock=FixedClock(AT),
    )
    result = feed.fetch()
    assert result.data == b"payload" and fetcher.urls == [url]
    assert result.acquisition.provider == "epss"
    assert result.acquisition.source == url and result.acquisition.acquired_at == AT
    assert feed.check().ready


FIXTURES = Path(__file__).parents[2] / "fixtures" / "dependencies" / "feeds"
RH_PAGE = (FIXTURES / "rh_cve_page.json").read_bytes()
PAGING = Paging(
    page_param="page",
    per_page=3,
    since_param="after",
    watermark_field="public_date",
    backfill_from="2026-05-01",
    key="CVE",
    project=("CVE", "public_date", "severity"),
)


class _Pages:
    """Serves the queued pages in order and records each URL asked for."""

    def __init__(self, *pages: bytes) -> None:
        self.pages = list(pages)
        self.urls: list[str] = []

    def get(self, url: str) -> bytes:
        self.urls.append(url)
        return self.pages.pop(0)


def _paged(http: _Pages, paging: Paging = PAGING) -> PagedJsonFeed:
    return PagedJsonFeed(
        "rh-cve",
        "https://rh.test/cve.json",
        "rh_cve.json",
        timedelta(hours=24),
        paging,
        http=http,  # type: ignore[arg-type]
        clock=FixedClock(AT),
    )


def _cves(data: bytes) -> list[str]:
    return [r["CVE"] for r in json.loads(data)]


def test_first_paged_fetch_backfills_and_keeps_only_the_projection() -> None:
    http = _Pages(RH_PAGE, b"[]")
    result = _paged(http).fetch()
    records = json.loads(result.data)
    assert _cves(result.data) == sorted(r["CVE"] for r in json.loads(RH_PAGE))
    assert all(set(r) == {"CVE", "public_date", "severity"} for r in records)
    assert http.urls == [
        "https://rh.test/cve.json?page=1&per_page=3&after=2026-05-01",
        "https://rh.test/cve.json?page=2&per_page=3&after=2026-05-01",
    ]
    assert result.acquisition.provider == "rh-cve" and result.acquisition.acquired_at == AT


def test_a_short_page_is_the_last() -> None:
    http = _Pages(json.dumps(json.loads(RH_PAGE)[:2]).encode())
    _paged(http).fetch()
    assert len(http.urls) == 1


def test_next_fetch_asks_from_the_newest_held_record_and_merges_newest_wins() -> None:
    held = [
        {"CVE": "CVE-2026-1", "public_date": "2026-06-01T00:00:00Z", "severity": "low"},
        {"CVE": "CVE-2026-114618", "public_date": "2026-10-20T00:00:00Z", "severity": "low"},
    ]
    http = _Pages(RH_PAGE, b"[]")
    data = _paged(http).fetch(lambda: json.dumps(held).encode()).data
    assert http.urls[0].endswith("after=2026-10-20")
    merged = {r["CVE"]: r for r in json.loads(data)}
    assert set(merged) == {"CVE-2026-1", *(r["CVE"] for r in json.loads(RH_PAGE))}
    assert merged["CVE-2026-114618"]["severity"] == "moderate"


def test_an_unchanged_upstream_gives_the_same_bytes() -> None:
    first = _paged(_Pages(RH_PAGE, b"[]")).fetch().data
    again = _paged(_Pages(b"[]")).fetch(lambda: first).data
    assert again == first


def test_a_feed_that_never_stops_paging_is_refused() -> None:
    full = json.dumps([{"CVE": "CVE-2026-1", "public_date": "2026-06-01"}] * 3).encode()
    with pytest.raises(ValidationError, match=f"more than {MAX_PAGES} pages"):
        _paged(_Pages(*[full] * MAX_PAGES)).fetch()


@pytest.mark.parametrize("page", [b"{broken", b'{"not": "a list"}', b"[1, 2]"])
def test_a_malformed_page_is_refused(page: bytes) -> None:
    with pytest.raises(ValidationError, match=r"rh_cve\.json"):
        _paged(_Pages(page)).fetch()


def test_epss_scores_skip_the_header_lines_and_bad_rows() -> None:
    raw = (FIXTURES / "epss_scores-current.csv").read_bytes() + b"CVE-2026-0,not-a-number,1\n"
    scores = epss_scores(gzip.compress(raw, mtime=0))
    assert scores["CVE-1999-0001"] == (0.04753, 0.91851)
    assert len(scores) == 4 and "CVE-2026-0" not in scores


def test_kev_entries_carry_date_added_and_ransomware_use() -> None:
    entries = kev_entries((FIXTURES / "known_exploited_vulnerabilities.json").read_bytes())
    assert entries == {
        "CVE-2026-59310": (date(2026, 8, 18), True),
        "CVE-2026-114625": (date(2026, 10, 23), False),
    }


@pytest.mark.parametrize(
    "raw",
    [b"[]", b'{"vulnerabilities": [{"cveID": "CVE-2026-1", "dateAdded": "yesterday"}]}'],
)
def test_a_malformed_kev_catalog_is_refused(raw: bytes) -> None:
    with pytest.raises(ValidationError, match="kev: malformed catalog"):
        kev_entries(raw)


@pytest.mark.parametrize(
    ("template", "identifier", "url"),
    [
        ("https://h/{year}/{ident_lower}.json", "CVE-2021-44228", "https://h/2021/cve-2021-44228.json"),
        ("https://h/{year}/{ident_lower}.json", "cve-2019-14540", "https://h/2019/cve-2019-14540.json"),
        # a '-' split of an RHSA id yields '2024:6493', an empty year segment
        ("https://h/{year}/{ident_lower_us}.json", "RHSA-2024:6493", "https://h/2024/rhsa-2024_6493.json"),
        ("https://h/q?cveId={ident_upper}", "cve-2021-44228", "https://h/q?cveId=CVE-2021-44228"),
        ("https://h/{ident}", "{ident_upper}", "https://h/{ident_upper}"),
        ("https://h/{year}", "no-year-here", "https://h/"),
    ],
)  # fmt: skip
def test_fill_template_is_lexical(template: str, identifier: str, url: str) -> None:
    assert fill_template(template, identifier) == url


def test_fill_template_refuses_an_unknown_placeholder() -> None:
    with pytest.raises(ConfigError, match="unknown placeholder"):
        fill_template("https://h/{token}", "CVE-2021-44228")


class _Http:
    """Answers each URL with its body, or raises the error queued for it."""

    def __init__(self, answers: dict[str, bytes | Exception] | None = None) -> None:
        self.answers = answers or {}
        self.sent: list[tuple[str, object]] = []

    def _answer(self, url: str, body: object) -> bytes:
        self.sent.append((url, body))
        answer = self.answers.get(url, b"{}")
        if isinstance(answer, Exception):
            raise answer
        return answer

    def get(self, url: str) -> bytes:
        return self._answer(url, None)

    def post_json(self, url: str, doc: object) -> bytes:
        return self._answer(url, doc)


NVD = "https://nvd.test/cves?cveId={ident_upper}"
LOG4SHELL = Probe("CVE-2021-44228")


def source(
    template: str | None = NVD,
    *,
    url: str | None = None,
    ident: str | None = "cve",
    post: bool = False,
    probe: Probe | None = LOG4SHELL,
    http: _Http | None = None,
) -> FeedSource:
    fetcher = http or _Http()
    return FeedSource(
        "nvd",
        url or template or "https://nvd.test/",
        template=template,
        ident=ident,
        post=post,
        probe=probe,
        http=fetcher,  # type: ignore[arg-type]
        probe_http=fetcher,  # type: ignore[arg-type]
        clock=FixedClock(AT),
    )


def test_a_document_is_fetched_from_the_filled_template_with_provenance() -> None:
    http = _Http({"https://nvd.test/cves?cveId=CVE-2021-44228": b'{"vulnerabilities": []}'})
    result = source(http=http).document("cve-2021-44228")
    assert result.data == b'{"vulnerabilities": []}'
    assert result.acquisition.provider == "nvd" and result.acquisition.acquired_at == AT
    assert result.acquisition.source == "https://nvd.test/cves?cveId=CVE-2021-44228"


@pytest.mark.parametrize(
    ("ident", "identifier"),
    [
        ("cve", "not-a-cve"),
        ("cve", "'; curl evil"),
        ("rhsa", "CVE-2021-44228"),
        ("repo", "kubernetes/kubernetes"),
    ],
)
def test_an_identifier_not_of_the_sources_kind_is_refused(ident: str, identifier: str) -> None:
    http = _Http()
    with pytest.raises(ValidationError, match="is not its kind of identifier"):
        source(ident=ident, http=http).document(identifier)
    assert http.sent == []


@pytest.mark.parametrize("identifier", [".evil.test/x", "@evil.test", ":8443/x"])
def test_an_identifier_that_moves_the_host_is_refused(identifier: str) -> None:
    with pytest.raises(ValidationError, match=r"not on its registered host nvd\.test"):
        source("https://nvd.test{ident}", ident=None).document(identifier)


def test_a_source_without_a_template_serves_no_documents() -> None:
    with pytest.raises(ValidationError, match="serves no per-identifier documents"):
        source(None, url="https://rh.test/cve.json").document("CVE-2021-44228")


def test_a_probe_answered_is_ready() -> None:
    http = _Http()
    readiness = source(http=http).check()
    assert readiness.ready and readiness.detail == "nvd.test answered the probe"
    assert http.sent == [("https://nvd.test/cves?cveId=CVE-2021-44228", None)]


def test_a_probe_without_an_identifier_asks_the_published_url() -> None:
    http = _Http()
    assert source(None, url="https://rh.test/cve.json", probe=Probe(None), http=http).check().ready
    assert http.sent == [("https://rh.test/cve.json", None)]


def test_a_package_probe_posts_the_package_query() -> None:
    http = _Http()
    osv = source(
        None, url="https://osv.test/v1/query", post=True, probe=Probe("lodash", "npm"), http=http
    )
    assert osv.check().ready
    assert http.sent == [
        ("https://osv.test/v1/query", {"package": {"name": "lodash", "ecosystem": "npm"}})
    ]


@pytest.mark.parametrize(
    ("error", "detail"),
    [
        (ServiceError("HTTP 404", status=404), "nvd.test answered HTTP 404 for the declared probe"),
        (ServiceError("HTTP 429", status=429), "could not reach nvd.test"),
        (ServiceError("gave up after 1 attempts (HTTP 503)"), "could not reach nvd.test"),
        (ServiceError("gave up (Name or service not known)"), "liveness undetermined"),
    ],
)
def test_a_refused_probe_disagrees_and_an_unreachable_one_is_undetermined(
    error: ServiceError, detail: str
) -> None:
    http = _Http({"https://nvd.test/cves?cveId=CVE-2021-44228": error})
    readiness = source(http=http).check()
    assert not readiness.ready and detail in readiness.detail


def test_a_probe_that_cannot_be_built_is_not_ready() -> None:
    readiness = source(probe=Probe("not-a-cve")).check()
    assert not readiness.ready and "probe URL could not be built" in readiness.detail


def test_a_source_without_a_probe_is_ready_and_says_liveness_is_unchecked() -> None:
    readiness = source(probe=None).check()
    assert readiness.ready and readiness.detail == "no probe declared; liveness unchecked"
