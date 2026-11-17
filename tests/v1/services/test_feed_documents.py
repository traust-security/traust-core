"""ExposureService.refresh_documents and stored_document on SQLite and Postgres (D11)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import IntegrityError, NotFoundError, ServiceError, ValidationError
from traust_core.v1.models.assessment import Artifact
from traust_core.v1.models.feed_documents import FeedDocumentManifest
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.operations import FeedSnapshot
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.feeds import FeedProvider, FeedSource
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore, ObjectKey
from traust_core.v1.services.artifact_publishing import record_artifact
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy

AT = datetime(2026, 11, 17, tzinfo=UTC)
TEMPLATE = "https://cve.test/api/cve/{ident_upper}"
A, B, C = "CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"


def doc(cve: str, rev: int = 1) -> bytes:
    return json.dumps({"cveMetadata": {"cveId": cve}, "rev": rev}).encode()


def doc_key(raw: bytes) -> ObjectKey:
    return ObjectKey.parse(f"feeds/cve-list/documents/{sha256_hex(raw)}.json")


class Clock:
    def __init__(self) -> None:
        self.at = AT

    def now(self) -> datetime:
        return self.at


class Http:
    """Answers each URL with its queued body, or raises the queued error."""

    def __init__(self) -> None:
        self.answers: dict[str, bytes | Exception] = {}

    def serve(self, cve: str, answer: bytes | Exception) -> None:
        self.answers[TEMPLATE.format(ident_upper=cve)] = answer

    def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        *,
        secret_headers: dict[str, str] | None = None,
    ) -> bytes:
        answer = self.answers.get(url, ServiceError("HTTP 404", status=404))
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


class World:
    def __init__(self, engine: Engine, key: str = "cve-list") -> None:
        self.engine = engine
        self.http = Http()
        self.clock = Clock()
        self.objects = InMemoryObjectStore()
        source = FeedSource(
            "cve-list",
            TEMPLATE,
            template=TEMPLATE,
            ident="cve",
            post=False,
            probe=None,
            http=self.http,  # type: ignore[arg-type]
            probe_http=self.http,  # type: ignore[arg-type]
            clock=self.clock,
        )
        sources: ProviderRegistry[FeedSource] = ProviderRegistry("feed-source")
        sources.register(key, lambda: source)
        uow = SqlTraustUnitOfWork(engine)
        self.svc = ExposureService(
            uow,
            FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
            feeds=ProviderRegistry[FeedProvider]("feed"),
            feed_sources=sources,
            objects=self.objects,
            clock=self.clock,
        )

    def latest(self) -> FeedSnapshot | None:
        with SqlTraustUnitOfWork(self.engine) as uow:
            return uow.feed_snapshots.latest("cve-list-documents")

    def run_order(self) -> UUID:
        with SqlTraustUnitOfWork(self.engine) as uow:
            order = Seed(uow).run_order(asset="feeds_cache", lane=None)
            uow.commit()
        assert order.id is not None
        return order.id


@pytest.fixture
def world(engine: Engine) -> World:
    return World(engine)


def test_each_document_is_kept_by_digest_under_one_manifest_snapshot(world: World) -> None:
    world.http.serve(A, doc(A))
    world.http.serve(B, doc(B))
    refresh = world.svc.refresh_documents("cve-list", [A, B, A])
    assert (refresh.fetched, refresh.failed, refresh.carried) == ((A, B), (), ())
    stored = world.svc.stored_document("cve-list", A)
    assert stored is not None
    assert (stored.data, stored.digest, stored.acquired_at) == (doc(A), sha256_hex(doc(A)), AT)
    assert world.objects.exists(doc_key(doc(B)))
    latest = world.latest()
    assert latest is not None and latest.retrieved_at == AT
    # the manifest names exactly the identifiers asked for, once each
    manifest = world.svc.document_manifest("cve-list")
    assert manifest is not None and sorted(manifest.documents) == [A, B]


def test_a_failed_fetch_keeps_the_last_document_and_an_unrequested_one_is_dropped(
    world: World,
) -> None:
    world.http.serve(A, doc(A))
    world.http.serve(B, doc(B))
    world.svc.refresh_documents("cve-list", [A, B])
    world.clock.at += timedelta(days=1)
    world.http.serve(A, ServiceError("HTTP 503", status=503))
    world.http.serve(C, doc(C))
    refresh = world.svc.refresh_documents("cve-list", [A, C])
    assert refresh.fetched == (C,) and refresh.carried == (A,)
    assert [(f.identifier, f.error) for f in refresh.failed] == [(A, "HTTP 503")]
    carried = world.svc.stored_document("cve-list", A)
    assert carried is not None and (carried.data, carried.acquired_at) == (doc(A), AT)
    assert world.svc.stored_document("cve-list", B) is None


def test_a_failed_fetch_with_nothing_to_carry_names_no_document(world: World) -> None:
    world.http.serve(A, doc(A))
    refresh = world.svc.refresh_documents("cve-list", [A, B])
    assert refresh.fetched == (A,) and refresh.carried == ()
    assert [f.identifier for f in refresh.failed] == [B]
    assert world.svc.stored_document("cve-list", B) is None


@pytest.mark.parametrize(
    ("answer", "error"),
    [(b"<html>", "not a JSON document"), (b"[]", "not a JSON object")],
)
def test_a_document_that_is_not_a_json_object_is_a_failure(
    world: World, answer: bytes, error: str
) -> None:
    world.http.serve(A, doc(A))
    world.http.serve(B, answer)
    [failure] = world.svc.refresh_documents("cve-list", [A, B]).failed
    assert failure.identifier == B and error in failure.error


def test_an_identifier_of_another_kind_is_a_failure_and_never_fetched(world: World) -> None:
    world.http.serve(A, doc(A))
    [failure] = world.svc.refresh_documents("cve-list", [A, "GHSA-jfh8-c2jp-5v3q"]).failed
    assert "not its kind of identifier" in failure.error


def test_when_nothing_is_fetched_the_refresh_raises_and_writes_nothing(world: World) -> None:
    world.http.serve(A, doc(A))
    world.svc.refresh_documents("cve-list", [A])
    before = world.latest()
    world.clock.at += timedelta(days=1)
    world.http.serve(A, ServiceError("HTTP 503", status=503))
    outage = r"no document fetched \(1 failed, each logged; first: HTTP 503\)"
    with pytest.raises(ServiceError, match=outage):
        world.svc.refresh_documents("cve-list", [A])
    assert world.latest() == before


def test_no_identifiers_is_refused_and_the_last_manifest_stays(world: World) -> None:
    world.http.serve(A, doc(A))
    world.svc.refresh_documents("cve-list", [A])
    before = world.latest()
    with pytest.raises(ValidationError, match="cve-list: no identifiers"):
        world.svc.refresh_documents("cve-list", [])
    assert world.latest() == before
    assert world.svc.stored_document("cve-list", A) is not None


def test_a_cve_id_is_kept_and_read_in_one_spelling(world: World) -> None:
    world.http.serve(A, doc(A))
    refresh = world.svc.refresh_documents("cve-list", [A.lower(), A])
    assert refresh.fetched == (A,)
    stored = world.svc.stored_document("cve-list", A.lower())
    assert stored is not None and stored.identifier == A


def test_a_retried_refresh_in_the_same_run_order_adds_no_snapshot(world: World) -> None:
    world.http.serve(A, doc(A))
    order = world.run_order()
    world.svc.refresh_documents("cve-list", [A], order)
    first = world.latest()
    world.clock.at += timedelta(minutes=5)  # a retry fetches later: only the documents compare
    world.svc.refresh_documents("cve-list", [A], order)
    assert world.latest() == first
    world.svc.refresh_documents("cve-list", [A], world.run_order())
    latest = world.latest()
    assert latest is not None and first is not None and latest.id != first.id


def test_a_retry_in_the_same_order_that_got_another_document_snapshots_it(world: World) -> None:
    world.http.serve(A, doc(A))
    order = world.run_order()
    world.svc.refresh_documents("cve-list", [A], order)
    first = world.latest()
    world.http.serve(A, doc(A, rev=2))
    world.svc.refresh_documents("cve-list", [A], order)
    latest = world.latest()
    assert latest is not None and first is not None and latest.id != first.id
    stored = world.svc.stored_document("cve-list", A)
    assert stored is not None and stored.data == doc(A, rev=2)


def test_a_changed_document_is_a_new_object_and_the_old_one_stays(world: World) -> None:
    world.http.serve(A, doc(A))
    world.svc.refresh_documents("cve-list", [A])
    world.http.serve(A, doc(A, rev=2))
    world.svc.refresh_documents("cve-list", [A])
    stored = world.svc.stored_document("cve-list", A)
    assert stored is not None and stored.data == doc(A, rev=2)
    assert world.objects.exists(doc_key(doc(A)))


def test_a_document_whose_bytes_changed_in_the_store_is_refused(world: World) -> None:
    world.http.serve(A, doc(A))
    world.svc.refresh_documents("cve-list", [A])
    world.objects.put(doc_key(doc(A)), b'{"tampered": 1}')
    with pytest.raises(IntegrityError):
        world.svc.stored_document("cve-list", A)


def test_another_sources_manifest_under_this_feed_is_refused(world: World) -> None:
    raw = FeedDocumentManifest(source="nvd", documents={}).to_bytes()
    ref = world.objects.put(ObjectKey.parse("feeds/nvd/manifests/x.json"), raw)
    with SqlTraustUnitOfWork(world.engine) as uow:
        artifact = record_artifact(uow, Artifact(digest=ref.sha256, kind="feed", uri=str(ref.key)))
        assert artifact.id is not None
        uow.feed_snapshots.add(
            FeedSnapshot(artifact_id=artifact.id, feed="cve-list-documents", retrieved_at=AT)
        )
        uow.commit()
    with pytest.raises(ValidationError, match="cve-list-documents: its manifest is nvd's"):
        world.svc.stored_document("cve-list", A)


def test_a_source_not_registered_is_not_found(world: World) -> None:
    with pytest.raises(NotFoundError, match=r"feed source nvd: not registered \(cve-list\)"):
        world.svc.refresh_documents("nvd", [A])
    assert world.svc.stored_document("nvd", A) is None


def test_before_the_first_refresh_nothing_is_stored(world: World) -> None:
    assert world.svc.stored_document("cve-list", A) is None


def test_a_document_missing_from_the_store_is_not_found(world: World) -> None:
    world.http.serve(A, doc(A))
    world.svc.refresh_documents("cve-list", [A])
    world.objects._blobs.pop(doc_key(doc(A)))
    with pytest.raises(NotFoundError):
        world.svc.stored_document("cve-list", A)


def test_an_unreadable_last_manifest_stops_the_refresh_for_a_person_to_act(world: World) -> None:
    world.http.serve(A, doc(A))
    world.svc.refresh_documents("cve-list", [A])
    latest = world.latest()
    assert latest is not None
    with SqlTraustUnitOfWork(world.engine) as uow:
        uri = uow.artifacts.get(latest.artifact_id).uri
    world.objects._blobs.pop(ObjectKey.parse(uri))
    with pytest.raises(NotFoundError):  # carrying forward needs it; it is never silently reset
        world.svc.refresh_documents("cve-list", [A])


def test_unchanged_content_keeps_its_first_fetch_time_and_one_manifest(world: World) -> None:
    world.http.serve(A, doc(A))
    world.svc.refresh_documents("cve-list", [A])
    first = world.latest()
    world.clock.at += timedelta(days=1)
    world.svc.refresh_documents("cve-list", [A])
    latest = world.latest()
    assert latest is not None and first is not None
    assert latest.id != first.id and latest.artifact_id == first.artifact_id
    stored = world.svc.stored_document("cve-list", A)
    assert stored is not None and stored.acquired_at == AT


def test_a_late_retry_of_a_superseded_order_changes_nothing(world: World) -> None:
    world.http.serve(A, doc(A))
    world.http.serve(B, doc(B))
    old, new = world.run_order(), world.run_order()
    world.svc.refresh_documents("cve-list", [A], old)
    world.svc.refresh_documents("cve-list", [A, B], new)
    newest = world.latest()
    world.svc.refresh_documents("cve-list", [A], old)
    assert world.latest() == newest
    assert world.svc.stored_document("cve-list", B) is not None


def test_a_clock_that_stepped_back_still_makes_the_new_manifest_latest(world: World) -> None:
    world.http.serve(A, doc(A))
    world.svc.refresh_documents("cve-list", [A])
    world.clock.at -= timedelta(hours=1)
    world.http.serve(A, doc(A, rev=2))
    world.svc.refresh_documents("cve-list", [A])
    latest = world.latest()
    assert latest is not None and latest.retrieved_at > AT
    stored = world.svc.stored_document("cve-list", A)
    assert stored is not None and stored.data == doc(A, rev=2)


def test_a_failed_fetch_never_carries_a_document_the_store_lost(world: World) -> None:
    world.http.serve(A, doc(A))
    world.http.serve(B, doc(B))
    world.svc.refresh_documents("cve-list", [A, B])
    world.objects._blobs.pop(doc_key(doc(A)))
    world.http.serve(A, ServiceError("HTTP 503", status=503))
    refresh = world.svc.refresh_documents("cve-list", [A, B])
    assert refresh.carried == () and [f.identifier for f in refresh.failed] == [A]
    assert world.svc.stored_document("cve-list", A) is None


def test_every_failure_is_logged_when_nothing_was_fetched(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    world.http.serve(A, ServiceError("HTTP 503", status=503))
    with pytest.raises(ServiceError, match="2 failed, each logged"):
        world.svc.refresh_documents("cve-list", [A, B])
    assert {A, B} <= {r.args[1] for r in caplog.records if r.args}  # type: ignore[index]


def test_a_source_registered_under_another_key_reads_back_what_it_kept(engine: Engine) -> None:
    aliased = World(engine, key="cna-records")  # the provider itself is named cve-list
    aliased.http.serve(A, doc(A))
    aliased.svc.refresh_documents("cna-records", [A])
    stored = aliased.svc.stored_document("cna-records", A)
    assert stored is not None and stored.data == doc(A)


@pytest.mark.parametrize(
    ("given", "kept"),
    [
        ("cve-2026-0001", "CVE-2026-0001"),
        ("rhsa-2024:6493", "RHSA-2024:6493"),
        ("rhsa-2024_6493", "RHSA-2024:6493"),
        ("GHSA-jfh8-c2jp-5v3q", "GHSA-jfh8-c2jp-5v3q"),
    ],
)
def test_identifiers_a_source_matches_in_any_case_are_kept_in_one_spelling(
    given: str, kept: str
) -> None:
    from traust_core.v1.services.exposure import _canonical

    assert _canonical(given) == kept


def test_a_failed_fetch_never_carries_a_document_whose_bytes_changed(world: World) -> None:
    world.http.serve(A, doc(A))
    world.http.serve(B, doc(B))
    world.svc.refresh_documents("cve-list", [A, B])
    world.objects.put(doc_key(doc(A)), b'{"tampered": 1}')
    world.http.serve(A, ServiceError("HTTP 503", status=503))
    refresh = world.svc.refresh_documents("cve-list", [A, B])
    assert refresh.carried == ()
    assert world.svc.stored_document("cve-list", A) is None


def test_a_failure_never_repeats_a_urls_credentials(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    world.http.serve(A, doc(A))
    leaked = "https://user:s3cret@cve.test/api/cve/CVE-2026-0002: HTTP 500"
    world.http.serve(B, ServiceError(leaked, status=500))
    [failure] = world.svc.refresh_documents("cve-list", [A, B]).failed
    assert failure.error == "https://cve.test/api/cve/CVE-2026-0002: HTTP 500"
    assert "s3cret" not in caplog.text
    world.http.serve(A, ServiceError(leaked, status=500))
    with pytest.raises(ServiceError) as raised:
        world.svc.refresh_documents("cve-list", [A, B])
    assert "s3cret" not in str(raised.value)
