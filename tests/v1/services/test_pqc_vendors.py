"""PQC vendor claims on SQLite and Postgres: the curated scope-ref document recorded as successor
versions, and the pqc-vendors view deriving fleet counts from the default-branch manifests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.test_pqc import (
    PROVENANCE,
    REPORT,
    SBOM,
    SHA,
    URL,
    World,
    engine,  # noqa: F401
    report,
)
from traust_core.v1.context import Config, Context
from traust_core.v1.contracts import DocumentError
from traust_core.v1.errors import ConflictError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import PqcVendorClaimsArtifact
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.vocabulary import PqcVendorClass, PqcVendorStatus
from traust_core.v1.rendering import MarkdownRenderer
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.insight import PqcVendorsView

FIXTURE = Path(__file__).parents[2] / "fixtures/pqc/vendor-claims.json"
CLAIMS: dict[str, Any] = json.loads(FIXTURE.read_text())


def claims(**changes: Any) -> PqcVendorClaimsArtifact:
    return PqcVendorClaimsArtifact.from_document({**json.loads(json.dumps(CLAIMS)), **changes})


@pytest.fixture
def world(engine: Engine) -> World:  # noqa: F811
    return World(engine, None)


def repository(world: World, url: str, *, sbom: bytes | None = SBOM, default: bool = True) -> UUID:
    with SqlTraustUnitOfWork(world.engine) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref(seed.repository(url=url), sha=SHA, is_default=default)
        uow.commit()
    assert ref.id is not None
    if sbom is not None:
        world.exposure.ingest_sbom(sbom, ref.id)
    return ref.id


def test_recording_reads_back_the_latest_claims(world: World) -> None:
    recorded = world.pqc.record_claims(claims(), PROVENANCE)
    latest = world.pqc.vendor_claims()
    assert latest == recorded
    assert (latest.version, len(latest.vendors)) == (1, 6)
    openssl = latest.vendors[0]
    assert (openssl.vendor_class, openssl.status) == (
        PqcVendorClass.PROVIDER,
        PqcVendorStatus.AVAILABLE,
    )
    assert [p.ecosystem for p in latest.vendors[4].packages] == [None, "pypi"]


def test_the_same_claims_again_add_nothing(world: World) -> None:
    first = world.pqc.record_claims(claims(), PROVENANCE)
    assert world.pqc.record_claims(claims(), PROVENANCE) == first
    assert len(world.publisher.history(PqcVendorClaimsArtifact, 10)) == 1


def test_a_review_is_a_successor_with_a_higher_version(world: World) -> None:
    world.pqc.record_claims(claims(), PROVENANCE)
    vendors = [{**CLAIMS["vendors"][2], "status": "in_progress"}]
    second = world.pqc.record_claims(claims(version=2, vendors=vendors), PROVENANCE)
    assert world.pqc.vendor_claims() == second
    assert [v.status for v in second.vendors] == [PqcVendorStatus.IN_PROGRESS]
    assert len(world.publisher.history(PqcVendorClaimsArtifact, 10)) == 2


def test_a_changed_document_must_raise_the_version(world: World) -> None:
    first = world.pqc.record_claims(claims(), PROVENANCE)
    with pytest.raises(ConflictError, match="does not supersede the recorded version 1"):
        world.pqc.record_claims(claims(note="edited in place"), PROVENANCE)
    assert world.pqc.vendor_claims() == first


def test_an_older_version_never_supersedes_a_newer_one(world: World) -> None:
    world.pqc.record_claims(claims(version=3), PROVENANCE)
    with pytest.raises(ConflictError, match="version 2 does not supersede the recorded version 3"):
        world.pqc.record_claims(claims(version=2), PROVENANCE)


def test_repeated_vendor_ids_are_refused_before_publishing(world: World) -> None:
    vendors = [CLAIMS["vendors"][0], CLAIMS["vendors"][1], CLAIMS["vendors"][0]]
    with pytest.raises(ValidationError, match="repeats vendor ids: openssl"):
        world.pqc.record_claims(claims(vendors=vendors), PROVENANCE)
    assert world.publisher.history(PqcVendorClaimsArtifact, 10) == []


def test_reading_before_any_claims_are_recorded(world: World) -> None:
    with pytest.raises(NotFoundError, match="no pqc-vendor-claims recorded"):
        world.pqc.vendor_claims()


@pytest.mark.parametrize(
    "change",
    [
        {"fleet_repos_via_graph": 3},
        {"status": "in-progress"},
        {"sources": []},
        {"reviewer": ""},
    ],
)
def test_counts_and_legacy_or_unsourced_rows_are_not_claims(change: dict[str, Any]) -> None:
    with pytest.raises(DocumentError):
        claims(vendors=[{**CLAIMS["vendors"][0], **change}])


def test_the_roadmap_counts_repositories_holding_each_vendors_packages(world: World) -> None:
    world.pqc.record_claims(claims(), PROVENANCE)
    repository(world, URL)
    repository(world, f"{URL}-b")
    repository(world, f"{URL}-c", sbom=None)
    repository(world, f"{URL}-d", default=False)
    view = PqcVendorsView(world.pqc, world.exposure, world.portfolio)

    model = view.build(ViewFilter())
    assert [(r.claim.id, r.repositories) for r in model.vendors] == [
        ("forge-app-jwt", None),
        ("go-jose", 0),
        ("pyca", 2),
        ("rustls", 2),
        ("go", None),
        ("openssl", 2),
    ]
    assert (model.repositories, model.unmeasured, model.version) == (4, 2, 1)
    assert model.blocked_external == ()


def test_the_roadmap_lists_repositories_whose_newest_readiness_is_blocked_external(
    world: World,
) -> None:
    world.pqc.record_claims(claims(), PROVENANCE)
    blocked, cleared = repository(world, URL), repository(world, f"{URL}-b")
    meta = {**REPORT["metadata"], "repository": f"{URL}-b"}
    world.pqc.record(blocked, report(readiness_bucket="blocked-external"), PROVENANCE)
    world.pqc.record(
        cleared, report(metadata=meta, readiness_bucket="blocked-external"), PROVENANCE
    )
    with SqlTraustUnitOfWork(world.engine) as uow:
        newer = Seed(uow).repository_ref(
            uow.repositories.get(uow.repository_refs.get(cleared).repository_id), sha="b" * 40
        )
        uow.commit()
    assert newer.id is not None
    later = PROVENANCE.model_copy(update={"occurred_at": T0.replace(year=2027)})
    unpinned = {k: v for k, v in meta.items() if k != "commit"}
    world.pqc.record(newer.id, report(metadata=unpinned, readiness_bucket="partial"), later)
    view = PqcVendorsView(world.pqc, world.exposure, world.portfolio)

    model = view.build(ViewFilter())
    assert model.blocked_external == (URL,)

    text = MarkdownRenderer().render(view.report(model, T0)).decode()
    for expected in (
        "Claims v1 (updated 2026-07-19)",
        "re-verify before external use",
        "(2 of 2 measured; the rest are not measured, not zero)",
        "| go-jose (JOSE/JWT) | library | ✗ none | 0 | IETF JOSE ML-DSA registration",
        "| Code forge (App JWT RS256) | service | ✗ none | - | - | 2026-07-19 |",
        "| OpenSSL (OS provider) | provider | ✓ available | 2 |",
        "- **rustls / Rust TLS stack**: X25519MLKEM768",
        "crypto-review team; https://github.com/rustls/rustls/releases)",
        f"Blocked-external repos (1)\n\n{URL}",
    ):
        assert expected in text, expected


def test_the_roadmap_needs_recorded_claims_and_is_fleet_wide_now(world: World) -> None:
    view = PqcVendorsView(world.pqc, world.exposure, world.portfolio)
    with pytest.raises(NotFoundError):
        view.build(ViewFilter())
    world.pqc.record_claims(claims(), PROVENANCE)
    with pytest.raises(ValidationError, match="fleet-wide"):
        view.build(ViewFilter(product_ids=(UUID(int=1),)))
    with pytest.raises(ValidationError, match="latest claims"):
        view.build(ViewFilter(as_of=T0))


def test_context_records_claims_and_serves_the_view(tmp_path: Path) -> None:
    services = Context(Config(home=tmp_path)).services()
    services.pqc.record_claims(claims(), PROVENANCE)
    model = services.insight.build(ViewName.PQC_VENDORS, ViewFilter())
    assert len(model.vendors) == 6  # type: ignore[attr-defined]
