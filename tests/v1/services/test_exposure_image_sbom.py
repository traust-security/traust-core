"""Image SBOM intake and an image's packages on SQLite and Postgres, from a recorded syft scan of a
public UBI image."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.test_exposure_dependencies import CDX, refs, service
from traust_core.v1.errors import ConflictError, ValidationError
from traust_core.v1.models.dependencies import NoImageSbomError
from traust_core.v1.models.sbom_formats import parse_sbom
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

FIXTURE = Path(__file__).parents[2] / "fixtures" / "code_facts" / "crypto" / "image"
IMAGE_SBOM = (FIXTURE / "syft-image-scan.cdx.json").read_bytes()
DIGEST = "sha256:2d4c4551af6831dcd26bbf86108c4385de5183ec8fe6b5868f6f9640fe47f4ed"


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def test_an_image_sbom_lands_on_the_image_row_with_its_os_packages(engine: Engine) -> None:
    [commit] = refs(engine)
    exposure = service(engine)
    image = exposure.ingest_image_sbom(IMAGE_SBOM, DIGEST, "linux/arm64", commit.id)
    assert (image.digest, image.platform, image.repository_ref_id) == (
        DIGEST,
        "linux/arm64",
        commit.id,
    )
    rows = exposure.image_dependencies(DIGEST)
    assert len(rows) == 109
    assert {r.package.ecosystem for r in rows} == {"rpm"}
    openssl = next(r for r in rows if r.package.name == "openssl-libs")
    assert openssl.dependency.version == "3.5.8-2.el9_8"
    keys = [(r.package.ecosystem, r.package.name, r.dependency.version) for r in rows]
    assert keys == sorted(keys)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.images.list_built_from(commit.id) == [image]


def test_image_sbom_event_does_not_log_untrusted_digest(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    digest = "sha256:synthetic-only-never-a-real-credential"
    with caplog.at_level(logging.INFO, logger="traust_core.v1.services.exposure"):
        image = service(engine, portfolio=False).ingest_image_sbom(IMAGE_SBOM, digest)
    assert digest not in caplog.text
    assert str(image.id) in caplog.text


def test_image_sbom_success_is_not_logged_before_an_outer_commit(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    exposure = service(engine, portfolio=False)
    logger = logging.getLogger("traust_core.v1.services.exposure")
    with caplog.at_level(logging.INFO, logger=logger.name):
        logger.addHandler(caplog.handler)
        try:
            with exposure._uow:
                image = exposure.ingest_image_sbom(IMAGE_SBOM, DIGEST)
                assert str(image.id) not in caplog.text
            assert str(image.id) not in caplog.text
        finally:
            logger.removeHandler(caplog.handler)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.images.find_by_digest(DIGEST) is None


def test_the_same_image_sbom_again_is_the_same_row(engine: Engine) -> None:
    exposure = service(engine, portfolio=False)
    image = exposure.ingest_image_sbom(IMAGE_SBOM, DIGEST)
    assert exposure.ingest_image_sbom(IMAGE_SBOM, DIGEST) == image
    other = exposure.ingest_image_sbom(IMAGE_SBOM, "sha256:" + "b" * 64)
    assert other.sbom_id == image.sbom_id and other.id != image.id


def test_image_sbom_replay_emits_no_second_outcome(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    exposure = service(engine, portfolio=False)
    logger = logging.getLogger("traust_core.v1.services.exposure")
    with caplog.at_level(logging.INFO, logger=logger.name):
        logger.addHandler(caplog.handler)
        try:
            first = exposure.ingest_image_sbom(IMAGE_SBOM, DIGEST)
            assert exposure.ingest_image_sbom(IMAGE_SBOM, DIGEST) == first
        finally:
            logger.removeHandler(caplog.handler)
    events = {
        id(record): record.getMessage()
        for record in caplog.records
        if record.name == logger.name and "for image" in record.getMessage()
    }
    assert len(events) == 1 and str(first.id) in next(iter(events.values()))


@pytest.mark.parametrize(
    "change",
    [{"raw": CDX}, {"platform": "linux/amd64"}, {"repository_ref_id": "commit"}],
    ids=["another sbom", "another platform", "declared provenance"],
)
def test_image_rows_are_append_only(engine: Engine, change: dict[str, object]) -> None:
    [commit] = refs(engine)
    exposure = service(engine)
    image = exposure.ingest_image_sbom(IMAGE_SBOM, DIGEST)
    asked: dict[str, object] = {"raw": IMAGE_SBOM, "digest": DIGEST, **change}
    if asked.get("repository_ref_id") == "commit":
        asked["repository_ref_id"] = commit.id
    with pytest.raises(ConflictError, match="append-only"):
        exposure.ingest_image_sbom(**asked)  # type: ignore[arg-type]
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.images.find_by_digest(DIGEST) == image


def test_a_conflict_rolls_back_the_new_sbom(engine: Engine) -> None:
    exposure = service(engine, portfolio=False)
    exposure.ingest_image_sbom(IMAGE_SBOM, DIGEST)
    with pytest.raises(ConflictError):
        exposure.ingest_image_sbom(CDX, DIGEST)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.sboms.find_by_digest(parse_sbom(CDX).digest) is None


def test_a_malformed_image_sbom_is_rejected_before_anything_is_stored(engine: Engine) -> None:
    with pytest.raises(ValidationError, match="sbom"):
        service(engine).ingest_image_sbom(b"{}", DIGEST)
    with pytest.raises(NoImageSbomError):
        service(engine).image_dependencies(DIGEST)


def test_an_unknown_image_or_one_without_an_sbom_has_unknown_packages(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        Seed(uow).image(digest="sha256:bare")
        uow.commit()
    for digest in ("sha256:bare", "sha256:never-seen"):
        with pytest.raises(NoImageSbomError, match=f"image {digest}: no SBOM ingested"):
            service(engine).image_dependencies(digest)
