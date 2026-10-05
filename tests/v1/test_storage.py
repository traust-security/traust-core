import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from tests.v1.contract_ddl import apply_contract_ddl
from traust_core.v1.domain import (
    ConflictError,
    DocumentError,
    FixedClock,
    NotFoundError,
    ValidationError,
)
from traust_core.v1.domain.storage import BindingContext, binding_id
from traust_core.v1.repositories import create_database_engine, schema_drift
from traust_core.v1.repositories.storage import (
    InMemoryStorageUnitOfWork,
    SqlStorageUnitOfWork,
    StorageUnitOfWork,
    metadata,
)
from traust_core.v1.services.storage import get_binding, record_artifact

PG_URL = os.environ.get("TRAUST_TEST_DATABASE_URL")
CLOCK = FixedClock(datetime(2026, 10, 5, tzinfo=UTC))
DIGEST = "a" * 64
RUN = BindingContext(subject_id="org/repo", run_id="r1")
TRIAGE = json.dumps(
    {
        "triage_completed": "2025-01-01",
        "triage_context": {
            "mode": "synthetic",
            "environment": "synthetic test environment",
            "scoring": "synthetic test scoring",
            "noise_tolerance": "synthetic",
            "votes_per_finding": 1,
            "repo": "example.invalid/synthetic/repository",
            "harness_version": "0.0.0",
            "reemitted": "2025-01-02",
            "reemit_method": "synthetic fixture generation",
        },
        "summary": {
            "input_count": 0,
            "true_positives": 0,
            "hardening": 0,
            "false_positives": 0,
            "undetermined": 0,
            "duplicates": 0,
            "needs_manual_test": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0},
        },
        "findings": [],
    }
).encode()
SQL_BACKENDS = ["sqlite", pytest.param("postgres", marks=pytest.mark.integration)]


@contextmanager
def storage_db(kind: str, tmp_path: Path) -> Iterator[Engine]:
    if kind == "postgres" and not PG_URL:
        pytest.skip("TRAUST_TEST_DATABASE_URL not set")
    engine = create_database_engine(PG_URL if kind == "postgres" else f"sqlite:///{tmp_path}/s.db")
    apply_contract_ddl(engine, "storage")
    try:
        yield engine
    finally:
        if kind == "postgres":
            with engine.begin() as conn:
                conn.exec_driver_sql("DROP SCHEMA traust_storage CASCADE")
        engine.dispose()


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with storage_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture(params=["memory", *SQL_BACKENDS])
def uow(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[StorageUnitOfWork]:
    if request.param == "memory":
        yield InMemoryStorageUnitOfWork()
        return
    with storage_db(request.param, tmp_path) as eng:
        yield SqlStorageUnitOfWork(eng)


@pytest.mark.parametrize(
    ("name", "context", "expected"),
    [
        (
            "triage",
            BindingContext(),
            "9949f898c09fbf4a2b823e7dc840a0882a222614a14df064e170c8dd4cabfe30",
        ),
        ("triage", RUN, "9786c5efd29f35bdffb4324d2cafc389867ab9ca356b6eb92f042e96c31d0ee6"),
        (
            "report",
            BindingContext(scope_id="team-a", subject_id="org/repo", run_id="r1", role="baseline"),
            "1dd74cb4859ba1aa3070e65f2177a23f3a79b2aa9838a7b4138a1bee44eb42e8",
        ),
        (
            "layer",
            BindingContext(layer_id="L1"),
            "849e32b2f0e43a169733395a436fc954dca2afa20e3da63120c1b31a66ef16b7",
        ),
        (
            "report",
            BindingContext(subject_id="", run_id="r1"),
            "d0f816254bef13e04684f8739200eb0e623572fbbe70107b4e65dce000834b7d",
        ),
    ],
)
def test_binding_id_matches_traust_contracts_reference(
    name: str, context: BindingContext, expected: str
) -> None:
    assert binding_id(DIGEST, name, context) == expected


def test_binding_id_rejects_nul() -> None:
    with pytest.raises(ValidationError):
        binding_id(DIGEST, "triage", BindingContext(subject_id="a\x00b"))


def test_tables_match_contracts_ddl(engine: Engine) -> None:
    assert schema_drift(engine, metadata) == []


def test_record_new_artifact(uow: StorageUnitOfWork) -> None:
    result = record_artifact(uow, "triage", TRIAGE, CLOCK, RUN, ["s3://bucket/triage.json"])
    assert not result.already_bound
    binding = get_binding(uow, result.binding_id)
    assert binding.artifact_digest == result.digest
    assert binding.byte_size == len(TRIAGE)
    assert binding.references == ("s3://bucket/triage.json",)
    assert binding.context == RUN
    assert binding.bound_at == CLOCK.now()


def test_recording_again_is_idempotent_and_adds_references(uow: StorageUnitOfWork) -> None:
    first = record_artifact(uow, "triage", TRIAGE, CLOCK, RUN, ["a"])
    again = record_artifact(uow, "triage", TRIAGE, CLOCK, RUN, ["a", "b"])
    assert again.already_bound and again.binding_id == first.binding_id
    assert get_binding(uow, first.binding_id).references == ("a", "b")


def test_invalid_document_is_rejected_before_writing(uow: StorageUnitOfWork) -> None:
    with pytest.raises(DocumentError):
        record_artifact(uow, "triage", b'{"findings": []}', CLOCK, RUN)
    with pytest.raises(NotFoundError):
        get_binding(uow, binding_id(DIGEST, "triage", RUN))


@pytest.mark.parametrize(
    "context",
    [BindingContext(), BindingContext(subject_id="org/repo", run_id="r1", role="nope")],
)
def test_binding_context_must_fit_the_storage_profile(
    uow: StorageUnitOfWork, context: BindingContext
) -> None:
    with pytest.raises(ValidationError):
        record_artifact(uow, "triage", TRIAGE, CLOCK, context)


def test_supersedes_must_name_a_known_binding(uow: StorageUnitOfWork) -> None:
    context = RUN.model_copy(update={"supersedes_binding_id": "f" * 64})
    with pytest.raises(ConflictError):
        record_artifact(uow, "triage", TRIAGE, CLOCK, context)
