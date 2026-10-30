"""LedgerService on SQLite and Postgres: append in the decision's transaction, restamp and
sign like traust-ledger's write path, verify detects tampering."""

from __future__ import annotations

import json
import logging
import subprocess
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed, saved_id
from traust_core.v1.context import Config, Context, LoggingConfig
from traust_core.v1.errors import (
    ConflictError,
    ForbiddenError,
    IntegrityError,
    NotFoundError,
    ServiceError,
    ValidationError,
)
from traust_core.v1.models.common import Cursor, PageRequest
from traust_core.v1.models.findings import Decision
from traust_core.v1.models.identity import IdentitySource, Principal, Role
from traust_core.v1.models.ledger import Event, Signing
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.correlation import correlation_scope
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.ledger import LedgerConfig, LedgerService


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[str, str]:
    """A throwaway cosign keypair (cosign reads the empty password from the environment)."""
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    prefix = tmp_path / "ledger"
    subprocess.run(
        ["cosign", "generate-key-pair", "--output-key-prefix", str(prefix)],
        check=True,
        capture_output=True,
    )
    return f"{prefix}.key", f"{prefix}.pub"


ADMIN = Principal(
    identity="admin@example.com",
    kind=ActorKind.HUMAN,
    display="admin",
    verified_by=IdentitySource.OIDC,
    roles=frozenset({Role.ADMIN}),
)


def ledger(uow: SqlTraustUnitOfWork, **config: object) -> LedgerService:
    return LedgerService(uow, LedgerConfig.model_validate(config))


def decisions(engine: Engine, n: int) -> tuple[UUID, list[Decision]]:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo, made = seed.repository(), [seed.decision() for _ in range(n)]
        uow.commit()
    assert repo.id is not None
    return repo.id, made


def tamper(engine: Engine, change: Callable[[sa.Table, sa.Table], sa.Executable]) -> None:
    """Change ledger rows behind the app's back, append-only triggers off (this test's own db)."""
    with SqlTraustUnitOfWork(engine) as uow:
        conn = uow.connection
        if conn.dialect.name == "postgresql":
            conn.execute(sa.text("ALTER TABLE traust_ledger.events DISABLE TRIGGER USER"))
        else:
            conn.execute(sa.text("DROP TRIGGER IF EXISTS ledger_events_reject_update"))
            conn.execute(sa.text("DROP TRIGGER IF EXISTS ledger_events_reject_delete"))
        conn.execute(change(uow.events.table, uow.layers.table))
        uow.commit()


def test_first_append_opens_the_repository_layer_and_stamps_it(engine: Engine) -> None:
    repo_id, (decision,) = decisions(engine, 1)
    receipt = ledger(SqlTraustUnitOfWork(engine)).append_decision(decision, repo_id)
    layer = receipt.checkpoint.layer
    assert (layer.repository_id, layer.line, layer.merkle_signing_method) == (
        repo_id,
        None,
        "keypair",
    )
    assert (layer.merkle_size, layer.merkle_epoch, layer.merkle_root_signature) == (1, 0, None)
    assert receipt.event.seq == 0
    assert receipt.event.decision_id == decision.id
    assert (receipt.checkpoint.signing, receipt.checkpoint.warning) == (Signing.UNCONFIGURED, None)


def test_appends_take_the_next_seq_and_advance_the_root(engine: Engine) -> None:
    repo_id, made = decisions(engine, 3)
    service = ledger(SqlTraustUnitOfWork(engine))
    receipts = [service.append_decision(d, repo_id) for d in made]
    assert [r.event.seq for r in receipts] == [0, 1, 2]
    assert len({r.checkpoint.layer.merkle_root for r in receipts}) == 3
    assert len({r.checkpoint.layer.id for r in receipts}) == 1
    final = receipts[-1].checkpoint.layer
    assert final.merkle_size == 3
    assert final.id is not None
    assert service.verify(final.id).passed


def test_append_is_idempotent_per_decision(engine: Engine) -> None:
    repo_id, (decision,) = decisions(engine, 1)
    service = ledger(SqlTraustUnitOfWork(engine))
    first = service.append_decision(decision, repo_id)
    again = service.append_decision(decision, repo_id)
    assert again.event == first.event
    assert again.checkpoint.layer.merkle_root == first.checkpoint.layer.merkle_root
    assert again.checkpoint.layer.merkle_size == 1


def test_append_event_waits_for_commit_and_skips_rollback_and_retry(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    repo_id, (first, second) = decisions(engine, 2)
    uow = SqlTraustUnitOfWork(engine)
    with caplog.at_level(logging.INFO, logger="traust_core.v1.services.ledger"):
        with uow:
            ledger(uow).append_decision(first, repo_id)
            assert "ledger append" not in caplog.text
            uow.commit()
        with uow:
            ledger(uow).append_decision(second, repo_id)
        ledger(uow).append_decision(first, repo_id)
        with uow:
            uow.commit()
    events = [r.getMessage() for r in caplog.records if r.name == "traust_core.v1.services.ledger"]
    assert len(events) == 1
    assert str(first.id) in events[0] and str(second.id) not in events[0]
    assert "duration_ms=" in events[0]


def test_deferred_ledger_event_keeps_its_request_scope(engine: Engine, tmp_path: Path) -> None:
    file = tmp_path / "ledger.log"
    Context(
        Config(home=tmp_path, logging=LoggingConfig(level="INFO", file=file))
    ).configure_logging()
    repo_id, (decision,) = decisions(engine, 1)
    uow = SqlTraustUnitOfWork(engine)
    with uow:
        with correlation_scope("job-123"):
            ledger(uow).append_decision(decision, repo_id)
        uow.commit()
    records = [json.loads(line) for line in file.read_text().splitlines()]
    events = [row for row in records if row["message"].startswith("ledger append")]
    assert len(events) == 1 and events[0]["request_id"] == "job-123"


def test_an_unsaved_decision_is_rejected(engine: Engine) -> None:
    repo_id, (decision,) = decisions(engine, 1)
    with pytest.raises(ValidationError, match="saved decision"):
        ledger(SqlTraustUnitOfWork(engine)).append_decision(
            decision.model_copy(update={"id": None}), repo_id
        )


@pytest.mark.parametrize("commit", [False, True])
def test_append_joins_the_callers_transaction(engine: Engine, commit: bool) -> None:
    uow = SqlTraustUnitOfWork(engine)
    with uow:
        seed = Seed(uow)
        repo, decision = seed.repository(), seed.decision()
        assert repo.id is not None and decision.id is not None
        ledger(uow).append_decision(decision, repo.id)  # its commit waits for ours
        if commit:
            uow.commit()
    with SqlTraustUnitOfWork(engine) as check:
        proof = check.events.find_by_decision(decision.id)
        layer = check.layers.find_for_update(repo.id)
    assert (proof is not None, layer is not None) == (commit, commit)


def test_a_racing_first_append_is_rejected_not_a_second_chain(engine: Engine) -> None:
    if engine.dialect.name != "postgresql":
        pytest.skip("SQLite serialises writers; concurrency is a Postgres property")
    repo_id, (first, second) = decisions(engine, 2)
    outcome: list[object] = []

    def racer() -> None:
        try:
            outcome.append(ledger(SqlTraustUnitOfWork(engine)).append_decision(second, repo_id))
        except ConflictError as e:
            outcome.append(e)

    holder = SqlTraustUnitOfWork(engine)
    with holder:
        ledger(holder).append_decision(first, repo_id)  # layer created, not yet committed
        thread = threading.Thread(target=racer)
        thread.start()
        thread.join(timeout=0.3)  # the racer can't see our layer, so it inserts its own
        holder.commit()
    thread.join()
    assert isinstance(outcome[0], ConflictError)  # the layer key made it wait, then refused
    with SqlTraustUnitOfWork(engine) as uow:
        assert len(uow.layers.list_for_repository(repo_id)) == 1


def test_verify_detects_a_tampered_event(engine: Engine) -> None:
    repo_id, made = decisions(engine, 3)
    service = ledger(SqlTraustUnitOfWork(engine))
    layer = [service.append_decision(d, repo_id) for d in made][-1].checkpoint.layer
    assert layer.id is not None
    tamper(
        engine,
        lambda events, _: (
            sa.update(events)
            .where(events.c.seq == 1)
            .values(event_payload=b'{"validity":"false_positive"}')
        ),
    )
    result = service.verify(layer.id)
    assert not result.passed
    assert any("merkle_root mismatch" in e for e in result.errors)


def test_verify_detects_a_removed_event(engine: Engine) -> None:
    repo_id, made = decisions(engine, 2)
    service = ledger(SqlTraustUnitOfWork(engine))
    layer = [service.append_decision(d, repo_id) for d in made][-1].checkpoint.layer
    assert layer.id is not None
    tamper(engine, lambda events, _: sa.delete(events).where(events.c.seq == 0))
    errors = service.verify(layer.id).errors
    assert any("merkle_root mismatch" in e for e in errors)
    assert any("merkle_size mismatch" in e for e in errors)


def test_verify_detects_a_forged_event(engine: Engine) -> None:
    repo_id, (real, forged) = decisions(engine, 2)
    service = ledger(SqlTraustUnitOfWork(engine))
    layer = service.append_decision(real, repo_id).checkpoint.layer
    assert layer.id is not None
    with SqlTraustUnitOfWork(engine) as uow:  # append-only allows inserts; only the app restamps
        uow.events.add(Event(layer_id=layer.id, decision_id=forged.id, seq=1, event_payload=b"{}"))
        uow.commit()
    assert any("merkle_root mismatch" in e for e in service.verify(layer.id).errors)


def test_verify_detects_an_edited_root(engine: Engine) -> None:
    repo_id, (decision,) = decisions(engine, 1)
    service = ledger(SqlTraustUnitOfWork(engine))
    layer = service.append_decision(decision, repo_id).checkpoint.layer
    assert layer.id is not None
    tamper(engine, lambda _, layers: sa.update(layers).values(merkle_root="00" * 32))
    assert any("merkle_root mismatch" in e for e in service.verify(layer.id).errors)


def test_an_unsigned_layer_fails_verify_when_signing_is_required(engine: Engine) -> None:
    repo_id, (decision,) = decisions(engine, 1)
    layer = ledger(SqlTraustUnitOfWork(engine)).append_decision(decision, repo_id).checkpoint.layer
    assert layer.id is not None
    result = ledger(SqlTraustUnitOfWork(engine), required=True).verify(layer.id)
    assert any("absent" in e for e in result.errors)


def test_verify_an_unknown_layer_raises(engine: Engine) -> None:
    with pytest.raises(NotFoundError):
        ledger(SqlTraustUnitOfWork(engine)).verify(uuid4())


def test_a_signed_root_verifies_with_the_public_key(engine: Engine, keys: tuple[str, str]) -> None:
    private, public = keys
    repo_id, made = decisions(engine, 2)
    service = ledger(
        SqlTraustUnitOfWork(engine),
        key_path=private,
        public_key_path=public,
    )
    checkpoint = [service.append_decision(d, repo_id) for d in made][-1].checkpoint
    layer = checkpoint.layer
    assert (checkpoint.signing, checkpoint.warning) == (Signing.SIGNED, None)
    assert layer.merkle_root_signature
    assert layer.merkle_signature_format == 4
    assert layer.id is not None
    assert service.verify(layer.id).passed

    tamper(engine, lambda _, layers: sa.update(layers).values(merkle_root_signature="AAAA"))
    assert service.verify(layer.id).errors  # the root still matches; the signature doesn't

    tamper(engine, lambda events, _: sa.update(events).values(event_payload=b"{}"))
    assert not service.verify(layer.id).passed


def test_a_signed_layer_without_the_public_key_does_not_pass(
    engine: Engine, keys: tuple[str, str]
) -> None:
    repo_id, (decision,) = decisions(engine, 1)
    signer = ledger(SqlTraustUnitOfWork(engine), key_path=keys[0])
    layer = signer.append_decision(decision, repo_id).checkpoint.layer
    assert layer.id is not None
    result = signer.verify(layer.id)
    assert (result.errors, result.passed) == ((), False)
    assert any("no public key" in w for w in result.warnings)


def test_an_unsigned_append_drops_the_stale_signature(
    engine: Engine, keys: tuple[str, str]
) -> None:
    repo_id, (first, second) = decisions(engine, 2)
    signed = ledger(SqlTraustUnitOfWork(engine), key_path=keys[0])
    signed.append_decision(first, repo_id)
    checkpoint = ledger(SqlTraustUnitOfWork(engine)).append_decision(second, repo_id).checkpoint
    assert checkpoint.signing is Signing.UNCONFIGURED
    assert checkpoint.layer.merkle_root_signature is None
    assert checkpoint.warning is not None and "UNSIGNED" in checkpoint.warning


def test_required_signing_without_a_key_rolls_the_append_back(engine: Engine) -> None:
    repo_id, (decision,) = decisions(engine, 1)
    assert decision.id is not None
    with pytest.raises(ServiceError, match="not signed"):
        ledger(SqlTraustUnitOfWork(engine), required=True).append_decision(decision, repo_id)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.events.find_by_decision(decision.id) is None
        assert uow.layers.find_for_update(repo_id) is None


def test_checkpoint_signs_an_existing_layer(engine: Engine, keys: tuple[str, str]) -> None:
    private, public = keys
    repo_id, (decision,) = decisions(engine, 1)
    unsigned = ledger(SqlTraustUnitOfWork(engine)).append_decision(decision, repo_id)
    signer = ledger(
        SqlTraustUnitOfWork(engine),
        key_path=private,
        public_key_path=public,
    )
    checkpoint = signer.checkpoint(repo_id, ADMIN)
    assert checkpoint.signing is Signing.SIGNED
    assert checkpoint.layer.merkle_root == unsigned.checkpoint.layer.merkle_root
    assert checkpoint.layer.id is not None
    assert signer.verify(checkpoint.layer.id).passed


def test_checkpoint_without_a_layer_raises(engine: Engine) -> None:
    with pytest.raises(NotFoundError):
        ledger(SqlTraustUnitOfWork(engine)).checkpoint(uuid4(), ADMIN)


def test_checkpoint_emits_one_safe_committed_outcome(
    engine: Engine, keys: tuple[str, str], caplog: pytest.LogCaptureFixture
) -> None:
    repo_id, layer_id = appended(engine, 1)
    uow = SqlTraustUnitOfWork(engine)
    service = ledger(uow, key_path=keys[0], public_key_path=keys[1])
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="traust_core.v1.services.ledger"), uow:
        checkpoint = service.checkpoint(repo_id, ADMIN)
        assert not any(
            getattr(record, "operation", None) == "ledger.checkpoint" for record in caplog.records
        )
        uow.commit()
    records = [
        record
        for record in caplog.records
        if getattr(record, "operation", None) == "ledger.checkpoint"
    ]
    assert len(records) == 1
    record = records[0]
    assert (record.outcome, record.repository_id, record.layer_id, record.status) == (
        "committed",
        str(repo_id),
        str(layer_id),
        "signed",
    )
    assert checkpoint.layer.merkle_root not in caplog.text
    assert keys[0] not in caplog.text and ADMIN.identity not in caplog.text


def appended(engine: Engine, n: int) -> tuple[UUID, UUID]:
    """n decisions appended to one repository's layer: (repository_id, layer_id)."""
    repo_id, made = decisions(engine, n)
    with SqlTraustUnitOfWork(engine) as uow:
        service = ledger(uow)
        receipts = [service.append_decision(d, repo_id) for d in made]
        uow.commit()
    layer_id = receipts[-1].checkpoint.layer.id if receipts else None
    assert layer_id is not None
    return repo_id, layer_id


def test_a_repositorys_layers_and_one_layer_read_back(engine: Engine) -> None:
    repo_id, layer_id = appended(engine, 2)
    service = ledger(SqlTraustUnitOfWork(engine))
    (layer,) = service.layers(repo_id)
    assert layer.id == layer_id and layer.merkle_size == 2
    assert service.layer(layer_id) == layer
    assert service.layers(uuid4()) == []
    with pytest.raises(NotFoundError):
        service.layer(uuid4())


@pytest.mark.parametrize(
    ("limit", "pages"),
    [(10, [[0, 1, 2]]), (2, [[0, 1], [2]]), (3, [[0, 1, 2]]), (1, [[0], [1], [2]])],
)
def test_events_page_by_seq(engine: Engine, limit: int, pages: list[list[int]]) -> None:
    _, layer_id = appended(engine, 3)
    service, seen, cursor = ledger(SqlTraustUnitOfWork(engine)), [], None
    while True:
        page = service.events(layer_id, PageRequest(limit=limit, cursor=cursor))
        seen.append([e.seq for e in page.items])
        if page.next is None:
            break
        cursor = page.next
    assert seen == pages


def test_events_of_an_unknown_layer_or_with_a_bad_cursor_are_refused(engine: Engine) -> None:
    _, layer_id = appended(engine, 1)
    service = ledger(SqlTraustUnitOfWork(engine))
    with pytest.raises(NotFoundError):
        service.events(uuid4(), PageRequest())
    with pytest.raises(ValidationError):
        service.events(layer_id, PageRequest(cursor=Cursor("seven")))
    assert service.events(layer_id, PageRequest(cursor=Cursor("0"))).items == ()


@pytest.mark.parametrize(
    "who",
    [
        ADMIN.model_copy(update={"roles": frozenset()}),
        ADMIN.model_copy(update={"verified_by": None}),
        ADMIN.model_copy(update={"kind": ActorKind.MACHINE, "roles": frozenset()}),
    ],
    ids=["no admin role", "unverified", "a machine without the role"],
)
def test_a_checkpoint_is_an_admins(engine: Engine, who: Principal) -> None:
    repo_id, _ = appended(engine, 1)
    with pytest.raises(ForbiddenError):
        ledger(SqlTraustUnitOfWork(engine)).checkpoint(repo_id, who)


def test_verification_reports_whether_it_passed(engine: Engine) -> None:
    _, layer_id = appended(engine, 2)
    result = ledger(SqlTraustUnitOfWork(engine)).verify(layer_id)
    assert result.passed and result.model_dump()["passed"] is True


def test_a_service_account_admin_checkpoints(engine: Engine) -> None:
    repo_id, _ = appended(engine, 1)
    rotation = ADMIN.model_copy(update={"identity": "key-rotation", "kind": ActorKind.MACHINE})
    assert ledger(SqlTraustUnitOfWork(engine)).checkpoint(repo_id, rotation).layer.merkle_size == 1


def keypair(tmp_path: Path, name: str) -> tuple[str, str]:
    """Another throwaway cosign keypair (the `keys` fixture sets the empty password)."""
    prefix = tmp_path / name
    subprocess.run(
        ["cosign", "generate-key-pair", "--output-key-prefix", str(prefix)],
        check=True,
        capture_output=True,
    )
    return f"{prefix}.key", f"{prefix}.pub"


def test_checkpoint_refuses_to_sign_over_tampered_events(engine: Engine) -> None:
    repo_id, layer_id = appended(engine, 3)
    tamper(
        engine,
        lambda events, _: sa.update(events).where(events.c.seq == 1).values(event_payload=b"{}"),
    )
    service = ledger(SqlTraustUnitOfWork(engine))
    before = service.layer(layer_id)
    with pytest.raises(IntegrityError, match="merkle_root mismatch"):
        service.checkpoint(repo_id, ADMIN)
    assert service.layer(layer_id) == before


def test_failed_checkpoint_does_not_claim_committed_success(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    repo_id, _ = appended(engine, 2)
    tamper(engine, lambda events, _: sa.update(events).values(event_payload=b"{}"))
    caplog.clear()
    with (
        caplog.at_level(logging.INFO, logger="traust_core.v1.services.ledger"),
        pytest.raises(IntegrityError),
    ):
        ledger(SqlTraustUnitOfWork(engine)).checkpoint(repo_id, ADMIN)
    assert not any(
        getattr(record, "operation", None) == "ledger.checkpoint" for record in caplog.records
    )


def test_checkpoint_refuses_a_signature_that_does_not_verify(
    engine: Engine, keys: tuple[str, str]
) -> None:
    private, public = keys
    repo_id, (decision,) = decisions(engine, 1)
    signer = ledger(SqlTraustUnitOfWork(engine), key_path=private, public_key_path=public)
    layer_id = signer.append_decision(decision, repo_id).checkpoint.layer.id
    assert layer_id is not None
    tamper(engine, lambda _, layers: sa.update(layers).values(merkle_root_signature="AAAA"))
    with pytest.raises(IntegrityError, match="won't be re-signed"):
        signer.checkpoint(repo_id, ADMIN)
    assert signer.layer(layer_id).merkle_root_signature == "AAAA"


def test_a_key_rotation_re_signs_with_the_new_key(
    engine: Engine, keys: tuple[str, str], tmp_path: Path
) -> None:
    old_private, old_public = keys
    new_private, new_public = keypair(tmp_path, "rotated")
    repo_id, (decision,) = decisions(engine, 1)
    old = ledger(SqlTraustUnitOfWork(engine), key_path=old_private, public_key_path=old_public)
    layer_id = old.append_decision(decision, repo_id).checkpoint.layer.id
    assert layer_id is not None
    new_only = ledger(SqlTraustUnitOfWork(engine), key_path=new_private, public_key_path=new_public)
    with pytest.raises(IntegrityError):
        new_only.checkpoint(repo_id, ADMIN)  # the old signature verifies against no configured key
    rotating = ledger(
        SqlTraustUnitOfWork(engine),
        key_path=new_private,
        public_key_path=new_public,
        previous_public_key_path=old_public,
    )
    assert rotating.verify(layer_id).passed
    assert rotating.checkpoint(repo_id, ADMIN).signing is Signing.SIGNED
    assert new_only.verify(layer_id).passed


def test_checkpoint_signs_an_unsigned_layer_even_when_signing_is_required(
    engine: Engine, keys: tuple[str, str]
) -> None:
    private, public = keys
    repo_id, _ = appended(engine, 2)
    strict = ledger(
        SqlTraustUnitOfWork(engine), key_path=private, public_key_path=public, required=True
    )
    checkpoint = strict.checkpoint(repo_id, ADMIN)
    assert checkpoint.signing is Signing.SIGNED
    assert checkpoint.layer.id is not None and strict.verify(checkpoint.layer.id).passed


def appended_with_one_left(engine: Engine) -> tuple[UUID, UUID, Decision]:
    """Three decisions appended, a fourth seeded but not yet appended."""
    repo_id, (*earlier, latest) = decisions(engine, 4)
    with SqlTraustUnitOfWork(engine) as uow:
        service = ledger(uow)
        layer_id = [service.append_decision(d, repo_id) for d in earlier][-1].checkpoint.layer.id
        uow.commit()
    assert layer_id is not None
    return repo_id, layer_id, latest


@pytest.mark.parametrize(
    "edit",
    [
        lambda events, _: sa.update(events).where(events.c.seq == 1).values(event_payload=b"{}"),
        lambda events, _: sa.delete(events).where(events.c.seq == 0),
    ],
    ids=["an edited event", "a removed event"],
)
def test_an_append_never_folds_an_edit_into_the_root(engine: Engine, edit: Any) -> None:
    repo_id, layer_id, latest = appended_with_one_left(engine)
    tamper(engine, edit)
    service = ledger(SqlTraustUnitOfWork(engine))
    service.append_decision(latest, repo_id)
    result = service.verify(layer_id)
    assert not result.passed
    assert any("merkle_root mismatch" in e for e in result.errors)


@pytest.mark.parametrize(
    "edit",
    [
        lambda _, layers: sa.update(layers).values(merkle_root=None),
        lambda _, layers: sa.update(layers).values(merkle_root="00" * 32),
        lambda _, layers: sa.update(layers).values(merkle_frontier="00" * 32),
        lambda _, layers: sa.update(layers).values(merkle_size=7),
        lambda events, _: sa.update(events).where(events.c.seq == 2).values(seq=3),
    ],
    ids=[
        "a removed root",
        "an edited root",
        "an edited frontier",
        "an edited size",
        "a moved event",
    ],
)
def test_an_append_refuses_a_layer_whose_tree_was_edited(engine: Engine, edit: Any) -> None:
    repo_id, layer_id, latest = appended_with_one_left(engine)
    tamper(engine, edit)
    service = ledger(SqlTraustUnitOfWork(engine))
    before = service.layer(layer_id)
    with pytest.raises(IntegrityError, match="disagree"):
        service.append_decision(latest, repo_id)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.events.find_by_decision(latest.id) is None
    assert service.layer(layer_id) == before


def test_a_repeated_append_changes_nothing(engine: Engine) -> None:
    repo_id, made = decisions(engine, 2)
    with SqlTraustUnitOfWork(engine) as uow:
        service = ledger(uow)
        first = service.append_decision(made[0], repo_id)
        service.append_decision(made[1], repo_id)
        uow.commit()
    service = ledger(SqlTraustUnitOfWork(engine))
    layer_id = first.checkpoint.layer.id
    assert layer_id is not None
    before = service.layer(layer_id)
    again = service.append_decision(made[0], repo_id)
    assert again.event == first.event and service.layer(layer_id) == before


def test_appends_from_the_frontier_match_a_full_rebuild(engine: Engine) -> None:
    _, layer_id = appended(engine, 37)
    service = ledger(SqlTraustUnitOfWork(engine))
    layer = service.layer(layer_id)
    assert service.verify(layer_id).errors == ()
    assert layer.merkle_size == 37 and layer.merkle_frontier is not None
    assert len(layer.merkle_frontier.split(",")) == (37).bit_count()


def test_an_older_layer_without_a_frontier_gets_one_verified_first(engine: Engine) -> None:
    repo_id, layer_id, latest = appended_with_one_left(engine)
    tamper(engine, lambda _, layers: sa.update(layers).values(merkle_frontier=None))
    service = ledger(SqlTraustUnitOfWork(engine))
    service.append_decision(latest, repo_id)
    assert service.verify(layer_id).errors == ()
    assert service.layer(layer_id).merkle_frontier is not None


def test_an_older_layer_with_edited_events_gets_no_frontier(engine: Engine) -> None:
    repo_id, _, latest = appended_with_one_left(engine)
    tamper(engine, lambda _, layers: sa.update(layers).values(merkle_frontier=None))
    tamper(
        engine,
        lambda events, _: sa.update(events).where(events.c.seq == 0).values(event_payload=b"{}"),
    )
    with pytest.raises(IntegrityError, match="won't be re-signed"):
        ledger(SqlTraustUnitOfWork(engine)).append_decision(latest, repo_id)


def test_a_layer_with_a_pre_epoch_prefix_is_refused(engine: Engine) -> None:
    repo_id, _, latest = appended_with_one_left(engine)
    tamper(engine, lambda _, layers: sa.update(layers).values(merkle_epoch=2))
    with pytest.raises(IntegrityError, match="pre-epoch"):
        ledger(SqlTraustUnitOfWork(engine)).append_decision(latest, repo_id)


def test_unsigned_appends_then_one_seal(engine: Engine, keys: tuple[str, str]) -> None:
    private, public = keys
    repo_id, made = decisions(engine, 3)
    signer = ledger(SqlTraustUnitOfWork(engine), key_path=private, public_key_path=public)
    receipts = [signer.append_decision(d, repo_id, sign=False) for d in made]
    layer_id = receipts[-1].checkpoint.layer.id
    assert layer_id is not None
    assert signer.layer(layer_id).merkle_root_signature is None
    sealed = signer.seal(repo_id)
    assert sealed.signing is Signing.SIGNED and signer.verify(layer_id).passed
    assert signer.seal(repo_id).layer == sealed.layer  # already signed: nothing to do
    with pytest.raises(NotFoundError):
        signer.seal(uuid4())


def test_an_append_after_a_signed_root_drops_the_stale_signature(
    engine: Engine, keys: tuple[str, str]
) -> None:
    private, public = keys
    repo_id, made = decisions(engine, 2)
    signer = ledger(SqlTraustUnitOfWork(engine), key_path=private, public_key_path=public)
    signer.append_decision(made[0], repo_id)
    unsigned = signer.append_decision(made[1], repo_id, sign=False).checkpoint
    assert unsigned.layer.merkle_root_signature is None
    assert unsigned.warning and "seal" in unsigned.warning


def test_signing_required_without_a_key_is_refused_up_front(
    engine: Engine, keys: tuple[str, str], tmp_path: Path
) -> None:
    with pytest.raises(ServiceError, match="not signed"):
        ledger(SqlTraustUnitOfWork(engine), required=True).require_signable()
    with pytest.raises(ServiceError, match="not signed"):
        ledger(
            SqlTraustUnitOfWork(engine), required=True, key_path=str(tmp_path / "missing.key")
        ).require_signable()
    ledger(SqlTraustUnitOfWork(engine), required=True, key_path=keys[0]).require_signable()
    ledger(SqlTraustUnitOfWork(engine)).require_signable()


def test_a_checkpoint_gives_an_older_layer_its_frontier(engine: Engine) -> None:
    repo_id, _ = appended(engine, 5)
    tamper(engine, lambda _, layers: sa.update(layers).values(merkle_frontier=None))
    service = ledger(SqlTraustUnitOfWork(engine))
    assert service.checkpoint(repo_id, ADMIN).layer.merkle_frontier is not None


def layers(engine: Engine, n: int) -> list[UUID]:
    """One decision appended for each of n repositories: their layer ids."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed, service = Seed(uow), ledger(uow)
        made = [
            (saved_id(seed.repository(url=f"https://github.com/org/audit-{i}")), seed.decision())
            for i in range(n)
        ]
        receipts = [service.append_decision(d, repo_id) for repo_id, d in made]
        uow.commit()
    return [saved_id(r.checkpoint.layer) for r in receipts]


def test_verify_and_audit_emit_bounded_terminal_summaries(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    _, layer_id = appended(engine, 1)
    tamper(engine, lambda events, _: sa.update(events).values(event_payload=b"{}"))
    service = ledger(SqlTraustUnitOfWork(engine))
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="traust_core.v1.services.ledger"):
        assert not service.verify(layer_id).passed
        assert not service.audit()[0].passed
    records = [
        record
        for record in caplog.records
        if getattr(record, "operation", None) in {"ledger.verify", "ledger.audit"}
    ]
    assert [(record.operation, record.outcome, record.count) for record in records] == [
        ("ledger.verify", "invalid", 1),
        ("ledger.audit", "invalid", 1),
    ]
    assert all(record.errors > 0 for record in records)
    assert "merkle_root mismatch" not in caplog.text
    assert 'event_payload=b"{}"' not in caplog.text


def test_audit_verifies_every_layer_and_names_the_tampered_one(engine: Engine) -> None:
    clean, edited = layers(engine, 2)
    tamper(
        engine,
        lambda events, _: (
            sa.update(events)
            .where(events.c.layer_id == edited, events.c.seq == 0)
            .values(event_payload=b"{}")
        ),
    )
    results = {r.layer_id: r for r in ledger(SqlTraustUnitOfWork(engine)).audit()}
    assert set(results) == {clean, edited}
    assert results[clean].passed
    assert any("merkle_root mismatch" in e for e in results[edited].errors)


def test_audit_of_an_empty_ledger_is_empty(engine: Engine) -> None:
    assert ledger(SqlTraustUnitOfWork(engine)).audit() == []


def test_audit_walks_past_one_batch(engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("traust_core.v1.services.ledger.AUDIT_BATCH", 2)
    made = layers(engine, 5)
    assert sorted(r.layer_id for r in ledger(SqlTraustUnitOfWork(engine)).audit()) == sorted(made)
