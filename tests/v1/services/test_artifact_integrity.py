"""ArtifactPublisher.verify (ported from traust verify_report_digests.py) and RedactionPolicy
(ported from traust-engine tests/test_redact.py)."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
import sqlalchemy as sa

from tests.v1.example.artifact_publishing import example_specs
from tests.v1.fixtures import TRIAGE
from tests.v1.repositories.tables import conftest as table_fixtures
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects.store import ObjectKey
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, RedactionPolicy

engine = table_fixtures.engine


@pytest.mark.parametrize("damage", [None, "truncate", "substitute", "delete"])
def test_verify_rehashes_the_stored_bytes(engine: sa.Engine, damage: str | None) -> None:
    store = InMemoryObjectStore()
    publisher = ArtifactPublisher(example_specs(), store, SqlTraustUnitOfWork(engine))
    raw = json.dumps(json.loads(TRIAGE)).encode()
    published = publisher.publish("triage", raw)
    key = ObjectKey.parse(published.written[0])
    if damage == "truncate":
        store.put(key, raw[:10])
    elif damage == "substitute":
        store.put(key, raw.replace(b"{", b"{ ", 1))
    elif damage == "delete":
        del store._blobs[key]
    check = publisher.verify(published.artifact_id)
    assert (check.recorded, check.uri) == (sha256_hex(raw), str(key))
    assert check.verified is (damage is None)
    assert check.actual == {None: sha256_hex(raw), "delete": None}.get(damage, check.actual)
    if damage in ("truncate", "substitute"):
        assert check.actual not in (None, check.recorded)


def test_verify_of_an_unknown_artifact_is_not_found(engine: sa.Engine) -> None:
    publisher = ArtifactPublisher(
        example_specs(), InMemoryObjectStore(), SqlTraustUnitOfWork(engine)
    )
    with pytest.raises(NotFoundError):
        publisher.verify(uuid4())


POLICY = RedactionPolicy()
BEGIN, END = "-----BEGIN " + "RSA PRIVATE KEY-----", "-----END " + "RSA PRIVATE KEY-----"


@pytest.mark.parametrize(
    ("text", "gone", "kept", "categories"),
    [
        (
            "a AKIAIOSFODNN7EXAMPLE b ghp_" + "x" * 36 + " c glpat-" + "y" * 20,
            ["AKIAIOSFODNN7EXAMPLE", "x" * 36, "y" * 20],
            ["AKIAI...REDACTED"],
            {"aws-access-key", "github-token", "gitlab-token"},
        ),
        ("build id 1234 5678 9012 3456 ok", [], ["1234 5678 9012 3456"], set()),
        (
            "card 4111 1111 1111 1111 x",
            ["4111 1111 1111 1111"],
            ["41111...REDACTED"],
            {"payment-card"},
        ),
        ("ssn 123-45-6789 but not 000-12-3456", ["123-45-6789"], ["000-12-3456"], {"us-ssn"}),
        (
            f"{BEGIN}\nMIIsecretsecret\n{END}",
            ["MIIsecretsecret"],
            [BEGIN, END],
            {"pem-private-key"},
        ),
        (
            "https://svc:sup3rsecret@git.example/x.git",
            ["sup3rsecret"],
            ["svc:"],
            {"url-credentials"},
        ),
        (
            'password = "hunter2secret"',
            ["hunter2secret"],
            ["password", "hunte...REDACTED"],
            {"password-assignment"},
        ),
        (
            "Authorization: Bearer " + "t" * 24,
            ["t" * 24],
            ["Bearer ttttt...REDACTED"],
            {"bearer-token"},
        ),
        ("nothing to see", [], ["nothing to see"], set()),
    ],
    ids=["vendor", "luhn-fails", "card", "ssn", "pem", "url", "assignment", "bearer", "clean"],
)
def test_redaction(text: str, gone: list[str], kept: list[str], categories: set[str]) -> None:
    out = POLICY.redact(text.encode())
    clean = out.payload.decode()
    assert not [g for g in gone if g in clean]
    assert all(k in clean for k in kept)
    assert {h.category for h in out.hits} == categories
    assert all(len(h.match_prefix) <= 5 for h in out.hits)


def test_redaction_is_idempotent() -> None:
    once = POLICY.redact(b"key AKIAIOSFODNN7EXAMPLE end")
    assert POLICY.redact(once.payload).hits == ()


def test_high_confidence_is_vendor_formats_only() -> None:
    hits = POLICY.redact(b'AKIAIOSFODNN7EXAMPLE password = "hunter2secret"').hits
    assert {h.category: h.high_confidence for h in hits} == {
        "aws-access-key": True,
        "password-assignment": False,
    }


def test_redaction_reads_text_only() -> None:
    with pytest.raises(ValidationError, match="UTF-8"):
        POLICY.redact(b"\xff\xfe")
