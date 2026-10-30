from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables import conftest as table_fixtures
from traust_core.v1.errors import DocumentError, ValidationError
from traust_core.v1.models.analysis_results import ResultKind
from traust_core.v1.models.artifacts import SecurityAuditArtifact
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects.store import ObjectKey
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    Companion,
    PublishSpec,
    PublishSpecs,
    RedactionHit,
    RedactionPolicy,
)

engine = table_fixtures.engine
REPORT = Path(__file__).parents[2] / "fixtures/assessments/widget-audit-report.json"
SECRET = "gh" + "p_" + "a1" * 18
SECRETS = [
    ("aws-access-key", "AKIA" + "IOSFODNN7EXAMPLE"),
    ("github-token", SECRET),
    ("github-pat", "github" + "_pat_" + "B2" * 12),
    ("gitlab-token", "glpat" + "-" + "c3" * 11),
    ("slack-token", "xox" + "b-1234567890abc"),
    ("google-api-key", "AIza" + "e" * 35),
    ("jwt", "eyJhbGciOiJIUz.eyJzdWIiOiIx.SflKxwRJSMeK"),
    (
        "pem-private-key",
        "-----BEGIN RSA PRIVATE KEY-----\nprivate material\n-----END RSA PRIVATE KEY-----",
    ),
    ("azure-client-secret", "\nabc8Q~" + "g" * 32),
    ("gcp-sa-key", 'Service-account JSON: {"private_key_id": "' + "a" * 40 + '"}'),
]


def audit(text: str) -> bytes:
    doc = json.loads(REPORT.read_bytes())
    doc["executive_summary"]["prose"] += f" Evidence: {text}"
    return (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode()


def markdown(doc: SecurityAuditArtifact) -> bytes:
    return f"# {doc.title}\n\n{doc.executive_summary.prose}\n".encode()


@dataclass
class Publishing:
    publisher: ArtifactPublisher
    objects: InMemoryObjectStore
    uow: SqlTraustUnitOfWork

    def with_companions(self, *companions: Companion[SecurityAuditArtifact]) -> ArtifactPublisher:
        specs = PublishSpecs(PublishSpec(SecurityAuditArtifact, companions=companions))
        return ArtifactPublisher(specs, self.objects, self.uow)


@pytest.fixture
def publishing(engine: Engine) -> Publishing:
    objects, uow = InMemoryObjectStore(), SqlTraustUnitOfWork(engine)
    specs = PublishSpecs(
        PublishSpec(
            SecurityAuditArtifact,
            companions=(Companion(ResultKind.SECURITY_AUDIT_MD, markdown),),
        )
    )
    return Publishing(ArtifactPublisher(specs, objects, uow), objects, uow)


@pytest.mark.parametrize(
    "entrypoint",
    [
        "publish",
        "publish_artifact",
        "publish_artifact_with_status",
        "publish_ref",
        "publish_successor",
    ],
)
@pytest.mark.parametrize("source", ["primary", "escaped", "companion"])
def test_every_publication_entry_point_refuses_secrets_before_any_write(
    publishing: Publishing,
    entrypoint: str,
    source: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    raw = audit(SECRET if source != "companion" else "Sanitized audit evidence.")
    publisher = publishing.publisher
    if source == "escaped":
        escaped = "".join(f"\\u{ord(c):04x}" for c in SECRET).encode()
        raw = raw.replace(SECRET.encode(), escaped)
        assert SECRET.encode() not in raw
    elif source == "companion":
        publisher = publishing.with_companions(
            Companion(ResultKind.SECURITY_AUDIT_MD, markdown),
            Companion(ResultKind.THREAT_MODEL_MD, lambda _: SECRET.encode()),
        )
    doc = SecurityAuditArtifact.parse(raw)
    with (
        caplog.at_level(logging.INFO, logger="traust_core.v1.services.artifact_publishing"),
        pytest.raises(DocumentError) as err,
    ):
        if entrypoint == "publish":
            publisher.publish(doc.name, raw)
        elif entrypoint == "publish_successor":
            publisher.publish_successor(doc, None)
        else:
            getattr(publisher, entrypoint)(doc)
    assert isinstance(err.value, ValidationError)
    assert err.value.document == "security-audit"
    assert {i.path for i in err.value.issues} == (
        {"companions/threat-model.md"} if source == "companion" else {"$"}
    )
    assert "github-token" in str(err.value)
    assert SECRET not in str(err.value) + repr(err.value.issues) + caplog.text
    assert SECRET[:5] not in str(err.value) + repr(err.value.issues)
    assert list(publishing.objects.list()) == []
    assert "artifact published" not in caplog.text
    with publishing.uow as uow:
        assert uow.artifacts.latest_imported("report") is None


@pytest.mark.parametrize(
    "text",
    [
        "Clean audit evidence: café, Δ and a tenant boundary.",
        'password = "quoted-evidence"; URL https://svc:dummy-password@example.test/path',
        "SSN 123-45-6789 and test card 4111 1111 1111 1111",
        "ghp_a...REDACTED",
    ],
    ids=["clean-unicode", "heuristics", "ssn-and-card", "already-redacted"],
)
def test_accepted_evidence_keeps_its_bytes_digest_and_idempotent_identity(
    publishing: Publishing, text: str
) -> None:
    raw = audit(text)
    result = publishing.publisher.publish("security-audit", raw)
    assert publishing.publisher.get(result.artifact_id).payload == raw
    assert publishing.publisher.verify(result.artifact_id).verified
    assert publishing.publisher.metadata(result.artifact_id).digest == sha256_hex(raw)
    assert publishing.publisher.publish("security-audit", raw) == result
    companion = publishing.objects.stat(ObjectKey.parse(result.written[1]))
    assert publishing.objects.get(companion) == markdown(SecurityAuditArtifact.parse(raw))


def test_explicit_redaction_can_be_published_without_another_rewrite(
    publishing: Publishing,
) -> None:
    redacted = RedactionPolicy().redact(audit(SECRET))
    assert redacted.hits
    result = publishing.publisher.publish("security-audit", redacted.payload)
    assert publishing.publisher.get(result.artifact_id).payload == redacted.payload
    assert publishing.publisher.verify(result.artifact_id).verified


@pytest.mark.parametrize("source", ["primary", "companion"])
def test_a_rejected_successor_leaves_prior_bytes_and_metadata_intact(
    publishing: Publishing, source: str
) -> None:
    prior = publishing.publisher.publish("security-audit", audit("Prior evidence."))
    before = {key: publishing.objects.stat(key) for key in publishing.objects.list()}
    publisher = publishing.publisher
    raw = audit(SECRET)
    if source == "companion":
        publisher = publishing.with_companions(
            Companion(ResultKind.SECURITY_AUDIT_MD, lambda _: SECRET.encode())
        )
        raw = audit("Next evidence.")
    with pytest.raises(DocumentError):
        publisher.publish_successor(SecurityAuditArtifact.parse(raw), prior.artifact_id)
    assert {key: publishing.objects.stat(key) for key in publishing.objects.list()} == before
    assert publishing.publisher.verify(prior.artifact_id).verified
    with publishing.uow as uow:
        assert uow.artifacts.latest_imported("report").id == prior.artifact_id


def test_a_non_text_companion_is_refused_before_writing(publishing: Publishing) -> None:
    publisher = publishing.with_companions(
        Companion(ResultKind.SECURITY_AUDIT_MD, markdown),
        Companion(ResultKind.THREAT_MODEL_MD, lambda _: b"\xff\xfe"),
    )
    with pytest.raises(DocumentError, match="UTF-8"):
        publisher.publish("security-audit", audit("Sanitized audit evidence."))
    assert list(publishing.objects.list()) == []
    with publishing.uow as uow:
        assert uow.artifacts.latest_imported("report") is None


def test_a_pem_placeholder_with_remaining_key_material_is_still_rejected(
    publishing: Publishing,
) -> None:
    pem = next(text for category, text in SECRETS if category == "pem-private-key")
    redacted = RedactionPolicy().redact(pem.encode()).payload.decode()
    unsafe = redacted.replace(
        "[PRIVATE KEY MATERIAL REDACTED]", "[PRIVATE KEY MATERIAL REDACTED]\nrest"
    )
    with pytest.raises(DocumentError, match="pem-private-key"):
        publishing.publisher.publish("security-audit", audit(unsafe))
    assert list(publishing.objects.list()) == []


@pytest.mark.parametrize("newline", ["\n", r"\n", r"\\n", "\r\n", r"\r\n"])
def test_redacted_pem_newline_encodings_do_not_create_a_false_secret(
    publishing: Publishing, newline: str
) -> None:
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----"
        f"{newline}[PRIVATE KEY MATERIAL REDACTED]{newline}"
        "-----END RSA PRIVATE KEY-----"
    )
    redacted = RedactionPolicy().redact(pem.encode())
    assert redacted.payload == pem.encode() and not redacted.hits
    raw = audit(pem)
    result = publishing.with_companions().publish("security-audit", raw)
    assert publishing.publisher.get(result.artifact_id).payload == raw
    assert publishing.publisher.verify(result.artifact_id).verified


def test_secret_categories_are_deduplicated_without_exposing_matches(
    publishing: Publishing,
) -> None:
    with pytest.raises(DocumentError) as err:
        publishing.publisher.publish("security-audit", audit(f"{SECRET} AKIAIOSFODNN7EXAMPLE"))
    assert [issue.message for issue in err.value.issues] == [
        "unredacted high-confidence secret (aws-access-key)",
        "unredacted high-confidence secret (github-token)",
    ]


def test_clean_escaped_json_is_scanned_without_changing_its_stored_bytes(
    publishing: Publishing,
) -> None:
    raw = audit("Escaped but clean evidence.").replace(b"clean", b"cl\\u0065an")
    result = publishing.publisher.publish("security-audit", raw)
    assert publishing.publisher.get(result.artifact_id).payload == raw
    assert publishing.publisher.verify(result.artifact_id).recorded == sha256_hex(raw)


def test_a_scanner_failure_cannot_publish_unchecked_evidence(
    publishing: Publishing, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_: object) -> None:
        raise ValidationError("scanner failed")

    monkeypatch.setattr(RedactionPolicy, "scan", broken)
    with pytest.raises(ValidationError, match="scanner failed"):
        publishing.publisher.publish("security-audit", audit("Sanitized audit evidence."))
    assert list(publishing.objects.list()) == []


@pytest.mark.parametrize(("category", "text"), SECRETS, ids=[c for c, _ in SECRETS])
def test_decoded_secret_classes_are_checked_even_without_companions(
    publishing: Publishing, category: str, text: str
) -> None:
    publisher = publishing.with_companions()
    with pytest.raises(DocumentError, match=category):
        publisher.publish("security-audit", audit(text))
    assert list(publishing.objects.list()) == []


@pytest.mark.parametrize(("category", "text"), SECRETS, ids=[c for c, _ in SECRETS])
def test_explicit_redaction_of_every_high_confidence_class_can_be_published(
    publishing: Publishing, category: str, text: str
) -> None:
    redacted = RedactionPolicy().redact(text.encode())
    assert category in {hit.category for hit in redacted.hits}
    raw = audit(redacted.payload.decode())
    result = publishing.publisher.publish("security-audit", raw)
    assert publishing.publisher.get(result.artifact_id).payload == raw
    assert publishing.publisher.verify(result.artifact_id).verified


@pytest.mark.parametrize("escaped", [False, True], ids=["literal", "escaped"])
def test_duplicate_members_cannot_hide_bytes_the_scanned_document_lost(
    publishing: Publishing, escaped: bool
) -> None:
    secret = "".join(f"\\u{ord(c):04x}" for c in SECRET) if escaped else SECRET
    raw = audit("Sanitized audit evidence.").replace(
        b'"prose":', f'"prose": "{secret}", "prose":'.encode(), 1
    )
    with pytest.raises(DocumentError, match="duplicate JSON member") as err:
        publishing.publisher.publish("security-audit", raw)
    assert SECRET not in str(err.value)
    assert list(publishing.objects.list()) == []
    with publishing.uow as uow:
        assert uow.artifacts.latest_imported("report") is None


def test_a_later_companion_scan_failure_leaves_no_publication(
    publishing: Publishing, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    scan = RedactionPolicy.scan

    def checked(policy: RedactionPolicy, text: str) -> tuple[RedactionHit, ...]:
        if text == "late-scanner-failure":
            raise ValidationError("scanner failed")
        return scan(policy, text)

    monkeypatch.setattr(RedactionPolicy, "scan", checked)
    publisher = publishing.with_companions(
        Companion(ResultKind.SECURITY_AUDIT_MD, markdown),
        Companion(ResultKind.THREAT_MODEL_MD, lambda _: b"late-scanner-failure"),
    )
    with caplog.at_level(logging.INFO), pytest.raises(ValidationError, match="scanner failed"):
        publisher.publish("security-audit", audit("Sanitized audit evidence."))
    assert list(publishing.objects.list()) == []
    assert "artifact published" not in caplog.text
    with publishing.uow as uow:
        assert uow.artifacts.latest_imported("report") is None
