"""`RedactionPolicy.redact` keeps serialized JSON valid and leaves no high-confidence secret
in it — the shape the SCI migration and any caller that redacts a whole document rely on."""

from __future__ import annotations

import json

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.services.artifact_publishing import RedactionPolicy

BEGIN, END = "-----BEGIN " + "RSA PRIVATE KEY-----", "-----END " + "RSA PRIVATE KEY-----"
SECRETS = (
    ("aws-access-key", "id AKIA" + "IOSFODNN7EXAMPLE" + " end"),
    ("github-token", "tok gh" + "p_" + "a1" * 18 + " end"),
    ("github-pat", "pat github" + "_pat_" + "B2" * 12 + " end"),
    ("gitlab-token", "gl glpat" + "-" + "c3" * 11 + " end"),
    ("slack-token", "sl xox" + "b-1234567890abc" + " end"),
    ("llm-api-key", "key sk" + "-" + "d4" * 12 + " end"),
    ("google-api-key", "g AIza" + "e" * 35 + " end"),
    ("bearer-token", "Authorization: Bearer " + "f5" * 12),
    ("jwt", "jwt eyJ" + "hbGciOiJIUz" + "." + "eyJzdWIiOiIx" + "." + "SflKxwRJSMeK end"),
    ("password-assignment", 'password = "' + "hunter2secret" + '"'),
    ("secret-assignment", 'client_secret="' + "s3cr3tvalue" + '"'),
    ("token-assignment", 'token: "' + "abcdefgh123" + '"'),
    ("apikey-assignment", 'api_key = "' + "zyxwvutsrq" + '"'),
    ("url-credentials", "https://svc:" + "sup3rsecret" + "@git.example/x.git"),
    ("us-ssn", "ssn 123-45-6789 not 000-12-3456"),
    ("azure-client-secret", "az abc8Q~" + "g" * 32 + " end"),
    ("gcp-sa-key", '"private_key_id": "' + "a" * 40 + '"'),
    ("pem-private-key", BEGIN + "\nMIIsecretsecret\nmore\n" + END),
    ("payment-card", "card 4111111111111111 x and 4111-1111-1111-1111"),
)
# A GCP service-account key blob a report holds as a string value: when the outer document is
# serialized every quote inside it is escaped, so redaction must read the escaped form too.
GCP_SA_KEY = json.dumps(
    {
        "type": "service_account",
        "private_key_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN\n-----END PRIVATE KEY-----\n",
    }
)


def _high(text: str) -> list[str]:
    return [h.category for h in RedactionPolicy().scan(text) if h.high_confidence]


@pytest.mark.parametrize("name,secret", SECRETS, ids=[n for n, _ in SECRETS])
def test_redaction_keeps_a_json_document_valid_and_secret_free(name: str, secret: str) -> None:
    """`json.loads` accepts the redacted bytes and no parsed value holds a secret."""
    payload = json.dumps({"evidence": secret}).encode()
    redacted = RedactionPolicy().redact(payload)
    assert redacted.hits, f"{name}: redaction found nothing to redact"
    doc = json.loads(redacted.payload)
    assert _high(doc["evidence"]) == []


@pytest.mark.parametrize("name,secret", SECRETS, ids=[n for n, _ in SECRETS])
def test_redaction_leaves_plain_text_secret_free(name: str, secret: str) -> None:
    out = RedactionPolicy().redact(secret.encode())
    assert out.hits, f"{name}: redaction found nothing to redact"
    assert _high(out.payload.decode()) == []


@pytest.mark.parametrize("name,secret", SECRETS, ids=[n for n, _ in SECRETS])
def test_redacting_an_already_redacted_payload_changes_nothing(name: str, secret: str) -> None:
    once = RedactionPolicy().redact(secret.encode())
    twice = RedactionPolicy().redact(once.payload)
    assert twice.payload == once.payload and twice.hits == ()


def test_a_json_embedded_gcp_service_account_key_is_redacted() -> None:
    """The SA key blob is a string value, so its quotes are escaped in the serialized form;
    redaction must read through the escaping or the publication gate refuses the document."""
    payload = json.dumps({"credentials": GCP_SA_KEY}).encode()
    redacted = RedactionPolicy().redact(payload)
    blob = json.loads(redacted.payload)["credentials"]
    assert "private_key_id" in json.loads(blob)  # the blob is still a parseable SA key JSON
    assert _high(blob) == []


def test_a_json_embedded_pem_stays_valid_json() -> None:
    """The PEM's newlines are escaped in the serialized form; the redacted marker must keep
    them escaped (at the same depth) or the payload no longer parses."""
    payload = json.dumps({"evidence": BEGIN + "\nMIIsecretsecret\n" + END}).encode()
    redacted = RedactionPolicy().redact(payload)
    evidence = json.loads(redacted.payload)["evidence"]
    assert evidence == BEGIN + "\n[PRIVATE KEY MATERIAL REDACTED]\n" + END
    assert _high(evidence) == []


def test_mixed_secrets_in_one_document_are_all_redacted() -> None:
    doc = {
        "credentials": GCP_SA_KEY,
        "pem": BEGIN + "\nMIIsecretsecret\n" + END,
        "token": "AKIA" + "IOSFODNN7EXAMPLE",
        "card": "4111111111111111",
    }
    redacted = RedactionPolicy().redact(json.dumps(doc).encode())
    parsed = json.loads(redacted.payload)
    assert _high(" ".join(str(v) for v in parsed.values())) == []


def test_empty_input_is_unchanged() -> None:
    out = RedactionPolicy().redact(b"")
    assert out.payload == b"" and out.hits == ()


def test_non_utf8_bytes_are_refused() -> None:
    with pytest.raises(ValidationError, match="UTF-8"):
        RedactionPolicy().redact(b"\xff\xfe\x00")


def test_a_plain_text_pem_keeps_raw_newlines() -> None:
    """The same PEM outside JSON still redacts to the raw-newline form (legacy parity)."""
    pem = BEGIN + "\nMIIsecretsecret\n" + END
    out = RedactionPolicy().redact(pem.encode())
    assert out.payload.decode() == (BEGIN + "\n[PRIVATE KEY MATERIAL REDACTED]\n" + END)


@pytest.mark.parametrize("body", ["", "MIIsecret", "\n\n"], ids=["empty", "unpadded", "all-pad"])
def test_degenerate_pem_bodies_redact_without_doubling_the_padding(body: str) -> None:
    """Malformed bodies (no padding, or nothing but newlines) still redact; the padding run
    is never emitted twice."""
    out = RedactionPolicy().redact((BEGIN + body + END).encode())
    text = out.payload.decode()
    assert text.count("[PRIVATE KEY MATERIAL REDACTED]") == 1
    assert not _high(text)
    again = RedactionPolicy().redact(text.encode())
    assert again.payload == out.payload and again.hits == ()


def test_scan_agrees_with_redaction_on_escaped_text() -> None:
    """`scan` and `redact` read the same patterns, so a secret one finds in escaped JSON the
    other must redact — the disagreement the SCI migration hit."""
    escaped = json.dumps({"credentials": GCP_SA_KEY})
    scan_hits = [h.category for h in RedactionPolicy().scan(escaped) if h.high_confidence]
    assert "gcp-sa-key" in scan_hits
    redacted = RedactionPolicy().redact(escaped.encode())
    assert [h.category for h in redacted.hits if h.high_confidence] == scan_hits
