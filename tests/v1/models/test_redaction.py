from __future__ import annotations

import json

import pytest

from traust_core.v1.models.redaction import SecretDetector


def detected(text: str) -> list[tuple[str, str]]:
    return [
        (span.tag, text[span.start : span.end])
        for rule in SecretDetector.evidence_rules()
        for span in rule.spans(text)
    ]


@pytest.mark.parametrize(
    "text,tag,value",
    [
        ("AIza" + "a" * 35, "google-api-key", "AIza" + "a" * 35),
        ("sk-" + "b" * 24, "llm-api-key", "sk-" + "b" * 24),
        ('"private_key_id": "' + "c" * 40 + '"', "gcp-sa-key", "c" * 40),
        ("ASIA" + "D" * 16, "aws-akid", "ASIA" + "D" * 16),
        ("ghp_" + "e" * 24, "github-token", "ghp_" + "e" * 24),
        ("bind_password=synthetic-credential", "generic-secret", "synthetic-credential"),
        ("Bearer " + "f" * 24, "bearer", "Bearer " + "f" * 24),
    ],
)
def test_evidence_spans_retain_exact_original_slices(text: str, tag: str, value: str) -> None:
    assert (tag, value) in detected(text)


def test_serialized_private_keys_are_one_complete_secret_span() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nprivate material\n-----END RSA PRIVATE KEY-----"
    text = json.dumps({"evidence": pem})
    assert ("pem-privkey", json.dumps(pem)[1:-1]) in detected(text)


def test_payment_card_detection_requires_luhn() -> None:
    found = detected("card 4111-1111-1111-1111 and build 1234-5678-9012-3456")
    assert ("payment-card", "4111-1111-1111-1111 ") in found
    assert all("1234" not in value for _, value in found)
