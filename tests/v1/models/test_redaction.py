from __future__ import annotations

import json
import re

import pytest

from traust_core.v1.models.redaction import SecretDetector, SecretRule


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


@pytest.mark.parametrize(
    "category,value",
    [
        ("aws-access-key", "AKIA" + "A" * 16),
        ("github-token", "ghp_" + "a" * 30),
        ("gitlab-token", "glpat-" + "a" * 20),
        ("slack-token", "xoxb-" + "a" * 16),
    ],
)
@pytest.mark.parametrize("prefix,suffix", [("", ""), ("x", ""), ("", "é"), ("x", "é")])
def test_evidence_keeps_publication_matches_without_word_boundaries(
    category: str, value: str, prefix: str, suffix: str
) -> None:
    rule = next(rule for rule in SecretDetector.evidence_rules() if rule.category == category)
    spans = list(rule.spans(prefix + value + suffix))
    assert [(span.start, span.end) for span in spans] == [(len(prefix), len(prefix + value))]


@pytest.mark.parametrize(
    "text,pattern,group,extension,extension_group,expected",
    [
        ("abc abc", r"abc", 0, r"abc", None, [(0, 3), (4, 7)]),
        ("abcde", r"abc", 0, r"cde", None, [(0, 5)]),
        ("abcdeabcde", r"abcde", 0, r"eab", None, [(0, 10)]),
        ("abcd", r"ab", 0, r"cd", None, [(0, 2), (2, 4)]),
        ("abc xyz", r"xyz", 0, r"abc", None, [(0, 3), (4, 7)]),
        ("Bearer abc", r"Bearer (\w+)", 1, r"Bearer \w+", 0, [(0, 10)]),
        ("xBearer abc", r"Bearer (\w+)", 1, r"\bBearer \w+", 0, [(8, 11)]),
    ],
)
def test_evidence_unions_overlapping_spans_without_duplicate_or_shifted_offsets(
    text: str,
    pattern: str,
    group: int,
    extension: str,
    extension_group: int | None,
    expected: list[tuple[int, int]],
) -> None:
    rule = SecretRule(
        "credential",
        re.compile(pattern),
        group,
        evidence_pattern=re.compile(extension),
        evidence_group=extension_group,
    )
    assert [(span.start, span.end) for span in rule.spans(text)] == expected
