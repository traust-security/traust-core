"""`services.redaction` redacts exactly as traust-engine's `_util.redact` (every pattern class)."""

from __future__ import annotations

from pathlib import Path

import pytest

from traust_core.v1.context import Config, Context
from traust_core.v1.services.artifact_publishing import RedactionPolicy

BEGIN, END = "-----BEGIN " + "RSA PRIVATE KEY-----", "-----END " + "RSA PRIVATE KEY-----"
INPUTS = {
    "aws-access-key": "id AKIA" + "IOSFODNN7EXAMPLE end",
    "github-token": "tok gh" + "p_" + "a1" * 18 + " end",
    "github-pat": "pat github" + "_pat_" + "B2" * 12 + " end",
    "gitlab-token": "gl glpat" + "-" + "c3" * 11 + " end",
    "slack-token": "sl xox" + "b-" + "1234567890abc end",
    "llm-api-key": "key sk" + "-" + "d4" * 12 + " end",
    "google-api-key": "g AIza" + "e" * 35 + " end",
    "bearer-token": "Authorization: Bearer " + "f5" * 12,
    "jwt": "jwt eyJ" + "hbGciOiJIUz" + "." + "eyJzdWIiOiIx" + "." + "SflKxwRJSMeK end",
    "password-assignment": 'password = "' + "hunter2secret" + '"',
    "passwd-assignment": "PASSWD: 'hunter22secret'",
    "secret-assignment": 'client_secret="' + "s3cr3tvalue" + '"',
    "token-assignment": 'token: "' + "abcdefgh123" + '"',
    "apikey-assignment": 'api_key = "' + "zyxwvutsrq" + '"',
    "escaped-assignment": 'json password: \\"' + "escapedvalue" + '\\"',
    "url-credentials": "https://svc:" + "sup3rsecret" + "@git.example/x.git",
    "us-ssn": "ssn 123-45-6789 not 000-12-3456 nor 666-12-3456 nor 123-00-4567",
    "azure-client-secret": "az abc8Q~" + "g" * 32 + " end",
    "gcp-sa-key": '"private_key_id": "' + "a" * 40 + '"',
    "pem-private-key": BEGIN + "\nMIIsecretsecret\nmore\n" + END,
    "payment-card": "card 4111 1111 1111 1111 x and 4111-1111-1111-1111",
    "luhn-fails": "build id 1234 5678 9012 3456 ok",
    "overlap": "Authorization: Bearer gh" + "p_" + "h7" * 18,
    "already-redacted": "id AKIAI...REDACTED end",
    "clean": "nothing to see",
}
# Produced by traust-engine upstream/development `_util.redact.redact_text` on INPUTS.
LEGACY = {
    "aws-access-key": (
        "id AKIAI...REDACTED end",
        (("aws-access-key", "AKIAI"),),
    ),
    "github-token": (
        "tok ghp_a...REDACTED end",
        (("github-token", "ghp_a"),),
    ),
    "github-pat": (
        "pat githu...REDACTED end",
        (("github-pat", "githu"),),
    ),
    "gitlab-token": (
        "gl glpat...REDACTED end",
        (("gitlab-token", "glpat"),),
    ),
    "slack-token": (
        "sl xoxb-...REDACTED end",
        (("slack-token", "xoxb-"),),
    ),
    "llm-api-key": (
        "key sk-d4...REDACTED end",
        (("llm-api-key", "sk-d4"),),
    ),
    "google-api-key": (
        "g AIzae...REDACTED end",
        (("google-api-key", "AIzae"),),
    ),
    "bearer-token": (
        "Authorization: Bearer f5f5f...REDACTED",
        (("bearer-token", "f5f5f"),),
    ),
    "jwt": (
        "jwt eyJhb...REDACTED end",
        (("jwt", "eyJhb"),),
    ),
    "password-assignment": (
        'password = "hunte...REDACTED"',
        (("password-assignment", "hunte"),),
    ),
    "passwd-assignment": (
        "PASSWD: 'hunte...REDACTED'",
        (("password-assignment", "hunte"),),
    ),
    "secret-assignment": (
        'client_secret="s3cr3...REDACTED"',
        (("secret-assignment", "s3cr3"),),
    ),
    "token-assignment": (
        'token: "abcde...REDACTED"',
        (("token-assignment", "abcde"),),
    ),
    "apikey-assignment": (
        'api_key = "zyxwv...REDACTED"',
        (("apikey-assignment", "zyxwv"),),
    ),
    "escaped-assignment": (
        'json password: \\"escap...REDACTED\\"',
        (("password-assignment", "escap"),),
    ),
    "url-credentials": (
        "https://svc:sup3r...REDACTED@git.example/x.git",
        (("url-credentials", "sup3r"),),
    ),
    "us-ssn": (
        "ssn 123-4...REDACTED not 000-12-3456 nor 666-12-3456 nor 123-00-4567",
        (("us-ssn", "123-4"),),
    ),
    "azure-client-secret": (
        "az abc8Q...REDACTED end",
        (("azure-client-secret", "abc8Q"),),
    ),
    "gcp-sa-key": (
        '"private_key_id": "aaaaa...REDACTED"',
        (("gcp-sa-key", "aaaaa"),),
    ),
    "pem-private-key": (
        "-----BEGIN RSA PRIVATE KEY-----\n[PRIVATE KEY MATERIAL REDACT"
        "ED]\n-----END RSA PRIVATE KEY-----",
        (("pem-private-key", "-----"),),
    ),
    "payment-card": (
        "card 41111...REDACTEDx and 41111...REDACTED",
        (
            ("payment-card", "41111"),
            ("payment-card", "41111"),
        ),
    ),
    "luhn-fails": (
        "build id 1234 5678 9012 3456 ok",
        (),
    ),
    "overlap": (
        "Authorization: Bearer ghp_h...REDACTED",
        (("github-token", "ghp_h"),),
    ),
    "already-redacted": (
        "id AKIAI...REDACTED end",
        (),
    ),
    "clean": (
        "nothing to see",
        (),
    ),
}


@pytest.mark.parametrize("case", list(INPUTS))
def test_redaction_matches_the_legacy_redactor(case: str) -> None:
    out = RedactionPolicy().redact(INPUTS[case].encode())
    text, hits = LEGACY[case]
    assert out.payload.decode() == text
    assert tuple((h.category, h.match_prefix) for h in out.hits) == hits


def test_redaction_is_a_services_door(tmp_path: Path) -> None:
    out = Context(Config(home=tmp_path)).services().redaction.redact(INPUTS["overlap"].encode())
    assert out.payload.decode() == LEGACY["overlap"][0]
    assert [h.high_confidence for h in out.hits] == [True]


# `_util.redact.scan_text` reads every pattern over the original text, so a secret two patterns
# match is found by both; everywhere else it finds what `redact_text` does.
LEGACY_SCAN = {case: hits for case, (_, hits) in LEGACY.items()} | {
    "overlap": (("github-token", "ghp_h"), ("bearer-token", "ghp_h")),
}


@pytest.mark.parametrize("case", list(INPUTS))
def test_scan_matches_the_legacy_scanner(case: str) -> None:
    hits = RedactionPolicy().scan(INPUTS[case])
    assert tuple((h.category, h.match_prefix) for h in hits) == LEGACY_SCAN[case]
