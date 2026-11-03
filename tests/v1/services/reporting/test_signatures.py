from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from traust_ledger.integrity import (
    CosignBackend,
    SigningConfig,
    sign_if_configured,
    stamp_merkle_metadata,
)
from traust_ledger.integrity.ledger import merkle_root_payload, merkle_signature_payload

from tests.v1.services.reporting.documents import valid_report, write
from traust_core.v1.errors import DocumentError
from traust_core.v1.models.artifacts import FindingsLayerArtifact
from traust_core.v1.models.ledger import IntegrityCheck
from traust_core.v1.services.ledger import LedgerService
from traust_core.v1.services.reporting import ReportingService


@pytest.fixture(scope="module")
def signing_keys(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path, Path]:
    root = tmp_path_factory.mktemp("historical-signatures")
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("COSIGN_PASSWORD", "")
        for name in ("trusted", "wrong"):
            subprocess.run(
                ["cosign", "generate-key-pair", "--output-key-prefix", str(root / name)],
                check=True,
                capture_output=True,
            )
    return root / "trusted.key", root / "trusted.pub", root / "wrong.pub"


@pytest.fixture
def signed_layer(
    signing_keys: tuple[Path, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    layer = {
        "metadata": {
            "audit_report": "widget-security-audit.json",
            "repository": "https://example.com/team/widget",
            "created": "2026-05-21T12:00:00Z",
            "harness_version": "0.1.0",
        },
        "events": [
            {
                "event_id": "a" * 64,
                "finding_ref": "WIDGET-abcdef0-001",
                "recorded_at": "2026-05-21T12:00:00Z",
                "source": {
                    "type": "triage_report",
                    "ref": "widget-triage.json",
                    "actor": {"kind": "machine", "identity": "triage"},
                },
                "disposition": {"validity": "confirmed"},
                "rationale": "A reviewer confirmed the supplied execution evidence.",
            }
        ],
        "needs_review": [],
    }
    stamp_merkle_metadata(layer)
    attempt = sign_if_configured(
        layer, SigningConfig(method="keypair", key_path=str(signing_keys[0]))
    )
    assert attempt.status == "signed", attempt.error
    return layer


@pytest.mark.parametrize("signature_format", [1, 2, 3, 4])
def test_historical_signature_formats_verify_without_a_database(
    signed_layer: dict[str, Any],
    signing_keys: tuple[Path, Path, Path],
    signature_format: int,
) -> None:
    metadata = signed_layer["metadata"]
    payload = (
        merkle_root_payload(metadata["merkle_root"])
        if signature_format == 1
        else merkle_signature_payload(metadata, fmt=signature_format)
    )
    signature = CosignBackend().sign(payload, str(signing_keys[0]))
    assert signature.success, signature.error
    metadata.update(
        merkle_root_signature=signature.signature, merkle_signature_format=signature_format
    )
    document = FindingsLayerArtifact.from_document(signed_layer)

    verified = LedgerService.verify_document(document, public_key_path=signing_keys[1])

    assert verified.passed
    assert verified.errors == ()
    assert [issue.check for issue in verified.warnings] == (
        [IntegrityCheck.SIGNATURE] if signature_format == 1 else []
    )
    assert json.loads(document.payload) == signed_layer


def test_reporting_verifies_the_signed_layer_and_preserves_its_bytes(
    reporting: ReportingService,
    tmp_path: Path,
    signed_layer: dict[str, Any],
    signing_keys: tuple[Path, Path, Path],
) -> None:
    path = write(tmp_path, "widget-findings-layer.json", signed_layer)
    original = path.read_bytes()

    (result,) = reporting.validate_reports(path, signing_pubkey=signing_keys[1])

    assert result.passed
    assert result.integrity is not None
    assert result.integrity.errors == result.integrity.warnings == ()
    assert path.read_bytes() == original


@pytest.mark.parametrize(
    ("mutation", "checks"),
    [
        ("event", {IntegrityCheck.MERKLE}),
        ("root", {IntegrityCheck.MERKLE, IntegrityCheck.SIGNATURE}),
        ("signature", {IntegrityCheck.SIGNATURE}),
        ("missing_signature", {IntegrityCheck.SIGNATURE}),
        ("empty_signature", {IntegrityCheck.SIGNATURE}),
        ("missing_root", {IntegrityCheck.MERKLE, IntegrityCheck.SIGNATURE}),
    ],
)
def test_reporting_returns_typed_integrity_failures(
    reporting: ReportingService,
    tmp_path: Path,
    signed_layer: dict[str, Any],
    signing_keys: tuple[Path, Path, Path],
    mutation: str,
    checks: set[IntegrityCheck],
) -> None:
    if mutation == "event":
        signed_layer["events"][0]["rationale"] = "An attacker substituted a different rationale."
    elif mutation == "root":
        signed_layer["metadata"]["merkle_root"] = "f" * 64
    elif mutation == "signature":
        signed_layer["metadata"]["merkle_root_signature"] = "not-a-signature"
    elif mutation == "missing_signature":
        del signed_layer["metadata"]["merkle_root_signature"]
    elif mutation == "empty_signature":
        signed_layer["metadata"]["merkle_root_signature"] = ""
    else:
        del signed_layer["metadata"]["merkle_root"]
    path = write(tmp_path, "widget-findings-layer.json", signed_layer)

    (result,) = reporting.validate_reports(path, signing_pubkey=signing_keys[1])

    assert not result.passed
    assert result.integrity is not None
    assert {issue.check for issue in result.integrity.errors} == checks
    assert result.errors == [issue.message for issue in result.integrity.errors]


@pytest.mark.parametrize("key_kind", ["wrong", "missing", "malformed"])
def test_reporting_rejects_an_unusable_or_wrong_public_key(
    reporting: ReportingService,
    tmp_path: Path,
    signed_layer: dict[str, Any],
    signing_keys: tuple[Path, Path, Path],
    key_kind: str,
) -> None:
    key = signing_keys[2] if key_kind == "wrong" else tmp_path / "invalid.pub"
    if key_kind == "malformed":
        key.write_text("not a PEM public key", encoding="utf-8")
    path = write(tmp_path, "widget-findings-layer.json", signed_layer)

    (result,) = reporting.validate_reports(path, signing_pubkey=key)

    assert not result.passed
    assert result.integrity is not None
    assert [issue.check for issue in result.integrity.errors] == [IntegrityCheck.SIGNATURE]


def test_explicit_verification_fails_closed_when_cosign_is_unavailable(
    reporting: ReportingService,
    tmp_path: Path,
    signed_layer: dict[str, Any],
    signing_keys: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = write(tmp_path, "widget-findings-layer.json", signed_layer)
    monkeypatch.setattr(CosignBackend, "available", lambda self: False)

    (result,) = reporting.validate_reports(path, signing_pubkey=signing_keys[1])

    assert not result.passed
    assert result.integrity is not None
    assert [issue.check for issue in result.integrity.errors] == [IntegrityCheck.SIGNATURE]


@pytest.mark.parametrize("signed", [False, True])
def test_ordinary_validation_does_not_require_or_verify_signatures(
    reporting: ReportingService, tmp_path: Path, signed_layer: dict[str, Any], signed: bool
) -> None:
    if signed:
        signed_layer["metadata"]["merkle_root_signature"] = "invalid-but-not-requested"
    else:
        del signed_layer["metadata"]["merkle_root_signature"]
    path = write(tmp_path, "widget-findings-layer.json", signed_layer)

    (result,) = reporting.validate_reports(path)

    assert result.passed
    assert result.integrity is None


def test_signature_verification_keeps_the_full_schema_gate(
    reporting: ReportingService,
    tmp_path: Path,
    signed_layer: dict[str, Any],
    signing_keys: tuple[Path, Path, Path],
) -> None:
    del signed_layer["needs_review"]
    with pytest.raises(DocumentError) as error:
        FindingsLayerArtifact.from_document(signed_layer)
    assert error.value.document == "layer"
    path = write(tmp_path, "widget-findings-layer.json", signed_layer)

    (result,) = reporting.validate_reports(path, signing_pubkey=signing_keys[1])

    assert not result.passed
    assert result.integrity is None
    assert result.errors


def test_mixed_sweep_verifies_only_historical_layers_and_keeps_later_results(
    reporting: ReportingService,
    tmp_path: Path,
    signed_layer: dict[str, Any],
    signing_keys: tuple[Path, Path, Path],
) -> None:
    tampered = copy.deepcopy(signed_layer)
    tampered["events"][0]["rationale"] = "A different rationale that was not signed."
    write(tmp_path, "a-findings-layer.json", tampered)
    write(tmp_path, "b-findings-layer.json", signed_layer)
    write(tmp_path, "c-security-audit.json", valid_report())

    results = reporting.validate_reports(tmp_path, signing_pubkey=signing_keys[1])

    assert [result.passed for result in results] == [False, True, True]
    assert [result.integrity is not None for result in results] == [True, True, False]


def test_explicit_layer_schema_verifies_a_nonstandard_filename(
    reporting: ReportingService,
    tmp_path: Path,
    signed_layer: dict[str, Any],
    signing_keys: tuple[Path, Path, Path],
) -> None:
    path = write(tmp_path, "historical.json", signed_layer)

    (result,) = reporting.validate_reports(path, schema="layer", signing_pubkey=signing_keys[1])

    assert result.passed
    assert result.integrity is not None and result.integrity.passed


def test_signature_parse_failure_does_not_abort_the_directory_sweep(
    reporting: ReportingService,
    tmp_path: Path,
    signed_layer: dict[str, Any],
    signing_keys: tuple[Path, Path, Path],
) -> None:
    path = tmp_path / "a-findings-layer.json"
    path.write_text(json.dumps(signed_layer)[:-1] + ', "needs_review": []}', encoding="utf-8")
    write(tmp_path, "b-findings-layer.json", signed_layer)

    results = reporting.validate_reports(tmp_path, signing_pubkey=signing_keys[1])

    assert [result.passed for result in results] == [False, True]
    assert results[0].integrity is None
    assert results[1].integrity is not None and results[1].integrity.passed


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("claim_hashes", {"WIDGET-abcdef0-001": "f" * 64}),
        ("audit_report_sha256", "f" * 64),
        ("artifact_digests", {"widget-triage.json": "f" * 64}),
    ],
)
def test_signature_verification_binds_historical_metadata_not_just_the_root(
    reporting: ReportingService,
    tmp_path: Path,
    signed_layer: dict[str, Any],
    signing_keys: tuple[Path, Path, Path],
    field: str,
    value: object,
) -> None:
    signed_layer["metadata"][field] = value
    path = write(tmp_path, "widget-findings-layer.json", signed_layer)

    (result,) = reporting.validate_reports(path, signing_pubkey=signing_keys[1])

    assert not result.passed
    assert result.integrity is not None
    assert [issue.check for issue in result.integrity.errors] == [IntegrityCheck.SIGNATURE]
