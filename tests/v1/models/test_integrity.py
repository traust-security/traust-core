import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.integrity import Fingerprint, canonical_json, sha256_hex


def test_canonical_json_is_order_independent_and_compact() -> None:
    expected = '{"a":[2,{"c":"é","d":3}],"b":1}'.encode()
    assert canonical_json({"b": 1, "a": [2, {"d": 3, "c": "é"}]}) == expected
    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})


def test_sha256_hex() -> None:
    assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_fingerprint_parses_only_versioned_hex() -> None:
    assert str(Fingerprint.parse("fp1:" + "a" * 64)).startswith("fp1:")
    with pytest.raises(ValidationError):
        Fingerprint.parse("a" * 64)
