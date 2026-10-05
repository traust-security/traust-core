from traust_core.v1.domain.integrity import canonical_json, sha256_hex


def test_canonical_json_is_order_independent_and_compact() -> None:
    expected = '{"a":[2,{"c":"é","d":3}],"b":1}'.encode()
    assert canonical_json({"b": 1, "a": [2, {"d": 3, "c": "é"}]}) == expected
    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})


def test_sha256_hex() -> None:
    assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_fingerprint_shape_is_fixed_before_rules() -> None:
    import pytest

    from traust_core.v1.domain import HttpsRepoUrl, ValidationError
    from traust_core.v1.domain.integrity import Fingerprint, FingerprintInput, fingerprint

    assert str(Fingerprint.parse("fp1:" + "a" * 64)).startswith("fp1:")
    with pytest.raises(ValidationError):
        Fingerprint.parse("a" * 64)
    with pytest.raises(NotImplementedError):
        fingerprint(
            FingerprintInput(
                repo=HttpsRepoUrl("example.com", "o/r"), rule_id="r", path="p", anchor="a"
            )
        )
