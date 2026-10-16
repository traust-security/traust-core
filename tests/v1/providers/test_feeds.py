import gzip

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.providers.feeds import validate_payload


@pytest.mark.parametrize(
    ("raw", "filename"),
    [
        (gzip.compress(b"cve,epss\n"), "epss_scores-current.csv.gz"),
        (b'{"a": 1}', "known_exploited_vulnerabilities.json"),
        (gzip.compress(b"[]"), "index.json.gz"),
        (b"anything", "archive_latest.txt"),
    ],
)
def test_well_formed_payload_passes(raw: bytes, filename: str) -> None:
    validate_payload(raw, filename)


@pytest.mark.parametrize(
    ("raw", "filename"),
    [
        (b"", "kev.json"),
        (b"not a gzip payload", "epss.csv.gz"),
        (b"{broken", "kev.json"),
        (b"\xff\xfe", "rh-cve.csv"),
    ],
)
def test_corrupt_payload_raises(raw: bytes, filename: str) -> None:
    with pytest.raises(ValidationError):
        validate_payload(raw, filename)
