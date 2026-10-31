from collections.abc import Iterator
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from traust_core.v1.errors import ConfigError, IntegrityError, RepositoryError
from traust_core.v1.repositories import ObjectKey
from traust_core.v1.repositories.objects.s3 import S3ObjectStore

KEY = ObjectKey.parse("feeds/epss/abc/epss.csv.gz")


@pytest.fixture
def client() -> Iterator[object]:
    with mock_aws():
        c = boto3.client("s3", region_name="us-east-1")
        c.create_bucket(Bucket="traust")
        yield c


def test_prefix_scopes_keys_and_list_hides_it(client) -> None:
    store = S3ObjectStore("traust", client=client, prefix="/deploy-a/")
    ref = store.put(KEY, b"x")
    assert client.head_object(Bucket="traust", Key=f"deploy-a/{KEY}")
    assert store.get(ref) == b"x"
    assert [str(k) for k in store.list("feeds")] == [str(KEY)]
    assert list(S3ObjectStore("traust", client=client, prefix="deploy-b").list()) == []


def test_bytes_changed_behind_the_store_fail_the_digest(client) -> None:
    store = S3ObjectStore("traust", client=client)
    ref = store.put(KEY, b"original")
    client.put_object(Bucket="traust", Key=str(KEY), Body=b"tampered")
    with pytest.raises(IntegrityError):
        store.get(ref)
    assert store.stat(KEY).sha256 != ref.sha256


def test_list_matches_whole_segments_and_skips_foreign_keys(client) -> None:
    store = S3ObjectStore("traust", client=client)
    store.put(ObjectKey.parse("a/x.json"), b"1")
    store.put(ObjectKey.parse("ab/y.json"), b"2")
    client.put_object(Bucket="traust", Key="a/not a key", Body=b"3")
    assert [str(k) for k in store.list("a")] == ["a/x.json"]
    assert [str(k) for k in store.list("a/")] == ["a/x.json"]


def test_list_follows_pages(client) -> None:
    store = S3ObjectStore("traust", client=client)
    for i in range(1005):
        client.put_object(Bucket="traust", Key=f"many/{i:04}.json", Body=b"")
    keys = list(store.list("many"))
    assert len(keys) == 1005
    assert str(keys[0]) == "many/0000.json"
    assert str(keys[-1]) == "many/1004.json"


def test_a_missing_bucket_fails_at_construction() -> None:
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        with pytest.raises(ConfigError, match="nope"):
            S3ObjectStore("nope", client=client)


def test_list_yields_before_reading_every_page() -> None:
    def pages(**_: object) -> Iterator[dict[str, object]]:
        yield {"Contents": [{"Key": "a/x.json"}]}
        raise ClientError({"Error": {"Code": "SlowDown", "Message": "later"}}, "ListObjectsV2")

    client = MagicMock()
    client.get_paginator.return_value.paginate.side_effect = pages
    listing = S3ObjectStore("traust", client=client).list("a")
    assert str(next(listing)) == "a/x.json"
    with pytest.raises(RepositoryError):
        next(listing)


def test_other_client_errors_are_repository_errors() -> None:
    denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetObject")
    client = MagicMock()
    client.get_object.side_effect = denied
    client.head_object.side_effect = denied
    client.put_object.side_effect = denied
    store = S3ObjectStore("traust", client=client)
    with pytest.raises(RepositoryError):
        store.stat(KEY)
    with pytest.raises(RepositoryError):
        store.exists(KEY)
    with pytest.raises(RepositoryError):
        store.put(KEY, b"x")
