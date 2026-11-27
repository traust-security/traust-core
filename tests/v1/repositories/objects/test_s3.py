from collections.abc import Iterator
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.client import BaseClient
from botocore.exceptions import ClientError
from botocore.model import OperationModel
from botocore.stub import Stubber
from moto import mock_aws

from traust_core.v1.context.feeds import ObjectCache
from traust_core.v1.errors import ConfigError, IntegrityError, NotFoundError, RepositoryError
from traust_core.v1.repositories import ObjectKey
from traust_core.v1.repositories.objects.s3 import S3ObjectStore

KEY = ObjectKey.parse("feeds/epss/abc/epss.csv.gz")


@pytest.fixture
def client() -> Iterator[BaseClient]:
    with mock_aws():
        c = boto3.client("s3", region_name="us-east-1")
        c.create_bucket(Bucket="traust")
        yield c


def test_prefix_scopes_keys_and_list_hides_it(client: BaseClient) -> None:
    store = S3ObjectStore("traust", client=client, prefix="/deploy-a/")
    ref = store.put(KEY, b"x")
    assert client.head_object(Bucket="traust", Key=f"deploy-a/{KEY}")
    assert store.get(ref) == b"x"
    assert [str(k) for k in store.list("feeds")] == [str(KEY)]
    assert list(S3ObjectStore("traust", client=client, prefix="deploy-b").list()) == []


def test_bytes_changed_behind_the_store_fail_the_digest(client: BaseClient) -> None:
    store = S3ObjectStore("traust", client=client)
    ref = store.put(KEY, b"original")
    client.put_object(Bucket="traust", Key=str(KEY), Body=b"tampered")
    with pytest.raises(IntegrityError):
        store.get(ref)
    assert store.stat(KEY).sha256 != ref.sha256


def test_a_read_by_digest_fetches_the_object_once(client: BaseClient) -> None:
    store = S3ObjectStore("traust", client=client)
    ref = store.put(KEY, b"original")
    calls: list[str] = []
    client.meta.events.register("before-call.s3.*", lambda model, **_: calls.append(model.name))
    assert store.read(KEY, ref.sha256) == b"original"
    assert calls == ["GetObject"]


def test_list_matches_whole_segments_and_skips_foreign_keys(client: BaseClient) -> None:
    store = S3ObjectStore("traust", client=client)
    store.put(ObjectKey.parse("a/x.json"), b"1")
    store.put(ObjectKey.parse("ab/y.json"), b"2")
    client.put_object(Bucket="traust", Key="a/not a key", Body=b"3")
    assert [str(k) for k in store.list("a")] == ["a/x.json"]
    assert [str(k) for k in store.list("a/")] == ["a/x.json"]


def test_list_follows_pages(client: BaseClient) -> None:
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


def test_prefix_scoped_permissions_allow_storage_without_bucket_wide_access(
    client: BaseClient,
) -> None:
    def prefix_only(model: OperationModel, params: dict[str, object], **_: object) -> None:
        query = params.get("query_string")
        scoped = isinstance(query, dict) and str(query.get("prefix", "")).startswith("deploy-a/")
        if model.name == "HeadBucket" or (model.name == "ListObjectsV2" and not scoped):
            raise ClientError(
                {"Error": {"Code": "AccessDenied"}, "ResponseMetadata": {"HTTPStatusCode": 403}},
                model.name,
            )

    client.meta.events.register("before-call.s3", prefix_only)
    store = S3ObjectStore("traust", client=client, prefix="deploy-a")
    ref = store.put(KEY, b"scoped data")
    assert store.get(ref) == b"scoped data"
    assert list(store.list()) == [KEY]
    assert not store.exists(ObjectKey.parse("missing.json"))


def test_scoped_list_distinguishes_missing_key_403_from_denied_existing_key(
    client: BaseClient,
) -> None:
    store = S3ObjectStore("traust", client=client, prefix="deploy-a")
    missing = ObjectKey.parse("cache/missing.json")
    protected = ObjectKey.parse("cache/protected.json")
    client.put_object(Bucket="traust", Key="deploy-a/cache/protected.json", Body=b"private")

    def denied_object(model: OperationModel, params: dict[str, object], **_: object) -> None:
        if model.name in {"HeadObject", "GetObject"}:
            raise ClientError({"Error": {"Code": "AccessDenied"}}, model.name)

    client.meta.events.register("before-call.s3", denied_object)
    assert not store.exists(missing)
    with pytest.raises(NotFoundError):
        store.stat(missing)
    with pytest.raises(RepositoryError):
        store.exists(protected)
    with pytest.raises(RepositoryError):
        store.stat(protected)
    client.delete_object(Bucket="traust", Key="deploy-a/cache/protected.json")
    client.delete_bucket(Bucket="traust")
    with pytest.raises(RepositoryError):
        store.exists(missing)


def test_losing_the_bucket_after_construction_is_not_a_cache_miss(client: BaseClient) -> None:
    cache = ObjectCache(S3ObjectStore("traust", client=client, prefix="deploy-a"), "cache")
    assert cache.get("missing.json") is None
    client.delete_bucket(Bucket="traust")
    with pytest.raises(RepositoryError):
        cache.get("missing.json")


def test_ambiguous_read_404_distinguishes_a_missing_key_from_a_lost_bucket(
    client: BaseClient,
) -> None:
    store = S3ObjectStore("traust", client=client, prefix="deploy-a")
    with Stubber(client) as stub:
        stub.add_client_error("get_object", service_error_code="404", http_status_code=404)
        stub.add_response("list_objects_v2", {})
        stub.add_client_error("get_object", service_error_code="404", http_status_code=404)
        stub.add_client_error(
            "list_objects_v2", service_error_code="NoSuchBucket", http_status_code=404
        )
        with pytest.raises(NotFoundError):
            store.stat(KEY)
        with pytest.raises(RepositoryError):
            store.stat(KEY)


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


def test_read_closes_body_after_success_and_failure() -> None:
    client = MagicMock()
    body = MagicMock()
    client.get_object.return_value = {"Body": body}
    body.read.return_value = b"stored"
    store = S3ObjectStore("traust", client=client)

    assert store.stat(KEY).size == len(b"stored")
    body.close.assert_called_once_with()

    error = ClientError({"Error": {"Code": "InternalError"}}, "GetObject")
    body.read.side_effect = error
    with pytest.raises(RepositoryError) as raised:
        store.stat(KEY)
    assert raised.value.__cause__ is error
    assert body.close.call_count == 2


def test_missing_object_preserves_s3_error_cause() -> None:
    client = MagicMock()
    error = ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
    client.get_object.side_effect = error
    store = S3ObjectStore("traust", client=client)

    with pytest.raises(NotFoundError) as raised:
        store.stat(KEY)
    assert raised.value.__cause__ is error


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
