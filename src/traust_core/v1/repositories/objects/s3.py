"""S3-compatible ObjectStore (AWS, MinIO, Ceph): the `[s3]` extra.

The caller builds the boto3 client, so endpoint and credentials stay deployment config.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from contextlib import closing
from typing import Literal, Protocol, TypedDict

from traust_core.v1.errors import ConfigError, NotFoundError, RepositoryError, ValidationError
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.repositories.objects.store import ObjectKey, ObjectRef, _verified

try:
    from botocore.exceptions import BotoCoreError, ClientError
    from botocore.response import StreamingBody
except ModuleNotFoundError as e:
    raise ModuleNotFoundError(
        "S3ObjectStore needs the s3 extra: pip install 'traust-core[s3]'", name=e.name
    ) from e

_MISSING = {"NoSuchKey", "NotFound", "404"}
_AMBIGUOUS_MISSING = {"NotFound", "404"}


class _S3Object(TypedDict):
    Key: str


class _S3Page(TypedDict, total=False):
    Contents: list[_S3Object]


class _S3Read(TypedDict):
    Body: StreamingBody


class _S3Paginator(Protocol):
    def paginate(self, *, Bucket: str, Prefix: str) -> Iterable[_S3Page]: ...


class S3Client(Protocol):
    def list_objects_v2(self, *, Bucket: str, Prefix: str, MaxKeys: int) -> _S3Page: ...
    def put_object(self, *, Bucket: str, Key: str, Body: bytes) -> object: ...
    def get_object(self, *, Bucket: str, Key: str) -> _S3Read: ...
    def head_object(self, *, Bucket: str, Key: str) -> object: ...
    def get_paginator(self, operation_name: Literal["list_objects_v2"]) -> _S3Paginator: ...


class S3ObjectStore:
    @classmethod
    def from_settings(
        cls,
        bucket: str,
        *,
        prefix: str = "",
        endpoint_url: str | None = None,
        region: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
    ) -> S3ObjectStore:
        import boto3

        options: dict[str, str] = {}
        if endpoint_url is not None:
            options["endpoint_url"] = endpoint_url
        if region is not None:
            options["region_name"] = region
        if access_key is not None and secret_key is not None:
            options["aws_access_key_id"] = access_key
            options["aws_secret_access_key"] = secret_key
        return cls(bucket, client=boto3.client("s3", **options), prefix=prefix)

    def __init__(self, bucket: str, *, client: S3Client, prefix: str = "") -> None:
        self._bucket = bucket
        self._client = client
        self._base = f"{prefix.strip('/')}/" if prefix.strip("/") else ""
        try:
            self._probe_bucket()
        except (BotoCoreError, ClientError) as e:
            raise ConfigError(f"S3ObjectStore: bucket {bucket!r} is not reachable") from e

    def _probe_bucket(self) -> None:
        self._client.list_objects_v2(Bucket=self._bucket, Prefix=self._base, MaxKeys=1)

    def _is_missing(self, error: ClientError, key: ObjectKey) -> bool:
        code = error.response.get("Error", {}).get("Code")
        if code in {"AccessDenied", "403"}:
            try:
                listed = self._client.list_objects_v2(
                    Bucket=self._bucket, Prefix=self._name(key), MaxKeys=1
                )
            except (BotoCoreError, ClientError) as e:
                raise RepositoryError(f"S3ObjectStore: check {key} failed") from e
            if not isinstance(listed, dict):
                raise RepositoryError(f"S3ObjectStore: check {key} returned an invalid listing")
            return not any(obj["Key"] == self._name(key) for obj in listed.get("Contents", ()))
        if code in _AMBIGUOUS_MISSING:
            try:
                self._probe_bucket()
            except (BotoCoreError, ClientError) as e:
                raise RepositoryError(
                    f"S3ObjectStore: bucket {self._bucket!r} is not reachable"
                ) from e
        return code in _MISSING

    def _name(self, key: ObjectKey) -> str:
        return f"{self._base}{key.value}"

    def put(self, key: ObjectKey, data: bytes) -> ObjectRef:
        try:
            self._client.put_object(Bucket=self._bucket, Key=self._name(key), Body=data)
        except (BotoCoreError, ClientError) as e:
            raise RepositoryError(f"S3ObjectStore: put {key} failed") from e
        return ObjectRef(key, sha256_hex(data), len(data))

    def _read(self, key: ObjectKey) -> bytes:
        try:
            with closing(
                self._client.get_object(Bucket=self._bucket, Key=self._name(key))["Body"]
            ) as body:
                return body.read()
        except ClientError as e:
            if self._is_missing(e, key):
                raise NotFoundError(f"artifact {key}") from e
            raise RepositoryError(f"S3ObjectStore: read {key} failed") from e
        except BotoCoreError as e:
            raise RepositoryError(f"S3ObjectStore: read {key} failed") from e

    def get(self, ref: ObjectRef) -> bytes:
        return _verified(ref, self._read(ref.key))

    def read(self, key: ObjectKey, sha256: str) -> bytes:
        """The bytes at `key`, checked against a digest recorded elsewhere: one read."""
        data = self._read(key)
        return _verified(ObjectRef(key, sha256, len(data)), data)

    def stat(self, key: ObjectKey) -> ObjectRef:
        # Re-hashed like the local store: ArtifactPublisher.verify trusts stat's digest.
        data = self._read(key)
        return ObjectRef(key, sha256_hex(data), len(data))

    def exists(self, key: ObjectKey) -> bool:
        try:
            self._client.head_object(Bucket=self._bucket, Key=self._name(key))
        except ClientError as e:
            if self._is_missing(e, key):
                return False
            raise RepositoryError(f"S3ObjectStore: head {key} failed") from e
        except BotoCoreError as e:
            raise RepositoryError(f"S3ObjectStore: head {key} failed") from e
        return True

    def list(self, prefix: str = "") -> Iterator[ObjectKey]:
        scope = f"{self._base}{prefix.rstrip('/')}/" if prefix else self._base
        # S3 lists in byte order, which is str order for the ASCII keys ObjectKey allows.
        try:
            pages = self._client.get_paginator("list_objects_v2").paginate(
                Bucket=self._bucket, Prefix=scope
            )
            for page in pages:
                for obj in page.get("Contents", ()):
                    try:
                        yield ObjectKey.parse(obj["Key"].removeprefix(self._base))
                    except ValidationError:
                        continue
        except (BotoCoreError, ClientError) as e:
            raise RepositoryError(f"S3ObjectStore: list {prefix!r} failed") from e
