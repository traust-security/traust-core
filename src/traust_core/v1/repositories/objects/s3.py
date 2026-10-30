"""S3-compatible ObjectStore (AWS, MinIO, Ceph): the `[s3]` extra.

The caller builds the boto3 client, so endpoint and credentials stay deployment config.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from traust_core.v1.errors import NotFoundError, RepositoryError, ValidationError
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.repositories.objects.store import ObjectKey, ObjectRef, _verified

_MISSING = {"NoSuchKey", "NotFound", "404"}


class S3ObjectStore:
    def __init__(self, bucket: str, *, client: Any, prefix: str = "") -> None:
        self._bucket = bucket
        self._client = client
        self._base = f"{prefix.strip('/')}/" if prefix.strip("/") else ""

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
            return self._client.get_object(Bucket=self._bucket, Key=self._name(key))["Body"].read()
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in _MISSING:
                raise NotFoundError(f"artifact {key}") from None
            raise RepositoryError(f"S3ObjectStore: read {key} failed") from e
        except BotoCoreError as e:
            raise RepositoryError(f"S3ObjectStore: read {key} failed") from e

    def get(self, ref: ObjectRef) -> bytes:
        return _verified(ref, self._read(ref.key))

    def stat(self, key: ObjectKey) -> ObjectRef:
        # Re-hashed like the local store: ArtifactPublisher.verify trusts stat's digest.
        data = self._read(key)
        return ObjectRef(key, sha256_hex(data), len(data))

    def exists(self, key: ObjectKey) -> bool:
        try:
            self._client.head_object(Bucket=self._bucket, Key=self._name(key))
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in _MISSING:
                return False
            raise RepositoryError(f"S3ObjectStore: head {key} failed") from e
        except BotoCoreError as e:
            raise RepositoryError(f"S3ObjectStore: head {key} failed") from e
        return True

    def list(self, prefix: str = "") -> Iterator[ObjectKey]:
        scope = f"{self._base}{prefix.rstrip('/')}/" if prefix else self._base
        names: list[str] = []
        try:
            pages = self._client.get_paginator("list_objects_v2").paginate(
                Bucket=self._bucket, Prefix=scope
            )
            for page in pages:
                names += [obj["Key"] for obj in page.get("Contents", ())]
        except (BotoCoreError, ClientError) as e:
            raise RepositoryError(f"S3ObjectStore: list {prefix!r} failed") from e
        for name in sorted(names):
            try:
                yield ObjectKey.parse(name.removeprefix(self._base))
            except ValidationError:
                continue
