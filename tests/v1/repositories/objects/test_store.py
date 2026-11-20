import os
from collections.abc import Iterator
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from traust_core.v1.errors import IntegrityError, NotFoundError, RepositoryError, ValidationError
from traust_core.v1.repositories import (
    InMemoryObjectStore,
    LocalObjectStore,
    ObjectKey,
    ObjectRef,
    ObjectStore,
)
from traust_core.v1.repositories.objects.s3 import S3ObjectStore

KEY = ObjectKey.parse("reports/org/repo/scan.json")


@pytest.fixture(params=["memory", "local", "s3"])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[ObjectStore]:
    if request.param == "s3":
        with mock_aws():
            client = boto3.client("s3", region_name="us-east-1")
            client.create_bucket(Bucket="traust")
            yield S3ObjectStore("traust", client=client)
        return
    yield InMemoryObjectStore() if request.param == "memory" else LocalObjectStore(tmp_path)


def test_put_then_get_round_trips(store: ObjectStore) -> None:
    ref = store.put(KEY, b'{"ok": true}')
    assert store.get(ref) == b'{"ok": true}'
    assert store.stat(KEY) == ref
    assert store.exists(KEY)


def test_get_with_wrong_digest_raises_integrity_error(store: ObjectStore) -> None:
    ref = store.put(KEY, b"original")
    with pytest.raises(IntegrityError):
        store.get(ObjectRef(ref.key, "0" * 64, ref.size))


def test_read_by_key_and_digest_checks_the_bytes(store: ObjectStore) -> None:
    ref = store.put(KEY, b"original")
    assert store.read(KEY, ref.sha256) == b"original"
    with pytest.raises(IntegrityError):
        store.read(KEY, "0" * 64)
    with pytest.raises(NotFoundError):
        store.read(ObjectKey.parse("absent/x.json"), ref.sha256)


def test_missing_key_raises_not_found(store: ObjectStore) -> None:
    assert not store.exists(KEY)
    with pytest.raises(NotFoundError):
        store.stat(KEY)


def test_overwrite_returns_new_ref(store: ObjectStore) -> None:
    first = store.put(KEY, b"v1")
    second = store.put(KEY, b"v2")
    assert first.sha256 != second.sha256
    with pytest.raises(IntegrityError):
        store.get(first)


@pytest.mark.parametrize("raw", ["", "/abs", "a/../b", "a//b", "a/./b", "a b", "a/\x00"])
def test_bad_keys_are_rejected(raw: str) -> None:
    with pytest.raises(ValidationError):
        ObjectKey.parse(raw)


def test_local_store_leaves_no_temp_files(tmp_path: Path) -> None:
    LocalObjectStore(tmp_path).put(KEY, b"x")
    assert [p.name for p in (tmp_path / "reports/org/repo").iterdir()] == ["scan.json"]


def test_local_store_put_honors_the_process_umask(tmp_path: Path) -> None:
    """The store's volume is shared by core's server, the engine and the claim workers under
    different uids and one supplemental group, and the deployments wrap each writer in
    `umask 0002` so the bytes land group-readable. mkstemp forced 0600 whatever the umask
    said, so every artifact was readable only by the pod that wrote it — a phantom row to
    every other reader (the census folds answered source_unavailable). The temp must be
    created where the umask applies, and a stricter umask must stay strict."""
    store = LocalObjectStore(tmp_path)
    shared = ObjectKey.parse("artifacts/run-manifest/shared.json")
    was = os.umask(0o002)
    try:
        store.put(shared, b"{}")
    finally:
        os.umask(was)
    assert (tmp_path / "artifacts/run-manifest/shared.json").stat().st_mode & 0o777 == 0o664

    private = ObjectKey.parse("artifacts/run-manifest/private.json")
    was = os.umask(0o077)
    try:
        store.put(private, b"{}")
    finally:
        os.umask(was)
    assert (tmp_path / "artifacts/run-manifest/private.json").stat().st_mode & 0o777 == 0o600


def test_local_store_failed_put_with_failing_cleanup_raises_repository_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # a write failure after temp-file creation, where cleanup fails too:
    # the original OSError must still surface as the RepositoryError's cause
    def refused(self: Path, *args: object, **kw: object) -> None:
        raise OSError("refused")

    monkeypatch.setattr(Path, "replace", refused)
    monkeypatch.setattr(Path, "unlink", refused)
    with pytest.raises(RepositoryError) as raised:
        LocalObjectStore(tmp_path).put(KEY, b"x")
    assert isinstance(raised.value.__cause__, OSError)


def test_dot_named_repos_are_valid_keys() -> None:
    assert str(ObjectKey.parse("findings/.github/.github-triage.json")).startswith("findings/")


def test_list_by_prefix(store: ObjectStore) -> None:
    store.put(ObjectKey.parse("a/x.json"), b"1")
    store.put(ObjectKey.parse("b/y.json"), b"2")
    assert [str(k) for k in store.list("a")] == ["a/x.json"]
    assert len(list(store.list())) == 2
