from pathlib import Path

import pytest

from traust_core.v1.errors import IntegrityError, NotFoundError, ValidationError
from traust_core.v1.repositories import (
    InMemoryObjectStore,
    LocalObjectStore,
    ObjectKey,
    ObjectRef,
    ObjectStore,
)

KEY = ObjectKey.parse("reports/org/repo/scan.json")


@pytest.fixture(params=["memory", "local"])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> ObjectStore:
    return InMemoryObjectStore() if request.param == "memory" else LocalObjectStore(tmp_path)


def test_put_then_get_round_trips(store: ObjectStore) -> None:
    ref = store.put(KEY, b'{"ok": true}')
    assert store.get(ref) == b'{"ok": true}'
    assert store.stat(KEY) == ref
    assert store.exists(KEY)


def test_get_with_wrong_digest_raises_integrity_error(store: ObjectStore) -> None:
    ref = store.put(KEY, b"original")
    with pytest.raises(IntegrityError):
        store.get(ObjectRef(ref.key, "0" * 64, ref.size))


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


def test_dot_named_repos_are_valid_keys() -> None:
    assert str(ObjectKey.parse("findings/.github/.github-triage.json")).startswith("findings/")


def test_list_by_prefix(store: ObjectStore) -> None:
    store.put(ObjectKey.parse("a/x.json"), b"1")
    store.put(ObjectKey.parse("b/y.json"), b"2")
    assert [str(k) for k in store.list("a")] == ["a/x.json"]
    assert len(list(store.list())) == 2
