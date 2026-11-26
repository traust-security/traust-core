from __future__ import annotations

import contextlib
import os
import re
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from traust_core.v1.errors import IntegrityError, NotFoundError, RepositoryError, ValidationError
from traust_core.v1.models.integrity import sha256_hex

_SEGMENT = re.compile(r"[A-Za-z0-9._-]+")


@dataclass(frozen=True, slots=True)
class ObjectKey:
    value: str

    @classmethod
    def parse(cls, raw: str) -> ObjectKey:
        segments = raw.split("/")
        if not raw or any(not _SEGMENT.fullmatch(s) or s in {".", ".."} for s in segments):
            raise ValidationError(f"invalid object key: {raw!r}")
        return cls(raw)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ObjectRef:
    key: ObjectKey
    sha256: str
    size: int


# NEED(vendor-agnostic): local disk and S3-compatible object storage behind this one port.
# Vendor SDKs live in optional adapters selected by config; core never imports one.
class ObjectStore(Protocol):
    def put(self, key: ObjectKey, data: bytes) -> ObjectRef: ...
    def get(self, ref: ObjectRef) -> bytes: ...
    def read(self, key: ObjectKey, sha256: str) -> bytes: ...
    def stat(self, key: ObjectKey) -> ObjectRef: ...
    def size(self, key: ObjectKey) -> int: ...
    def exists(self, key: ObjectKey) -> bool: ...
    def list(self, prefix: str = "") -> Iterator[ObjectKey]: ...


def _verified(ref: ObjectRef, data: bytes) -> bytes:
    if (actual := sha256_hex(data)) != ref.sha256:
        raise IntegrityError(f"artifact {ref.key}: sha256 {actual} != expected {ref.sha256}")
    return data


class LocalObjectStore:
    def __init__(self, root: Path) -> None:
        self._root = root

    def _path(self, key: ObjectKey) -> Path:
        return self._root / key.value

    def put(self, key: ObjectKey, data: bytes) -> ObjectRef:
        path = self._path(key)
        tmp: Path | None = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # The artifact store is one volume shared by every writer and reader — core's
            # server, the engine and the claim workers — under different uids and one
            # supplemental group, and the deployments wrap each of them in `umask 0002`
            # exactly so the bytes land group-readable. mkstemp would force 0600 whatever
            # the umask says, leaving every artifact readable only by the pod that wrote
            # it: a phantom to every other reader (a row whose bytes nothing else can
            # read — the census folds answered source_unavailable). Create the temp with
            # O_EXCL at mode 0666 instead, where the process umask applies at creation
            # like open()'s, so the mode the wrapper chose is the mode the bytes keep.
            for _ in range(10):
                candidate = path.with_name(f".{path.name}.{uuid.uuid4().hex}")
                try:
                    fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
                except FileExistsError:
                    continue
                tmp = candidate
                break
            else:
                raise OSError(f"no free temp name beside {path}")
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            Path(tmp).replace(path)
        except OSError as e:
            # a failed write must not leave the dot-prefixed temp file behind —
            # list() would surface it as a phantom object. Cleanup cannot be
            # allowed to mask the original failure: the RepositoryError below
            # carries it as cause, so a failing unlink is only swallowed.
            if tmp:
                with contextlib.suppress(OSError):
                    Path(tmp).unlink(missing_ok=True)
            raise RepositoryError(f"LocalObjectStore: put {key} failed") from e
        return ObjectRef(key, sha256_hex(data), len(data))

    def _read(self, key: ObjectKey) -> bytes:
        try:
            return self._path(key).read_bytes()
        except FileNotFoundError:
            raise NotFoundError(f"artifact {key}") from None
        except OSError as e:
            raise RepositoryError(f"LocalObjectStore: read {key} failed") from e

    def get(self, ref: ObjectRef) -> bytes:
        return _verified(ref, self._read(ref.key))

    def read(self, key: ObjectKey, sha256: str) -> bytes:
        """The bytes at `key`, checked against a digest recorded elsewhere: one read."""
        data = self._read(key)
        return _verified(ObjectRef(key, sha256, len(data)), data)

    def stat(self, key: ObjectKey) -> ObjectRef:
        data = self._read(key)
        return ObjectRef(key, sha256_hex(data), len(data))

    def size(self, key: ObjectKey) -> int:
        """The stored size alone: listings state it without reading the bytes."""
        try:
            return self._path(key).stat().st_size
        except FileNotFoundError:
            raise NotFoundError(f"artifact {key}") from None
        except OSError as e:
            raise RepositoryError(f"LocalObjectStore: size {key} failed") from e

    def exists(self, key: ObjectKey) -> bool:
        return self._path(key).is_file()

    def list(self, prefix: str = "") -> Iterator[ObjectKey]:
        start = self._root / prefix
        for path in sorted(start.rglob("*")) if start.is_dir() else ():
            if path.is_file() and not path.is_symlink():
                try:
                    yield ObjectKey.parse(path.relative_to(self._root).as_posix())
                except ValidationError:
                    continue


class InMemoryObjectStore:
    def __init__(self) -> None:
        self._blobs: dict[ObjectKey, bytes] = {}

    def put(self, key: ObjectKey, data: bytes) -> ObjectRef:
        self._blobs[key] = data
        return ObjectRef(key, sha256_hex(data), len(data))

    def _read(self, key: ObjectKey) -> bytes:
        try:
            return self._blobs[key]
        except KeyError:
            raise NotFoundError(f"artifact {key}") from None

    def get(self, ref: ObjectRef) -> bytes:
        return _verified(ref, self._read(ref.key))

    def read(self, key: ObjectKey, sha256: str) -> bytes:
        """The bytes at `key`, checked against a digest recorded elsewhere: one read."""
        data = self._read(key)
        return _verified(ObjectRef(key, sha256, len(data)), data)

    def stat(self, key: ObjectKey) -> ObjectRef:
        data = self._read(key)
        return ObjectRef(key, sha256_hex(data), len(data))

    def size(self, key: ObjectKey) -> int:
        """The stored size alone: listings state it without reading the bytes."""
        return len(self._read(key))

    def exists(self, key: ObjectKey) -> bool:
        return key in self._blobs

    def list(self, prefix: str = "") -> Iterator[ObjectKey]:
        scope = f"{prefix.rstrip('/')}/" if prefix else ""
        yield from sorted((k for k in self._blobs if k.value.startswith(scope)), key=str)
