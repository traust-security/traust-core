"""Object storage: document bytes by key (local disk, S3-compatible), never database rows.

Rows that point at these bytes live in the artifact table (uri + digest).
"""

from traust_core.v1.repositories.objects.store import (
    InMemoryObjectStore,
    LocalObjectStore,
    ObjectKey,
    ObjectRef,
    ObjectStore,
)

__all__ = [
    "InMemoryObjectStore",
    "LocalObjectStore",
    "ObjectKey",
    "ObjectRef",
    "ObjectStore",
]
