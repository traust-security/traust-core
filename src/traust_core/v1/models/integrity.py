from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import Model
from traust_core.v1.models.values import HttpsRepoUrl


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_FP = re.compile(r"fp[0-9]+:[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class Fingerprint:
    value: str

    @classmethod
    def parse(cls, raw: str) -> Fingerprint:
        if not _FP.fullmatch(raw):
            raise ValidationError(f"not a fingerprint: {raw!r}")
        return cls(raw)

    def __str__(self) -> str:
        return self.value


class FingerprintInput(Model):
    repo: HttpsRepoUrl
    rule_id: str
    path: str
    anchor: str
