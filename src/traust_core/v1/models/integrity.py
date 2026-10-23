from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import Model


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_HEX64 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """A finding's identity: the recipe version that minted it and its hex digest."""

    algo: str
    value: str

    def __post_init__(self) -> None:
        if not self.algo or not _HEX64.fullmatch(self.value):
            raise ValidationError(f"not a fingerprint: {self.algo!r} {self.value!r}")

    def __str__(self) -> str:
        return self.value


class FingerprintLocation(Model):
    path: str | None = None
    resource: str | None = None


class FingerprintInput(Model):
    """What the identity recipe reads from a reported finding, kept as reported."""

    repo: str = ""
    cwes: tuple[str, ...] = ()
    cwe: str | None = None
    check_id: str | None = None
    locations: tuple[FingerprintLocation, ...] = ()

    @classmethod
    def from_report(cls, finding: Mapping[str, Any], repo: str | None) -> FingerprintInput:
        def text(value: object) -> str | None:
            return value if isinstance(value, str) else None

        return cls(
            repo=repo or "",
            cwes=tuple(c for c in finding.get("cwes") or () if isinstance(c, str)),
            cwe=text(finding.get("cwe")),
            check_id=text(finding.get("check_id")),
            locations=tuple(
                FingerprintLocation(path=text(loc.get("path")), resource=text(loc.get("resource")))
                for loc in finding.get("locations") or ()
                if isinstance(loc, Mapping)
            ),
        )
