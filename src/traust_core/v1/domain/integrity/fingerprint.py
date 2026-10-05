from __future__ import annotations

import re
from dataclasses import dataclass

from traust_core.v1.domain.errors import ValidationError
from traust_core.v1.domain.model import Model
from traust_core.v1.domain.values import HttpsRepoUrl

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


def fingerprint(subject: FingerprintInput) -> Fingerprint:
    raise NotImplementedError("fingerprint rules pending the integrity spec (D5)")
