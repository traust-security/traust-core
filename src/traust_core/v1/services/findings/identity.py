from __future__ import annotations

from traust_core.v1.models.findings import FindingCandidate
from traust_core.v1.models.integrity import Fingerprint, FingerprintInput


class IdentityPolicy:
    def match_key(self, candidate: FindingCandidate) -> Fingerprint:
        raise NotImplementedError(
            "stub: replaces _util/finding_identity.py, traust-ledger _internal/identity.py"
        )

    def fingerprint(self, subject: FingerprintInput) -> Fingerprint:
        raise NotImplementedError("stub: fingerprint rules pending the integrity spec (D5)")
