from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from traust_core.v1.domain import GitSha, HttpsRepoUrl, Model


class ObserveStatus(StrEnum):
    OK = "ok"
    UNREACHABLE = "unreachable"


class RepoState(Model):
    repo: HttpsRepoUrl
    status: ObserveStatus
    head: GitSha | None = None
    audited_head: GitSha | None = None
    observed_at: datetime

    @property
    def changed_since_audit(self) -> bool | None:
        if self.head is None or self.audited_head is None:
            return None
        return self.head != self.audited_head
