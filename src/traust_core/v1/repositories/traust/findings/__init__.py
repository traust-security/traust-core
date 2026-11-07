"""3b · Findings & decisions - what was found and judged. One repository per table."""

from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Protocol, Self

from traust_core.v1.repositories.traust.findings.cwe import CWE, CweRepository, SqlCweRepository
from traust_core.v1.repositories.traust.findings.decision import (
    DECISION,
    DecisionRepository,
    SqlDecisionRepository,
)
from traust_core.v1.repositories.traust.findings.decision_approver import (
    DECISION_APPROVER,
    DecisionApproverRepository,
    SqlDecisionApproverRepository,
)
from traust_core.v1.repositories.traust.findings.finding import (
    FINDING,
    FindingRepository,
    SqlFindingRepository,
)
from traust_core.v1.repositories.traust.findings.finding_cwe import (
    FINDING_CWE,
    FindingCweRepository,
    SqlFindingCweRepository,
)
from traust_core.v1.repositories.traust.findings.finding_external_ref import (
    FINDING_EXTERNAL_REF,
    FindingExternalRefRepository,
    SqlFindingExternalRefRepository,
)
from traust_core.v1.repositories.traust.findings.finding_label import (
    FINDING_LABEL,
    FindingLabelRepository,
    SqlFindingLabelRepository,
)
from traust_core.v1.repositories.traust.findings.location_hash import (
    LOCATION_HASH,
    LocationHashRepository,
    SqlLocationHashRepository,
)
from traust_core.v1.repositories.traust.findings.review_item import (
    REVIEW_ITEM,
    ReviewItemRepository,
    SqlReviewItemRepository,
)
from traust_core.v1.repositories.unit_of_work import UnitOfWork

TABLES = (
    FINDING,
    CWE,
    FINDING_CWE,
    FINDING_LABEL,
    FINDING_EXTERNAL_REF,
    DECISION,
    DECISION_APPROVER,
    REVIEW_ITEM,
    LOCATION_HASH,
)


class FindingsUnitOfWork(UnitOfWork, Protocol):
    def write(self) -> AbstractContextManager[Self]: ...

    findings: FindingRepository
    cwes: CweRepository
    finding_cwes: FindingCweRepository
    finding_labels: FindingLabelRepository
    finding_external_refs: FindingExternalRefRepository
    decisions: DecisionRepository
    decision_approvers: DecisionApproverRepository
    review_items: ReviewItemRepository
    location_hashes: LocationHashRepository


__all__ = [
    "TABLES",
    "CweRepository",
    "DecisionApproverRepository",
    "DecisionRepository",
    "FindingCweRepository",
    "FindingExternalRefRepository",
    "FindingLabelRepository",
    "FindingRepository",
    "FindingsUnitOfWork",
    "LocationHashRepository",
    "ReviewItemRepository",
    "SqlCweRepository",
    "SqlDecisionApproverRepository",
    "SqlDecisionRepository",
    "SqlFindingCweRepository",
    "SqlFindingExternalRefRepository",
    "SqlFindingLabelRepository",
    "SqlFindingRepository",
    "SqlLocationHashRepository",
    "SqlReviewItemRepository",
]
