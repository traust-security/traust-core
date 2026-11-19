from __future__ import annotations

from fastapi import APIRouter
from pydantic import Field

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import Model
from traust_core.v1.models.findings import OccurrenceClaim, OccurrenceClaimReport
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.findings.service import Findings

router = APIRouter()

# The batch routes' own bound: a page's worth of claims per request.
MAX_OCCURRENCE_CLAIMS = 500


class OccurrenceClaimsBody(Model):
    """A batch of declared CVSS claims under one authority: a verified person's
    ticket and rationale."""

    ticket: str = Field(min_length=1, max_length=200)
    rationale: str = Field(min_length=10, max_length=20_000)
    claims: tuple[OccurrenceClaim, ...]


@router.post("/v1/occurrence-claims", responses=PROBLEMS(401, 403, 422))
def record_occurrence_claims(
    body: OccurrenceClaimsBody, findings: Findings, caller: Caller
) -> OccurrenceClaimReport:
    """Record CVSS claims occurrences' reports stated: each claim (the finding by its
    fingerprint, the assessment that reported it, the vector and score) is answered
    per claim — recorded, already recorded, already carried by the occurrence's own
    columns, conflicting (never an overwrite), or refused with its reason. The write
    is append-only: a person's data-error decision, never a column mutation."""
    if not body.claims:
        raise ValidationError("record named occurrence claims; the set is required")
    if len(body.claims) > MAX_OCCURRENCE_CLAIMS:
        raise ValidationError(
            f"record at most {MAX_OCCURRENCE_CLAIMS} occurrence claims per request"
        )
    return findings.record_occurrence_claims(
        body.claims,
        ticket=body.ticket,
        rationale=body.rationale,
        principal=caller,
    )
