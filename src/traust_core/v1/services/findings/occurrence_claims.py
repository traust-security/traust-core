"""The occurrence-claim door: CVSS claims recorded as governed statements.

The caller declares the claims a report stated (the finding by its fingerprint, the
assessment that reported it, the CVSS itself); each claim validates through core's
own CVSS discipline and records as a person's data-error decision — never a column
mutation, since occurrence rows are append-only by contracts constraint. What the
occurrence already carries needs no recording; a conflicting claim is refused, never
an overwrite.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from typing import TYPE_CHECKING

from traust_core.v1.errors import ForbiddenError, ValidationError
from traust_core.v1.models.cvss import CvssSource, score_of
from traust_core.v1.models.findings import (
    RATIONALE_MIN_LENGTH,
    OccurrenceClaim,
    OccurrenceClaimOutcome,
    OccurrenceClaimReport,
    OccurrenceClaimResult,
)
from traust_core.v1.models.identity import Principal
from traust_core.v1.repositories.contract import TraustUnitOfWork

if TYPE_CHECKING:
    from traust_core.v1.services.findings.decisions import FindingDecisions


class OccurrenceClaims:
    """Records per-occurrence CVSS claims as governed, person-gated statements."""

    def __init__(self, uow: TraustUnitOfWork, decisions: FindingDecisions) -> None:
        self._uow = uow
        self._decisions = decisions

    def record(
        self,
        claims: Sequence[OccurrenceClaim],
        *,
        ticket: str,
        rationale: str,
        principal: Principal,
    ) -> OccurrenceClaimReport:
        """One batch of declared claims, one transaction: every claim's answer in the
        report, nothing guessed and nothing overwritten."""
        if not principal.is_verified_human():
            raise ForbiddenError("an occurrence claim needs a verified human")
        if not ticket.strip():
            raise ValidationError("an occurrence claim names its authority: a ticket")
        if len(rationale.strip()) < RATIONALE_MIN_LENGTH:
            raise ValidationError(f"a rationale of at least {RATIONALE_MIN_LENGTH} characters")
        # A deterministic processing order: the append locks each finding's row, and
        # two concurrent batches locking the same findings in different orders would
        # deadlock where sorted they queue.
        ordered = sorted(
            dict.fromkeys(claims),
            key=lambda c: (c.repository_id, c.fingerprint_algo, c.fingerprint, c.assessment_id),
        )
        answers: dict[OccurrenceClaim, OccurrenceClaimResult] = {}
        with self._uow.write() as uow:
            for claim in ordered:
                answers[claim] = self._record_one(
                    uow, claim, ticket=ticket, rationale=rationale, principal=principal
                )
            uow.commit()
        results = [answers[claim] for claim in claims]
        counts = Counter(row.outcome for row in results)
        return OccurrenceClaimReport(results=tuple(results), counts=dict(counts))

    def _record_one(
        self,
        uow: TraustUnitOfWork,
        claim: OccurrenceClaim,
        *,
        ticket: str,
        rationale: str,
        principal: Principal,
    ) -> OccurrenceClaimResult:
        # The CVSS discipline first (models.cvss.score_of): a malformed vector — no
        # version prefix, a malformed metric, an uncomputable base score — is refused,
        # never guessed at.
        if score_of(CvssSource.SCANNER, claim.cvss_vector, document="occurrence-claim") is None:
            return OccurrenceClaimResult(claim=claim, outcome=OccurrenceClaimOutcome.INVALID)
        finding = uow.findings.find_by_fingerprint(
            claim.repository_id, claim.fingerprint_algo, claim.fingerprint
        )
        if finding is None or finding.id is None:
            return OccurrenceClaimResult(
                claim=claim, outcome=OccurrenceClaimOutcome.UNKNOWN_FINDING
            )
        occurrence = uow.occurrences.find(finding.id, claim.assessment_id)
        if occurrence is None:
            return OccurrenceClaimResult(
                claim=claim, outcome=OccurrenceClaimOutcome.UNREPORTED, finding_id=finding.id
            )
        assert occurrence.id is not None
        if occurrence.cvss_score is not None or occurrence.cvss_vector is not None:
            # the occurrence said something: an equal claim is the idempotent answer,
            # anything else is refused, never overwritten
            carried = (occurrence.cvss_vector, occurrence.cvss_score) == (
                claim.cvss_vector,
                claim.cvss_score,
            )
            return OccurrenceClaimResult(
                claim=claim,
                outcome=(
                    OccurrenceClaimOutcome.ALREADY_CARRIED
                    if carried
                    else OccurrenceClaimOutcome.CONFLICTING
                ),
                finding_id=finding.id,
                occurrence_id=occurrence.id,
            )
        decision, appended = self._decisions.append_occurrence_claim(
            finding.id, principal, ticket=ticket, rationale=rationale
        )
        return OccurrenceClaimResult(
            claim=claim,
            outcome=(
                OccurrenceClaimOutcome.RECORDED
                if appended
                else OccurrenceClaimOutcome.ALREADY_RECORDED
            ),
            finding_id=finding.id,
            occurrence_id=occurrence.id,
            decision_id=decision.id,
        )
