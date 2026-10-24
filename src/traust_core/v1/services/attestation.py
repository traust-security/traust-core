from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from uuid import UUID

from traust_core.v1.errors import ConfigError, ForbiddenError, ValidationError
from traust_core.v1.models.attestation import (
    AttestationDecision,
    Comment,
    CommentSourceName,
    ImportReport,
    Statement,
    TrustTier,
)
from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.findings import (
    Decision,
    FindingExternalRef,
    RecordDecision,
    ReviewFilter,
    ReviewItem,
)
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.remediation import ExternalRef
from traust_core.v1.models.vocabulary import (
    DispositionResolution,
    ReviewReason,
    SourceType,
    Validity,
)
from traust_core.v1.providers.collaboration import CommentSource
from traust_core.v1.providers.comments import JIRA
from traust_core.v1.repositories.traust.findings import FindingsUnitOfWork
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.records import FindingRecords
from traust_core.v1.services.findings.review import FindingReview

log = logging.getLogger(__name__)

Said = tuple[Validity | None, DispositionResolution | None]

# The structured convention a person types in an MR, PR or Jira comment.
_GRAMMAR = re.compile(
    r"^\s*/traust\s+(?P<what>false-positive|confirmed|risk-accepted|fix-in-progress|resolved)"
    r"\s+(?P<id>\S+)\s+(?P<why>\S.*?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_GRAMMAR_SAYS: Mapping[str, Said] = {
    "false-positive": (Validity.FALSE_POSITIVE, None),
    "confirmed": (Validity.CONFIRMED, None),
    "risk-accepted": (None, DispositionResolution.RISK_ACCEPTED),
    "fix-in-progress": (None, DispositionResolution.FIX_IN_PROGRESS),
    "resolved": (None, DispositionResolution.RESOLVED),
}
# A commit naming the finding it fixes. Never `resolved`: verify-remediation says that.
_FIX_TRAILER = re.compile(
    r"^\s*(?:fixes|fixed|resolves|closes)\s*:?\s+(?P<id>\S+?)[.,;]?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_JIRA_SAYS: Mapping[str, Said] = {
    "done": (None, DispositionResolution.RESOLVED),
    "fixed": (None, DispositionResolution.RESOLVED),
    "not a bug": (Validity.FALSE_POSITIVE, None),
    "in progress": (None, DispositionResolution.FIX_IN_PROGRESS),
    "won't do": (None, DispositionResolution.RISK_ACCEPTED),
    "won't fix": (None, DispositionResolution.RISK_ACCEPTED),
}
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)


class StatementPolicy:
    """What a comment may change on its own; everything else waits for a person.

    Recorded as it stands only when it needs no interpretation: the `/traust` grammar from a
    forge maintainer who isn't a bot, or a commit's fix trailer. Any other mention of a finding
    is queued with the reason a person must look.
    """

    def trust(self, comment: Comment, findings: Mapping[str, UUID]) -> list[Statement]:
        """One statement per finding the comment speaks about; `findings` maps labels to ids."""
        if comment.status is not None:
            return self._transition(comment, findings)
        if comment.source == SourceType.COMMIT:
            explicit = [
                (m["id"], (None, DispositionResolution.FIX_IN_PROGRESS), m[0], True)
                for m in _FIX_TRAILER.finditer(comment.body)
            ]
        else:
            explicit = [
                (m["id"], _GRAMMAR_SAYS[m["what"].lower()], m["why"], False)
                for m in _GRAMMAR.finditer(comment.body)
            ]
        out: list[Statement] = []
        for label, (validity, resolution), why, trailer in explicit:
            finding_id = _resolve(label, findings)
            reason = (
                ReviewReason.NO_FINDING_ID
                if finding_id is None
                else None
                if trailer
                else self._authority(comment, why)
            )
            out.append(_statement(comment, finding_id, label, validity, resolution, reason))
        named = {s.finding_id for s in out}
        for label, finding_id in _mentions(comment.body, findings):
            if finding_id not in named:
                named.add(finding_id)
                out.append(
                    _statement(
                        comment, finding_id, label, None, None, ReviewReason.AMBIGUOUS_STATEMENT
                    )
                )
        return out

    def _authority(self, comment: Comment, why: str) -> ReviewReason | None:
        if comment.bot:
            return ReviewReason.UNVERIFIED_IDENTITY
        if not comment.maintainer:
            return ReviewReason.INSUFFICIENT_AUTHORITY
        if len(why.strip()) < 10:
            return ReviewReason.AMBIGUOUS_STATEMENT
        return None

    def _transition(self, comment: Comment, findings: Mapping[str, UUID]) -> list[Statement]:
        """A tracker status change for the findings its ticket names. Without the changelog the
        person who made it is unknown, so it waits for a person (as the legacy skill did)."""
        said = _JIRA_SAYS.get((comment.status or "").strip().lower())
        validity, resolution = said or (None, None)
        reason = (
            ReviewReason.AMBIGUOUS_STATEMENT
            if said is None
            else ReviewReason.UNVERIFIED_IDENTITY
            if not comment.author
            else None
        )
        return [
            _statement(comment, finding_id, label, validity, resolution, reason)
            for label, finding_id in _mentions(comment.body, findings)
        ]


def _resolve(token: str, findings: Mapping[str, UUID]) -> UUID | None:
    if token in findings:
        return findings[token]
    if _UUID.fullmatch(token) and UUID(token) in findings.values():
        return UUID(token)
    return None


def _mentions(body: str, findings: Mapping[str, UUID]) -> list[tuple[str, UUID]]:
    found = [
        (label, finding_id)
        for label, finding_id in findings.items()
        if re.search(rf"(?<![\w-]){re.escape(label)}(?![\w-])", body)
    ]
    known = set(findings.values())
    found += [(m[0], UUID(m[0])) for m in _UUID.finditer(body) if UUID(m[0]) in known]
    return list(dict.fromkeys(found))


def _statement(
    comment: Comment,
    finding_id: UUID | None,
    label: str,
    validity: Validity | None,
    resolution: DispositionResolution | None,
    reason: ReviewReason | None,
) -> Statement:
    return Statement(
        source=comment.source,
        author=comment.author,
        body=comment.body,
        url=comment.url,
        at=comment.at,
        trust=TrustTier.QUEUE if reason is not None else TrustTier.RECORD,
        finding_id=finding_id,
        label=label,
        validity=validity,
        resolution=resolution,
        reason=reason,
    )


class AttestationService:
    """Human statements from other systems, and the people who confirm what waits for them."""

    def __init__(
        self,
        uow: FindingsUnitOfWork,
        decisions: FindingDecisions,
        review: FindingReview,
        comments: Mapping[str, CommentSource],
        policy: StatementPolicy,
    ) -> None:
        self._uow = uow
        # Reads only the findings section, the one this service may hold.
        self._records = FindingRecords(uow)  # type: ignore[arg-type]
        self._decisions = decisions
        self._review = review
        self._comments = comments
        self._policy = policy

    def request(
        self, finding_id: UUID, decision_id: UUID | None, reason: ReviewReason
    ) -> ReviewItem:
        return self._review.request_signoff(finding_id, reason, decision_id)

    def import_statements(
        self,
        source: CommentSourceName,
        ref: ExternalRef,
        findings: Mapping[str, UUID],
        principal: Principal,
    ) -> ImportReport:
        """Read `ref`'s comments: record what may stand, as `principal`, and queue the rest.

        Each statement's comment becomes a `finding_external_ref` (a lead back to the system of
        record), so importing the same thing again changes nothing.
        """
        provider = self._comments.get(source)
        if provider is None:
            raise ConfigError(f"no comment source {source!r}; known: {sorted(self._comments)}")
        recorded: list[Decision] = []
        queued: list[ReviewItem] = []
        unmatched: list[Statement] = []
        seen = 0
        for comment in provider.comments(ref).data:
            for said in self._policy.trust(comment, findings):
                if said.finding_id is None:
                    unmatched.append(said)
                    continue
                link = said.url or ref.ref
                with self._uow as uow:
                    if not self._records.link_external(said.finding_id, source, link):
                        seen += 1
                        continue
                    uow.commit()
                if said.trust == TrustTier.RECORD:
                    try:
                        recorded.append(self._decisions.decide(_command(said, link), principal))
                        continue
                    except (ForbiddenError, ValidationError) as refused:
                        # Core's own gates refused it as stated: a person decides instead.
                        log.info("statement on %s queued: %s", said.finding_id, refused)
                queued.append(
                    self._review.request_signoff(
                        said.finding_id, said.reason or ReviewReason.AMBIGUOUS_STATEMENT
                    )
                )
        log.info(
            "imported %s: %d recorded, %d queued, %d unmatched, %d already imported",
            ref.ref,
            len(recorded),
            len(queued),
            len(unmatched),
            seen,
        )
        return ImportReport(
            recorded=tuple(recorded),
            queued=tuple(queued),
            unmatched=tuple(unmatched),
            already_imported=seen,
        )

    def attest(
        self,
        review_item_id: UUID,
        principal: Principal,
        decision: AttestationDecision,
        statement: RecordDecision | None,
    ) -> ReviewItem:
        """A person's answer to a review item: confirm records `statement` as theirs."""
        if decision == AttestationDecision.REJECT:
            return self._review.reject(review_item_id)
        item = self._review.require_pending(review_item_id)
        if statement is None or statement.finding_id != item.finding_id:
            raise ValidationError(
                f"confirming review item {review_item_id} needs a statement on its finding"
            )
        made = self._decisions.decide(statement, principal)
        assert made.id is not None
        return self._review.resolve(review_item_id, made.id)

    def sources(self, finding_id: UUID) -> list[FindingExternalRef]:
        """Where people spoke about a finding: the comments and tickets imported for it."""
        return self._records.external_refs([finding_id])

    def tickets(self, repository_id: UUID, system: str = JIRA) -> list[FindingExternalRef]:
        """The tickets filed against a repository's findings (auto-discovery's sources)."""
        with self._uow:
            return self._records.external_refs(
                self._records.ids_for_repository(repository_id), system
            )

    def statements(self, review_item_id: UUID, findings: Mapping[str, UUID]) -> list[Statement]:
        """What was said about the item's finding, re-read from each source now (the system of
        record): an edited comment reads as edited, a deleted one is simply gone."""
        with self._uow:
            item = self._review.get(review_item_id)
            leads = self._records.external_refs([item.finding_id])
        out: list[Statement] = []
        for lead in leads:
            provider = self._comments.get(lead.system)
            if provider is None:
                continue  # a lead from a source this deployment doesn't read
            parent = ExternalRef(system=lead.system, ref=_parent(lead.system, lead.ref))
            for comment in provider.comments(parent).data:
                if comment.url == lead.ref:
                    out += [
                        s
                        for s in self._policy.trust(comment, findings)
                        if s.finding_id == item.finding_id
                    ]
        return out

    def pending(self, filter: ReviewFilter, page: PageRequest) -> Page[ReviewItem]:
        return Page(items=tuple(self._review.pending(page.limit)))

    def for_finding(self, finding_id: UUID) -> list[ReviewItem]:
        return self._review.for_finding(finding_id)


def _command(said: Statement, link: str) -> RecordDecision:
    """The decision a recordable statement makes; who said it and where goes in the rationale."""
    assert said.finding_id is not None
    return RecordDecision(
        finding_id=said.finding_id,
        rationale=f'{said.author} on {link}: "{said.body.strip()}"',
        validity=said.validity,
        resolution=said.resolution,
        source_channel=said.source,
        occurred_at=said.at,
    )


def _parent(system: str, link: str) -> str:
    """The thing a comment's permalink belongs to: the ticket key, or the MR / PR / commit URL."""
    if system == JIRA:
        found = re.search(r"/browse/([A-Z][A-Z0-9]+-\d+)", link)
        if found is None:
            raise ValidationError(f"not a Jira link: {link}")
        return found[1]
    return link.split("#", 1)[0]
