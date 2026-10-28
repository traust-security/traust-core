from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from uuid import UUID

from pydantic import ValidationError as ModelValidationError

from traust_core.v1 import contracts
from traust_core.v1.errors import ConflictError, ForbiddenError, ValidationError
from traust_core.v1.models.common import CodeSpan
from traust_core.v1.models.dependencies import AdvisoryMatch
from traust_core.v1.models.findings import (
    Cwe,
    ExposureKey,
    Finding,
    FindingCandidate,
    FindingCwe,
    FindingLabel,
    FindingView,
    IdentityMove,
    IntakeResult,
    Location,
    Occurrence,
    normalize_finding,
)
from traust_core.v1.models.integrity import Fingerprint, FingerprintInput, FingerprintLocation
from traust_core.v1.models.inventory import Repository
from traust_core.v1.models.vocabulary import ActorKind, FindingKind, ReviewItemStatus, ReviewReason
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.artifact_publishing import AssessmentLog
from traust_core.v1.services.findings.identity import IdentityPolicy
from traust_core.v1.services.findings.taxonomy import TaxonomyPolicy
from traust_core.v1.services.portfolio import Inventory

log = logging.getLogger(__name__)

CATEGORY = "category"
# A finding's OWASP Top 10 for LLM Applications categories, one label each.
OWASP_LLM = "owasp-llm"
REBASELINE_MAPPING = ReviewReason("rebaseline_mapping")
# NEED(contracts): advisory-match vocabulary (confirmed | probable) once a schema carries it.
CWE_IDENTIFIER = re.compile(r"CWE-\d{1,5}")


class FindingIntake:
    def __init__(
        self, uow: TraustUnitOfWork, identity: IdentityPolicy, taxonomy: TaxonomyPolicy
    ) -> None:
        self._uow = uow
        self._inventory = Inventory(uow)
        self._log = AssessmentLog(uow)
        self._identity = identity
        self._taxonomy = taxonomy

    def record(self, finding: Finding) -> Finding:
        """Register an identified finding; classifier validation precedes deduplication."""
        finding = Finding.model_validate(dict(finding))
        if any(value is not None for value in (finding.id, finding.created_at, finding.updated_at)):
            raise ValidationError("new findings cannot supply database identity or timestamps")
        if finding.kind is not None:
            contracts.validate_enum("finding_kind", finding.kind)
        with self._uow as uow:
            previous = uow.findings.find_by_fingerprint(
                finding.repository_id, finding.fingerprint_algo, finding.fingerprint
            )
            if previous is not None:
                fields = {"id", "created_at", "updated_at"}
                if previous.model_dump(exclude=fields) != finding.model_dump(exclude=fields):
                    raise ConflictError("finding fingerprint already identifies a different record")
                return previous
            saved = uow.findings.add(finding)
            uow.commit()
            return saved

    def get(self, finding_id: UUID) -> Finding:
        with self._uow as uow:
            finding = uow.findings.get(finding_id)
            return normalize_finding(finding, uow.decisions.list_for_finding(finding_id))

    def accept(self, assessment_id: UUID, candidates: Sequence[FindingCandidate]) -> IntakeResult:
        """Record what one assessment reported, in one transaction; accepting it again adds nothing.

        A finding is the one the candidate confirms, else matched by fingerprint, else created;
        the assessment's occurrence of it carries the reported severity, rule and locations.
        """
        with self._uow as uow:
            _, repo = self._inventory.resolve(self._log.get(assessment_id).repository_ref_id)
            candidates = tuple(self._validate(c) for c in candidates)
            catalog: dict[str, UUID] = {}
            pending: dict[UUID, dict[tuple[str, int | None], str | None]] = {}
            keys, kinds = self._fingerprints(repo, candidates, f"assessment {assessment_id}")
            taken = {
                c.label: self._take(uow, assessment_id, c, fp, catalog, pending, kind=kinds.get(fp))
                for c, fp in zip(candidates, keys, strict=True)
            }
            for occurrence_id, locations in pending.items():
                for (path, line), symbol in locations.items():
                    uow.locations.add(
                        Location(
                            occurrence_id=occurrence_id,
                            path=path,
                            line_start=line,
                            line_end=line,
                            symbol=symbol,
                        )
                    )
            uow.commit()
        return IntakeResult(
            findings={label: finding_id for label, (finding_id, _) in taken.items()},
            created=tuple(dict.fromkeys(f for f, new in taken.values() if new)),
        )

    def check(self, repository_id: UUID, candidates: Sequence[FindingCandidate]) -> None:
        """Refuse, writing nothing, what `accept` would refuse: lets a caller check before it
        records the assessment the candidates belong to."""
        candidates = tuple(self._validate(c) for c in candidates)
        self._fingerprints(
            self._inventory.get_repository(repository_id), candidates, "the assessment"
        )

    def match(self, repository_id: UUID, reported: FingerprintInput) -> UUID | None:
        """The recorded finding a report entry is, by fingerprint; None if it was never accepted."""
        with self._uow as uow:
            fp = self._identity.match_key(reported, strict=True)
            found = uow.findings.find_by_fingerprint(repository_id, fp.algo, fp.value)
        return None if found is None else found.id

    def _validate(self, candidate: FindingCandidate) -> FindingCandidate:
        try:
            candidate = FindingCandidate.model_validate(dict(candidate))
            locations = tuple(CodeSpan.model_validate(dict(span)) for span in candidate.locations)
            exposure = (
                ExposureKey.model_validate(dict(candidate.exposure))
                if candidate.exposure is not None
                else None
            )
        except ModelValidationError as error:
            raise ValidationError("invalid finding candidate") from error
        if candidate.kind is not None:
            contracts.validate_enum("finding_kind", candidate.kind)
        return candidate.model_copy(update={"locations": locations, "exposure": exposure})

    def _fingerprints(
        self, repo: Repository, candidates: Sequence[FindingCandidate], examiner: str
    ) -> tuple[list[Fingerprint], dict[Fingerprint, FindingKind]]:
        """Each identity and its agreed kind, checked before anything is written."""
        keys = [self._fingerprint(repo, c, examiner) for c in candidates]
        placed: dict[Fingerprint, dict[tuple[str, int | None], str]] = {}
        kinds: dict[Fingerprint, FindingKind] = {}
        for candidate, fp in zip(candidates, keys, strict=True):
            if candidate.kind is not None:
                known_kind = kinds.setdefault(fp, candidate.kind)
                if known_kind != candidate.kind:
                    raise ValidationError(
                        f"{candidate.label}: conflicting finding kinds for the same fingerprint"
                    )
            symbols = placed.setdefault(fp, {})
            for span in candidate.locations:
                if span.symbol is None:
                    continue
                known = symbols.setdefault((span.path, span.line), span.symbol)
                if known != span.symbol:
                    raise ValidationError(
                        f"{candidate.label}: conflicting symbols at {span.path}:{span.line}"
                    )
        return keys, kinds

    def _fingerprint(
        self, repo: Repository, candidate: FindingCandidate, examiner: str
    ) -> Fingerprint:
        if candidate.repository_id != repo.id:
            raise ValidationError(
                f"{candidate.label}: reported for repository {candidate.repository_id}, "
                f"but {examiner} examined {repo.id}"
            )
        if candidate.reported_severity is None:
            raise ValidationError(f"{candidate.label}: no severity reported")
        contracts.validate_enum("scanner_severity", candidate.reported_severity)
        if malformed := [c for c in candidate.cwes if not CWE_IDENTIFIER.fullmatch(c)]:
            raise ValidationError(f"{candidate.label}: not CWE identifiers: {malformed}")
        for span in candidate.locations:
            if not span.path or (span.line is not None and span.line < 1):
                raise ValidationError(
                    f"{candidate.label}: invalid location {span.path}:{span.line}"
                )
        if candidate.finding_id is not None:
            with self._uow as uow:
                confirmed = uow.findings.get(candidate.finding_id)
            if confirmed.repository_id != repo.id:
                raise ValidationError(
                    f"{candidate.label}: confirms finding {candidate.finding_id} of repository "
                    f"{confirmed.repository_id}, but {examiner} examined {repo.id}"
                )
            return Fingerprint(confirmed.fingerprint_algo, confirmed.fingerprint)
        if candidate.exposure is not None:
            if candidate.policy:
                raise ValidationError(
                    f"{candidate.label}: both an exposure and a policy check; "
                    "a finding has one identity"
                )
            return self._identity.exposure_key(repo.url, candidate.exposure)
        spots = tuple(FingerprintLocation(path=s.path) for s in candidate.locations)
        if candidate.policy and candidate.resources:
            spots = tuple(FingerprintLocation(resource=r) for r in candidate.resources)
        return self._identity.match_key(
            FingerprintInput(
                repo=repo.url,
                cwes=candidate.cwes,
                check_id=candidate.rule if candidate.policy else None,
                locations=spots,
            ),
            strict=True,
        )

    def _take(
        self,
        uow: TraustUnitOfWork,
        assessment_id: UUID,
        candidate: FindingCandidate,
        fp: Fingerprint,
        catalog: dict[str, UUID],
        pending: dict[UUID, dict[tuple[str, int | None], str | None]],
        *,
        kind: FindingKind | None,
    ) -> tuple[UUID, bool]:
        """The candidate's finding id, and whether this intake created it."""
        exposure = candidate.exposure
        finding = uow.findings.find_by_fingerprint(candidate.repository_id, fp.algo, fp.value)
        new = finding is None
        if finding is None:
            finding = uow.findings.add(
                Finding(
                    repository_id=candidate.repository_id,
                    fingerprint_algo=fp.algo,
                    fingerprint=fp.value,
                    title=candidate.title,
                    kind=kind,
                    advisory_id=exposure.advisory_id if exposure else None,
                    advisory_match=AdvisoryMatch.CONFIRMED if exposure else None,
                )
            )
        assert finding.id is not None
        occurrence = uow.occurrences.find(finding.id, assessment_id)
        if occurrence is None:
            occurrence = uow.occurrences.add(
                Occurrence(
                    finding_id=finding.id,
                    assessment_id=assessment_id,
                    severity=candidate.reported_severity,
                    rule=candidate.rule,
                )
            )
            assert occurrence.id is not None
            pending[occurrence.id] = {}
        locations = pending.get(occurrence.id, {})
        for span in candidate.locations:
            key = (span.path, span.line)
            locations[key] = locations.get(key) or span.symbol
        self._link_cwes(uow, finding.id, candidate, catalog)
        if candidate.category:
            self._label(uow, finding.id, CATEGORY, candidate.category)
        for llm_category in dict.fromkeys(candidate.owasp_llm_references):
            self._label(uow, finding.id, OWASP_LLM, llm_category)
        return finding.id, new

    def _link_cwes(
        self,
        uow: TraustUnitOfWork,
        finding_id: UUID,
        candidate: FindingCandidate,
        catalog: dict[str, UUID],
    ) -> None:
        linked = {fc.cwe_id for fc in uow.finding_cwes.list_for_finding(finding_id)}
        for identifier in dict.fromkeys(candidate.cwes):
            if identifier not in catalog:
                # As the report schemas did, any well-formed CWE is accepted; loading the MITRE
                # catalog fills in abstraction and mapping usage later (NEED(cwe-catalog)).
                cwe = uow.cwes.get_or_add(Cwe(identifier=identifier))
                assert cwe.id is not None
                catalog[identifier] = cwe.id
            if catalog[identifier] not in linked:
                uow.finding_cwes.add(FindingCwe(finding_id=finding_id, cwe_id=catalog[identifier]))

    def _label(self, uow: TraustUnitOfWork, finding_id: UUID, taxonomy: str, label: str) -> None:
        if not any(
            fl.taxonomy == taxonomy and fl.label == label
            for fl in uow.finding_labels.list_for_finding(finding_id)
        ):
            uow.finding_labels.add(
                FindingLabel(finding_id=finding_id, taxonomy=taxonomy, label=label)
            )

    def moves(
        self, previous: Sequence[FindingView], candidates: Sequence[FindingCandidate]
    ) -> list[IdentityMove]:
        """Which recorded findings a re-audit's candidates report under another identity."""
        if not candidates:
            return []
        repository_ids = {c.repository_id for c in candidates}
        if len(repository_ids) != 1:
            raise ValidationError("a rebaseline compares candidates of one repository")
        repo = self._inventory.get_repository(repository_ids.pop())
        keys, _ = self._fingerprints(repo, candidates, "the re-audit")
        return self._identity.moves(previous, candidates, keys)

    def rebaseline(self, moves: Sequence[IdentityMove], review_item_id: UUID) -> list[Finding]:
        """Move a finding onto the identity a re-audit gives it: same id, so its occurrences and
        decisions follow; a person accepting its `rebaseline_mapping` review attests the move."""
        if not moves:
            raise ValidationError("rebaseline needs a move")
        with self._uow as uow:
            item = uow.review_items.get(review_item_id)
            if (
                item.reason != REBASELINE_MAPPING
                or item.status != ReviewItemStatus.ACCEPTED
                or item.resolved_by_decision_id is None
                or not (uow.decisions.get(item.resolved_by_decision_id).actor or "").startswith(
                    f"{ActorKind.HUMAN}:"
                )
            ):
                raise ForbiddenError(
                    f"review item {review_item_id} is not a person's accepted "
                    f"{REBASELINE_MAPPING} review"
                )
            if {m.finding_id for m in moves} != {item.finding_id} or len(moves) != 1:
                raise ForbiddenError(
                    f"review item {review_item_id} attests one move of finding {item.finding_id}"
                )
            (move,) = moves
            finding = uow.findings.get(move.finding_id)
            key = (move.fingerprint_algo, move.fingerprint)
            if (finding.fingerprint_algo, finding.fingerprint) == key:
                return [finding]
            if uow.findings.find_by_fingerprint(finding.repository_id, *key) is not None:
                raise ConflictError(
                    f"finding {finding.id}: another finding already holds {move.fingerprint}"
                )
            moved = uow.findings.update(
                finding.model_copy(update={"fingerprint_algo": key[0], "fingerprint": key[1]})
            )
            uow.commit()
        self._uow.after_commit(lambda: log.info("finding %s moved", finding.id))
        return [moved]
