from __future__ import annotations

import re
from collections.abc import Sequence
from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.errors import ConflictError, ValidationError
from traust_core.v1.models.findings import (
    Cwe,
    Finding,
    FindingCandidate,
    FindingCwe,
    FindingLabel,
    IdentityMove,
    IntakeResult,
    Location,
    Occurrence,
)
from traust_core.v1.models.integrity import FingerprintInput, FingerprintLocation
from traust_core.v1.models.inventory import Repository
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.findings.identity import IdentityPolicy
from traust_core.v1.services.findings.taxonomy import TaxonomyPolicy

CATEGORY = "category"
CWE_IDENTIFIER = re.compile(r"CWE-\d{1,5}")


class FindingIntake:
    def __init__(
        self, uow: TraustUnitOfWork, identity: IdentityPolicy, taxonomy: TaxonomyPolicy
    ) -> None:
        self._uow = uow
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
            kind = finding.kind
            if kind is None:
                for decision in uow.decisions.list_for_finding(finding_id):
                    if decision.validity is None:
                        continue
                    for pair in contracts.normalize_enum("validity", decision.validity).pairs:
                        if pair.enum == "finding_kind":
                            kind = pair.value
            else:
                normalized = contracts.normalize_enum("finding_kind", kind)
                kind = next((p.value for p in normalized.pairs if p.enum == "finding_kind"), kind)
            return Finding.model_validate({**dict(finding), "kind": kind})

    def accept(self, assessment_id: UUID, candidates: Sequence[FindingCandidate]) -> IntakeResult:
        """Record what one assessment reported, in one transaction; accepting it again adds nothing.

        A finding is matched by fingerprint, else created; the assessment's occurrence of it
        carries the reported severity, rule and locations.
        """
        with self._uow as uow:
            ref = uow.repository_refs.get(uow.assessments.get(assessment_id).repository_ref_id)
            repo = uow.repositories.get(ref.repository_id)
            catalog: dict[str, UUID] = {}
            pending: dict[UUID, dict[tuple[str, int | None], str | None]] = {}
            taken = {
                c.label: self._take(uow, repo, assessment_id, c, catalog, pending)
                for c in candidates
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

    def match(self, repository_id: UUID, reported: FingerprintInput) -> UUID | None:
        """The recorded finding a report entry is, by fingerprint; None if it was never accepted."""
        with self._uow as uow:
            fp = self._identity.match_key(reported, strict=True)
            found = uow.findings.find_by_fingerprint(repository_id, fp.algo, fp.value)
        return None if found is None else found.id

    def _take(
        self,
        uow: TraustUnitOfWork,
        repo: Repository,
        assessment_id: UUID,
        candidate: FindingCandidate,
        catalog: dict[str, UUID],
        pending: dict[UUID, dict[tuple[str, int | None], str | None]],
    ) -> tuple[UUID, bool]:
        """The candidate's finding id, and whether this intake created it."""
        if candidate.repository_id != repo.id:
            raise ValidationError(
                f"{candidate.label}: reported for repository {candidate.repository_id}, "
                f"but assessment {assessment_id} examined {repo.id}"
            )
        if candidate.reported_severity is None:
            raise ValidationError(f"{candidate.label}: no severity reported")
        if malformed := [c for c in candidate.cwes if not CWE_IDENTIFIER.fullmatch(c)]:
            raise ValidationError(f"{candidate.label}: not CWE identifiers: {malformed}")
        spots = tuple(FingerprintLocation(path=s.path) for s in candidate.locations)
        fp = self._identity.match_key(
            FingerprintInput(repo=repo.url, cwes=candidate.cwes, locations=spots), strict=True
        )
        finding = uow.findings.find_by_fingerprint(candidate.repository_id, fp.algo, fp.value)
        new = finding is None
        if finding is None:
            finding = uow.findings.add(
                Finding(
                    repository_id=candidate.repository_id,
                    fingerprint_algo=fp.algo,
                    fingerprint=fp.value,
                    title=candidate.title,
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
            known = locations.get(key)
            if known is not None and span.symbol is not None and known != span.symbol:
                raise ValidationError(
                    f"{candidate.label}: conflicting symbols at {span.path}:{span.line}"
                )
            locations[key] = known if known is not None else span.symbol
        self._link_cwes(uow, finding.id, candidate, catalog)
        if candidate.category:
            self._label(uow, finding.id, CATEGORY, candidate.category)
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

    def rebaseline(self, moves: Sequence[IdentityMove], decision_id: UUID) -> list[Finding]:
        raise NotImplementedError("stub: replaces finding_identity.rebaseline")
