from __future__ import annotations

import re
from collections.abc import Sequence
from uuid import UUID

from traust_core.v1.errors import ValidationError
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
from traust_core.v1.models.integrity import Fingerprint, FingerprintInput, FingerprintLocation
from traust_core.v1.models.inventory import Repository
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.artifact_publishing import AssessmentLog
from traust_core.v1.services.findings.identity import IdentityPolicy
from traust_core.v1.services.findings.taxonomy import TaxonomyPolicy
from traust_core.v1.services.portfolio import Inventory

CATEGORY = "category"
# NEED(contracts): advisory-match vocabulary (confirmed | probable) once a schema carries it.
ADVISORY_CONFIRMED = "confirmed"
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

    def accept(self, assessment_id: UUID, candidates: Sequence[FindingCandidate]) -> IntakeResult:
        """Record what one assessment reported, in one transaction; accepting it again adds nothing.

        A finding is matched by fingerprint, else created; the assessment's occurrence of it
        carries the reported severity, rule and locations.
        """
        with self._uow as uow:
            _, repo = self._inventory.resolve(self._log.get(assessment_id).repository_ref_id)
            catalog: dict[str, UUID] = {}
            pending: dict[UUID, dict[tuple[str, int | None], str | None]] = {}
            keys = self._fingerprints(repo, candidates, f"assessment {assessment_id}")
            taken = {
                c.label: self._take(uow, assessment_id, c, fp, catalog, pending)
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
        self._fingerprints(
            self._inventory.get_repository(repository_id), candidates, "the assessment"
        )

    def match(self, repository_id: UUID, reported: FingerprintInput) -> UUID | None:
        """The recorded finding a report entry is, by fingerprint; None if it was never accepted."""
        with self._uow as uow:
            fp = self._identity.match_key(reported, strict=True)
            found = uow.findings.find_by_fingerprint(repository_id, fp.algo, fp.value)
        return None if found is None else found.id

    def _fingerprints(
        self, repo: Repository, candidates: Sequence[FindingCandidate], examiner: str
    ) -> list[Fingerprint]:
        """Each candidate's identity, every candidate checked before anything is written."""
        keys = [self._fingerprint(repo, c, examiner) for c in candidates]
        placed: dict[Fingerprint, dict[tuple[str, int | None], str]] = {}
        for candidate, fp in zip(candidates, keys, strict=True):
            symbols = placed.setdefault(fp, {})
            for span in candidate.locations:
                if span.symbol is None:
                    continue
                known = symbols.setdefault((span.path, span.line), span.symbol)
                if known != span.symbol:
                    raise ValidationError(
                        f"{candidate.label}: conflicting symbols at {span.path}:{span.line}"
                    )
        return keys

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
        if malformed := [c for c in candidate.cwes if not CWE_IDENTIFIER.fullmatch(c)]:
            raise ValidationError(f"{candidate.label}: not CWE identifiers: {malformed}")
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
                    advisory_id=exposure.advisory_id if exposure else None,
                    advisory_match=ADVISORY_CONFIRMED if exposure else None,
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
