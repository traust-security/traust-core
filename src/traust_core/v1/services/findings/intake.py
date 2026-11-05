from __future__ import annotations

import logging
import re
from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime
from uuid import UUID

from pydantic import ValidationError as ModelValidationError

from traust_core.v1 import contracts
from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    ForbiddenError,
    IntegrityError,
    NotFoundError,
    ValidationError,
)
from traust_core.v1.models.artifacts import ReportArtifact
from traust_core.v1.models.common import CodeHash, CodeSpan
from traust_core.v1.models.dependencies import AdvisoryMatch
from traust_core.v1.models.findings import (
    ClaimCorrection,
    ClaimCorrectionBinding,
    Cwe,
    Decision,
    ExposureKey,
    Finding,
    FindingCandidate,
    FindingCwe,
    FindingLabel,
    FindingView,
    IdentityMove,
    IntakeResult,
    Location,
    LocationHash,
    Occurrence,
    is_claim_correction,
    normalize_finding,
)
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.integrity import (
    Fingerprint,
    FingerprintInput,
    FingerprintLocation,
    sha256_hex,
)
from traust_core.v1.models.inventory import Repository
from traust_core.v1.models.vocabulary import ActorKind, FindingKind, ReviewItemStatus, ReviewReason
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectStore
from traust_core.v1.services.artifact_publishing import AssessmentLog, stored_bytes
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
        self,
        uow: TraustUnitOfWork,
        identity: IdentityPolicy,
        taxonomy: TaxonomyPolicy,
        objects: ObjectStore | None = None,
    ) -> None:
        self._uow = uow
        self._inventory = Inventory(uow)
        self._log = AssessmentLog(uow)
        self._identity = identity
        self._taxonomy = taxonomy
        self._objects = objects

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
            pending: dict[UUID, dict[tuple[str, int | None], CodeSpan]] = {}
            baselines: dict[UUID, set[tuple[str, int | None]]] = {}
            keys, kinds = self._fingerprints(repo, candidates, f"assessment {assessment_id}")
            taken = {
                c.label: self._take(
                    uow, assessment_id, c, fp, catalog, pending, baselines, kind=kinds.get(fp)
                )
                for c, fp in zip(candidates, keys, strict=True)
            }
            for occurrence_id, locations in pending.items():
                for (path, line), span in locations.items():
                    saved = uow.locations.add(
                        Location(
                            occurrence_id=occurrence_id,
                            path=path,
                            line_start=line,
                            line_end=line,
                            symbol=span.symbol,
                        )
                    )
                    assert saved.id is not None
                    for claim in span.hashes:
                        uow.location_hashes.add(
                            LocationHash(
                                location_id=saved.id, algorithm=claim.algorithm, digest=claim.digest
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

    def match(
        self, repository_id: UUID, reported: FingerprintInput | FindingCandidate
    ) -> UUID | None:
        """The recorded finding a report entry is, by fingerprint; None if it was never accepted."""
        with self._uow as uow:
            fp = (
                self._fingerprint(
                    self._inventory.get_repository(repository_id),
                    self._validate(reported),
                    "intake binding",
                )
                if isinstance(reported, FindingCandidate)
                else self._identity.match_key(reported, strict=True)
            )
            found = uow.findings.find_by_fingerprint(repository_id, fp.algo, fp.value)
            if found is None and self._objects is not None:
                findings = uow.findings.list_for_repository(repository_id)
                matches = {
                    finding_id
                    for finding_id, revisions in claim_revisions_for_findings(
                        uow, self._objects, findings
                    ).items()
                    for _, binding, _ in revisions
                    if (binding.fingerprint_algo, binding.fingerprint) == (fp.algo, fp.value)
                }
                if len(matches) > 1:
                    raise ConflictError("historical claim fingerprint identifies multiple findings")
                return next(iter(matches), None)
        return None if found is None else found.id

    def _validate(self, candidate: FindingCandidate) -> FindingCandidate:
        try:
            candidate = FindingCandidate.model_validate(dict(candidate))
            locations = tuple(
                CodeSpan.model_validate(
                    {
                        **dict(span),
                        "hashes": tuple(CodeHash.model_validate(dict(h)) for h in span.hashes),
                    }
                )
                for span in candidate.locations
            )
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
        claims: dict[Fingerprint, dict[tuple[str, int | None, str], str]] = {}
        kinds: dict[Fingerprint, FindingKind] = {}
        for candidate, fp in zip(candidates, keys, strict=True):
            if candidate.kind is not None:
                known_kind = kinds.setdefault(fp, candidate.kind)
                if known_kind != candidate.kind:
                    raise ValidationError(
                        f"{candidate.label}: conflicting finding kinds for the same fingerprint"
                    )
            symbols = placed.setdefault(fp, {})
            reported_hashes = claims.setdefault(fp, {})
            for span in candidate.locations:
                for claim in span.hashes:
                    key = (span.path, span.line, claim.algorithm)
                    known_hash = reported_hashes.setdefault(key, claim.digest)
                    if known_hash != claim.digest:
                        raise ValidationError(
                            f"{candidate.label}: conflicting hashes at {span.path}:{span.line}"
                        )
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
        pending: dict[UUID, dict[tuple[str, int | None], CodeSpan]],
        baselines: dict[UUID, set[tuple[str, int | None]]],
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
                    cvss_vector=candidate.cvss_vector,
                    cvss_score=candidate.cvss_score,
                    rule=candidate.rule,
                )
            )
            assert occurrence.id is not None
            pending[occurrence.id] = {}
        else:
            assert occurrence.id is not None
            if occurrence.id not in pending:
                # first touch this call of an occurrence recorded earlier: the locations
                # it already stated are the baseline — a re-run adds only what is new
                # (a new line on a stated path never feeds the fingerprint), never
                # silently dropping it; candidates later in this same call still merge
                baselines[occurrence.id] = {
                    (loc.path, loc.line_start)
                    for loc in uow.locations.list_for_occurrence(occurrence.id)
                }
                pending[occurrence.id] = {}
        locations = pending[occurrence.id]
        for span in candidate.locations:
            key = (span.path, span.line)
            if key in baselines.get(occurrence.id, ()):
                continue
            previous = locations.get(key)
            merged = (
                {h.algorithm: h for h in (*previous.hashes, *span.hashes)}
                if previous
                else {h.algorithm: h for h in span.hashes}
            )
            locations[key] = span.model_copy(
                update={
                    "symbol": (previous.symbol if previous else None) or span.symbol,
                    "hashes": tuple(merged[a] for a in sorted(merged)),
                }
            )
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

    def prepare_correction(
        self, command: ClaimCorrection, report: ReportArtifact, principal: Principal
    ) -> ReportArtifact:
        command = ClaimCorrection.model_validate(dict(command))
        principal = Principal.model_validate(dict(principal))
        command.validate_authority(principal)
        if self._objects is None:
            raise ConfigError("claim corrections require the canonical artifact object store")
        report = ReportArtifact.parse(report.payload)
        with self._uow as uow:
            finding = uow.findings.get_for_update(command.finding_id)
            assessment = self._log.get(command.assessment_id)
            ref, repo = self._inventory.resolve(assessment.repository_ref_id)
            if finding.repository_id != repo.id:
                raise ValidationError("claim correction assessment is in another repository")
            if uow.occurrences.find(command.finding_id, command.assessment_id) is None:
                raise ValidationError("claim correction must revise an existing occurrence")
            if report.metadata.repository != repo.url or report.metadata.commit != ref.sha:
                raise ValidationError(
                    "corrected report must name the original repository and commit"
                )
            candidate = correction_candidate(report, command, finding.repository_id)
            candidate = self._validate(candidate)
            keys, _ = self._fingerprints(repo, [candidate], "claim correction")
            (key,) = keys
            links = uow.finding_cwes.list_for_finding(command.finding_id)
            names = tuple(
                c.identifier for c in uow.cwes.list_by_ids({link.cwe_id for link in links})
            )
            labels = uow.finding_labels.list_for_finding(command.finding_id)
            revisions = claim_revisions(uow, self._objects, command.finding_id)
            previous = revisions[-1][2] if revisions else None
            binding = ClaimCorrectionBinding(
                **command.model_dump(),
                fingerprint_algo=finding.fingerprint_algo,
                fingerprint=finding.fingerprint,
                previous_title=finding.title,
                corrected_fingerprint_algo=key.algo,
                corrected_fingerprint=key.value,
                previous_correction_id=revisions[-1][0].id if revisions else None,
                previous_cwes=tuple(previous.cwes) if previous else names,
                previous_categories=(
                    ((str(previous.category),) if previous.category else ())
                    if previous is not None
                    else tuple(label.label for label in labels if label.taxonomy == CATEGORY)
                ),
                previous_owasp_llm_references=(
                    tuple(previous.owasp_llm_references)
                    if previous
                    else tuple(label.label for label in labels if label.taxonomy == OWASP_LLM)
                ),
            )
        return report.with_claim_correction(binding)

    def correct_claim(
        self, review_item_id: UUID, report: ReportArtifact, principal: Principal
    ) -> Finding:
        """Apply only the immutable claim a verified human accepted, retaining all occurrences."""
        principal = Principal.model_validate(dict(principal))
        report = ReportArtifact.parse(report.payload)
        binding = report.claim_correction()
        if binding is None:
            raise ValidationError("report has no canonical claim correction binding")
        binding.validate_authority(principal)
        with self._uow.write() as uow:
            item = uow.review_items.get_for_update(review_item_id)
            if (
                item.reason != REBASELINE_MAPPING
                or item.status != ReviewItemStatus.ACCEPTED
                or item.finding_id != binding.finding_id
                or item.decision_id is None
                or item.resolved_by_decision_id is None
            ):
                raise ForbiddenError("claim correction needs its accepted mapping review")
            proposal = uow.decisions.get(item.decision_id)
            answer = uow.decisions.get(item.resolved_by_decision_id)
            if (
                proposal.artifact_id is None
                or answer.artifact_id != proposal.artifact_id
                or answer.ticket != binding.ticket
                or not (answer.actor or "").startswith(f"{ActorKind.HUMAN}:")
            ):
                raise ForbiddenError("accepted review does not attest this corrected claim")
            artifact = self._log.get_artifact(proposal.artifact_id)
            if artifact.digest != sha256_hex(report.payload):
                raise ForbiddenError("accepted review binds different corrected claim bytes")
            finding = uow.findings.get_for_update(binding.finding_id)
            if self._objects is None:
                raise ConfigError("claim corrections require the canonical artifact object store")
            earlier = [
                revision
                for revision in claim_revisions(uow, self._objects, binding.finding_id)
                if revision[0].id != item.resolved_by_decision_id
            ]
            previous_id = earlier[-1][0].id if earlier else None
            if previous_id != binding.previous_correction_id:
                raise ConflictError("claim changed after the correction was proposed")
            candidate = self._validate(correction_candidate(report, binding, finding.repository_id))
            assessment = self._log.get(binding.assessment_id)
            _, repo = self._inventory.resolve(assessment.repository_ref_id)
            keys, _ = self._fingerprints(repo, [candidate], "claim correction")
            (key,) = keys
            if (key.algo, key.value) != (
                binding.corrected_fingerprint_algo,
                binding.corrected_fingerprint,
            ):
                raise ConflictError("corrected claim no longer has its reviewed identity")
            current = (finding.fingerprint_algo, finding.fingerprint)
            if current not in (
                (binding.fingerprint_algo, binding.fingerprint),
                (key.algo, key.value),
            ):
                raise ConflictError("finding identity changed after the correction was proposed")
            held = uow.findings.find_by_fingerprint(repo.id, key.algo, key.value)
            if held is not None and held.id != finding.id:
                raise ConflictError("another finding already holds the corrected fingerprint")
            saved = uow.findings.update(
                finding.model_copy(
                    update={
                        "title": candidate.title,
                        "fingerprint_algo": key.algo,
                        "fingerprint": key.value,
                    }
                )
            )
            self._link_cwes(uow, binding.finding_id, candidate, {})
            if candidate.category:
                self._label(uow, binding.finding_id, CATEGORY, candidate.category)
            for category in candidate.owasp_llm_references:
                self._label(uow, binding.finding_id, OWASP_LLM, category)
            uow.commit()
            return saved

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
            if item.decision_id is not None:
                proposal = uow.decisions.get(item.decision_id)
                if proposal.reason == "baseline_rewrite" and proposal.ticket:
                    raise ForbiddenError(
                        "a claim correction cannot attest an arbitrary identity move"
                    )
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


def correction_candidate(
    report: ReportArtifact, command: ClaimCorrection, repository_id: UUID
) -> FindingCandidate:
    candidates = [
        candidate
        for candidate in FindingCandidate.of_report(report.findings, repository_id)
        if candidate.label == command.label
    ]
    if len(candidates) != 1:
        raise ValidationError("corrected report must contain the selected label exactly once")
    return candidates[0]


def claim_revisions(
    uow: TraustUnitOfWork,
    objects: ObjectStore,
    finding_id: UUID,
    as_of: datetime | None = None,
) -> list[tuple[Decision, ClaimCorrectionBinding, FindingCandidate]]:
    finding = uow.findings.get(finding_id)
    return claim_revisions_for_findings(uow, objects, [finding], as_of=as_of).get(finding_id, [])


def claim_revisions_for_findings(
    uow: TraustUnitOfWork,
    objects: ObjectStore,
    findings: Sequence[Finding],
    *,
    history: Sequence[Decision] | None = None,
    as_of: datetime | None = None,
) -> dict[UUID, list[tuple[Decision, ClaimCorrectionBinding, FindingCandidate]]]:
    by_id = {finding.id: finding for finding in findings if finding.id is not None}
    if not by_id:
        return {}
    if history is None:
        history = uow.decisions.list_for_findings(by_id)
    revised = {
        decision.finding_id
        for decision in history
        if decision.finding_id in by_id and is_claim_correction(decision)
    }
    if not revised:
        return {}
    decisions = {decision.id: decision for decision in history}
    corrections = [
        decisions[item.resolved_by_decision_id]
        for item in uow.review_items.list_for_findings(revised)
        if item.reason == REBASELINE_MAPPING
        and item.status == ReviewItemStatus.ACCEPTED
        and item.decision_id is not None
        and item.resolved_by_decision_id is not None
        and item.resolved_by_decision_id in decisions
        and item.decision_id in decisions
        and decisions[item.decision_id].finding_id == item.finding_id
        and decisions[item.resolved_by_decision_id].finding_id == item.finding_id
        and decisions[item.decision_id].artifact_id is not None
        and decisions[item.decision_id].artifact_id
        == decisions[item.resolved_by_decision_id].artifact_id
        and decisions[item.resolved_by_decision_id].ticket
        and (as_of is None or decisions[item.resolved_by_decision_id].occurred_at <= as_of)
    ]
    artifact_ids = {decision.artifact_id for decision in corrections if decision.artifact_id}
    artifacts = {
        artifact.id: artifact for artifact in AssessmentLog(uow).list_artifacts_by_ids(artifact_ids)
    }
    if missing := artifact_ids - artifacts.keys():
        raise NotFoundError(f"claim correction artifacts {sorted(missing, key=str)}")
    reports: dict[UUID, ReportArtifact] = {}
    revisions: defaultdict[
        UUID, list[tuple[Decision, ClaimCorrectionBinding, FindingCandidate]]
    ] = defaultdict(list)
    for decision in sorted(corrections, key=lambda value: (value.occurred_at, str(value.id))):
        assert decision.artifact_id is not None
        if decision.artifact_id not in reports:
            reports[decision.artifact_id] = ReportArtifact.parse(
                stored_bytes(objects, artifacts[decision.artifact_id])
            )
        report = reports[decision.artifact_id]
        binding = report.claim_correction()
        if (
            binding is None
            or binding.finding_id != decision.finding_id
            or binding.ticket != decision.ticket
        ):
            raise IntegrityError("claim correction evidence does not match its accepted review")
        finding = by_id[decision.finding_id]
        revisions[decision.finding_id].append(
            (decision, binding, correction_candidate(report, binding, finding.repository_id))
        )
    return dict(revisions)


def corrected_claim(
    uow: TraustUnitOfWork,
    objects: ObjectStore,
    finding_id: UUID,
    as_of: datetime | None = None,
) -> FindingCandidate | None:
    revisions = claim_revisions(uow, objects, finding_id, as_of)
    return revisions[-1][2] if revisions else None
