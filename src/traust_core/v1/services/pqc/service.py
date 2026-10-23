from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import TypeVar, overload
from urllib.parse import urlsplit
from uuid import UUID

from traust_core.v1.errors import ConfigError, IntegrityError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import (
    ArtifactDocument,
    PqcFactsArtifact,
    PqcReadinessArtifact,
)
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    Artifact,
    Assessment,
    AssessmentKind,
)
from traust_core.v1.models.code_facts import CryptoProbeId
from traust_core.v1.models.common import Provenance, ToolRequest
from traust_core.v1.models.findings import FindingContext, SubjectRef
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.pqc import (
    PqcBlocker,
    PqcDimension,
    PqcFilter,
    PqcPrescan,
    PqcReadiness,
    PqcReadinessInput,
    PqcRollup,
    PqcRoute,
)
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.providers.clock import Clock, SystemClock
from traust_core.v1.providers.crypto import long_validity
from traust_core.v1.providers.pqc import PqcScanner
from traust_core.v1.repositories.traust.assessments import AssessmentsUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, record_artifact
from traust_core.v1.services.code_facts import CodeFactsService
from traust_core.v1.services.lint import Lint, LintContext, LintReport
from traust_core.v1.services.portfolio import PortfolioService
from traust_core.v1.services.pqc import facts as pqc_facts
from traust_core.v1.services.pqc import readiness as pqc_readiness

log = logging.getLogger(__name__)

READINESS_LINT = Lint({PqcReadinessArtifact: [pqc_readiness.ReadinessRules()]})
_KIND = AssessmentKind.PQC_READINESS
_SCANNER = "pqc-scan"
_SKILL = "skill:pqc-readiness"
_BATCH = 500

D = TypeVar("D", bound=ArtifactDocument)


class PqcService:
    def __init__(
        self,
        uow: AssessmentsUnitOfWork,
        code_facts: CodeFactsService,
        portfolio: PortfolioService,
        publisher: ArtifactPublisher,
        scanner: PqcScanner | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._uow = uow
        self._code_facts = code_facts
        self._portfolio = portfolio
        self._publisher = publisher
        self._scanner = scanner
        self._clock = clock or SystemClock()

    def prescan(self, repository_ref_id: UUID, request: ToolRequest | None) -> PqcPrescan:
        """Layer 1 for the commit: the pinned scan plus the crypto census over its checkout, or
        its manifest SBOM's crypto packages alone (`request` None, sbom-only). A commit already
        scanned by the current pack on the same basis is not scanned again."""
        scanner = self._require_scanner()
        stamps = scanner.stamps()
        subject = self._subject(repository_ref_id)
        latest = self._latest(repository_ref_id, PqcFactsArtifact)
        if latest is not None:
            assessment, doc = latest
            current = pqc_facts.read_stamps(doc).same_pack(stamps)
            basis = doc.coverage.assessment_basis == ("sbom-only" if request is None else "source")
            if current and basis:
                return self._prescanned(assessment, doc, scanned=False)
        if request is None:
            scan = None
            facts = pqc_facts.sbom_facts(self._code_facts.packages(repository_ref_id))
        else:
            if not (readiness := scanner.check()).ready:
                raise ConfigError(f"{scanner.name} is not ready: {readiness.detail}")
            census = [
                f
                for f in self._code_facts.crypto(repository_ref_id, request)
                if f.probe_id != CryptoProbeId.SBOM_COMPONENT
            ]
            scan = scanner.scan(request).data
            if not scan.stamps.same_pack(stamps):
                raise IntegrityError(f"{scanner.name} scanned with a pack it does not stamp")
            scan = scan.model_copy(
                update={"findings": (*scan.findings, *long_validity(request.workspace))}
            )
            facts = pqc_facts.source_facts(scan, census)
        doc = pqc_facts.facts_document(
            subject.repository_url, scan.stamps if scan else stamps, facts, scan
        )
        log.info("prescanned ref %s: %d facts", repository_ref_id, len(facts))
        return self._record_facts(subject, doc, self._clock.now(), scanned=True)

    def prepare(self, repository_ref_id: UUID) -> PqcReadinessInput:
        """What Layer 2 scores: the commit's latest facts, how much work they need, and the
        report they would replace. NotFoundError before a prescan."""
        latest = self._latest(repository_ref_id, PqcFactsArtifact)
        if latest is None:
            raise NotFoundError(f"ref {repository_ref_id} has no pqc-facts; prescan it first")
        assessment, doc = latest
        facts = pqc_facts.read_facts(doc)
        prior = self.find(repository_ref_id)
        stale = self._scanner is not None and not pqc_facts.read_stamps(doc).same_pack(
            self._scanner.stamps()
        )
        subject = self._subject(repository_ref_id)
        return PqcReadinessInput(
            subject=subject.model_copy(update={"assessment_id": assessment.id}),
            findings=FindingContext(),
            prepared_at=self._clock.now(),
            facts=tuple(facts),
            no_crypto_detected_assertion=doc.coverage.no_crypto_detected_assertion,
            route=PqcRoute.UNREFRESHED if stale else pqc_readiness.route(facts, prior),
            prior=prior,
        )

    def check(self, doc: PqcReadinessArtifact) -> LintReport:
        """The readiness gate past its schema; `record` refuses a report that fails."""
        return READINESS_LINT.run(doc, LintContext())

    @overload
    def record(
        self, repository_ref_id: UUID, doc: PqcFactsArtifact, provenance: Provenance
    ) -> PqcPrescan: ...
    @overload
    def record(
        self, repository_ref_id: UUID, doc: PqcReadinessArtifact, provenance: Provenance
    ) -> PqcReadiness: ...
    def record(
        self,
        repository_ref_id: UUID,
        doc: PqcFactsArtifact | PqcReadinessArtifact,
        provenance: Provenance,
    ) -> PqcPrescan | PqcReadiness:
        """Facts produced elsewhere, or a Layer-2 report with its pqc-blockers projection, as a
        pqc-readiness assessment of the commit. The same document again adds nothing."""
        subject = self._subject(repository_ref_id)
        if isinstance(doc, PqcFactsArtifact):
            self._require_repository(subject, doc.repository)
            return self._record_facts(subject, doc, provenance.occurred_at, scanned=False)
        if violations := self.check(doc).violations:
            listed = "; ".join(f"{v.item}: {v.message}" for v in violations)
            raise ValidationError(f"pqc-readiness report fails its gate: {listed}")
        self._require_repository(subject, doc.metadata.repository)
        if doc.metadata.commit not in (None, subject.sha):
            raise ValidationError(
                f"report commit {doc.metadata.commit} is not ref {repository_ref_id}'s "
                f"{subject.sha}"
            )
        assessment = self._existing(repository_ref_id, doc) or self._add(
            repository_ref_id,
            [doc, *self._projection(doc, repository_ref_id, provenance.occurred_at)],
            _SKILL,
            doc.metadata.tool.adapter_version or "",
            provenance.occurred_at,
        )
        assert assessment.id is not None
        return pqc_readiness.readiness(
            doc, assessment.id, repository_ref_id, assessment.occurred_at
        )

    def find(self, repository_ref_id: UUID) -> PqcReadiness | None:
        """The commit's latest recorded readiness."""
        found = self._readiness([repository_ref_id])
        return found[0] if found else None

    def summary(self, filter: PqcFilter, group_by: PqcDimension) -> list[PqcRollup]:
        """Latest readiness per commit in scope, rolled up by bucket or dominant provenance."""
        groups: dict[str, list[PqcReadiness]] = {}
        for r in self._scoped(filter):
            key = (r.bucket or "unbucketed") if group_by == PqcDimension.BUCKET else r.dominant
            groups.setdefault(str(key), []).append(r)
        rollups = []
        for key, members in sorted(groups.items()):
            counts: dict[str, int] = {}
            for rem in (rem for r in members for rem in r.remediations):
                counts[rem.category] = counts.get(rem.category, 0) + 1
            rollups.append(
                PqcRollup(
                    key=key,
                    repositories=len(members),
                    mean_overall=round(sum(r.overall for r in members) / len(members), 1),
                    clock_2030=sum(r.has_2030_clock_items for r in members),
                    hndl_priority=sum(r.hndl_priority for r in members),
                    blocked=sum(r.is_blocked() for r in members),
                    remediations=dict(sorted(counts.items())),
                )
            )
        return rollups

    def blockers(self, filter: PqcFilter) -> list[PqcBlocker]:
        """The remediations of each in-scope commit's latest readiness, in /patch's vocabulary."""
        return [
            b
            for r in self._scoped(filter)
            for b in pqc_readiness.blockers(r)
            if (not filter.categories or b.remediation.category in filter.categories)
            and (filter.patchable is None or b.patchable == filter.patchable)
        ]

    def _require_scanner(self) -> PqcScanner:
        if self._scanner is None:
            raise ConfigError("prescan needs the pqc-scan provider (traust-engine registers it)")
        return self._scanner

    def _subject(self, repository_ref_id: UUID) -> SubjectRef:
        ref = self._portfolio.get_ref(repository_ref_id)
        repository = self._portfolio.get_repository(ref.repository_id)
        assert repository.id is not None
        return SubjectRef(
            repository_id=repository.id,
            repository_url=repository.url,
            repository_ref_id=repository_ref_id,
            sha=ref.sha,
        )

    @staticmethod
    def _require_repository(subject: SubjectRef, raw: str) -> None:
        host = urlsplit(subject.repository_url).hostname or ""
        if str(HttpsRepoUrl.parse(raw, [host])) != subject.repository_url:
            raise ValidationError(f"document is for {raw}, not {subject.repository_url}")

    def _record_facts(
        self, subject: SubjectRef, doc: PqcFactsArtifact, at: datetime, *, scanned: bool
    ) -> PqcPrescan:
        ref_id = subject.repository_ref_id
        existing = self._existing(ref_id, doc)
        if existing is not None:
            return self._prescanned(existing, doc, scanned=scanned)
        docs: list[ArtifactDocument] = [doc]
        stamps = pqc_facts.read_stamps(doc)
        if pqc_readiness.zero_hit(doc):
            name = subject.repository_url.rstrip("/").rsplit("/", 1)[-1]
            assertion = doc.coverage.no_crypto_detected_assertion
            docs.append(
                pqc_readiness.zero_hit_report(
                    name, subject.repository_url, subject.sha, stamps, assertion
                )
            )
        assessment = self._add(ref_id, docs, _SCANNER, stamps.adapter_version, at)
        return self._prescanned(assessment, doc, scanned=scanned)

    def _prescanned(
        self, assessment: Assessment, doc: PqcFactsArtifact, *, scanned: bool
    ) -> PqcPrescan:
        assert assessment.id is not None
        templated = self._documents([assessment], PqcReadinessArtifact)
        return PqcPrescan(
            assessment_id=assessment.id,
            facts=tuple(pqc_facts.read_facts(doc)),
            scanned=scanned,
            readiness=next(
                (
                    pqc_readiness.readiness(
                        d, assessment.id, assessment.repository_ref_id, assessment.occurred_at
                    )
                    for _, d in templated
                ),
                None,
            ),
        )

    def _projection(
        self, doc: PqcReadinessArtifact, repository_ref_id: UUID, at: datetime
    ) -> list[ArtifactDocument]:
        # The projection reads only the report, so any placeholder ids serve it.
        draft = pqc_readiness.readiness(doc, repository_ref_id, repository_ref_id, at)
        projected = pqc_readiness.blockers_document(doc, draft, doc.name)
        return [] if projected is None else [projected]

    def _existing(self, repository_ref_id: UUID, doc: ArtifactDocument) -> Assessment | None:
        digest = sha256_hex(doc.payload)
        with self._uow as uow:
            return next(
                (
                    a
                    for a in uow.assessments.list_for_refs([repository_ref_id], _KIND)
                    if uow.artifacts.find(a.id, digest) is not None
                ),
                None,
            )

    def _add(
        self,
        repository_ref_id: UUID,
        docs: Sequence[ArtifactDocument],
        assessor: str,
        version: str,
        at: datetime,
    ) -> Assessment:
        published = [self._publisher.publish_artifact(d) for d in docs]
        with self._uow as uow:
            assessment = uow.assessments.add(
                Assessment(
                    repository_ref_id=repository_ref_id,
                    kind=_KIND,
                    status=ASSESSMENT_COMPLETED,
                    assessor=assessor,
                    assessor_version=version,
                    occurred_at=at,
                )
            )
            assert assessment.id is not None
            for p in published:
                row = uow.artifacts.get(p.artifact_id)
                record_artifact(
                    uow,
                    Artifact(
                        assessment_id=assessment.id, digest=row.digest, kind=row.kind, uri=row.uri
                    ),
                )
            uow.commit()
        log.info("recorded %s assessment %s of ref %s", assessor, assessment.id, repository_ref_id)
        return assessment

    def _latest(self, repository_ref_id: UUID, kind: type[D]) -> tuple[Assessment, D] | None:
        with self._uow as uow:
            assessments = uow.assessments.list_for_refs([repository_ref_id], _KIND)
        found = self._documents(assessments, kind)
        return found[0] if found else None

    def _documents(
        self, assessments: Iterable[Assessment], kind: type[D]
    ) -> list[tuple[Assessment, D]]:
        """Each commit's newest assessment holding a `kind` document, with it, newest first."""
        ordered = sorted(
            (a for a in assessments if a.id is not None),
            key=lambda a: (a.occurred_at, a.created_at or a.occurred_at),
            reverse=True,
        )
        by_id = {a.id: a for a in ordered}
        held: dict[UUID, Artifact] = {}
        ids = list(by_id)
        with self._uow as uow:
            for i in range(0, len(ids), _BATCH):
                for row in uow.artifacts.list_for_assessments(ids[i : i + _BATCH], [kind.schema]):
                    assert row.assessment_id is not None
                    held.setdefault(row.assessment_id, row)
        seen: set[UUID] = set()
        found = []
        for a in ordered:
            row = held.get(a.id)  # type: ignore[arg-type]
            if row is None or a.repository_ref_id in seen:
                continue
            seen.add(a.repository_ref_id)
            assert row.id is not None
            doc = self._publisher.get(row.id)
            if not isinstance(doc, kind):
                raise IntegrityError(f"artifact {row.id} is not a {kind.schema} document")
            found.append((a, doc))
        return found

    def _readiness(self, repository_ref_ids: Sequence[UUID] | None) -> list[PqcReadiness]:
        with self._uow as uow:
            if repository_ref_ids is None:
                assessments = []
                after = None
                while page := uow.assessments.search(kind=_KIND, limit=_BATCH, after=after):
                    assessments += page
                    after = (page[-1].occurred_at, page[-1].id)
            else:
                assessments = [
                    a
                    for i in range(0, len(repository_ref_ids), _BATCH)
                    for a in uow.assessments.list_for_refs(
                        repository_ref_ids[i : i + _BATCH], _KIND
                    )
                ]
        return [
            pqc_readiness.readiness(doc, a.id, a.repository_ref_id, a.occurred_at)  # type: ignore[arg-type]
            for a, doc in self._documents(assessments, PqcReadinessArtifact)
        ]

    def _scoped(self, filter: PqcFilter) -> list[PqcReadiness]:
        refs = None if filter.repository_ref_ids is None else list(filter.repository_ref_ids)
        if filter.product_id is not None:
            shipped = [r.id for r in self._portfolio.list_product_refs(filter.product_id) if r.id]
            refs = shipped if refs is None else [r for r in refs if r in set(shipped)]
        found = self._readiness(refs) if refs is None or refs else []
        return [r for r in found if not filter.buckets or r.bucket in filter.buckets]
