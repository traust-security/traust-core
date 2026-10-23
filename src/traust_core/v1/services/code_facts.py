from __future__ import annotations

import logging
from collections.abc import Sequence
from uuid import UUID

from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    ValidationError,
)
from traust_core.v1.models.artifacts import CodeFactsArtifact
from traust_core.v1.models.assessment import ASSESSMENT_COMPLETED, AssessmentKind
from traust_core.v1.models.code_facts import (
    CodeFact,
    CodeFactCursor,
    CodeFactDetail,
    CodeFactKind,
    CollectResult,
    CryptoFact,
    LanguageCount,
    LanguageStats,
    SymbolFact,
    SymbolQuery,
)
from traust_core.v1.models.common import CodeSpan, Cursor, Page, PageRequest
from traust_core.v1.providers.tools import FactEnumerator, ToolRequest
from traust_core.v1.services.artifact_publishing import ArtifactPublisher
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.crypto_packages import CryptoPackagePolicy
from traust_core.v1.services.exposure import ExposureService

log = logging.getLogger(__name__)


class CodeFactsService:
    def __init__(
        self,
        assessments: AssessmentService,
        artifacts: ArtifactPublisher,
        enumerators: Sequence[FactEnumerator] = (),
        exposure: ExposureService | None = None,
        packages: CryptoPackagePolicy | None = None,
    ) -> None:
        self._assessments = assessments
        self._artifacts = artifacts
        self._enumerators = {e.kind: e for e in enumerators}
        self._exposure = exposure
        self._packages = packages or CryptoPackagePolicy()

    def enumerate(self, kind: CodeFactKind, request: ToolRequest) -> list[CodeFactDetail]:
        """Run the deterministic enumerator for `kind` over a checkout; nothing is recorded."""
        enumerator = self._enumerators.get(kind)
        if enumerator is None:
            raise ValidationError(f"no enumerator for code fact kind {kind}")
        readiness = enumerator.check()
        if not readiness.ready:
            raise ConfigError(f"{kind} enumerator is not ready: {readiness.detail}")
        result = enumerator.enumerate(request)
        log.info("enumerated %d %s facts", len(result.data), kind)
        return result.data

    def crypto(self, repository_ref_id: UUID, request: ToolRequest) -> list[CryptoFact]:
        """The commit's crypto census, recording nothing: what its checkout (`request`) configures,
        then the crypto packages of its manifest SBOM. `NoManifestSbomError` if none was
        ingested, raised before the checkout is read."""
        if self._exposure is None:
            raise ConfigError("the crypto census needs the exposure service's dependency rows")
        packages = self._packages.facts(self._exposure.dependencies(repository_ref_id))
        configured = self.enumerate(CodeFactKind.CRYPTO, request)
        crypto = [f for f in configured if isinstance(f, CryptoFact)]
        if len(crypto) != len(configured):
            raise IntegrityError(
                f"crypto enumerator returned {len(configured) - len(crypto)} non-crypto facts"
            )
        return crypto + packages

    def collect(self, repository_ref_id: UUID, kinds: Sequence[CodeFactKind]) -> CollectResult:
        requested = set(kinds)
        unsupported = requested - {CodeFactKind.SYMBOL, CodeFactKind.LANGUAGES}
        if unsupported:
            raise ValidationError(f"unsupported code fact kinds: {', '.join(sorted(unsupported))}")
        assessment = self._assessments.latest(repository_ref_id, AssessmentKind.TOOL_SCAN)
        if assessment is None:
            raise NotFoundError(f"no tool_scan assessment for ref {repository_ref_id}")
        if assessment.status != ASSESSMENT_COMPLETED:
            raise ValidationError(f"tool_scan assessment {assessment.id} is {assessment.status}")
        assert assessment.id is not None
        artifacts = self._artifacts.list_for_assessment(
            assessment.id, kind=CodeFactsArtifact.schema
        )
        if not artifacts:
            raise NotFoundError(f"assessment {assessment.id} has no code-facts artifact")
        if len(artifacts) != 1:
            raise IntegrityError(f"assessment {assessment.id} has multiple code-facts artifacts")
        artifact_id = artifacts[0].id
        assert artifact_id is not None
        doc = self._artifacts.get(artifact_id)
        if not isinstance(doc, CodeFactsArtifact):
            raise IntegrityError(f"artifact {artifact_id} is not a code-facts document")
        facts: list[CodeFact] = []
        if CodeFactKind.SYMBOL in requested:
            if doc.symbols is None:
                raise NotFoundError(f"artifact {artifact_id}: symbols were not measured")
            for symbol in sorted(
                doc.symbols, key=lambda s: (s.path, s.line, s.name, s.kind or "", s.language or "")
            ):
                fact = SymbolFact(
                    name=symbol.name,
                    location=CodeSpan(path=symbol.path, line=symbol.line, symbol=symbol.name),
                    kind=symbol.kind,
                    language=symbol.language,
                )
                facts.append(
                    CodeFact(
                        repository_ref_id=repository_ref_id,
                        kind=CodeFactKind.SYMBOL,
                        location=fact.location,
                        detail=fact,
                    )
                )
        if CodeFactKind.LANGUAGES in requested:
            if doc.languages is None:
                raise NotFoundError(f"artifact {artifact_id}: languages were not measured")
            names = [language.name for language in doc.languages]
            if len(names) != len(set(names)):
                raise IntegrityError(f"artifact {artifact_id} has duplicate language measurements")
            stats = LanguageStats(
                languages=tuple(
                    LanguageCount(
                        name=language.name,
                        files=language.files,
                        code=language.code,
                        comments=language.comments,
                        blanks=language.blanks,
                    )
                    for language in sorted(doc.languages, key=lambda language: language.name)
                )
            )
            facts.append(
                CodeFact(
                    repository_ref_id=repository_ref_id, kind=CodeFactKind.LANGUAGES, detail=stats
                )
            )
        return CollectResult(
            repository_ref_id=repository_ref_id,
            assessment_id=assessment.id,
            artifact_id=artifact_id,
            facts=tuple(facts),
        )

    def list(
        self, repository_ref_id: UUID, kinds: Sequence[CodeFactKind], page: PageRequest
    ) -> Page[CodeFact]:
        if not 1 <= page.limit <= 1000:
            raise ValidationError("page limit must be between 1 and 1000")
        requested = tuple(sorted(set(kinds)))
        result = self.collect(repository_ref_id, requested)
        offset = 0
        if page.cursor is not None:
            try:
                cursor = CodeFactCursor.model_validate_json(page.cursor)
            except ValueError as exc:
                raise ValidationError(f"malformed code-facts cursor: {page.cursor!r}") from exc
            if (cursor.artifact_id, cursor.kinds) != (result.artifact_id, requested):
                raise ConflictError("code-facts cursor belongs to a different snapshot or filter")
            offset = cursor.offset
            if offset > len(result.facts):
                raise ValidationError("code-facts cursor offset is beyond the snapshot")
        end = offset + page.limit
        following = (
            None
            if end >= len(result.facts)
            else Cursor(
                CodeFactCursor(
                    artifact_id=result.artifact_id, kinds=requested, offset=end
                ).model_dump_json()
            )
        )
        return Page(items=result.facts[offset:end], next=following)

    def symbols(self, repository_ref_id: UUID, query: SymbolQuery) -> list[SymbolFact]:
        result = self.collect(repository_ref_id, [CodeFactKind.SYMBOL])
        symbols = [fact.detail for fact in result.facts if isinstance(fact.detail, SymbolFact)]
        return [
            symbol
            for symbol in symbols
            if (query.name is None or symbol.name == query.name)
            and (query.path is None or symbol.location.path == query.path)
        ][: query.limit]

    def language_stats(self, repository_ref_id: UUID) -> LanguageStats:
        result = self.collect(repository_ref_id, [CodeFactKind.LANGUAGES])
        stats = result.facts[0].detail
        assert isinstance(stats, LanguageStats)
        return stats
