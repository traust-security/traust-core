from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from typing import TypeVar
from uuid import UUID

from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    ServiceError,
    ValidationError,
)
from traust_core.v1.models.artifacts import CodeFactsArtifact, PrivProfileArtifact
from traust_core.v1.models.assessment import ASSESSMENT_COMPLETED, AssessmentKind
from traust_core.v1.models.code_facts import (
    ClusterCensus,
    ClusterRequest,
    CodeFact,
    CodeFactCursor,
    CodeFactDetail,
    CodeFactKind,
    CollectResult,
    CryptoFact,
    ForkLagFact,
    GrpcGuardFact,
    ImageCensus,
    ImageRequest,
    LanguageCount,
    LanguageStats,
    NamespaceScope,
    PrivilegeFact,
    RouteGuardFact,
    SymbolFact,
    SymbolQuery,
)
from traust_core.v1.models.common import CodeSpan, Cursor, Page, PageRequest
from traust_core.v1.models.validation import (
    ScopeDecision,
    ValidationAction,
    ValidationActionKind,
    ValidationScope,
    ValidationTarget,
)
from traust_core.v1.providers.clock import Clock, SystemClock
from traust_core.v1.providers.crypto_cluster import ClusterCryptoProbe
from traust_core.v1.providers.crypto_image import ImageCryptoProbe
from traust_core.v1.providers.tools import FactEnumerator, ToolRequest
from traust_core.v1.services.artifact_publishing import ArtifactPublisher
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.crypto_packages import CryptoPackagePolicy
from traust_core.v1.services.exposure import ExposureService

log = logging.getLogger(__name__)

T = TypeVar("T")

_K8S_EXEC = ValidationAction(kind=ValidationActionKind.K8S, verb="exec")
_CALLABLE_KINDS = frozenset({"func", "function", "method"})
_HANDLER_NAME = re.compile(r"\w+")


def _require_ready(probe: ImageCryptoProbe | ClusterCryptoProbe) -> None:
    readiness = probe.check()
    if not readiness.ready:
        raise ConfigError(f"{probe.name} is not ready: {readiness.detail}")


class CodeFactsService:
    def __init__(
        self,
        assessments: AssessmentService,
        artifacts: ArtifactPublisher,
        enumerators: Sequence[FactEnumerator] = (),
        exposure: ExposureService | None = None,
        packages: CryptoPackagePolicy | None = None,
        image: ImageCryptoProbe | None = None,
        cluster: ClusterCryptoProbe | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._assessments = assessments
        self._artifacts = artifacts
        self._enumerators = {e.kind: e for e in enumerators}
        self._exposure = exposure
        self._packages = packages or CryptoPackagePolicy()
        self._image = image
        self._cluster = cluster
        self._clock = clock or SystemClock()

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

    def _single(self, kind: CodeFactKind, request: ToolRequest, of: type[T]) -> T:
        facts = self.enumerate(kind, request)
        if len(facts) != 1 or not isinstance(facts[0], of):
            raise IntegrityError(f"{kind} enumerator returned {len(facts)} facts, not one {of}")
        return facts[0]

    def route_guards(
        self, request: ToolRequest, *, resolve_handlers: bool = False
    ) -> RouteGuardFact:
        """The checkout's route x guard matrix, recording nothing; `resolve_handlers` also places
        each handler at its definition through the symbol index."""
        matrix = self._single(CodeFactKind.ROUTE_GUARD, request, RouteGuardFact)
        if not resolve_handlers:
            return matrix
        defs: dict[str, CodeSpan] = {}
        for s in self.enumerate(CodeFactKind.SYMBOL, request):
            if isinstance(s, SymbolFact) and s.kind in _CALLABLE_KINDS:
                defs.setdefault(s.name, CodeSpan(path=s.location.path, line=s.location.line))
        routes = []
        for row in matrix.routes:
            name = re.sub(r"\(.*$", "", row.handler.expr).split(".")[-1]
            resolved = defs.get(name) if _HANDLER_NAME.fullmatch(name) else None
            handler = row.handler.model_copy(update={"resolved": resolved})
            routes.append(row.model_copy(update={"handler": handler}))
        return matrix.model_copy(update={"routes": tuple(routes)})

    def grpc_guards(self, request: ToolRequest) -> GrpcGuardFact:
        """The checkout's gRPC service x interceptor matrix, recording nothing."""
        return self._single(CodeFactKind.GRPC_GUARD, request, GrpcGuardFact)

    def priv_profile(self, request: ToolRequest, repo: str) -> PrivProfileArtifact:
        """The checkout's operator privilege profile (tiers 1-2) as the contract document named
        `repo`, recording nothing."""
        fact = self._single(CodeFactKind.PRIVILEGE, request, PrivilegeFact)
        doc = fact.model_dump(mode="json", by_alias=True)
        doc["tier2_required_vs_granted"] = fact.tier2_required_vs_granted.model_dump(
            mode="json", exclude_none=True
        )
        return PrivProfileArtifact.from_document({"repo": repo, **doc})

    def fork_lag(self, request: ToolRequest, *, offline: bool = False) -> ForkLagFact:
        """The checkout's fork signals and upstreams, recording nothing; unless `offline`, each
        tracked version's advisories (the advisory source by package and version). A failed read
        is the result's `network` error with what was found so far, never a stall."""
        fork = self._single(CodeFactKind.FORK_LAG, request, ForkLagFact)
        if offline or not fork.upstreams:
            return fork
        if self._exposure is None:
            raise ConfigError("fork advisory lag needs the exposure service's advisory reads")
        upstreams = list(fork.upstreams)
        for i, up in enumerate(upstreams):
            if up.tracked_version is None:
                continue
            try:
                found = self._exposure.package_advisories(
                    up.ecosystem, up.package, up.tracked_version
                )
            except ServiceError as e:
                log.warning(
                    "fork advisory lag: %s@%s not answered: %s", up.package, up.tracked_version, e
                )
                return fork.model_copy(
                    update={"upstreams": tuple(upstreams), "network": f"error: {e}"}
                )
            upstreams[i] = up.model_copy(update={"advisories": found.advisories})
        return fork.model_copy(update={"upstreams": tuple(upstreams), "network": "ok"})

    def crypto(self, repository_ref_id: UUID, request: ToolRequest) -> list[CryptoFact]:
        """The commit's crypto census, recording nothing: what its checkout (`request`) configures,
        then the crypto packages of its manifest SBOM. `NoManifestSbomError` if none was
        ingested, raised before the checkout is read."""
        packages = self.packages(repository_ref_id)
        configured = self.enumerate(CodeFactKind.CRYPTO, request)
        crypto = [f for f in configured if isinstance(f, CryptoFact)]
        if len(crypto) != len(configured):
            raise IntegrityError(
                f"crypto enumerator returned {len(configured) - len(crypto)} non-crypto facts"
            )
        return crypto + packages

    def packages(self, repository_ref_id: UUID) -> list[CryptoFact]:
        """The crypto packages of the commit's manifest SBOM, no checkout needed.
        `NoManifestSbomError` if none was ingested."""
        if self._exposure is None:
            raise ConfigError("the crypto census needs the exposure service's dependency rows")
        return self._packages.facts(self._exposure.dependencies(repository_ref_id))

    def image_crypto(self, digest: str, request: ImageRequest) -> ImageCensus:
        """The image's crypto census, recording nothing: what it ships (linked libraries, certs,
        policy, FIPS files, env, labels), then the crypto packages of its SBOM.
        `NoImageSbomError` if none was ingested, raised before the image is touched."""
        if self._exposure is None or self._image is None:
            raise ConfigError("the image crypto census needs the exposure service and image probe")
        packages = self._packages.facts(self._exposure.image_dependencies(digest))
        _require_ready(self._image)
        census = self._image.collect(request.name, digest, pull=request.pull).data
        return census.model_copy(update={"facts": (*census.facts, *packages)})

    def cluster_crypto(self, request: ClusterRequest, scope: ValidationScope) -> ClusterCensus:
        """The cluster's runtime crypto census, recording nothing. `oc exec` is an engagement
        action: each namespace passes `scope` (k8s, exec) first, denied ones are never probed,
        and none allowed returns the decisions alone (fail closed)."""
        if self._cluster is None:
            raise ConfigError("the cluster crypto census needs the cluster probe")
        as_of = self._clock.now().date()
        decisions: dict[str, ScopeDecision] = {}

        def gate(namespace: str) -> ScopeDecision:
            if namespace not in decisions:
                target = ValidationTarget(context=request.context, namespace=namespace)
                decision = scope.decide(_K8S_EXEC, target, as_of=as_of)
                log.log(
                    logging.INFO if decision.allowed else logging.WARNING,
                    "scope k8s/exec context=%s namespace=%s allowed=%s reason=%s",
                    request.context,
                    namespace,
                    decision.allowed,
                    decision.reason,
                )
                decisions[namespace] = decision
            return decisions[namespace]

        allowed = [ns for ns in request.namespaces if gate(ns).allowed]
        denied = tuple(
            f"scope denied: {ns} — {decisions[ns].reason}"
            for ns in request.namespaces
            if not decisions[ns].allowed
        )
        census = ClusterCensus(context=request.context)
        if allowed:
            _require_ready(self._cluster)
            census = self._cluster.collect(request, allowed, gate).data
        scoped = tuple(NamespaceScope(namespace=ns, decision=d) for ns, d in decisions.items())
        return census.model_copy(update={"scope": scoped, "gaps": (*census.gaps, *denied)})

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
        doc = self._artifacts.read(artifact_id, CodeFactsArtifact)
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
