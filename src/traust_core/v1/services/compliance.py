from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator, Mapping, Sequence
from datetime import datetime
from typing import overload
from uuid import UUID

from pydantic import JsonValue

from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    ValidationError,
)
from traust_core.v1.models.artifacts import (
    AdrRegistryArtifact,
    ArtifactDocument,
    ComplianceAssessmentArtifact,
    ComplianceMappingArtifact,
    ComplianceScopeArtifact,
    DocVarianceArtifact,
    OrgParametersArtifact,
)
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    Assessment,
    AssessmentKind,
)
from traust_core.v1.models.common import (
    ArtifactRef,
    Page,
    PageRequest,
    Provenance,
    Sha256,
    encode_cursor,
)
from traust_core.v1.models.compliance import (
    CAVEATS,
    CLOUD_INVENTORY,
    COVERAGE_KEYS,
    CRYPTO_AUDIT,
    FINDINGS_DB,
    NON_CITABLE_ADR,
    OFFICIAL_DOCS,
    SPINE_PROFILE,
    Adr,
    AwaitingReview,
    ComplianceAssessment,
    ComplianceDimension,
    ComplianceEvidence,
    ComplianceFilter,
    ComplianceInput,
    ComplianceMapping,
    ComplianceRollup,
    ComplianceScope,
    ComplianceTarget,
    DocGuide,
    DocVariance,
    DocVarianceFilter,
    EfficacyKey,
    EvaluationRequest,
    EvaluationRun,
    InventorySnapshot,
    JsonObject,
    ResolvedScope,
    RunCalibration,
    ScopeFilter,
    ScopeMember,
    TargetRef,
    adr_citations,
    boundaries,
    canonical_json,
    coverage,
    crypto_snapshot,
    divergences,
    doc_text,
    evaluate_control,
    evidence_id,
    findings_snapshot,
    framework_of,
    is_decision_record,
    merge_variances,
    oscal_assessment_results,
    parse_adr,
    scope_id_of,
)
from traust_core.v1.models.findings import FindingFilter
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import Repository, RepositoryRef
from traust_core.v1.models.values import HttpsRepoUrl, ProductSlug
from traust_core.v1.models.vocabulary import (
    ComplianceEvidenceKind,
    ComplianceFramework,
    ComplianceTargetKind,
)
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.collaboration import AdrSource, DocSource
from traust_core.v1.providers.runtime import CloudInventoryProvider
from traust_core.v1.repositories.objects import ObjectKey, ObjectStore
from traust_core.v1.repositories.traust.assessments import AssessmentsUnitOfWork
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    AssessmentLog,
    PublishResult,
)
from traust_core.v1.services.findings.service import FindingService
from traust_core.v1.services.lint import (
    Lint,
    LintAction,
    LintContext,
    LintReport,
    LintRuleId,
    Violation,
)
from traust_core.v1.services.portfolio import PortfolioService

log = logging.getLogger(__name__)

ASSESSOR = "skill:compliance-check"
DOC_VARIANCE_ASSESSOR = "doc-variance"
SCOPE_HISTORY = 1000
EVIDENCE_PREFIX = "compliance/evidence"
FORGE = "github.com"  # scope edges name repos as org/name on the forge the registry was written for
FORBIDDEN_SUMMARY_KEYS = (
    "compliance_pct",
    "percent_compliant",
    "compliance_score",
    "overall_compliance",
)


def evidence_key(sha256: str) -> ObjectKey:
    return ObjectKey.parse(f"{EVIDENCE_PREFIX}/{sha256}.json")


class ComplianceCitations:
    """The compliance citation gate beyond its schema: a narrative verdict cannot ship."""

    id = LintRuleId("compliance.citations")

    def check(self, subject: ArtifactDocument, context: LintContext) -> list[Violation]:
        if not isinstance(subject, ComplianceAssessmentArtifact):
            raise ValidationError(
                f"{self.id} checks compliance assessments, not {type(subject).__name__}"
            )
        doc = json.loads(subject.payload)
        return [
            Violation(rule=self.id, item=item, message=message, action=LintAction.REVIEW)
            for item, message in (
                *_verdict_source(doc),
                *_n_pass(doc),
                *_coverage(doc),
                *_preconditions(doc),
            )
        ]


def _ref(i: int, r: Mapping[str, JsonValue]) -> str:
    return f"results[{i}] {r.get('framework')}:{r.get('control_id')}"


def _concluded(r: Mapping[str, JsonValue]) -> bool:
    return r.get("verdict") in ("satisfied", "not_satisfied")


def _verdict_source(doc: dict[str, JsonValue]) -> list[tuple[str, str]]:
    out = []
    for i, r in enumerate(doc["results"]):  # type: ignore[arg-type]
        if (
            r["classification"] == "deterministic"
            and _concluded(r)
            and r["verdict_source"] == "agent"
        ):
            out.append(
                (
                    _ref(i, r),
                    "deterministic control with agent-sourced verdict — verdicts come from the "
                    "check or an attributed override",
                )
            )
        if r["classification"] == "organizational" and _concluded(r):
            out.append(
                (
                    _ref(i, r),
                    "organizational control carries a satisfied/not_satisfied verdict — out of "
                    "technical scope, must be not_assessed",
                )
            )
    return out


def _n_pass(doc: dict[str, JsonValue]) -> list[tuple[str, str]]:
    out = []
    for i, r in enumerate(doc["results"]):  # type: ignore[arg-type]
        if r["verdict_source"] != "agent" or not _concluded(r):
            continue
        agreement = r.get("n_pass_agreement")
        if not agreement:
            out.append(
                (
                    _ref(i, r),
                    "agent-sourced verdict without n_pass_agreement — judge at least twice and "
                    "record it",
                )
            )
        elif not agreement.get("agreed") or agreement.get("passes", 0) < 2:
            out.append(
                (
                    _ref(i, r),
                    "n_pass_agreement shows disagreement or <2 passes — the verdict must be "
                    "not_assessed (unstable judgment, human review)",
                )
            )
    return out


def _coverage(doc: dict[str, JsonValue]) -> list[tuple[str, str]]:
    recomputed = coverage(doc["results"])  # type: ignore[arg-type]
    declared: Mapping[str, Mapping[str, int]] = doc["coverage"]  # type: ignore[assignment]
    out = [
        (f"coverage[{fw}].{k}", f"declared {declared[fw].get(k, 0)} but results contain {n}")
        for fw, counts in sorted(recomputed.items())
        if fw in declared
        for k, n in counts.items()
        if declared[fw].get(k, 0) != n
    ]
    out += [
        ("coverage", f"framework '{fw}' has results but no coverage block")
        for fw in sorted(recomputed)
        if fw not in declared
    ]
    out += [
        ("coverage", f"block for '{fw}' but no results") for fw in declared if fw not in recomputed
    ]
    text = json.dumps(doc)
    out += [
        (k, "blended compliance percentage — coverage honesty forbids a single compliance number")
        for k in FORBIDDEN_SUMMARY_KEYS
        if f'"{k}"' in text
    ]
    return out


def _preconditions(doc: dict[str, JsonValue]) -> list[tuple[str, str]]:
    metadata: Mapping[str, JsonValue] = doc["metadata"]  # type: ignore[assignment]
    target: Mapping[str, JsonValue] = metadata["target"]  # type: ignore[assignment]
    entries = {f["id"]: f for f in metadata["frameworks"]}  # type: ignore[union-attr,index]
    assessed = {r["framework"] for r in doc["results"]}  # type: ignore[union-attr,index]
    out = []
    if "pci-dss-v4" in assessed and not target.get("cde_boundary"):
        out.append(
            ("pci-dss-v4", "results without a declared cde_boundary — PCI scope is human input")
        )
    if "gdpr-technical" in assessed and not target.get("personal_data_stores"):
        out.append(("gdpr-technical", "results without declared personal_data_stores"))
    if "soc2-tsc" in assessed:
        if not target.get("trust_service_categories"):
            out.append(("soc2-tsc", "results without declared trust_service_categories"))
        if "point-in-time" not in str((entries.get("soc2-tsc") or {}).get("caveat", "")):
            out.append(("soc2-tsc", "framework entry missing the point-in-time vs Type 2 caveat"))
    return out


PolicyArtifact = ComplianceMappingArtifact | AdrRegistryArtifact | OrgParametersArtifact
GATE = Lint({ComplianceAssessmentArtifact: [ComplianceCitations()]})


class ComplianceService:
    def __init__(
        self,
        uow: AssessmentsUnitOfWork,
        *,
        portfolio: PortfolioService,
        findings: FindingService,
        publisher: ArtifactPublisher,
        objects: ObjectStore,
        clock: Clock,
        hosts: Mapping[str, str],
        inventory: CloudInventoryProvider | None = None,
        parameters: Mapping[str, JsonValue] | None = None,
        adr_source: AdrSource | None = None,
        docs: DocSource | None = None,
    ) -> None:
        self._uow = uow
        self._log = AssessmentLog(uow)
        self._portfolio = portfolio
        self._findings = findings
        self._publisher = publisher
        self._objects = objects
        self._clock = clock
        self._hosts = hosts
        self._inventory = inventory
        self._parameters = dict(parameters or {})
        self._adr_source = adr_source
        self._docs = docs

    def set_scope(
        self, doc: ComplianceScopeArtifact, principal: Principal, *, replace: bool = False
    ) -> ComplianceScope:
        """Declare one boundary. Signed only when the verified caller is its declarant (else
        `draft:`); an existing boundary changes only with `replace`; it must resolve first."""
        ((name, entry),) = _single(doc).items()
        if entry["resolves_via"] == "deployment-iac":
            # NEED(compliance): deployment-iac reads a deployment inventory file; it has no
            # home in the model yet. Declare repo-graph or explicit membership.
            raise ValidationError(f"{name}: resolves_via=deployment-iac is not supported")
        current = self._current_scopes()
        if name in current and not replace:
            raise ConflictError(f"boundary {name!r} already declared — pass replace to modify it")
        declarant = str(entry["declared_by"]).removeprefix("draft:")
        signed = principal.is_verified_human() and _is(principal, declarant)
        today = self._clock.now().date().isoformat()
        entry = {
            **entry,
            "declared_by": declarant if signed else f"draft:{declarant}",
            "declared_at": today,
        }
        declared = ComplianceScopeArtifact.from_document(
            {"version": 1, "updated": today, "boundaries": {name: entry}}
        )
        members = self._members(ComplianceScope.of(None, declared))
        published = self._publisher.publish_artifact(declared)
        scope = ComplianceScope.of(published.artifact_id, declared)
        log.info(
            "declared compliance boundary %s (%s, %d repos) as %s",
            name,
            "DRAFT" if scope.draft else "signed",
            len(members),
            published.artifact_id,
        )
        return scope

    def get_scope(self, scope_id: UUID) -> ComplianceScope:
        doc = self._publisher.get(scope_id)
        if not isinstance(doc, ComplianceScopeArtifact):
            raise NotFoundError(f"compliance scope {scope_id}: artifact is a {doc.name}")
        return ComplianceScope.of(scope_id, doc)

    def resolve(self, scope_id: UUID) -> ResolvedScope:
        """The boundary's repositories now, under its current declaration."""
        scope = self.get_scope(scope_id)
        current = self._current_scopes().get(scope.boundary)
        if current is None or current.scope_id != scope_id:
            raise ConflictError(
                f"compliance scope {scope_id} ({scope.boundary}) is superseded by "
                f"{None if current is None else current.scope_id}"
            )
        return ResolvedScope(scope=scope, members=self._members(scope))

    def collect_inventory(self, scope_id: UUID) -> InventorySnapshot:
        """A read-only snapshot of the boundary's environment; the provider enforces its scope."""
        if self._inventory is None:
            raise ConfigError("collect_inventory needs a cloud inventory provider")
        if not (ready := self._inventory.check()).ready:
            raise ConfigError(f"cloud inventory {self._inventory.name} not ready: {ready.detail}")
        resolved = self.resolve(scope_id)
        targets = [
            ComplianceTarget(
                kind=ComplianceTargetKind("product"),
                ref=TargetRef(m.repo),
                resolves_via=resolved.scope.resolves_via,
            )
            for m in resolved.members
        ]
        snapshot = self._inventory.collect(targets).data
        log.info(
            "collected inventory %s: %d resources, %d gaps",
            snapshot.snapshot_id,
            len(snapshot.resources),
            len(snapshot.gaps),
        )
        return snapshot

    def evaluate(self, request: EvaluationRequest) -> EvaluationRun:
        """The deterministic runner: code-computed verdicts, the evidence bundle, the gate."""
        resolved = self.resolve(request.scope_id)
        mapping_doc = self._mapping_doc()
        mapping = ComplianceMapping.of(mapping_doc)
        wanted = request.frameworks or resolved.scope.frameworks
        skipped = {str(fw): why for fw in wanted if (why := request.skip_reason(fw))}
        frameworks = [fw for fw in wanted if str(fw) not in skipped]
        parameters = self._parameters or self._org_parameters()
        snapshots = {**request.snapshots, FINDINGS_DB: self._findings_view(resolved)}
        if request.crypto is not None:
            snapshots[CRYPTO_AUDIT] = crypto_snapshot(request.crypto)
        if request.inventory is not None:
            snapshots[CLOUD_INVENTORY] = request.inventory.document()
        results = [
            evaluate_control(control, fw, mapping, snapshots, parameters)
            for control in mapping.controls
            for fw in frameworks
            if framework_of(fw) == control.framework
        ]
        stored = self._store_evidence(e for r in results for e in r.evidence)
        dumped = [r.model_dump(mode="json", exclude_none=True) for r in results]
        for item in dumped:
            if not item["evidence"]:
                del item["evidence"]
        doc = ComplianceAssessmentArtifact.from_document(
            {
                "metadata": self._metadata(
                    request, resolved, frameworks, skipped, snapshots, mapping_doc, parameters
                ),
                "coverage": coverage(dumped),
                "results": dumped,
            }
        )
        failures = tuple(f"{v.item}: {v.message}" for v in self.check(doc).violations)
        log.info(
            "evaluated %s over %s: %d results, %d skipped, gate %s",
            resolved.scope.boundary,
            ",".join(map(str, frameworks)) or "(none)",
            len(results),
            len(skipped),
            "failed" if failures else "passed",
        )
        return EvaluationRun(scope=resolved, document=doc, evidence=stored, failures=failures)

    def calibrate(
        self, request: EvaluationRequest, key: EfficacyKey | None = None
    ) -> RunCalibration:
        """`evaluate` twice: the same inputs must give byte-identical verdicts, evidence, coverage
        and gate (`generated_at` aside). Given a seeded target's key, the run is scored on it."""
        first, second = self.evaluate(request), self.evaluate(request)
        return RunCalibration(
            controls=len(json.loads(first.document.payload)["results"]),
            divergences=divergences(first, second),
            efficacy=None if key is None else key.score(first.document),
        )

    def check(self, doc: ComplianceAssessmentArtifact) -> LintReport:
        """The citation gate: the document's rules, every cited evidence item in the bundle, and
        no satisfied verdict citing a superseded or unknown ADR."""
        report = GATE.run(doc, LintContext())
        body = json.loads(doc.payload)
        missing = [
            Violation(
                rule=LintRuleId("compliance.evidence"),
                item=f"results[{i}] {r['framework']}:{r['control_id']}",
                message=message,
                action=LintAction.REVIEW,
            )
            for i, r in enumerate(body["results"])
            for j, ev in enumerate(r.get("evidence") or [])
            if (message := self._evidence_defect(j, ev["sha256"]))
        ]
        return LintReport(violations=(*report.violations, *missing, *self._adr_defects(body)))

    def prepare(self, run: EvaluationRun) -> ComplianceInput:
        """The agent pass's input: the draft and the evidence_review controls awaiting artifacts."""
        requests = {
            (c.framework, c.control_id): c.evidence_request or ""
            for c in ComplianceMapping.of(self._mapping_doc()).controls
        }
        body = json.loads(run.document.payload)
        awaiting = tuple(
            AwaitingReview(
                framework=r["framework"],
                control_id=r["control_id"],
                evidence_request=requests.get((framework_of(r["framework"]), r["control_id"]), ""),
            )
            for r in body["results"]
            if r["classification"] == "evidence_review" and r["verdict"] == "not_assessed"
        )
        return ComplianceInput(
            scope=run.scope, assessment=body, awaiting=awaiting, prepared_at=self._clock.now()
        )

    @overload
    def record(
        self, doc: ComplianceAssessmentArtifact, provenance: Provenance
    ) -> ComplianceAssessment: ...
    @overload
    def record(
        self, doc: DocVarianceArtifact, provenance: Provenance, *, update: bool = False
    ) -> list[DocVariance]: ...
    @overload
    def record(self, doc: PolicyArtifact, provenance: Provenance) -> PublishResult: ...
    def record(
        self,
        doc: ComplianceAssessmentArtifact | DocVarianceArtifact | PolicyArtifact,
        provenance: Provenance,
        *,
        update: bool = False,
    ) -> ComplianceAssessment | list[DocVariance] | PublishResult:
        """A gated assessment, attached to each in-scope commit it assessed; doc-variance
        records appended to their repository's register; or the next version of the policy data
        (the control mapping, the ADR registers, the org parameters). Re-recording adds nothing;
        a provenance without an artifact has the document published here."""
        if isinstance(doc, DocVarianceArtifact):
            return self._record_variances(doc, provenance, update=update)
        if isinstance(doc, PolicyArtifact):
            return self._record_policy(doc, provenance)
        if violations := self.check(doc).violations:
            listed = "; ".join(f"{v.item}: {v.message}" for v in violations)
            raise ValidationError(f"compliance assessment fails its gate: {listed}")
        resolved = self.resolve(scope_id_of(doc))
        members = _assessed(resolved, doc)
        digest = sha256_hex(doc.payload)
        earlier = [
            a
            for a, _ in self._log.find_recorded(
                [m.repository_ref_id for m in members],
                AssessmentKind.COMPLIANCE,
                doc.schema,
                digest,
            )
        ]
        imported = self._publisher.find(digest)
        if earlier and imported is not None and imported.id is not None:
            ref = ArtifactRef(id=imported.id, name=doc.name, digest=digest)
            return ComplianceAssessment.of(
                doc, ref, earlier[0].occurred_at, [a.id for a in earlier if a.id is not None]
            )
        artifact = provenance.artifact or self._publisher.publish_ref(doc)
        if artifact.digest != digest:
            raise IntegrityError(
                f"artifact {artifact.id}: doc digest {digest} != {artifact.digest}"
            )
        version = json.loads(doc.payload)["metadata"]["harness_version"]
        ids = []
        with self._uow as uow:
            for m in members:
                a, _ = self._log.add(
                    Assessment(
                        repository_ref_id=m.repository_ref_id,
                        kind=AssessmentKind.COMPLIANCE,
                        status=ASSESSMENT_COMPLETED,
                        assessor=ASSESSOR,
                        assessor_version=version,
                        occurred_at=provenance.occurred_at,
                    ),
                    artifact.id,
                    digest,
                )
                assert a.id is not None
                ids.append(a.id)
            uow.commit()
        log.info("recorded compliance assessment %s over %d refs", digest, len(ids))
        return ComplianceAssessment.of(doc, artifact, provenance.occurred_at, ids)

    def add_evidence(
        self, kind: ComplianceEvidenceKind, locator: str, value: JsonValue
    ) -> ComplianceEvidence:
        """Hash an artifact the agent pass judged into the evidence bundle; cite what returns."""
        evidence = ComplianceEvidence.identify(kind, locator, value)
        self._store_evidence([evidence])
        log.info("added %s evidence %s to the bundle", kind, evidence.sha256)
        return evidence

    def latest(self, scope_id: UUID, framework: ComplianceFramework) -> ComplianceAssessment | None:
        """The newest recorded assessment of the scope that covers the framework."""
        return next(
            (a for a in self._recorded(self.get_scope(scope_id)) if framework in a.frameworks),
            None,
        )

    def collect_product_docs(self, product_id: UUID) -> list[DocGuide]:
        """The product's official guides as plain text with section anchors, for claim
        extraction; fetched through the DocSource, never stored."""
        if self._docs is None:
            raise ConfigError(
                "collect_product_docs needs a DocSource — NEED(engine): the official-docs fetcher"
            )
        if not (ready := self._docs.check()).ready:
            raise ConfigError(f"doc source {self._docs.name} not ready: {ready.detail}")
        self._portfolio.get_product(product_id)
        pages = self._docs.fetch(product_id).data
        if not pages:
            raise NotFoundError(f"product {product_id}: the doc source found no guides")
        if unofficial := sorted(p.url for p in pages if not p.url.startswith(OFFICIAL_DOCS)):
            raise ValidationError(
                f"only {OFFICIAL_DOCS} documentation is a variance source: {', '.join(unofficial)}"
            )
        guides = [
            DocGuide(
                product_slug=p.product_slug,
                version=p.version,
                guide=p.guide,
                url=p.url,
                text=doc_text(p.html, p.url),
            )
            for p in pages
        ]
        log.info("collected %d official guides for product %s", len(guides), product_id)
        return guides

    def scopes(self, filter: ScopeFilter, page: PageRequest) -> Page[ComplianceScope]:
        """The current declaration of each boundary, newest first."""
        after = page.position()
        found = [
            (at, scope)
            for at, scope in self._declarations()
            if filter.admits(scope)
            and (after is None or (at[0], str(at[1])) < (after[0], str(after[1])))
        ]
        more = len(found) > page.limit
        return Page(
            items=tuple(scope for _, scope in found[: page.limit]),
            next=encode_cursor(*found[page.limit - 1][0]) if more else None,
        )

    def summary(
        self, filter: ComplianceFilter, group_by: ComplianceDimension
    ) -> list[ComplianceRollup]:
        """Posture per framework or per boundary: each declared (boundary, framework) pair
        counts once, assessed by its newest recorded assessment."""
        groups: dict[str, ComplianceRollup] = {}
        for _, scope in self._declarations():
            if filter.scope_id is not None and scope.scope_id != filter.scope_id:
                continue
            newest: dict[ComplianceFramework, ComplianceAssessment] = {}
            for recorded in self._recorded(scope):
                for fw in recorded.frameworks:
                    newest.setdefault(fw, recorded)
            for fw in scope.frameworks:
                if filter.framework is not None and fw != filter.framework:
                    continue
                key = str(fw) if group_by == ComplianceDimension.FRAMEWORK else scope.boundary
                group = groups.setdefault(
                    key, ComplianceRollup(key=key, pairs=0, assessed=0, coverage={})
                )
                found = newest.get(fw)
                counts = found.posture().coverage.get(str(fw), {}) if found else {}
                summed = group.coverage.get(str(fw), {})
                groups[key] = group.model_copy(
                    update={
                        "pairs": group.pairs + 1,
                        "assessed": group.assessed + (found is not None),
                        "coverage": {
                            **group.coverage,
                            str(fw): {
                                k: summed.get(k, 0) + counts.get(k, 0) for k in COVERAGE_KEYS
                            },
                        },
                    }
                )
        return [groups[k] for k in sorted(groups)]

    def adrs(self, product_id: UUID) -> list[Adr]:
        """The decisions of every pinned register governing the product or a repo it ships."""
        product = self._portfolio.get_product(product_id)
        governs = {f"product:{product.slug}"} | {
            f"repo:{_repo_name(self._portfolio.get_repository(r.repository_id).url)}"
            for r in self._portfolio.list_product_refs(product_id)
        }
        artifact, registers = self._adr_registry()
        return [
            adr
            for register in registers
            if governs & set(register.get("governs") or ())  # type: ignore[arg-type]
            for adr in self._decisions(register, artifact)
        ]

    def doc_variances(self, filter: DocVarianceFilter, page: PageRequest) -> Page[DocVariance]:
        """Records of each repository's current doc-variance register, oldest verified first."""
        after = page.position()
        refs = (
            None
            if filter.repository_id is None
            else [r.id for r in self._portfolio.inventory.list_refs(filter.repository_id) if r.id]
        )
        found = sorted(
            (
                v
                for repository_id, (artifact, register) in self._registers(refs).items()
                for v in _variances(repository_id, artifact, register)
                if v.admitted_by(filter)
                and (
                    after is None or (v.position[0], str(v.position[1])) > (after[0], str(after[1]))
                )
            ),
            key=lambda v: (v.position[0], str(v.position[1])),
        )
        return Page.of(found[: page.limit + 1], page.limit, lambda v: v.position)

    def export_oscal(self, artifact_id: UUID) -> JsonObject:
        """A recorded compliance assessment's 800-53-spine results as OSCAL assessment-results."""
        return oscal_assessment_results(
            self._publisher.read(artifact_id, ComplianceAssessmentArtifact)
        )

    def _record_variances(
        self, doc: DocVarianceArtifact, provenance: Provenance, *, update: bool
    ) -> list[DocVariance]:
        incoming = json.loads(doc.payload)
        url = str(incoming["metadata"]["repository"])
        repo = self._portfolio.find_repository(HttpsRepoUrl.parse(url, self._hosts))
        if repo is None or repo.id is None:
            raise NotFoundError(f"doc-variance register: {url} is not in the inventory")
        ref = self._portfolio.default_ref(repo.id)
        if ref is None or ref.id is None:
            raise NotFoundError(f"doc-variance register: {url} has no observed default-branch head")
        refs = [r.id for r in self._portfolio.inventory.list_refs(repo.id) if r.id]
        prior = self._registers(refs).get(repo.id)
        now = self._clock.now().isoformat(timespec="seconds")
        merged = merge_variances(
            None if prior is None else json.loads(prior[1].payload), incoming, now, update=update
        )
        if merged is None:
            assert prior is not None
            return _variances(repo.id, *prior)
        register = DocVarianceArtifact.from_document(merged)
        digest = sha256_hex(register.payload)
        artifact = provenance.artifact or self._publisher.publish_ref(register)
        if artifact.digest != digest:
            raise IntegrityError(
                f"artifact {artifact.id}: merged register digest {digest} != {artifact.digest}"
            )
        with self._uow as uow:
            _, attached = self._log.add(
                Assessment(
                    repository_ref_id=ref.id,
                    kind=AssessmentKind.COMPLIANCE,
                    status=ASSESSMENT_COMPLETED,
                    assessor=DOC_VARIANCE_ASSESSOR,
                    assessor_version=str(merged["metadata"]["harness_version"]),  # type: ignore[index,call-overload]
                    occurred_at=provenance.occurred_at,
                ),
                artifact.id,
                digest,
            )
            uow.commit()
        assert attached.id is not None
        log.info("recorded doc-variance register %s for %s", digest, url)
        return _variances(
            repo.id, ArtifactRef(id=attached.id, name=doc.name, digest=digest), register
        )

    def _record_policy(self, doc: PolicyArtifact, provenance: Provenance) -> PublishResult:
        if isinstance(doc, ComplianceMappingArtifact):
            ComplianceMapping.of(doc)
        prior = self._publisher.latest_imported(type(doc))
        result = self._publisher.publish_successor(
            doc, None if prior is None else prior.artifact_id
        )
        log.info("recorded %s %s by run %s", doc.name, result.artifact_id, provenance.run_id)
        return result

    def _registers(
        self, refs: Sequence[UUID] | None
    ) -> dict[UUID, tuple[ArtifactRef, DocVarianceArtifact]]:
        """The newest-recorded doc-variance register per repository (on these refs, or all)."""
        kind = DocVarianceArtifact
        held = self._log.documents(
            self._log.list_of(AssessmentKind.COMPLIANCE, refs), [kind.schema]
        )
        newest: dict[UUID, tuple[ArtifactRef, DocVarianceArtifact]] = {}
        for a, row in sorted(held, key=lambda h: (h[0].created_at, h[1].created_at), reverse=True):
            repository_id = self._portfolio.inventory.get_ref(a.repository_ref_id).repository_id
            if repository_id not in newest:
                assert row.id is not None
                ref = ArtifactRef(id=row.id, name=kind.name, digest=row.digest)
                newest[repository_id] = (ref, self._publisher.read(row.id, kind))
        return newest

    def _adr_registry(self) -> tuple[ArtifactRef, list[JsonObject]]:
        latest = self._publisher.latest_imported(AdrRegistryArtifact)
        if latest is None:
            raise ConfigError("no adr-registry published: ADRs are read from pinned registers")
        doc = latest.document
        ref = ArtifactRef(id=latest.artifact_id, name=doc.name, digest=sha256_hex(doc.payload))
        return ref, list(json.loads(doc.payload)["registers"])

    def _decisions(self, register: JsonObject, artifact: ArtifactRef) -> list[Adr]:
        if self._adr_source is None:
            raise ConfigError("reading ADR registers needs an AdrSource — NEED(engine): the reader")
        if not (ready := self._adr_source.check()).ready:
            raise ConfigError(f"ADR source {self._adr_source.name} not ready: {ready.detail}")
        paths = [str(p) for p in register["paths"]]  # type: ignore[union-attr]
        files = self._adr_source.files(str(register["repo"]), str(register["pin"]), paths).data
        return [
            parse_adr(register, f.path, f.text, f.url, artifact)
            for f in sorted(files, key=lambda f: f.path)
            if is_decision_record(f.path, paths)
        ]

    def _adr_defects(self, body: Mapping[str, JsonValue]) -> list[Violation]:
        """Superseded-decision rule: a satisfied verdict cites no non-citable or unknown ADR."""
        if not (cited := adr_citations(body)):
            return []
        names = {key.split("/", 1)[0] for *_, key in cited}
        artifact, registers = self._adr_registry()
        status = {
            adr.key: adr.status
            for register in registers
            if register["name"] in names
            for adr in self._decisions(register, artifact)
        }
        results: list[JsonObject] = body["results"]  # type: ignore[assignment]
        out = []
        for i, j, key in cited:
            found = status.get(key)
            if found is None:
                message = f"evidence[{j}] cites unknown decision '{key}' — not in the ADR registers"
            elif found in NON_CITABLE_ADR:
                message = (
                    f"evidence[{j}] cites {found} decision '{key}' — non-citable for satisfied"
                )
                message += " verdicts (superseded-ADR rule)"
            else:
                continue
            out.append(
                Violation(
                    rule=LintRuleId("compliance.adr"),
                    item=_ref(i, results[i]),
                    message=message,
                    action=LintAction.REVIEW,
                )
            )
        return out

    def _current_scopes(self) -> dict[str, ComplianceScope]:
        return {scope.boundary: scope for _, scope in self._declarations()}

    def _declarations(self) -> list[tuple[tuple[datetime, UUID], ComplianceScope]]:
        """The current declaration per boundary with its position, newest first."""
        rows = self._publisher.history(ComplianceScopeArtifact, SCOPE_HISTORY)
        current: dict[str, tuple[tuple[datetime, UUID], ComplianceScope]] = {}
        for row in rows:
            assert row.id is not None and row.created_at is not None
            scope = self.get_scope(row.id)
            current.setdefault(scope.boundary, ((row.created_at, row.id), scope))
        return sorted(current.values(), key=lambda d: (d[0][0], str(d[0][1])), reverse=True)

    def _recorded(self, scope: ComplianceScope) -> Iterator[ComplianceAssessment]:
        """The scope's recorded assessments, newest first."""
        ref_id = self._members(scope)[0].repository_ref_id
        kind = ComplianceAssessmentArtifact
        recorded = self._log.list_of(AssessmentKind.COMPLIANCE, [ref_id])
        for a, row in self._log.documents(recorded, [kind.schema]):
            assert row.id is not None and a.id is not None
            doc = self._publisher.read(row.id, kind)
            found = ComplianceAssessment.of(
                doc, ArtifactRef(id=row.id, name=doc.name, digest=row.digest), a.occurred_at, [a.id]
            )
            if found.scope_id == scope.scope_id:
                yield found

    def _members(self, scope: ComplianceScope) -> tuple[ScopeMember, ...]:
        """Fail loud: an unknown product or repo, a stale exclude or an empty set is an error."""
        name = scope.boundary
        found: dict[str, tuple[Repository, RepositoryRef]] = {}
        if scope.resolves_via == "repo-graph":
            if not scope.product:
                raise ValidationError(f"{name}: resolves_via=repo-graph requires 'product'")
            product = self._portfolio.find_product(ProductSlug.parse(scope.product))
            if product is None or product.id is None:
                raise NotFoundError(f"{name}: product {scope.product!r} is not in the inventory")
            for ref in self._portfolio.list_product_refs(product.id):
                repo = self._portfolio.get_repository(ref.repository_id)
                found.setdefault(_repo_name(repo.url), (repo, ref))
            if not found:
                raise ValidationError(f"{name}: product {scope.product!r} ships no repositories")
        elif not scope.include:
            raise ValidationError(
                f"{name}: resolves_via=explicit requires a non-empty include list"
            )
        for edge in scope.include:
            found.setdefault(edge.repo, self._included(name, edge.repo))
        if stale := sorted(e.repo for e in scope.exclude if e.repo not in found):
            raise ValidationError(
                f"{name}: exclude entries match nothing in the resolved set ({', '.join(stale)}) "
                "— stale boundary claim"
            )
        excluded = {e.repo for e in scope.exclude}
        members = tuple(
            ScopeMember(repository_id=repo.id, repository_ref_id=ref.id, repo=r)  # type: ignore[arg-type]
            for r, (repo, ref) in sorted(found.items())
            if r not in excluded
        )
        if not members:
            raise ValidationError(f"{name}: resolution produced an empty repo set")
        return members

    def _included(self, name: str, repo_name: str) -> tuple[Repository, RepositoryRef]:
        url = HttpsRepoUrl.parse(f"https://{FORGE}/{repo_name}", self._hosts)
        repo = self._portfolio.find_repository(url)
        if repo is None or repo.id is None:
            raise NotFoundError(f"{name}: included repository {repo_name} is not in the inventory")
        ref = self._portfolio.default_ref(repo.id)
        if ref is None:
            raise NotFoundError(f"{name}: {repo_name} has no observed default-branch head")
        return repo, ref

    def _findings_view(self, resolved: ResolvedScope) -> dict[str, JsonValue]:
        views = [
            (m.repo, v)
            for m in resolved.members
            for v in self._findings.all(FindingFilter(repository_id=m.repository_id, open=True))
        ]
        return findings_snapshot(views)

    def _mapping_doc(self) -> ComplianceMappingArtifact:
        mapping = self._publisher.latest(ComplianceMappingArtifact)
        if mapping is None:
            raise ConfigError("no compliance-mapping registry published")
        return mapping

    def _org_parameters(self) -> dict[str, JsonValue]:
        """The newest recorded org parameters' values; none recorded leaves `param:` undeclared."""
        doc = self._publisher.latest(OrgParametersArtifact)
        if doc is None:
            return {}
        return {k: p["value"] for k, p in json.loads(doc.payload)["parameters"].items()}

    def _store_evidence(self, evidence: Iterable[ComplianceEvidence]) -> tuple[Sha256, ...]:
        stored: dict[Sha256, None] = {}
        for e in evidence:
            if e.sha256 not in stored:
                self._objects.put(evidence_key(e.sha256), canonical_json(e.value).encode())
                stored[e.sha256] = None
        return tuple(stored)

    def _evidence_defect(self, j: int, sha256: str) -> str | None:
        key = evidence_key(sha256)
        if not self._objects.exists(key):
            return f"evidence[{j}] cites {sha256[:12]}… but the bundle has no such item"
        try:
            value = json.loads(self._objects.get(self._objects.stat(key)))
        except json.JSONDecodeError:
            return f"evidence[{j}] bundle item is not JSON"
        if evidence_id(value) != sha256:
            return f"evidence[{j}] content does not hash to its id ({sha256[:12]}…)"
        return None

    def _metadata(
        self,
        request: EvaluationRequest,
        resolved: ResolvedScope,
        frameworks: list[ComplianceFramework],
        skipped: dict[str, str],
        snapshots: Mapping[str, JsonValue],
        mapping: ComplianceMappingArtifact,
        parameters: Mapping[str, JsonValue],
    ) -> dict[str, JsonValue]:
        scope = resolved.scope
        target: dict[str, JsonValue] = {
            "kind": str(request.target_kind),
            "scope": {
                "boundary": scope.boundary,
                "resolves_via": str(scope.resolves_via),
                "declared_by": scope.declared_by,
                "declared_at": scope.declared_at,
                "excluded": [e.model_dump() for e in scope.exclude],
                "draft": scope.draft,
            },
            "product": scope.product or scope.boundary,
            "repos": sorted(resolved.repos),
        }
        if request.environment:
            target["environment"] = request.environment
        if request.inventory is not None:
            target["snapshot_id"] = request.inventory.snapshot_id
        if request.cde_boundary:
            target["cde_boundary"] = request.cde_boundary
        if request.personal_data_stores:
            target["personal_data_stores"] = list(request.personal_data_stores)
        if request.trust_categories:
            target["trust_service_categories"] = list(request.trust_categories)
        metadata: dict[str, JsonValue] = {
            "artifact": "compliance-assessment",
            "harness_version": request.harness_version,
            "scope_id": str(scope.scope_id),
            "target": target,
            "frameworks": [
                {
                    "id": str(fw),
                    **({"caveat": CAVEATS[fw]} if fw in CAVEATS else {}),
                    **({"profile": SPINE_PROFILE[fw]} if fw in SPINE_PROFILE else {}),
                }
                for fw in frameworks
            ],
            "skipped_frameworks": skipped,
            "registry_hash": evidence_id(json.loads(mapping.payload)),
            "collector_versions": {
                k: str((v.get("metadata") or {}).get("collector", k)) if isinstance(v, dict) else k
                for k, v in snapshots.items()
            },
            "generated_at": self._clock.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        if parameters:
            metadata["org_parameters_hash"] = evidence_id(dict(parameters))
        return metadata


def _single(doc: ComplianceScopeArtifact) -> dict[str, JsonObject]:
    declared = boundaries(doc)
    if len(declared) != 1:
        raise ValidationError(f"declare one boundary at a time, not {len(declared)}")
    return declared


def _is(principal: Principal, declarant: str) -> bool:
    want = declarant.strip().lower()
    have = principal.identity.lower()
    return bool(want) and want in {have, have.split("@")[0]}


def _repo_name(url: str) -> str:
    return "/".join(url.rstrip("/").removesuffix(".git").split("/")[-2:])


def _variances(
    repository_id: UUID, artifact: ArtifactRef, register: DocVarianceArtifact
) -> list[DocVariance]:
    return [
        DocVariance.of(repository_id, r, artifact) for r in json.loads(register.payload)["records"]
    ]


def _assessed(
    resolved: ResolvedScope, doc: ComplianceAssessmentArtifact
) -> tuple[ScopeMember, ...]:
    repos = set(json.loads(doc.payload)["metadata"]["target"].get("repos") or ())
    if gone := sorted(repos - set(resolved.repos)):
        raise ConflictError(
            f"scope membership changed since evaluation ({', '.join(gone)}): re-run"
        )
    return tuple(m for m in resolved.members if m.repo in repos)
