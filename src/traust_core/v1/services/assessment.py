from __future__ import annotations

import copy
import json
import logging
from collections import Counter, defaultdict
from collections.abc import Collection, Mapping, Sequence
from datetime import UTC, datetime, time
from pathlib import Path
from time import monotonic
from typing import Any
from uuid import UUID

import pydantic

from traust_core.v1 import contracts
from traust_core.v1.errors import (
    ConfigError,
    IntegrityError,
    NotFoundError,
    ServiceError,
    ValidationError,
)
from traust_core.v1.models import candidate_formats
from traust_core.v1.models.artifacts import (
    AssessmentArtifact,
    CloudConfigAuditArtifact,
    IsolationReviewArtifact,
    PrivProfileArtifact,
    ReportArtifact,
    RepoStateArtifact,
    ThreatModelArtifact,
)
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    ASSESSMENT_DEGRADED,
    RECORDED_SCHEMAS,
    REPORTED_FINDINGS,
    Artifact,
    Assessment,
    AssessmentFilter,
    AssessmentKind,
    AssessmentSkillInput,
    AttackScenario,
    Coverage,
    CoverageGap,
    DiffCaller,
    DiffCluster,
    DiffFile,
    DiffRefused,
    DiffRequest,
    DiffResolution,
    DiffScope,
    Freshness,
    Population,
    PopulationRow,
    PrivilegeProfile,
    ReportGap,
    TenantBoundary,
    Threat,
    ThreatFilter,
    ThreatRatings,
    ToolName,
    report_gaps,
)
from traust_core.v1.models.cloud_config import audit_candidates, audit_judgments
from traust_core.v1.models.code_facts import SymbolFact
from traust_core.v1.models.common import ArtifactRef, Page, PageRequest, Provenance
from traust_core.v1.models.findings import (
    CandidateFormat,
    Decision,
    FindingCandidate,
    FindingContext,
    FindingView,
    IntakeResult,
    Label,
    OwaspFactors,
    RatingInputs,
)
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import DEFAULT_FORGE_HOSTS, default_line
from traust_core.v1.models.observation import (
    CHURN_FULL_LINES,
    SENSITIVE_RX,
    ObservationTarget,
    is_deps_manifest,
    is_first_party,
)
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.checkout import GitCheckout, NumstatRow
from traust_core.v1.providers.clock import Clock, SystemClock
from traust_core.v1.providers.symbols import SymbolIndex, SymbolReference
from traust_core.v1.providers.tools import ToolProvider, ToolRequest, ToolRun
from traust_core.v1.repositories.traust.assessments import AssessmentsUnitOfWork
from traust_core.v1.services.artifact_publishing import A, ArtifactPublisher, AssessmentLog
from traust_core.v1.services.cloud_config import CloudConfigCitations
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.intake import FindingIntake
from traust_core.v1.services.findings.rating import RatingPolicy
from traust_core.v1.services.findings.service import FindingService
from traust_core.v1.services.isolation_review import GapInterfaces
from traust_core.v1.services.lint import Lint, LintContext, LintReport
from traust_core.v1.services.observation import parse_audit_date
from traust_core.v1.services.portfolio import Inventory

log = logging.getLogger(__name__)

AUDIT_LINT = Lint(
    {
        CloudConfigAuditArtifact: [CloudConfigCitations()],
        IsolationReviewArtifact: [GapInterfaces()],
    }
)
MAX_GAP_EXAMPLES = 8


MAX_CHANGED_FILE_RATIO = 0.30
MAX_CLUSTERS = 5
HUNK_CONTEXT_LINES = 10
MAX_FILE_HUNK_BYTES = 20_000
MAX_TOTAL_HUNK_BYTES = 400_000
MAX_SYMBOLS_PER_FILE = 10
MAX_CALLERS = 40


def clusters(paths: Sequence[str]) -> list[tuple[str, list[str]]]:
    """Paths grouped by top-level directory (root files under "(root)"), largest first; past
    MAX_CLUSTERS the smallest merge into "other", which bounds one reviewer per cluster."""
    groups: dict[str, list[str]] = defaultdict(list)
    for p in paths:
        groups[p.split("/", 1)[0] if "/" in p else "(root)"].append(p)
    ranked = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    if len(ranked) > MAX_CLUSTERS:
        head, tail = ranked[: MAX_CLUSTERS - 1], ranked[MAX_CLUSTERS - 1 :]
        ranked = [*head, ("other", [p for _, ps in tail for p in ps])]
    return [(name, sorted(ps)) for name, ps in ranked]


def touches(location: str, paths: Collection[str]) -> bool:
    """A reported location names one of `paths`, allowing for a component- or repo-root prefix."""
    a = location.removeprefix("./").lstrip("/")
    return any(
        a == b or a.endswith("/" + b) or b.endswith("/" + a)
        for b in (p.removeprefix("./").lstrip("/") for p in paths)
    )


class AssessmentService:
    def __init__(
        self,
        uow: AssessmentsUnitOfWork,
        intake: FindingIntake | None = None,  # record doors only
        *,
        clock: Clock | None = None,
        hosts: Mapping[str, str] | None = None,
        tools: ProviderRegistry[ToolProvider[Any]] | None = None,
        decisions: FindingDecisions | None = None,  # record_audit only
        publisher: ArtifactPublisher | None = None,  # record_audit only
        findings: FindingService | None = None,  # prepare only
        git: GitCheckout | None = None,  # prepare's diff mode
        symbols: SymbolIndex | None = None,  # prepare's diff mode
        rating: RatingPolicy | None = None,  # rate_threats only
    ) -> None:
        self._uow = uow
        self._inventory = Inventory(uow)
        self._log = AssessmentLog(uow)
        self._intake = intake
        self._clock = clock or SystemClock()
        self._hosts = dict(hosts or DEFAULT_FORGE_HOSTS)
        self._tools = tools
        self._decisions = decisions
        self._publisher = publisher
        self._findings = findings
        self._git = git
        self._symbols = symbols
        self._rating = rating

    def run_tools(self, workspace: Path, tools: Sequence[ToolName]) -> ToolRun:
        """Each tool over one checkout; any tool not ready stops the run before one starts."""
        if self._tools is None:
            raise ConfigError("run_tools needs the tool providers (Context wires them)")
        if not tools:
            raise ValidationError("run_tools needs at least one tool")
        providers = {name: self._tools.get(name) for name in dict.fromkeys(tools)}
        if unready := [
            f"{name}: {readiness.detail}"
            for name, p in providers.items()
            if not (readiness := p.check()).ready
        ]:
            raise ConfigError(f"tools not ready: {'; '.join(unready)}")
        results = {}
        for name, provider in providers.items():
            started = monotonic()
            results[name] = result = provider.acquire(ToolRequest(workspace=workspace))
            log.info(
                "tool %s %s over %s in %.1fs",
                name,
                result.acquisition.version,
                workspace,
                monotonic() - started,
            )
        return ToolRun(results)

    def prepare(
        self, repository_ref_id: UUID, kind: AssessmentKind, diff: DiffRequest | None = None
    ) -> AssessmentSkillInput:
        """What an assessment of one commit starts from: the repository's findings, its latest
        threat model, its baseline audit and, in diff mode, the changes since that audit.
        `DiffRefused` when the diff can't stand in for that audit."""
        if self._findings is None:
            raise ConfigError("prepare needs the finding reads (Context wires them)")
        if diff is not None and not self._require_git().is_checkout(diff.checkout):
            raise DiffRefused(
                "target is not a git checkout — no diff is computable against any baseline"
            )
        subject = self._inventory.subject(repository_ref_id)
        line = sorted(default_line(self._inventory.list_refs(subject.repository_id)))
        with self._uow as uow:
            modelled = self._latest_for_refs(
                uow, line, AssessmentKind.THREAT_MODEL, ASSESSMENT_COMPLETED
            )
            threat_model = (
                uow.artifacts.list_for_assessment(modelled.id) if modelled and modelled.id else []
            )
            baseline = self._baseline(uow, diff, line)
        document = self._threat_model_document(modelled)
        anchor = None
        if diff is not None:
            audited = self._inventory.get_ref(baseline.repository_ref_id) if baseline else None
            if audited is not None and audited.repository_id != subject.repository_id:
                raise ValidationError(
                    f"assessment {diff.baseline_assessment_id} is of another repository"
                )
            anchor = diff.since or (audited.sha if audited else None)
            if anchor is None:
                raise DiffRefused(
                    f"no valid HEAD code-audit baseline resolvable for {subject.repository_url}"
                )
        now = self._clock.now()
        known = self._findings.baseline(
            subject.repository_id, baseline.occurred_at if diff and baseline else now
        )
        return AssessmentSkillInput(
            subject=subject,
            findings=FindingContext(baseline=tuple(known)),
            prepared_at=now,
            kind=kind,
            threat_model=tuple(threat_model),
            threat_model_document=document,
            baseline_assessment_id=baseline.id if baseline else None,
            diff=self._scope(diff, baseline, anchor, known) if diff and anchor else None,
        )

    def _threat_model_document(self, modelled: Assessment | None) -> dict[str, Any] | None:
        if modelled is None:
            return None
        if self._publisher is None:
            raise ConfigError("reading the recorded threat model needs the publisher")
        for _, row in self._log.documents([modelled], [ThreatModelArtifact.schema]):
            assert row.id is not None
            return json.loads(self._publisher.read(row.id, ThreatModelArtifact).payload)
        return None

    def _baseline(
        self, uow: AssessmentsUnitOfWork, diff: DiffRequest | None, line: list[UUID]
    ) -> Assessment | None:
        if diff is not None and diff.baseline_assessment_id is not None:
            return self._read(uow.assessments.get(diff.baseline_assessment_id))
        return self._latest_for_refs(uow, line, AssessmentKind.SECURE_CODE, ASSESSMENT_COMPLETED)

    def _latest_for_refs(
        self, uow: AssessmentsUnitOfWork, refs: Collection[UUID], kind: str, status: str
    ) -> Assessment | None:
        rows = [
            uow.assessments.latest_for_refs(refs, spelling, status)
            for spelling in self._kind_spellings(kind)
        ]
        found = max(
            (row for row in rows if row is not None),
            key=lambda row: (row.occurred_at, row.created_at, row.id),
            default=None,
        )
        return None if found is None else self._read(found)

    def _scope(
        self,
        diff: DiffRequest,
        baseline: Assessment | None,
        anchor: str,
        known: Sequence[FindingView],
    ) -> DiffScope:
        git, checkout = self._require_git(), diff.checkout
        if not git.reachable(checkout, anchor):
            raise DiffRefused(
                f"anchor {anchor} is not reachable in the clone — the checkout does not contain "
                "the audited commit"
            )
        rows = git.numstat(checkout, anchor)
        total = sum(map(is_first_party, git.tracked(checkout)))
        changed = [r for r in rows if is_first_party(r.path)]
        lines = sum(r.added + r.deleted for r in changed)
        ratio = len(changed) / total if total else float(bool(changed))
        if ratio > MAX_CHANGED_FILE_RATIO:
            raise DiffRefused(
                f"{len(changed)}/{total} ({ratio:.0%}) of first-party files changed since the "
                "anchor — the diff invalidates the baseline"
            )
        if lines >= CHURN_FULL_LINES:
            raise DiffRefused(
                f"C={lines} first-party changed lines >= {CHURN_FULL_LINES} (rescan rule-2 "
                "threshold) — the diff invalidates the baseline"
            )
        files, omitted = self._hunks(checkout, anchor, changed)
        callers, note, unlisted = self._callers(checkout, {r.path for r in changed})
        return DiffScope(
            anchor=anchor,
            resolution=DiffResolution.OVERRIDE
            if diff.baseline_assessment_id or diff.since
            else DiffResolution.AUTO,
            baseline_assessment_id=baseline.id if baseline else None,
            changed_lines=lines,
            sensitive_lines=sum(
                r.added + r.deleted for r in changed if SENSITIVE_RX.search(r.path)
            ),
            deps_manifests_changed=any(is_deps_manifest(r.path) for r in rows),
            first_party_files=total,
            changed_ratio=round(ratio, 4),
            clusters=tuple(
                DiffCluster(
                    name=name,
                    files=tuple(files[p] for p in paths),
                    callers=tuple(c for c in callers if c.defined_in in paths),
                    baseline=tuple(
                        v for v in known if any(touches(loc.path, paths) for loc in v.locations)
                    ),
                )
                for name, paths in clusters(list(files))
            ),
            callers_note=note,
            omitted=(*omitted, *unlisted),
        )

    def _hunks(
        self, checkout: Path, anchor: str, changed: Sequence[NumstatRow]
    ) -> tuple[dict[str, DiffFile], list[str]]:
        files, omitted, spent = {}, [], 0
        for row in changed:
            hunks, truncated = None, False
            if spent >= MAX_TOTAL_HUNK_BYTES:
                omitted.append(
                    f"{row.path}: total packet byte cap ({MAX_TOTAL_HUNK_BYTES}) reached — hunks "
                    "not embedded; run git diff to view"
                )
            else:
                raw = self._require_git().hunks(checkout, anchor, row.path, HUNK_CONTEXT_LINES)
                encoded = raw.encode("utf-8", "replace")
                if truncated := len(encoded) > MAX_FILE_HUNK_BYTES:
                    raw = encoded[:MAX_FILE_HUNK_BYTES].decode("utf-8", "replace") + (
                        f"\n... [truncated at {MAX_FILE_HUNK_BYTES} bytes — Read the file for "
                        "the rest]"
                    )
                spent += len(raw.encode("utf-8", "replace"))
                hunks = raw
            files[row.path] = DiffFile(
                path=row.path,
                added=row.added,
                deleted=row.deleted,
                sensitive=bool(SENSITIVE_RX.search(row.path)),
                hunks=hunks,
                truncated=truncated,
            )
        return files, omitted

    def _callers(
        self, checkout: Path, changed: set[str]
    ) -> tuple[list[DiffCaller], str | None, list[str]]:
        """Reference sites outside the changed set of the symbols the changed files define."""
        if self._symbols is None:
            raise ConfigError("diff mode needs the symbol index (Context wires it)")
        try:
            facts = self._symbols.enumerate(ToolRequest(workspace=checkout)).data
        except ServiceError as e:
            log.warning("symbol index over %s failed: %s", checkout, e)
            return [], "skipped: symbol index build failed — enumerate callers manually", []
        symbols = [f for f in facts if isinstance(f, SymbolFact)]
        defined = {(s.name, s.location.path, s.location.line) for s in symbols}
        names: dict[str, list[str]] = {}
        unlisted = []
        for path in sorted(changed):
            own = list(dict.fromkeys(s.name for s in symbols if s.location.path == path))
            if len(own) > MAX_SYMBOLS_PER_FILE:
                unlisted.append(
                    f"{path}: {len(own) - MAX_SYMBOLS_PER_FILE} symbol(s) beyond the per-file "
                    "cap unqueried"
                )
            names[path] = own[:MAX_SYMBOLS_PER_FILE]
        sites: dict[str, list[SymbolReference]] = defaultdict(list)
        for r in self._symbols.references(checkout, {n for ns in names.values() for n in ns}):
            if r.path not in changed and (r.symbol, r.path, r.line) not in defined:
                sites[r.symbol].append(r)
        callers: list[DiffCaller] = []
        for path, own in names.items():
            for name in own:
                for r in sites[name]:
                    if len(callers) >= MAX_CALLERS:
                        unlisted.append(
                            f"caller cap ({MAX_CALLERS}) reached at {path}:{name} — remaining "
                            "references unlisted"
                        )
                        return callers, None, unlisted
                    callers.append(
                        DiffCaller(
                            symbol=name,
                            defined_in=path,
                            path=r.path,
                            line=r.line,
                            context=r.context,
                        )
                    )
        return callers, None, unlisted

    def _require_git(self) -> GitCheckout:
        if self._git is None:
            raise ConfigError("diff mode needs the checkout reader (Context wires it)")
        return self._git

    def record_scan(
        self,
        repository_ref_id: UUID,
        raw: bytes,
        format: CandidateFormat,
        provenance: Provenance,
    ) -> tuple[Assessment, IntakeResult]:
        """Third-party scanner output (SARIF, Dependabot, govulncheck) as an assessment of the
        commit and its findings; the same output again is the same assessment and adds nothing."""
        if self._intake is None:
            raise ConfigError("record_scan needs finding intake (Context wires it)")
        if self._intake._uow is not self._uow:
            raise ConfigError(
                "record_scan needs assessment and finding intake to share a unit of work"
            )
        with self._uow as uow:
            name, version = candidate_formats.scanner(format.value, raw)
            ref = self._inventory.get_ref(repository_ref_id)
            candidates = FindingCandidate.parse_many(raw, format, ref.repository_id)
            assessment = uow.assessments.find_scan(repository_ref_id, name, provenance.occurred_at)
            if assessment is None:
                assessment = uow.assessments.add(
                    Assessment(
                        repository_ref_id=repository_ref_id,
                        kind=AssessmentKind.SCANNER,
                        status=ASSESSMENT_COMPLETED,
                        assessor=name,
                        assessor_version=version,
                        occurred_at=provenance.occurred_at,
                    )
                )
                assert assessment.id is not None
                assessment = uow.assessments.get(assessment.id)
            assert assessment.id is not None
            result = self._intake.accept(assessment.id, candidates)
            uow.commit()
        return assessment, result

    def record(
        self,
        doc: AssessmentArtifact,
        repository_ref_id: UUID,
        kind: AssessmentKind,
        assessor: str,
        assessor_version: str,
        provenance: Provenance,
        *,
        status: str = ASSESSMENT_COMPLETED,
    ) -> Assessment:
        """An assessment of `kind` on the commit holding `doc`, published here unless provenance
        names it (whose bytes must be `doc`'s); the same document at the same time is one run.
        A container, RPM or vuln-scan document's findings are findings of the assessment; a
        document failing its gate (`check_audit`) is refused."""
        contracts.validate_enum("assessment_kind", kind)
        if provenance.artifact is None and self._publisher is None:
            raise ValidationError("record requires a published artifact reference")
        self._gate(doc)
        ref = self._inventory.get_ref(repository_ref_id)
        assessment = Assessment(
            repository_ref_id=repository_ref_id,
            kind=kind,
            status=status,
            assessor=assessor,
            assessor_version=assessor_version,
            occurred_at=provenance.occurred_at,
        )
        stated = REPORTED_FINDINGS.get(kind)
        if stated is None or doc.schema != RECORDED_SCHEMAS[kind]:
            return self._record(doc, assessment, provenance.artifact)[0]
        candidates = stated(doc.findings, ref.repository_id)
        return self._record_findings(doc, assessment, provenance.artifact, candidates)[0]

    def _record_findings(
        self,
        doc: AssessmentArtifact,
        assessment: Assessment,
        artifact: ArtifactRef | None,
        candidates: Sequence[FindingCandidate],
    ) -> tuple[Assessment, Artifact, IntakeResult]:
        """`_record` and the findings the document states, refused before anything is written."""
        if self._intake is None:
            raise ConfigError(f"recording {assessment.kind} findings needs finding intake")
        if self._intake._uow is not self._uow:
            raise ConfigError(
                "recording findings needs assessment and intake to share a unit of work"
            )
        with self._uow as uow:
            repository_id = self._inventory.get_ref(assessment.repository_ref_id).repository_id
            self._intake.check(repository_id, candidates)
            recorded, report = self._record(doc, assessment, artifact)
            assert recorded.id is not None
            taken = self._intake.accept(recorded.id, candidates)
            uow.commit()
        return recorded, report, taken

    def _record(
        self, doc: AssessmentArtifact, assessment: Assessment, artifact: ArtifactRef | None
    ) -> tuple[Assessment, Artifact]:
        contracts.validate_enum("assessment_kind", assessment.kind)
        if (schema := RECORDED_SCHEMAS.get(AssessmentKind(assessment.kind))) is None:
            raise ConfigError(f"{assessment.kind} assessments are recorded by their owner's door")
        if doc.schema != schema:
            raise ValidationError(
                f"a {assessment.kind} assessment holds a {schema} document, not {doc.schema}"
            )
        digest = sha256_hex(doc.payload)
        with self._uow as uow:
            if artifact is not None:
                published = self._log.get_artifact(artifact.id)
                if published.digest != digest:
                    raise IntegrityError(
                        f"artifact {artifact.id}: doc digest {digest} "
                        f"!= published {published.digest}"
                    )
            for spelling in self._kind_spellings(assessment.kind):
                for held in self._log.find_recorded(
                    [assessment.repository_ref_id], spelling, doc.schema, digest
                ):
                    if held[0].occurred_at == assessment.occurred_at:
                        return self._read(held[0]), held[1]
            if artifact is None:
                if self._publisher is None:
                    raise ConfigError(f"recording {doc.name} needs a publisher to publish it")
                if self._publisher._uow is not self._uow:
                    raise ConfigError(
                        "recording needs assessment and publisher to share a unit of work"
                    )
                artifact = self._publisher.publish_ref(doc)
            recorded, report = self._log.add(assessment, artifact.id, digest)
            uow.commit()
        return self._read(recorded), report

    def record_observation(
        self,
        doc: RepoStateArtifact,
        artifact_id: UUID,
        repository_ref_id: UUID,
        *,
        baseline_assessment_id: UUID | None,
        assessor: str,
        assessor_version: str,
        occurred_at: datetime,
    ) -> Assessment:
        """A forge observation of the commit, measured against the audit it compared with."""
        return self._log.add(
            Assessment(
                repository_ref_id=repository_ref_id,
                baseline_assessment_id=baseline_assessment_id,
                kind=AssessmentKind.REPO_STATE_CANONICAL,
                status=ASSESSMENT_COMPLETED,
                assessor=assessor,
                assessor_version=assessor_version,
                occurred_at=occurred_at,
            ),
            artifact_id,
            sha256_hex(doc.payload),
        )[0]

    def check_audit(self, doc: AssessmentArtifact) -> LintReport:
        """A document's gate past its schema (cloud-config audits, isolation reviews);
        `record` and `record_audit` refuse a document that fails."""
        return AUDIT_LINT.run(doc, LintContext())

    def _gate(self, doc: AssessmentArtifact) -> None:
        if violations := self.check_audit(doc).violations:
            listed = "; ".join(f"{v.item}: {v.message}" for v in violations)
            raise ValidationError(f"{doc.name} report fails its gate: {listed}")

    def record_audit(
        self, doc: CloudConfigAuditArtifact, repository_ref_id: UUID, provenance: Provenance
    ) -> tuple[Assessment, list[Decision]]:
        """An audit of the commit (degraded when its report lists gaps) with its published report,
        every finding it states, and its judgment on each as a decision. A provenance without an
        artifact has the report published here. Re-recording the same run adds nothing."""
        if self._intake is None or self._decisions is None:
            raise ConfigError(
                "record_audit needs finding intake and decisions (Context wires them)"
            )
        if self._intake._uow is not self._uow or self._decisions._uow is not self._uow:
            raise ConfigError(
                "record_audit needs assessment, intake and decisions to share a unit of work"
            )
        with self._uow.write() as uow:
            doc = CloudConfigAuditArtifact.parse(doc.payload)
            self._gate(doc)
            self._decisions.require_signable()
            ref = self._inventory.get_ref(repository_ref_id)
            candidates, judgments = audit_candidates(doc, ref.repository_id), audit_judgments(doc)
            assessment, report, taken = self._record_findings(
                doc,
                Assessment(
                    repository_ref_id=repository_ref_id,
                    kind=AssessmentKind.CLOUD_CONFIG_CANONICAL,
                    status=ASSESSMENT_DEGRADED if doc.gaps else ASSESSMENT_COMPLETED,
                    assessor=f"skill:{doc.name}",
                    assessor_version=doc.metadata.harness_version,
                    occurred_at=provenance.occurred_at,
                ),
                provenance.artifact,
                candidates,
            )
            assert assessment.id is not None and report.id is not None
            decisions = self._decisions.record_assessed(
                assessment.id, report.id, [(taken.findings[label], j) for label, j in judgments]
            )
            uow.commit()
        return assessment, decisions

    def get(self, assessment_id: UUID) -> Assessment:
        return self._read(self._log.get(assessment_id))

    def latest(
        self, repository_ref_id: UUID, kind: AssessmentKind, *, status: str | None = None
    ) -> Assessment | None:
        spellings = self._kind_spellings(kind)
        with self._uow as uow:
            rows = [uow.assessments.latest(repository_ref_id, value, status) for value in spellings]
            found = max(
                (row for row in rows if row is not None),
                key=lambda row: (row.occurred_at, row.created_at, row.id),
                default=None,
            )
            return None if found is None else self._read(found)

    @staticmethod
    def _kind_spellings(kind: str) -> list[str]:
        target = contracts.normalize_enum("assessment_kind", kind)
        return [
            value
            for value in contracts.enum_values("assessment-kind")
            if contracts.normalize_enum("assessment_kind", value) == target
        ]

    @staticmethod
    def _read(assessment: Assessment) -> Assessment:
        normalized = contracts.normalize_enum("assessment_kind", assessment.kind)
        kind = next(
            (p.value for p in normalized.pairs if p.enum == "assessment_kind"), assessment.kind
        )
        return Assessment.model_validate({**dict(assessment), "kind": kind})

    def list(self, filter: AssessmentFilter, page: PageRequest) -> Page[Assessment]:
        after = page.position()
        if filter.repository_ref_id is None:
            raise ValidationError("list requires a repository_ref_id (no index for an open scan)")
        kinds = self._kind_spellings(filter.kind) if filter.kind is not None else [None]
        with self._uow as uow:
            rows = [
                self._read(row)
                for kind in kinds
                for row in uow.assessments.search(
                    repository_ref_id=filter.repository_ref_id,
                    kind=kind,
                    status=filter.status,
                    limit=page.limit + 1,
                    after=after,
                )
            ]
        rows.sort(key=lambda a: (a.occurred_at, a.id), reverse=True)
        return Page.of(rows, page.limit, lambda a: (a.occurred_at, a.id))

    def list_for_repository(
        self, repository_id: UUID, kind: AssessmentKind | None = None
    ) -> list[Assessment]:
        """The assessments across every ref of the repository, oldest first."""
        refs = [r.id for r in self._inventory.list_refs(repository_id) if r.id]
        kinds = self._kind_spellings(kind) if kind is not None else [None]
        rows = [self._read(row) for spelling in kinds for row in self._log.list_of(spelling, refs)]
        return sorted(rows, key=lambda a: (a.occurred_at, a.id))

    def population(
        self, as_of: datetime, filter: AssessmentFilter, repository_ids: Collection[UUID]
    ) -> Population:
        """Of these repositories, what was assessed by `as_of` (of `filter.kind`, any when None):
        a row per repository and kind, and the repositories never assessed at all."""
        held = self._held(as_of, filter, repository_ids)
        rows = [
            PopulationRow(
                repository_id=repository_id,
                kind=kind,
                latest=default[-1] if default else None,
                default_line=len(default),
                branches=len(branch),
            )
            for (repository_id, kind), (default, branch) in sorted(held.items(), key=str)
        ]
        assessed = {r.repository_id for r in rows}
        return Population(
            as_of=as_of,
            rows=tuple(rows),
            never_assessed_repository_ids=tuple(
                sorted(i for i in dict.fromkeys(repository_ids) if i not in assessed)
            ),
        )

    def _held(
        self, as_of: datetime, filter: AssessmentFilter, repository_ids: Collection[UUID]
    ) -> dict[tuple[UUID, str], tuple[list[Assessment], list[Assessment]]]:
        """Per (repository, kind): its assessments by `as_of` on the default line and on other
        branches, oldest first."""
        if filter.repository_ref_id is not None:
            raise ValidationError("population and coverage are per repository, not per commit")
        if as_of.tzinfo is None:
            raise ValidationError("as_of must be timezone-aware")
        listed = self._inventory.list_refs_of(repository_ids)
        refs, line = {r.id: r for r in listed if r.id}, default_line(listed)
        held: dict[tuple[UUID, str], tuple[list[Assessment], list[Assessment]]] = {}
        kinds = self._kind_spellings(filter.kind) if filter.kind is not None else [None]
        rows = [self._read(a) for kind in kinds for a in self._log.list_of(kind, list(refs))]
        for a in sorted(rows, key=lambda a: (a.occurred_at, a.created_at, a.id)):
            if a.occurred_at > as_of or (filter.status and a.status != filter.status):
                continue
            ref = refs[a.repository_ref_id]
            default, branch = held.setdefault((ref.repository_id, a.kind), ([], []))
            (default if ref.id in line else branch).append(a)
        return held

    def freshness(
        self,
        repository_ref_id: UUID | None = None,
        *,
        baseline: ObservationTarget | None = None,
        changed_lines: int | None = None,
        as_of: datetime | None = None,
    ) -> Freshness:
        """How long since the repository's latest completed code audit, and how far it has
        churned since; measured against `baseline`, else against the ref's repository's."""
        if baseline is None:
            if repository_ref_id is None:
                raise ValidationError(
                    "freshness requires a repository ref or an observation baseline"
                )
            ref = self._inventory.get_ref(repository_ref_id)
            baseline = self.observation_target(repository_id=ref.repository_id)
        now = as_of or self._clock.now()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValidationError("freshness requires a timezone-aware clock")
        audited = parse_audit_date(baseline.audit_date) if baseline.has_audit else None
        return Freshness(
            repository_ref_id=repository_ref_id or baseline.repository_ref_id,
            last_assessed_at=datetime.combine(audited, time()) if audited else None,
            churn_ratio=changed_lines / baseline.lines_reviewed
            if changed_lines is not None and baseline.lines_reviewed
            else None,
        )

    def observation_target(
        self, *, repository_id: UUID | None = None, repo_url: str | None = None
    ) -> ObservationTarget:
        """Resolve what an observation measures: the repository, its latest audit,
        and the commit that audit pinned (the ref it occurred on)."""
        if (repository_id is None) == (repo_url is None):
            raise ValidationError("supply exactly one repository id or URL")
        with self._uow:
            repo = (
                self._inventory.get_repository(repository_id)
                if repository_id is not None
                else self._inventory.find_repository(repo_url)
            )
            if repo is None:
                raise NotFoundError(f"repository not in inventory: {repository_id or repo_url}")
            latest = None
            for ref in self._inventory.list_refs(repo.id):
                # a degraded or failed run is never read as clean (the DDL rule)
                found = self.latest(ref.id, AssessmentKind.SECURE_CODE, status=ASSESSMENT_COMPLETED)
                if found is not None and (
                    latest is None or found.occurred_at > latest[1].occurred_at
                ):
                    latest = (ref, found)
        if latest is None:
            return ObservationTarget(repository_id=repo.id, repo_url=repo.url, has_audit=False)
        ref, audit = latest
        return ObservationTarget(
            repository_id=repo.id,
            repo_url=repo.url,
            has_audit=True,
            audit_date=audit.occurred_at.astimezone(UTC).date().isoformat(),
            pinned_sha=ref.sha,
            repository_ref_id=ref.id,
            audit_assessment_id=audit.id,
        )

    def threats(self, filter: ThreatFilter, page: PageRequest) -> Page[Threat]:
        """The threats each repository's latest completed threat model states, newest model
        first; narrowed by status and ATT&CK technique."""
        after = page.position()
        scope = AssessmentFilter(kind=AssessmentKind.THREAT_MODEL, status=ASSESSMENT_COMPLETED)
        _, documents = self._latest_documents(
            scope, filter.repository_ids, ThreatModelArtifact, filter.as_of
        )
        at = {a.id: a.occurred_at for _, a, _ in documents}
        rows = sorted(
            (
                t
                for repository_id, a, doc in documents
                for t in Threat.of(a, repository_id, json.loads(doc.payload))
                if (not filter.statuses or t.status in filter.statuses)
                and (filter.technique is None or filter.technique in {x.id for x in t.techniques})
                and (after is None or (a.occurred_at, t.id) < after)
            ),
            key=lambda t: (at[t.assessment_id], t.id),
            reverse=True,
        )
        return Page.of(rows[: page.limit + 1], page.limit, lambda t: (at[t.assessment_id], t.id))

    def attack_scenarios(
        self, repository_ids: Collection[UUID], as_of: datetime | None = None
    ) -> list[AttackScenario]:
        """The attack scenarios each repository's latest completed threat model narrates, in the
        model's order; a model without any adds none."""
        scope = AssessmentFilter(kind=AssessmentKind.THREAT_MODEL, status=ASSESSMENT_COMPLETED)
        _, documents = self._latest_documents(scope, repository_ids, ThreatModelArtifact, as_of)
        return [
            AttackScenario(
                assessment_id=a.id,  # type: ignore[arg-type]
                repository_id=repository_id,
                label=Label(s["id"]),
                threat=s.get("threat"),
                steps=tuple(s["steps"]),
            )
            for repository_id, a, doc in sorted(documents, key=lambda d: str(d[0]))
            for s in json.loads(doc.payload).get("attack_scenarios") or ()
        ]

    def tenant_boundaries(
        self, repository_ids: Collection[UUID], as_of: datetime | None = None
    ) -> list[TenantBoundary]:
        """The tenant boundaries each repository's latest completed threat model states (its
        section 10), in the model's order; a single-tenant model adds none."""
        scope = AssessmentFilter(kind=AssessmentKind.THREAT_MODEL, status=ASSESSMENT_COMPLETED)
        _, documents = self._latest_documents(scope, repository_ids, ThreatModelArtifact, as_of)
        return [
            b
            for repository_id, a, doc in sorted(documents, key=lambda d: str(d[0]))
            for b in TenantBoundary.of(a, repository_id, json.loads(doc.payload))
        ]

    def rate_threats(self, model: Mapping[str, Any]) -> ThreatRatings:
        """Each threat's OWASP risk_rating rebuilt from its factor scores (scores, levels,
        severity); a threat with no rating is left alone. `model` may be a draft."""
        if self._rating is None:
            raise ConfigError("rate_threats needs the rating policy (Context wires it)")
        rated = copy.deepcopy(dict(model))
        changed, failed = [], {}
        for threat in rated.get("threats") or ():
            if not (stated := threat.get("risk_rating")):
                continue
            label = Label(threat.get("id", "?"))
            if not isinstance(stated, Mapping):
                failed[label] = "risk_rating must be an object"
                continue
            try:
                factors = OwaspFactors.of_stated(stated)
            except pydantic.ValidationError as e:
                failed[label] = "; ".join(_reason(err) for err in e.errors())
                continue
            rating = self._rating.rate(RatingInputs(factors=factors))
            if (rebuilt := rating.stated(factors, stated.get("rationale"))) != stated:
                changed.append(label)
                threat["risk_rating"] = rebuilt
        return ThreatRatings(model=rated, changed=tuple(changed), failed=failed)

    def _latest_documents(
        self,
        filter: AssessmentFilter,
        repository_ids: Collection[UUID],
        artifact: type[A],
        as_of: datetime | None = None,
    ) -> tuple[int, list[tuple[UUID, Assessment, A]]]:
        """How many repositories have an assessment in scope on their default line, and the
        `artifact` documents their latest one holds, with the repository each belongs to."""
        if self._publisher is None:
            raise ConfigError(f"reading {artifact.schema} documents needs the publisher")
        held = self._held(as_of or self._clock.now(), filter, repository_ids)
        latest = {d[-1].id: r for (r, _), (d, _) in held.items() if d}
        assessments = [d[-1] for d, _ in held.values() if d]
        documents = []
        for a, row in self._log.documents(assessments, [artifact.schema]):
            assert row.id is not None
            documents.append((latest[a.id], a, self._publisher.read(row.id, artifact)))
        return len(latest), documents

    def coverage(self, filter: AssessmentFilter, repository_ids: Collection[UUID]) -> Coverage:
        """What the repositories' latest default-line audits (`filter.kind`, secure-code when
        None; degraded runs included) say they could not examine, as gap families."""
        if self._publisher is None:
            raise ConfigError("coverage needs the report reader (Context wires it)")
        scope = filter.model_copy(update={"kind": filter.kind or AssessmentKind.SECURE_CODE})
        latest, documents = self._latest_documents(scope, repository_ids, ReportArtifact)
        families: dict[tuple[str, str], list[tuple[UUID, ReportGap]]] = defaultdict(list)
        for repository_id, _, doc in documents:
            for gap in report_gaps(json.loads(doc.payload)):
                families[gap.tool, gap.system].append((repository_id, gap))
        gaps = [
            CoverageGap(
                tool=tool,
                system=system,
                repositories=len(repos := list(dict.fromkeys(r for r, _ in found))),
                items=sum(counts)
                if (counts := [g.count for _, g in found if g.count is not None])
                else None,
                signals=dict(Counter(g.signal for _, g in found)),
                example_repository_ids=tuple(repos[:MAX_GAP_EXAMPLES]),
            )
            for (tool, system), found in families.items()
        ]
        gaps.sort(key=lambda g: (-g.repositories, g.tool, g.system))
        return Coverage(
            examined=len({a.id for _, a, _ in documents}), total=latest, gaps=tuple(gaps)
        )

    def privileges(
        self,
        filter: AssessmentFilter,
        repository_ids: Collection[UUID],
        as_of: datetime | None = None,
    ) -> list[PrivilegeProfile]:
        """Each repository's declared privileges, from its latest completed default-line
        priv-profile by `as_of` (else now; `filter.status` overrides completed)."""
        if filter.kind is not None and filter.kind not in self._kind_spellings(
            AssessmentKind.PRIV_PROFILE_CANONICAL
        ):
            raise ValidationError(f"privileges reads priv-profile assessments, not {filter.kind}")
        scope = filter.model_copy(
            update={
                "kind": AssessmentKind.PRIV_PROFILE_CANONICAL,
                "status": filter.status or ASSESSMENT_COMPLETED,
            }
        )
        _, documents = self._latest_documents(scope, repository_ids, PrivProfileArtifact, as_of)
        return [
            PrivilegeProfile.of(a, repository_id, json.loads(doc.payload))
            for repository_id, a, doc in documents
        ]


def _reason(err: Any) -> str:
    msg = str(err["msg"]).removeprefix("Value error, ")
    return f"{'.'.join(map(str, err['loc']))}: {msg}" if err["loc"] else msg
