"""Integration tests for component PURL monorepo audits, reuse, and lease target binding."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from tests.fixtures.component_purl.builder import (
    build_langchain_fixture,
    build_pi_fixture,
    build_spring_fixture,
    build_tenant_cache_fixture,
)
from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.errors import ForbiddenError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import RunManifestArtifact, SecurityAuditArtifact
from traust_core.v1.models.assessment import AssessmentFilter, AssessmentKind, DiffRequest
from traust_core.v1.models.common import PageRequest, Provenance
from traust_core.v1.models.component_target import (
    ComponentTarget,
    ComponentTargetRequest,
    ComponentTargetStrategy,
)
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.operations import (
    AssetName,
    OrderRequest,
    RecordingStartScope,
    WorkerId,
)
from traust_core.v1.models.values import GitSha, LocalRepoUrl
from traust_core.v1.models.vocabulary import ActorKind, SourceType
from traust_core.v1.providers.checkout import GitCheckout
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.local import LocalCheckout
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.sources import CheckoutRequest
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    AssessmentLog,
    PublishSpec,
    PublishSpecs,
)
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.component_target import ComponentTargetResolver
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.identity import IdentityPolicy
from traust_core.v1.services.findings.intake import FindingIntake
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.findings.rating import RatingConfig, RatingPolicy
from traust_core.v1.services.findings.review import FindingReview, ReviewPolicy
from traust_core.v1.services.findings.service import FindingService, FindingViewQuery
from traust_core.v1.services.findings.taxonomy import TaxonomyPolicy
from traust_core.v1.services.lint import Lint
from traust_core.v1.services.operations import OpsService
from traust_core.v1.services.portfolio import Inventory
from traust_core.v1.services.reporting import ReportingService

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed


def _report_doc(
    *,
    repo_url: str,
    commit: str,
    target: ComponentTarget | None,
    findings: list[dict[str, Any]] | None = None,
    title: str = "Component PURL Security Audit",
) -> SecurityAuditArtifact:
    items = findings or []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    by_sev: dict[str, list[str]] = {k: [] for k in counts}
    for f in items:
        counts[f["severity"]] += 1
        by_sev[f["severity"]].append(f["id"])
    meta: dict[str, Any] = {
        "date": "2026-11-22",
        "scope": (
            f"Component PURL audit of {target.purl} ({target.module_path})"
            if target is not None
            else "Whole repository security audit"
        ),
        "repository": repo_url,
        "commit": commit,
        "audit_profile": "code",
    }
    if target is not None:
        meta["target"] = target.model_dump(mode="json", exclude_none=True)
    doc = {
        "title": title,
        "metadata": meta,
        "executive_summary": {
            "prose": "Fresh initial source audit at the pinned commit with cross-module evidence.",
            "severity_counts": counts,
        },
        "severity_criteria": [
            {"level": "critical", "definition": "Unauthenticated remote code execution or bypass."},
            {"level": "high", "definition": "Cross-tenant data exposure or privilege escalation."},
            {"level": "medium", "definition": "Scoped weakness requiring extra preconditions."},
            {"level": "low", "definition": "Defense-in-depth hardening improvement."},
        ],
        "findings": items,
        "findings_summary": [
            {"severity": sev, "count": counts[sev], "finding_ids": by_sev[sev]}
            for sev in ("critical", "high", "medium", "low")
        ],
        "remediation_roadmap": [
            {
                "priority": "p1" if items else "p3",
                "addresses": [items[0]["id"]] if items else ["NONE"],
                "action": "Namespace cache keys by tenant identifier across shared cache callers.",
                "effort": "s",
            }
        ],
    }
    return SecurityAuditArtifact.parse(json.dumps(doc).encode("utf-8"))


class _FixtureCheckouts:
    def __init__(self, repo_url: str, local_path: Path) -> None:
        self._repo_url = repo_url
        self._origin = LocalRepoUrl.parse(local_path.as_uri())
        self._local = LocalCheckout(ProcessRunner(allowed=("git",)), FixedClock(T0))

    def checkout(self, request: CheckoutRequest) -> Any:
        assert str(request.repo) == self._repo_url
        return self._local.checkout(
            CheckoutRequest(
                repo=self._origin,
                ref=GitSha.parse(str(request.ref)),
                shared=request.shared,
                writable=request.writable,
            )
        )

    def release(self, workspace: Any) -> None:
        self._local.release(workspace)


def _stack(
    uow: SqlTraustUnitOfWork, repository_id: UUID, repo_url: str, local_path: Path
) -> tuple[AssessmentService, OpsService, Principal]:
    objects = InMemoryObjectStore()
    clock = FixedClock(T0)
    runner = Principal(
        identity="sci-worker",
        display="SCI Worker",
        kind=ActorKind.MACHINE,
        verified_by="oidc",
    )
    ops = OpsService(
        uow,
        clock,
        ArtifactPublisher(PublishSpecs(PublishSpec(RunManifestArtifact)), objects, uow),
        recording_assets={"assessment": (AssetName("sci_scan"),)},
        recording_starts=(
            RecordingStartScope(
                principal=runner.ref,
                assets=(AssetName("sci_scan"),),
                repository_ids=(repository_id,),
            ),
        ),
        inventory=Inventory(uow),
        assessments=AssessmentLog(uow),
        checkouts=_FixtureCheckouts(repo_url, local_path),
        component_targets=ComponentTargetResolver(GitCheckout(ProcessRunner(allowed=("git",)))),
    )
    intake = FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy(), objects=objects)
    precedents = FindingPrecedents(uow)
    rating = RatingPolicy(RatingConfig())
    review = ReviewPolicy("test-salt")
    decisions = FindingDecisions(
        uow, None, Lint({}), precedents, clock=clock, objects=objects, review=review, rating=rating
    )
    findings = FindingService(
        uow,
        intake,
        decisions,
        FindingReview(uow, review, decisions, FindingViewQuery(rating, objects)),
        precedents,
        rating,
        objects,
    )
    assessments = AssessmentService(
        uow,
        intake=intake,
        clock=clock,
        git=GitCheckout(ProcessRunner(allowed=("git",))),
        publisher=ArtifactPublisher(PublishSpecs(PublishSpec(SecurityAuditArtifact)), objects, uow),
        findings=findings,
        recording=ops,
    )
    return assessments, ops, runner


def test_two_child_purls_at_one_commit_reuse_context_and_stay_distinct(
    uow: SqlTraustUnitOfWork, seed: Seed, tmp_path: Path
) -> None:
    spring = build_spring_fixture(tmp_path)
    repo = seed.repository(url=spring.repo_url)
    ref = seed.repository_ref(repository_id=repo.id, name="v7.1.0", kind="tag", sha=spring.commit)
    assessments, ops, runner = _stack(uow, repo.id, spring.repo_url, spring.path)

    local = LocalCheckout(ProcessRunner(allowed=("git",)), FixedClock(T0))
    resolver = ComponentTargetResolver(GitCheckout(ProcessRunner(allowed=("git",))))
    origin = LocalRepoUrl.parse(spring.path.as_uri())
    ws_a = local.checkout(
        CheckoutRequest(repo=origin, ref=GitSha.parse(spring.commit), shared=True)
    ).data
    ws_b = local.checkout(
        CheckoutRequest(repo=origin, ref=GitSha.parse(spring.commit), shared=True)
    ).data
    assert ws_a.path == ws_b.path

    target_a = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:maven/org.springframework/spring-beans@7.1.0",
            repository=spring.repo_url,
            commit=spring.commit,
        ),
        ws_a.path,
    )
    target_b = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:maven/org.springframework/spring-context@7.1.0",
            repository=spring.repo_url,
            commit=spring.commit,
        ),
        ws_b.path,
    )
    order_a = ops.start(
        OrderRequest(
            asset=AssetName("sci_scan"),
            priority=1,
            repository_id=repo.id,
            target_purl=target_a.purl,
            target_sha=target_a.commit,
            target_module_path=target_a.module_path,
        ),
        runner,
        WorkerId(runner.ref),
        timedelta(minutes=30),
    )
    order_b = ops.start(
        OrderRequest(
            asset=AssetName("sci_scan"),
            priority=1,
            repository_id=repo.id,
            target_purl=target_b.purl,
            target_sha=target_b.commit,
            target_module_path=target_b.module_path,
        ),
        runner,
        WorkerId(runner.ref),
        timedelta(minutes=30),
    )
    assert order_a.id != order_b.id

    rec_a = assessments.record_secure_code(
        _report_doc(
            repo_url=spring.repo_url,
            commit=spring.commit,
            target=target_a,
            title="Spring Beans Security Audit",
        ),
        ref.id,
        "1.0.0",
        Provenance(run_id=order_a.id, source=SourceType.VULN_SCAN_REPORT, occurred_at=T0),
        run_order_id=order_a.id,
        lease_generation=order_a.lease_generation,
        principal=runner,
    )
    rec_b = assessments.record_secure_code(
        _report_doc(
            repo_url=spring.repo_url,
            commit=spring.commit,
            target=target_b,
            title="Spring Context Security Audit",
        ),
        ref.id,
        "1.0.0",
        Provenance(run_id=order_b.id, source=SourceType.VULN_SCAN_REPORT, occurred_at=T0),
        run_order_id=order_b.id,
        lease_generation=order_b.lease_generation,
        principal=runner,
    )

    assert rec_a.assessment_id != rec_b.assessment_id
    assert rec_a.artifact_id != rec_b.artifact_id
    latest_a = assessments.latest_recorded(
        repo.id, AssessmentKind.SECURE_CODE_CANONICAL, target_purl=target_a.purl
    )
    latest_b = assessments.latest_recorded(
        repo.id, AssessmentKind.SECURE_CODE_CANONICAL, target_purl=target_b.purl
    )
    assert latest_a.id == rec_a.assessment_id and latest_a.target_purl == target_a.purl
    assert latest_b.id == rec_b.assessment_id and latest_b.target_purl == target_b.purl

    # Whole-repository latest_recorded must NEVER be shadowed by component-PURL audits.
    with pytest.raises(NotFoundError):
        assessments.latest_recorded(repo.id, AssessmentKind.SECURE_CODE_CANONICAL)

    # Filtered list returns only the requested child PURL.
    page_a = assessments.list(
        AssessmentFilter(
            repository_ref_id=ref.id,
            kind=AssessmentKind.SECURE_CODE_CANONICAL,
            target_purl=target_a.purl,
        ),
        PageRequest(limit=10),
    )
    assert [row.id for row in page_a.items] == [rec_a.assessment_id]

    local.release(ws_a)
    assert ws_b.path.is_dir()
    local.release(ws_b)
    assert not ws_b.path.exists()


def test_lease_rejects_valid_sibling_b_report_on_sibling_a_order(
    uow: SqlTraustUnitOfWork, seed: Seed, tmp_path: Path
) -> None:
    """Regression: a valid report for sibling B at the exact same (repo, SHA) must be rejected
    under sibling A's recording lease, and whole-repo/component orders must never cross."""
    pi = build_pi_fixture(tmp_path)
    repo = seed.repository(url=pi.repo_url)
    ref = seed.repository_ref(repository_id=repo.id, name="v1.6.0", kind="tag", sha=pi.commit)
    assessments, ops, runner = _stack(uow, repo.id, pi.repo_url, pi.path)
    resolver = ComponentTargetResolver(GitCheckout(ProcessRunner(allowed=("git",))))

    target_a = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:npm/%40earendil-works/pi-ai@1.6.0",
            repository=pi.repo_url,
            commit=pi.commit,
        ),
        pi.path,
    )
    target_b = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:npm/%40earendil-works/pi-coding-agent@1.6.0",
            repository=pi.repo_url,
            commit=pi.commit,
        ),
        pi.path,
    )
    order_a = ops.start(
        OrderRequest(
            asset=AssetName("sci_scan"),
            priority=1,
            repository_id=repo.id,
            target_purl=target_a.purl,
            target_sha=target_a.commit,
            target_module_path=target_a.module_path,
        ),
        runner,
        WorkerId(runner.ref),
        timedelta(minutes=30),
    )

    # 1. Valid sibling B report submitted against sibling A's leased order -> ForbiddenError.
    with pytest.raises(ForbiddenError, match="does not match leased order target"):
        assessments.record_secure_code(
            _report_doc(repo_url=pi.repo_url, commit=pi.commit, target=target_b),
            ref.id,
            "1.0.0",
            Provenance(run_id=order_a.id, source=SourceType.VULN_SCAN_REPORT, occurred_at=T0),
            run_order_id=order_a.id,
            lease_generation=order_a.lease_generation,
            principal=runner,
        )

    # 2. Valid whole-repo report (no metadata.target) submitted against component order -> refused.
    with pytest.raises(ForbiddenError, match=r"has no metadata\.target"):
        assessments.record_secure_code(
            _report_doc(repo_url=pi.repo_url, commit=pi.commit, target=None),
            ref.id,
            "1.0.0",
            Provenance(run_id=order_a.id, source=SourceType.VULN_SCAN_REPORT, occurred_at=T0),
            run_order_id=order_a.id,
            lease_generation=order_a.lease_generation,
            principal=runner,
        )

    # 3. Wrong module_path with same PURL and SHA -> refused.
    tampered_path = target_a.model_copy(update={"module_path": "packages/coding-agent"})
    with pytest.raises(ForbiddenError, match="does not match leased order target"):
        assessments.record_secure_code(
            _report_doc(repo_url=pi.repo_url, commit=pi.commit, target=tampered_path),
            ref.id,
            "1.0.0",
            Provenance(run_id=order_a.id, source=SourceType.VULN_SCAN_REPORT, occurred_at=T0),
            run_order_id=order_a.id,
            lease_generation=order_a.lease_generation,
            principal=runner,
        )

    # 3b. Direct AssessmentService.record(..., run_order_id=order_a.id) also enforces target
    # binding under OpsService.bound, preventing sibling-B swap through the CLI record door.
    with pytest.raises(ForbiddenError, match="does not match leased order target"):
        assessments.record(
            _report_doc(repo_url=pi.repo_url, commit=pi.commit, target=target_b),
            ref.id,
            AssessmentKind.SECURE_CODE_CANONICAL,
            "skill:secure-code-audit",
            "1.0.0",
            Provenance(run_id=order_a.id, source=SourceType.VULN_SCAN_REPORT, occurred_at=T0),
            run_order_id=order_a.id,
            worker=order_a.lease_holder,
            lease_generation=order_a.lease_generation,
        )

    # Nothing was persisted by any rejected attempt.
    assert assessments.list_for_order(order_a.id) == []
    # 4. Whole-repo order refuses a component-scoped report.
    whole_order = ops.start(
        OrderRequest(asset=AssetName("sci_scan"), priority=1, repository_id=repo.id),
        runner,
        WorkerId(runner.ref),
        timedelta(minutes=30),
    )
    with pytest.raises(ForbiddenError, match="whole-repository order refuses component report"):
        assessments.record_secure_code(
            _report_doc(repo_url=pi.repo_url, commit=pi.commit, target=target_a),
            ref.id,
            "1.0.0",
            Provenance(run_id=whole_order.id, source=SourceType.VULN_SCAN_REPORT, occurred_at=T0),
            run_order_id=whole_order.id,
            principal=runner,
            lease_generation=whole_order.lease_generation,
        )


def test_tenant_cache_three_location_report_and_langchain_resolution(
    uow: SqlTraustUnitOfWork, seed: Seed, tmp_path: Path
) -> None:
    vuln = build_tenant_cache_fixture(tmp_path, shared_cache=True)
    safe = build_tenant_cache_fixture(tmp_path, shared_cache=False)
    lc = build_langchain_fixture(tmp_path)
    resolver = ComponentTargetResolver(GitCheckout(ProcessRunner(allowed=("git",))))

    lc_target = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:pypi/langchain-core@1.8.4",
            repository=lc.repo_url,
            release_ref=lc.tag,
        ),
        lc.path,
    )
    assert lc_target.verification.strategy is ComponentTargetStrategy.PACKAGE_RELEASE

    vuln_target = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:npm/%40acme/cache-lib@1.2.0",
            repository=vuln.repo_url,
            commit=vuln.commit,
        ),
        vuln.path,
    )
    safe_target = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:npm/%40acme/cache-lib@1.2.0",
            repository=safe.repo_url,
            commit=safe.commit,
        ),
        safe.path,
    )
    assert vuln_target.module_path == safe_target.module_path == "packages/cache-lib"

    repo_v = seed.repository(url=vuln.repo_url)
    ref_v = seed.repository_ref(repository_id=repo_v.id, name="v1.2.0", kind="tag", sha=vuln.commit)
    assessments, ops, runner = _stack(uow, repo_v.id, vuln.repo_url, vuln.path)
    prepared = assessments.prepare(
        ref_v.id, AssessmentKind.SECURE_CODE_CANONICAL, component_target=vuln_target
    )
    assert prepared.component_target == vuln_target

    order = ops.start(
        OrderRequest(
            asset=AssetName("sci_scan"),
            priority=1,
            repository_id=repo_v.id,
            target_purl=vuln_target.purl,
            target_sha=vuln_target.commit,
            target_module_path=vuln_target.module_path,
        ),
        runner,
        WorkerId(runner.ref),
        timedelta(minutes=30),
    )
    finding = {
        "id": f"CACHE_LIB-{vuln.commit[:7]}-001",
        "title": "Cross-tenant cache key collision across shared ItemCache",
        "severity": "high",
        "kind": "vulnerability",
        "cwes": ["CWE-200"],
        "locations": [
            {
                "path": "packages/cache-lib/src/cache.ts",
                "lines": "3-4",
                "description": "ItemCache keys stored entries only by bare id.",
            },
            {
                "path": "packages/tenant-ids/src/id.ts",
                "lines": "3-7",
                "description": "nextTenantItemId produces tenant-local sequential IDs.",
            },
            {
                "path": "apps/api-server/src/server.ts",
                "lines": "3-8",
                "description": "GLOBAL_CACHE shares one ItemCache instance across tenants.",
            },
        ],
        "description": (
            "ItemCache keys values solely by bare ID while sibling @acme/tenant-ids generates "
            "tenant-local IDs and apps/api-server shares one GLOBAL_CACHE across all tenants."
        ),
        "remediation": "Key cache entries by (tenantId, id) or isolate caches per tenant.",
        "remediation_effort": "s",
    }
    report = _report_doc(
        repo_url=vuln.repo_url,
        commit=vuln.commit,
        target=vuln_target,
        findings=[finding],
    )
    # Content checks pass cleanly on the 3-location component report.
    report_path = tmp_path / "cache-lib-security-audit.json"
    report_path.write_bytes(report.payload)
    checked = ReportingService((), None).validate_reports(report_path)
    assert checked[0].passed, checked[0].errors

    recorded = assessments.record_secure_code(
        report,
        ref_v.id,
        "1.0.0",
        Provenance(run_id=order.id, source=SourceType.VULN_SCAN_REPORT, occurred_at=T0),
        run_order_id=order.id,
        lease_generation=order.lease_generation,
        principal=runner,
    )
    assert len(recorded.intake.findings) == 1
    with uow as tx:
        occs = tx.occurrences.list_for_assessment(recorded.assessment_id)
        assert len(occs) == 1
        locs = {loc.path for loc in tx.locations.list_for_occurrence(occs[0].id)}
    assert locs == {
        "packages/cache-lib/src/cache.ts",
        "packages/tenant-ids/src/id.ts",
        "apps/api-server/src/server.ts",
    }

    # Check reporting checks reject mismatched metadata.target commit.
    bad_payload = json.loads(report.payload)
    bad_payload["metadata"]["target"]["commit"] = "0" * 40
    bad_path = tmp_path / "bad-target-security-audit.json"
    bad_path.write_text(json.dumps(bad_payload), encoding="utf-8")
    bad_checked = ReportingService((), None).validate_reports(bad_path)
    assert not bad_checked[0].passed
    assert any("metadata.target.commit" in e for e in bad_checked[0].errors)

    # Confirm diff mode and mismatched commits are refused on component PURL prepare.
    with pytest.raises(ValidationError, match="not diff scans"):
        assessments.prepare(
            ref_v.id,
            AssessmentKind.SECURE_CODE_CANONICAL,
            diff=DiffRequest(checkout=vuln.path),
            component_target=vuln_target,
        )
    with pytest.raises(ValidationError, match="!= ref sha"):
        assessments.prepare(
            ref_v.id,
            AssessmentKind.SECURE_CODE_CANONICAL,
            component_target=vuln_target.model_copy(update={"commit": "0" * 40}),
        )

    # Explicit --baseline-assessment must also reject a same-repo component PURL audit.
    with pytest.raises(ValidationError, match="cannot anchor a whole-repository diff"):
        assessments.prepare(
            ref_v.id,
            AssessmentKind.SECURE_CODE_CANONICAL,
            diff=DiffRequest(
                checkout=vuln.path,
                baseline_assessment_id=recorded.assessment_id,
            ),
        )

    # Markdown rendering surfaces metadata.target provenance clearly.
    from traust_core.v1.services.reporting.report_markdown import render_report

    md = render_report(json.loads(report.payload))
    assert f"`{vuln_target.purl}`" in md
    assert f"`{vuln_target.module_path}`" in md
    assert f"`{vuln_target.verification.strategy.value}`" in md
