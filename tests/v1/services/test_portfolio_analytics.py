from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.test_insight import context as context
from tests.v1.services.test_insight import engine as engine
from traust_core.v1.context import Context
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.artifacts import PrivProfileArtifact, ThreatModelArtifact
from traust_core.v1.models.assessment import (
    Assessment,
    AssessmentKind,
    Population,
    PrivilegeProfile,
)
from traust_core.v1.models.common import Page
from traust_core.v1.models.corpus import CorpusRegistry, CorpusSubject
from traust_core.v1.models.dependencies import InternalCoupling
from traust_core.v1.models.insight import ViewFilter
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import Repository
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.portfolio_analytics import CrownJewelSignal, IacClass
from traust_core.v1.models.values import GitSha
from traust_core.v1.providers.base import Acquisition, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.sources import RepoInfo, RepoTree, SourceError, SourceProvider
from traust_core.v1.rendering import MarkdownRenderer
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import AssessmentLog, PublishSpec, PublishSpecs
from traust_core.v1.services.portfolio import PortfolioPolicy
from traust_core.v1.services.portfolio_analytics import (
    CrownJewelDraftView,
    IacCensusView,
    OrganizationIndexView,
    PortfolioAnalyticsService,
    classify_iac_paths,
    privilege_tier,
)

AS_OF = T0 + timedelta(days=2)
FIXTURES = Path(__file__).parents[2] / "fixtures" / "assessments"


def analytics(context: Context, sources: SourceProvider | None = None) -> PortfolioAnalyticsService:
    services = context.services()
    return PortfolioAnalyticsService(
        services.portfolio,
        services.assessment,
        services.findings,
        services.artifacts,
        sources or Mock(spec=SourceProvider),
        services.exposure,
        PortfolioPolicy(),
        FixedClock(AS_OF),
        hosts={"github.com": "github", "gitlab.com": "gitlab"},
    )


def test_weighted_unsigned_proposal_joins_ids_and_uses_default_line_findings(
    context: Context,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        library = seed.repository(url="https://github.com/example/library")
        consumer = seed.repository(url="https://github.com/example/consumer")
        duplicate_slug = seed.repository(url="https://github.com/another/library")
        ref = seed.repository_ref(library, is_default=True)
        sbom = seed.sbom()
        consumer_ref = seed.repository_ref(consumer, is_default=True, manifest_sbom_id=sbom.id)
        another_sbom = seed.sbom()
        other_ref = seed.repository_ref(
            duplicate_slug, is_default=True, manifest_sbom_id=another_sbom.id
        )
        package = seed.package(source_repository_id=library.id)
        seed.dependency(sbom, package)
        seed.dependency(another_sbom, package)
        audit = seed.assessment(ref, kind=AssessmentKind.SECURE_CODE_CANONICAL)
        second_audit = seed.assessment(consumer_ref, kind=AssessmentKind.SECURE_CODE_CANONICAL)
        seed.assessment(other_ref, kind=AssessmentKind.SECURE_CODE_CANONICAL)
        critical = seed.finding(library)
        seed.occurrence(critical, audit, severity="critical")
        high = seed.finding(consumer)
        seed.occurrence(high, second_audit, severity="high")
        branch = seed.repository_ref(duplicate_slug, name="feature", sha="b" * 40)
        branch_audit = seed.assessment(branch, kind=AssessmentKind.SECURE_CODE_CANONICAL)
        seed.occurrence(seed.finding(duplicate_slug), branch_audit, severity="critical")
        owner = seed.team(name="Platform")
        seed.ownership(library, owner)
        threat_assessment = seed.assessment(ref, kind=AssessmentKind.THREAT_MODEL_CANONICAL)
        profile_assessment = seed.assessment(ref, kind=AssessmentKind.PRIV_PROFILE_CANONICAL)
        uow.commit()
    publisher = context.artifact_publisher(
        PublishSpecs(PublishSpec(ThreatModelArtifact), PublishSpec(PrivProfileArtifact))
    )
    threat = ThreatModelArtifact.parse((FIXTURES / "widget-threat-model.json").read_bytes())
    profile_body = json.loads((FIXTURES / "widget-operator-priv-profile.json").read_text())
    profile_body["summary"]["privileged_or_host_workloads"] = 1
    profile = PrivProfileArtifact.from_document(profile_body)
    for assessment, doc in ((threat_assessment, threat), (profile_assessment, profile)):
        published = publisher.publish_artifact(doc)
        with SqlTraustUnitOfWork(engine) as uow:
            AssessmentLog(uow).attach(assessment.id, published.artifact_id, sha256_hex(doc.payload))
            uow.commit()

    service = analytics(context)
    registry = CorpusRegistry(
        subjects=(
            CorpusSubject(
                subject_id="library",
                tree="library",
                ownership="owned",
                business_unit="Platform",
                repo_url=library.url,
            ),
            CorpusSubject(
                subject_id="upstream",
                tree="upstream",
                ownership="upstream",
                business_unit="Other",
                repo_url=duplicate_slug.url,
            ),
        )
    ).to_artifact()
    monkeypatch.setattr(service._portfolio, "corpus_registry", lambda as_of: registry)
    draft = service.crown_jewel_draft(ViewFilter(as_of=AS_OF), tier1_size=1)
    rows = {r.repository_id: r for r in draft.repositories}
    assert draft.weights_effective == pytest.approx(
        {"fanin": 0.35, "threat": 0.25, "priv": 0.20, "findings": 0.20}
    )
    assert rows[library.id].score == pytest.approx(95.14)
    assert rows[library.id].components.fanin == 2
    assert rows[library.id].components.threat_impact == pytest.approx(7.25 / 9)
    assert rows[library.id].components.privilege_tier == 3
    assert rows[library.id].components.open_critical == 1
    assert rows[consumer.id].components.open_high == 1
    assert rows[duplicate_slug.id].components.open_critical == 0
    assert rows[duplicate_slug.id].components.fanin is None
    assert rows[library.id].owners == ("Platform",)
    assert rows[library.id].ownership_classes == ("owned",)
    assert rows[duplicate_slug.id].ownership_classes == ("upstream",)
    assert rows[consumer.id].ownership_gap is True
    assert [r.repository_id for r in draft.tiers.tier1] == [library.id]
    assert [r.repository_id for r in draft.tiers.tier2] == [consumer.id]
    assert draft.tiers.watch == ()
    assert draft.dispatch_allowed is False
    assert draft.status == "draft-unsigned"
    assert draft.model_dump(mode="json")["dispatch_allowed"] is False
    assert service.crown_jewel_draft(ViewFilter(as_of=AS_OF), 1) == draft
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.repositories.get(library.id) == library
        assert uow.repository_refs.get(ref.id) == ref
    report = CrownJewelDraftView(service).report(draft, AS_OF)
    assert report.sections[0].body == report.sections[-1].body == draft.notice
    assert report.sections[2].table.rows[0][1] == library.url


def test_absent_and_unreadable_sources_renormalize_without_inventing_measurements(
    context: Context,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        ref = seed.repository_ref(repo, is_default=True)
        audit = seed.assessment(ref, kind=AssessmentKind.SECURE_CODE_CANONICAL)
        seed.occurrence(seed.finding(repo), audit, severity="high")
        uow.commit()
    service = analytics(context)

    def unavailable(*args: object) -> object:
        raise ConfigError("manifest source unavailable")

    monkeypatch.setattr(service._exposure, "internal_coupling", unavailable)
    draft = service.crown_jewel_draft(ViewFilter(as_of=AS_OF))
    assert draft.weights_effective == {CrownJewelSignal.FINDINGS: 1.0}
    [row] = draft.repositories
    assert row.score == 100
    assert row.components.fanin is None
    assert row.components.open_threats is None
    assert row.components.privilege_tier is None
    assert row.gaps == (CrownJewelSignal.FANIN, CrownJewelSignal.THREAT, CrownJewelSignal.PRIVILEGE)
    assert [(s.signal, s.available) for s in draft.sources] == [
        (CrownJewelSignal.FANIN, False),
        (CrownJewelSignal.THREAT, False),
        (CrownJewelSignal.PRIVILEGE, False),
        (CrownJewelSignal.FINDINGS, True),
    ]


@pytest.mark.parametrize("size", [0, -1, 101])
def test_draft_rejects_invalid_pilot_sizes(context: Context, size: int) -> None:
    with pytest.raises(ValidationError):
        analytics(context).crown_jewel_draft(ViewFilter(), size)


def test_empty_fleet_remains_unsigned_and_does_not_divide_by_zero(context: Context) -> None:
    draft = analytics(context).crown_jewel_draft(ViewFilter(as_of=AS_OF))
    assert draft.universe_repositories == draft.scored_repositories == 0
    assert draft.weights_effective == {}
    assert draft.repositories == draft.tiers.tier1 == draft.tiers.tier2 == draft.tiers.watch == ()
    assert draft.dispatch_allowed is False


def test_tier_boundaries_are_twenty_eighty_and_one_hundred_with_stable_url_ties() -> None:
    repositories = tuple(
        Repository(id=UUID(int=n + 1), url=f"https://github.com/example/repo-{n:03}", public=True)
        for n in range(205)
    )
    portfolio, assessment, findings, artifacts, sources, exposure = (Mock() for _ in range(6))
    portfolio.list_repositories.return_value = Page(items=tuple(reversed(repositories)))
    portfolio.list_owners.return_value = []
    portfolio.corpus_registry.return_value = None
    assessment.population.return_value = Population(as_of=AS_OF, rows=())
    assessment.privileges.return_value = []
    assessment.threats.return_value = Page(items=())
    findings.all.return_value = []
    exposure.internal_coupling.return_value = [
        InternalCoupling(
            repository_id=r.id,
            packages=(),
            consumer_repository_ids=(uuid4(),),
            consumer_repository_ref_ids=(),
        )
        for r in repositories
    ]
    service = PortfolioAnalyticsService(
        portfolio,
        assessment,
        findings,
        artifacts,
        sources,
        exposure,
        PortfolioPolicy(),
        FixedClock(AS_OF),
        hosts={},
    )
    draft = service.crown_jewel_draft(ViewFilter())
    assert tuple(
        len(rows)
        for rows in (
            draft.tiers.tier1,
            draft.tiers.tier2,
            draft.tiers.watch,
        )
    ) == (20, 80, 100)
    assert [r.rank for r in draft.tiers.tier1] == list(range(1, 21))
    assert [r.rank for r in draft.tiers.tier2] == list(range(21, 101))
    assert [r.rank for r in draft.tiers.watch] == list(range(101, 201))
    assert [r.repository_url for r in draft.repositories] == [r.url for r in repositories]
    assert draft.scored_repositories == 205


@pytest.mark.parametrize(
    ("changes", "tier"),
    [
        ({}, 1),
        ({"flags": {"secrets_access": 1}}, 2),
        ({"scc_requests": ("restricted",)}, 2),
        ({"flags": {"rbac_write": 1}}, 3),
        ({"privileged_workloads": 1}, 3),
        ({"privileged_sccs": ("privileged",)}, 3),
    ],
)
def test_privilege_tiers_preserve_cluster_escalation_and_sccs(
    changes: dict[str, object],
    tier: int,
) -> None:
    profile = PrivilegeProfile(
        assessment_id=uuid4(), repository_id=uuid4(), workloads=1, rbac_rules=0, **changes
    )
    assert privilege_tier(profile) == tier


def test_iac_path_classes_do_not_treat_openshift_templates_or_helm_as_lane_triggers() -> None:
    classes = classify_iac_paths(
        [
            "main.tf",
            "env.tfvars",
            "modules/a.tf.json",
            "cloudformation/stack.yaml",
            "cfn/stack.json",
            "arm-templates/stack.json",
            "arm/stack.json",
            "azuredeploy-prod.json",
            "main.bicep",
            "chart/Chart.yaml",
            "Dockerfile.dev",
            "openshift/app.template.yaml",
            "vendor/main.tf",
            "node_modules/main.bicep",
            "main.tf",
        ]
    )
    assert classes.terraform == ("env.tfvars", "main.tf", "modules/a.tf.json")
    assert classes.cloudformation == ("cfn/stack.json", "cloudformation/stack.yaml")
    assert classes.arm_bicep == (
        "arm-templates/stack.json",
        "arm/stack.json",
        "azuredeploy-prod.json",
        "main.bicep",
    )
    assert classes.helm_chart == ("chart/Chart.yaml",)
    assert classes.dockerfile == ("Dockerfile.dev",)
    assert classes.lane_files() == 9
    assert classify_iac_paths(["Chart.yaml", "Dockerfile", "app.template.json"]).lane_files() == 0


def test_iac_census_accounts_for_unobserved_hosts_and_ranks_only_missing_baselines(
    context: Context,
    engine: Engine,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repos = [
            seed.repository(url=url)
            for url in (
                "https://github.com/example/critical",
                "https://github.com/example/baselined",
                "https://gitlab.com/example/private",
                "https://unknown.example/org/a",
                "https://github.com/example/helm-only",
                "https://github.com/example/never-audited",
            )
        ]
        refs = [seed.repository_ref(r, is_default=True) for r in repos]
        for ref in refs[:-1]:
            seed.assessment(ref, kind=AssessmentKind.SECURE_CODE_CANONICAL)
        audit = seed.assessment(refs[0], kind=AssessmentKind.SECURE_CODE_CANONICAL)
        for _ in range(5):
            seed.occurrence(seed.finding(repos[0]), audit, severity="high")
        seed.assessment(refs[1], kind=AssessmentKind.CLOUD_CONFIG_CANONICAL)
        uow.commit()
    provider = Mock(spec=SourceProvider)
    acquisition = Acquisition(provider="fixture", acquired_at=AS_OF)

    def info(url: object) -> Result[RepoInfo]:
        if str(url).startswith("https://gitlab.com/"):
            raise SourceError("private forge unavailable", ComparisonStatus.UNREACHABLE)
        return Result(RepoInfo(repo=url, head=GitSha.parse("a" * 40)), acquisition)

    def tree(url: object, sha: str) -> Result[RepoTree]:
        assert sha == "a" * 40
        paths = (
            ("Chart.yaml", "Dockerfile")
            if str(url).endswith("helm-only")
            else (
                "main.tf",
                "cloudformation/stack.yaml",
                "arm/stack.json",
            )
        )
        return Result(RepoTree(paths=paths, truncated=str(url).endswith("critical")), acquisition)

    provider.info.side_effect = info
    provider.tree.side_effect = tree
    service = analytics(context, provider)
    census = service.iac_census(ViewFilter(as_of=AS_OF))
    assert census.population == 5
    assert census.observed == 3
    assert census.never_audited == (repos[-1].id,)
    assert census.unobserved_by_host == {"gitlab.com": 1, "unknown.example": 1}
    assert census.by_class == {
        IacClass.TERRAFORM: 2,
        IacClass.CLOUDFORMATION: 2,
        IacClass.ARM_BICEP: 2,
        IacClass.HELM_CHART: 1,
        IacClass.DOCKERFILE: 1,
    }
    [candidate] = census.worklist
    assert candidate.repository_id == repos[0].id
    assert candidate.risk_tier == "P0"
    assert candidate.open_critical_high == 5
    assert candidate.truncated is True
    assert candidate.has_cloud_config_baseline is False
    by_id = {r.repository_id: r for r in census.repositories}
    assert by_id[repos[1].id].has_cloud_config_baseline is True
    assert by_id[repos[2].id].classification is None
    assert by_id[repos[3].id].classification is None
    report = IacCensusView(service).report(census, AS_OF)
    assert report.sections[1].table.rows[0][1] == repos[0].url
    assert dict(report.sections[3].table.rows) == {"gitlab.com": "1", "unknown.example": "1"}


def test_organization_index_inverts_source_namespaces_across_products_and_keeps_links(
    context: Context,
    engine: Engine,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        a = seed.repository(url="https://github.com/example/a")
        b = seed.repository(url="https://github.com/example/b")
        nested = seed.repository(url="https://gitlab.com/group/subgroup/a")
        refs = [seed.repository_ref(r, is_default=True) for r in (a, b, nested)]
        products = [seed.product(slug=slug) for slug in ("alpha", "beta")]
        for product, ref in zip(products, refs, strict=False):
            seed.component(seed.release(product), ref)
        audits = [seed.assessment(ref, kind=AssessmentKind.SECURE_CODE_CANONICAL) for ref in refs]
        artifacts = [
            seed.artifact(audit, uri=f"https://reports.example/{n}.json")
            for n, audit in enumerate(audits)
        ]
        seed.assessment(refs[0], occurred_at=AS_OF + timedelta(days=1))
        uow.commit()
    service = analytics(context)
    index = service.organization_index(ViewFilter(as_of=AS_OF))
    assert [(o.host, o.namespace) for o in index.organizations] == [
        ("github.com", "example"),
        ("gitlab.com", "group/subgroup"),
    ]
    assert [r.repository_id for r in index.organizations[0].repositories] == [a.id, b.id]
    held = index.organizations[0].repositories[0].assessments
    assert [a.assessment.id for a in held] == [audits[0].id]
    assert held[0].artifacts[0].artifact_id == artifacts[0].id
    assert held[0].artifacts[0].uri == "https://reports.example/0.json"
    assert held[0].artifacts[0].digest == artifacts[0].digest
    scoped = service.organization_index(ViewFilter(as_of=AS_OF, product_ids=(products[1].id,)))
    assert [r.repository_id for r in scoped.organizations[0].repositories] == [b.id]
    assert scoped.unlocated == ()
    text = MarkdownRenderer().render(OrganizationIndexView(service).report(index, AS_OF)).decode()
    assert "https://reports.example/0.json" in text
    assert "https://reports.example/1.json" in text


def test_iac_worklist_prioritizes_externality_then_visibility_then_risk(
    context: Context,
    engine: Engine,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repositories = [
            seed.repository(url=f"https://github.com/example/{name}", public=public)
            for name, public in (
                ("public-external", True),
                ("private-external", False),
                ("public-internal", True),
                ("private-internal", False),
                ("public-internal-risky", True),
            )
        ]
        refs = [seed.repository_ref(r, is_default=True) for r in repositories]
        audits = [seed.assessment(ref, kind=AssessmentKind.SECURE_CODE_CANONICAL) for ref in refs]
        release = seed.release()
        seed.component(release, refs[0])
        seed.component(release, refs[1])
        for _ in range(5):
            seed.occurrence(seed.finding(repositories[4]), audits[4], severity="high")
        uow.commit()
    provider = Mock(spec=SourceProvider)
    acquired = Acquisition(provider="fixture", acquired_at=AS_OF)
    provider.info.side_effect = lambda url: Result(
        RepoInfo(repo=url, head=GitSha.parse("a" * 40)), acquired
    )
    provider.tree.return_value = Result(RepoTree(paths=("main.tf",), truncated=False), acquired)
    census = analytics(context, provider).iac_census(ViewFilter(as_of=AS_OF))
    assert [r.repository_id for r in census.worklist] == [
        repositories[n].id for n in (0, 1, 4, 2, 3)
    ]
    assert [r.risk_tier for r in census.worklist] == ["P2", "P2", "P0", "P2", "P2"]


def test_privilege_projection_keeps_an_unnamed_privileged_scc_as_tier_three() -> None:
    assessment = Assessment(
        id=uuid4(),
        repository_ref_id=uuid4(),
        kind=AssessmentKind.PRIV_PROFILE_CANONICAL,
        status="completed",
        assessor="fixture",
        assessor_version="1",
        occurred_at=AS_OF,
    )
    profile = PrivilegeProfile.of(
        assessment,
        uuid4(),
        {
            "summary": {"workloads": 0, "rbac_rules": 0},
            "sccs_shipped": [{"name": None, "allowPrivilegedContainer": True}],
        },
    )
    assert profile.privileged_sccs == (None,)
    assert privilege_tier(profile) == 3
