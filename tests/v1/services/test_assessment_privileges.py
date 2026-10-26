"""AssessmentService.privileges: each repository's declared privileges from its priv-profile.

Replaces the executive summary's load_least_priv and crown-jewel tiering's profile discovery
(globbing *-priv-profile.json): the profile is the recorded document of the latest assessment.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.artifacts import PrivProfileArtifact
from traust_core.v1.models.assessment import (
    ASSESSMENT_DEGRADED,
    AssessmentFilter,
    AssessmentKind,
    Permission,
    PrivilegeProfile,
)
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import Repository, RepositoryRef
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    AssessmentLog,
    PublishSpec,
    PublishSpecs,
)
from traust_core.v1.services.assessment import AssessmentService

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed

PROFILE = json.loads(
    (
        Path(__file__).parents[2] / "fixtures" / "assessments" / "widget-operator-priv-profile.json"
    ).read_text()
)
PRIV_PROFILE = AssessmentKind.PRIV_PROFILE_CANONICAL.value
NOW = T0 + timedelta(days=30)


def profile(workloads: int, **changes: Any) -> dict[str, Any]:
    return {**PROFILE, **changes, "summary": {**PROFILE["summary"], "workloads": workloads}}


class Profiles:
    def __init__(self, uow: SqlTraustUnitOfWork, seed: Seed) -> None:
        self.uow, self.seed = uow, seed
        self.publisher = ArtifactPublisher(
            PublishSpecs(PublishSpec(PrivProfileArtifact)), InMemoryObjectStore(), uow
        )
        self.service = AssessmentService(uow, clock=FixedClock(NOW), publisher=self.publisher)

    def repo(self) -> tuple[Repository, RepositoryRef, RepositoryRef]:
        repo = self.seed.repository()
        main = self.seed.repository_ref(repo, is_default=True)
        return repo, main, self.seed.repository_ref(repo, name="release-1", sha="b" * 40)

    def record(self, ref: RepositoryRef, day: int, doc: dict[str, Any], **kw: Any) -> UUID:
        values = {"kind": PRIV_PROFILE, "occurred_at": T0 + timedelta(days=day), **kw}
        a = self.seed.assessment(ref, **values)
        assert a.id is not None
        artifact = PrivProfileArtifact.from_document(doc)
        published = self.publisher.publish_artifact(artifact)
        AssessmentLog(self.uow).attach(a.id, published.artifact_id, sha256_hex(artifact.payload))
        return a.id


@pytest.fixture
def profiles(uow: SqlTraustUnitOfWork, seed: Seed) -> Profiles:
    return Profiles(uow, seed)


def ids(*repos: Repository) -> list[UUID]:
    return [r.id for r in repos if r.id]


def test_a_profile_states_its_grants_posture_and_flags(profiles: Profiles) -> None:
    repo, main, _ = profiles.repo()
    assessment_id = profiles.record(main, 1, PROFILE)

    (found,) = profiles.service.privileges(AssessmentFilter(), ids(repo))

    assert found == PrivilegeProfile(
        assessment_id=assessment_id,
        repository_id=repo.id,
        permissions=(
            Permission(resource="secrets", verb="get"),
            Permission(resource="secrets", verb="list"),
        ),
        workloads=2,
        privileged_workloads=0,
        rbac_rules=1,
        wildcard_rules=0,
        flags={"secrets_access": 1, "escalate_bind_impersonate": 1},
        containers=1,
        privileged_containers=0,
        run_as_non_root_containers=0,
        namespaces=("example-operator-system",),
        install_modes=("AllNamespaces", "OwnNamespace"),
        kubebuilder_markers=12,
    )
    assert found.tenancy is None


@pytest.mark.parametrize(
    ("rules", "expected"),
    [
        ([], ()),
        (
            [
                {
                    "scope": "cluster",
                    "apiGroups": ["apps", ""],
                    "resources": ["pods"],
                    "verbs": ["*"],
                }
            ],
            (
                Permission(api_group="apps", resource="pods", verb="*", cluster_scoped=True),
                Permission(resource="pods", verb="*", cluster_scoped=True),
            ),
        ),
        (
            [
                {"scope": "namespace", "resources": ["configmaps"], "verbs": ["get"]},
                {
                    "scope": "namespace",
                    "apiGroups": [""],
                    "resources": ["configmaps"],
                    "verbs": ["get"],
                },
            ],
            (Permission(resource="configmaps", verb="get"),),
        ),
        ([{"apiGroups": [""], "resources": [], "verbs": ["get"]}], ()),
    ],
)
def test_rules_expand_to_distinct_grants(
    profiles: Profiles, rules: list[dict[str, Any]], expected: tuple[Permission, ...]
) -> None:
    repo, main, _ = profiles.repo()
    profiles.record(main, 1, {**PROFILE, "rbac_rules": rules, "rbac_flags": {}})
    (found,) = profiles.service.privileges(AssessmentFilter(), ids(repo))
    assert (found.permissions, found.flags) == (expected, {})


def test_each_repositorys_latest_completed_default_line_profile_counts(profiles: Profiles) -> None:
    (a, a_main, a_branch), (b, b_main, _), (c, _, _) = (
        profiles.repo(),
        profiles.repo(),
        profiles.repo(),
    )
    profiles.record(a_main, 1, profile(1))
    profiles.record(a_main, 2, profile(5))
    profiles.record(a_main, 3, profile(9), status=ASSESSMENT_DEGRADED)
    profiles.record(a_branch, 4, profile(8))
    profiles.record(b_main, 1, profile(3))
    profiles.record(a_main, 40, profile(7))  # after now

    found = profiles.service.privileges(AssessmentFilter(), ids(a, b, c))
    assert sorted((p.repository_id == a.id, p.workloads) for p in found) == [(False, 3), (True, 5)]

    degraded = profiles.service.privileges(AssessmentFilter(status=ASSESSMENT_DEGRADED), ids(a))
    assert [p.workloads for p in degraded] == [9]


def test_no_profiles_is_empty(profiles: Profiles) -> None:
    repo, _, _ = profiles.repo()
    assert profiles.service.privileges(AssessmentFilter(), ids(repo)) == []
    assert profiles.service.privileges(AssessmentFilter(), []) == []


def test_privileges_reject_another_kind_and_need_the_publisher(
    uow: SqlTraustUnitOfWork, profiles: Profiles
) -> None:
    with pytest.raises(ValidationError, match="priv-profile"):
        profiles.service.privileges(AssessmentFilter(kind=AssessmentKind.SECURE_CODE_CANONICAL), [])
    with pytest.raises(ConfigError, match="operator-priv-profile"):
        AssessmentService(uow).privileges(AssessmentFilter(), [])


@pytest.mark.parametrize(("day", "workloads"), [(0, None), (1, 1), (2, 5), (45, 7)])
def test_privileges_read_the_profile_held_as_of_a_point_in_time(
    profiles: Profiles, day: int, workloads: int | None
) -> None:
    repo, main, _ = profiles.repo()
    profiles.record(main, 1, profile(1))
    profiles.record(main, 2, profile(5))
    profiles.record(main, 40, profile(7))
    found = profiles.service.privileges(AssessmentFilter(), ids(repo), T0 + timedelta(days=day))
    assert [p.workloads for p in found] == ([] if workloads is None else [workloads])


def workload(pod: dict[str, Any] | None, *containers: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "kind": "Deployment",
        **({} if pod is None else {"pod_securityContext": pod}),
        "containers": [{"name": f"c{i}", "securityContext": c} for i, c in enumerate(containers)],
    }


@pytest.mark.parametrize(
    ("workloads", "posture"),
    [
        ([], (0, 0, 0)),
        ([workload(None, None, {})], (2, 0, 0)),
        ([workload({}, {"privileged": True, "runAsNonRoot": True})], (1, 1, 1)),
        ([workload({"runAsNonRoot": True}, None, {"runAsNonRoot": None})], (2, 0, 2)),
        ([workload({"runAsNonRoot": True}, {"runAsNonRoot": False})], (1, 0, 0)),
        (
            [workload(None, {"privileged": False}), workload({"runAsNonRoot": True}, {})],
            (2, 0, 1),
        ),
        ([{"kind": "Deployment"}], (0, 0, 0)),
    ],
)
def test_container_posture_counts_privileged_and_non_root_with_pod_inheritance(
    profiles: Profiles, workloads: list[dict[str, Any]], posture: tuple[int, int, int]
) -> None:
    repo, main, _ = profiles.repo()
    profiles.record(main, 1, {**PROFILE, "workloads": workloads})
    (found,) = profiles.service.privileges(AssessmentFilter(), ids(repo))
    assert (
        found.containers,
        found.privileged_containers,
        found.run_as_non_root_containers,
    ) == posture


def test_a_profile_without_workloads_or_tiers_reads_unknown_not_zero(profiles: Profiles) -> None:
    repo, main, _ = profiles.repo()
    bare = {"repo": "bare-operator", "summary": {"workloads": 0, "rbac_rules": 0}}
    profiles.record(main, 1, bare)
    (found,) = profiles.service.privileges(AssessmentFilter(), ids(repo))
    assert (found.containers, found.privileged_containers, found.run_as_non_root_containers) == (
        None,
        None,
        None,
    )
    assert (found.kubebuilder_markers, found.surplus) == (None, None)
    assert (found.namespaces, found.install_modes) == ((), ())
    assert (found.distinct_rule_triples, found.distinct_cluster_triples) == (0, 0)


@pytest.mark.parametrize(
    ("tier2", "install_modes", "expected"),
    [
        ({"kubebuilder_markers": 0, "note": "no markers"}, {}, (0, None, ())),
        (
            {"kubebuilder_markers": 4, "shipped_not_declared_count": 7},
            {"OwnNamespace": True, "AllNamespaces": False, "MultiNamespace": True},
            (4, 7, ("OwnNamespace", "MultiNamespace")),
        ),
        (
            {"kubebuilder_markers": 9, "shipped_not_declared_count": 0},
            {"AllNamespaces": True},
            (9, 0, ("AllNamespaces",)),
        ),
    ],
)
def test_tier2_surplus_markers_and_supported_install_modes(
    profiles: Profiles,
    tier2: dict[str, Any],
    install_modes: dict[str, bool],
    expected: tuple[int, int | None, tuple[str, ...]],
) -> None:
    repo, main, _ = profiles.repo()
    profiles.record(
        main,
        1,
        {**PROFILE, "tier2_required_vs_granted": tier2, "install_modes": install_modes},
    )
    (found,) = profiles.service.privileges(AssessmentFilter(), ids(repo))
    assert (found.kubebuilder_markers, found.surplus, found.install_modes) == expected


@pytest.mark.parametrize(
    ("rules", "triples"),
    [
        ([], (0, 0)),
        (
            [
                {"scope": "cluster", "apiGroups": [""], "resources": ["pods"], "verbs": ["get"]},
                {"scope": "namespace", "apiGroups": [""], "resources": ["pods"], "verbs": ["get"]},
            ],
            (1, 1),
        ),
        (
            [
                {
                    "scope": "cluster",
                    "apiGroups": ["", "apps"],
                    "resources": ["pods", "deployments"],
                    "verbs": ["get"],
                },
                {"scope": "namespace", "resources": ["secrets"], "verbs": ["get", "list"]},
            ],
            (6, 4),
        ),
    ],
)
def test_distinct_triples_count_grants_once_whatever_their_scope(
    profiles: Profiles, rules: list[dict[str, Any]], triples: tuple[int, int]
) -> None:
    repo, main, _ = profiles.repo()
    profiles.record(main, 1, {**PROFILE, "rbac_rules": rules})
    (found,) = profiles.service.privileges(AssessmentFilter(), ids(repo))
    assert (found.distinct_rule_triples, found.distinct_cluster_triples) == triples
    assert found.model_dump()["distinct_rule_triples"] == triples[0]
