"""AssessmentService.threats: the register's rows, read from each repository's latest model.

Replaces traust's threat-register parse_model (markdown tables): the model is the recorded
threat-model document, keyed by its assessment instead of a folder slug.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid5

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.artifacts import ThreatModelArtifact
from traust_core.v1.models.assessment import (
    ASSESSMENT_DEGRADED,
    AssessmentKind,
    AttackTechnique,
    Threat,
    ThreatFilter,
    ThreatMitigation,
)
from traust_core.v1.models.common import PageRequest, every_item
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

MODEL = json.loads(
    (
        Path(__file__).parents[2] / "fixtures" / "assessments" / "widget-threat-model.json"
    ).read_text()
)
THREAT_MODEL = AssessmentKind.THREAT_MODEL.value
NOW = T0 + timedelta(days=30)


def model(*threats: dict[str, Any]) -> dict[str, Any]:
    return {**MODEL, "threats": list(threats), "mitigations": [], "tenant_boundaries": []}


def threat(n: int, status: str = "unmitigated", **kw: Any) -> dict[str, Any]:
    return {
        "id": f"T{n}",
        "threat": f"Threat {n} reaches tenant data",
        "actor": ["remote_unauth"],
        "impact": "high",
        "likelihood": "possible",
        "status": status,
        **kw,
    }


class Models:
    def __init__(self, uow: SqlTraustUnitOfWork, seed: Seed) -> None:
        self.uow, self.seed = uow, seed
        self.publisher = ArtifactPublisher(
            PublishSpecs(PublishSpec(ThreatModelArtifact)), InMemoryObjectStore(), uow
        )
        self.service = AssessmentService(uow, clock=FixedClock(NOW), publisher=self.publisher)

    def repo(self) -> tuple[Repository, RepositoryRef, RepositoryRef]:
        repo = self.seed.repository()
        main = self.seed.repository_ref(repo, is_default=True)
        return repo, main, self.seed.repository_ref(repo, name="release-1", sha="b" * 40)

    def record(self, ref: RepositoryRef, day: int, doc: dict[str, Any], **kw: Any) -> UUID:
        values = {"kind": THREAT_MODEL, "occurred_at": T0 + timedelta(days=day), **kw}
        a = self.seed.assessment(ref, **values)
        assert a.id is not None
        published = self.publisher.publish_artifact(ThreatModelArtifact.from_document(doc))
        AssessmentLog(self.uow).attach(
            a.id, published.artifact_id, sha256_hex(ThreatModelArtifact.from_document(doc).payload)
        )
        return a.id

    def threats(self, *repos: Repository, **kw: Any) -> list[Threat]:
        f = ThreatFilter(repository_ids=tuple(r.id for r in repos if r.id), **kw)
        return list(every_item(lambda page: self.service.threats(f, page), limit=2))


@pytest.fixture
def models(uow: SqlTraustUnitOfWork, seed: Seed) -> Models:
    return Models(uow, seed)


def test_a_model_states_its_threats_joined_to_boundaries_and_mitigations(models: Models) -> None:
    repo, main, _ = models.repo()
    assessment_id = models.record(main, 1, MODEL)

    t1, t2 = sorted(models.threats(repo), key=lambda t: t.label)

    assert t1.id == uuid5(assessment_id, "T1")
    assert (t1.assessment_id, t1.repository_id, t1.title) == (
        assessment_id,
        repo.id,
        "Cross-tenant data theft via SQL injection in list parameters",
    )
    assert (t1.actor, t1.actors) == ("remote_auth", ("remote_auth", "insider"))
    assert (t1.impact, t1.likelihood, t1.severity) == ("critical", "almost_certain", None)
    assert t1.techniques == (AttackTechnique(id="T1190"), AttackTechnique(id="T1078"))
    assert t1.evidence == ("EXAMPLE-001", "EXAMPLE-002")
    assert t1.boundary_ids == ("IF-1",)
    assert t1.mitigations == (
        ThreatMitigation(text="parameterized queries everywhere", closes_class="yes", effort="S"),
    )
    assert (t2.status, t2.severity, t2.impact, t2.likelihood) == (
        "partially_mitigated",
        "high",
        None,
        None,
    )
    assert (t2.evidence, t2.boundary_ids, t2.mitigations, t2.linddun) == ((), (), (), False)


def test_only_each_repositorys_latest_completed_default_line_model_counts(models: Models) -> None:
    (a, a_main, a_branch), (b, b_main, _), (c, _, _) = models.repo(), models.repo(), models.repo()
    models.record(a_main, 1, model(threat(1), threat(2)))
    latest = models.record(a_main, 2, model(threat(1, "mitigated")))
    models.record(a_main, 3, model(threat(9)), status=ASSESSMENT_DEGRADED)
    models.record(a_branch, 4, model(threat(8)))
    models.record(b_main, 1, model(threat(1), threat(2, linddun=None) if False else threat(2)))
    models.record(a_main, 40, model(threat(7)))  # after now

    found = models.threats(a, b, c)

    assert sorted((t.repository_id == a.id, t.label, t.status) for t in found) == [
        (False, "T1", "unmitigated"),
        (False, "T2", "unmitigated"),
        (True, "T1", "mitigated"),
    ]
    assert {t.assessment_id for t in found if t.repository_id == a.id} == {latest}


@pytest.mark.parametrize(
    ("kw", "labels"),
    [
        ({}, {"T1", "T2", "T3"}),
        ({"statuses": ("unmitigated", "partially_mitigated")}, {"T1", "T2"}),
        ({"statuses": ("risk_accepted",)}, set()),
        ({"technique": "T1190"}, {"T1"}),
        ({"technique": "T9999"}, set()),
    ],
)
def test_threats_narrow_by_status_and_technique(
    models: Models, kw: dict[str, Any], labels: set[str]
) -> None:
    repo, main, _ = models.repo()
    models.record(
        main,
        1,
        model(
            threat(1, attack_refs=["T1190"]),
            threat(2, "partially_mitigated"),
            threat(3, "mitigated", threat="linddun: profile linkage across tenants"),
        ),
    )
    assert {t.label for t in models.threats(repo, **kw)} == labels


def test_pages_are_newest_model_first_with_no_gaps_or_repeats(models: Models) -> None:
    (a, a_main, _), (b, b_main, _) = models.repo(), models.repo()
    older = models.record(a_main, 1, model(*(threat(n) for n in range(1, 4))))
    newer = models.record(b_main, 2, model(*(threat(n) for n in range(1, 5))))
    f = ThreatFilter(repository_ids=(a.id, b.id))  # type: ignore[arg-type]

    first = models.service.threats(f, PageRequest(limit=3))
    found = models.threats(a, b)

    assert len(first.items) == 3 and first.next is not None
    assert [t.assessment_id for t in found] == [newer] * 4 + [older] * 3
    assert len({t.id for t in found}) == 7


def test_a_linddun_row_is_marked(models: Models) -> None:
    repo, main, _ = models.repo()
    models.record(main, 1, model(threat(1, threat="linddun: profile linkage across tenants")))
    assert [t.linddun for t in models.threats(repo)] == [True]


def test_no_repositories_or_no_models_is_an_empty_page(models: Models) -> None:
    repo, _, _ = models.repo()
    assert models.threats(repo) == []
    assert models.threats() == []


def test_threats_need_the_publisher_and_a_positive_limit(
    uow: SqlTraustUnitOfWork, models: Models
) -> None:
    with pytest.raises(ConfigError, match="threat-model"):
        AssessmentService(uow).threats(ThreatFilter(repository_ids=()), PageRequest())
    with pytest.raises(ValidationError, match="positive"):
        models.service.threats(ThreatFilter(repository_ids=()), PageRequest(limit=0))


@pytest.mark.parametrize(("day", "labels"), [(0, []), (1, ["T1"]), (45, ["T1", "T2"])])
def test_threats_read_the_model_held_as_of_a_point_in_time(
    models: Models, day: int, labels: list[str]
) -> None:
    repo, main, _ = models.repo()
    models.record(main, 1, model(threat(1)))
    models.record(main, 40, model(threat(1), threat(2)))
    found = models.threats(repo, as_of=T0 + timedelta(days=day))
    assert sorted(t.label for t in found) == labels


def test_attack_scenarios_are_the_latest_models_narratives_verbatim(models: Models) -> None:
    repo, main, branch = models.repo()
    quiet, quiet_main, _ = models.repo()
    told = [
        {"id": "T1", "threat": "Tenant escape", "steps": ["An attacker signs up.", "Then pivots."]},
        {"id": "T2", "steps": ["A second story."]},
    ]
    models.record(main, 1, {**MODEL, "attack_scenarios": [{"id": "T1", "steps": ["Old."]}]})
    latest = models.record(main, 2, {**MODEL, "attack_scenarios": told})
    models.record(branch, 3, {**MODEL, "attack_scenarios": [{"id": "T9", "steps": ["Branch."]}]})
    models.record(quiet_main, 1, MODEL)

    found = models.service.attack_scenarios([r.id for r in (repo, quiet) if r.id])

    assert [(s.assessment_id, s.repository_id, s.label, s.threat, s.steps) for s in found] == [
        (latest, repo.id, "T1", "Tenant escape", ("An attacker signs up.", "Then pivots.")),
        (latest, repo.id, "T2", None, ("A second story.",)),
    ]
    assert models.service.attack_scenarios([repo.id], T0 + timedelta(days=1, hours=1))[  # type: ignore[list-item]
        0
    ].steps == ("Old.",)
    assert models.service.attack_scenarios([]) == []


def test_attack_scenarios_need_the_publisher(uow: SqlTraustUnitOfWork) -> None:
    with pytest.raises(ConfigError, match="needs the publisher"):
        AssessmentService(uow, clock=FixedClock(NOW)).attack_scenarios([])
