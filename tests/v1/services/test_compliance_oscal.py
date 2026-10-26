"""OSCAL export of a recorded compliance assessment, ported from traust (fabdb13)
harnessing/3-audit/compliance-check/scripts/run_compliance_check.py `export_oscal`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_DNS, UUID, uuid5

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.test_compliance import NIST, NOW, SOC2, World, provenance
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import IntegrityError, ValidationError
from traust_core.v1.models.compliance import EvaluationRequest, oscal_assessment_results
from traust_core.v1.models.insight import OscalAssessmentResults, ViewFilter, ViewName
from traust_core.v1.models.vocabulary import ComplianceFramework
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.insight import InsightService, OscalExport

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed

MODERATE = ComplianceFramework("fedramp-moderate")


@pytest.fixture
def world(uow: SqlTraustUnitOfWork, seed: Seed) -> World:
    world = World(uow, seed)
    world.publish_mapping()
    return world


def recorded(world: World, *frameworks: str, **request: Any) -> UUID:
    scope_id = world.declared(frameworks=list(frameworks))
    run = world.service.evaluate(
        EvaluationRequest(scope_id=scope_id, harness_version="9.9.9", **request)
    )
    return world.service.record(run.document, provenance()).artifact.id


def assessment_results(world: World, artifact_id: UUID) -> dict[str, Any]:
    return world.service.export_oscal(artifact_id)["assessment-results"]  # type: ignore[return-value]


def test_identical_inputs_give_a_byte_identical_document(world: World) -> None:
    scope_id = world.declared()
    request = EvaluationRequest(
        scope_id=scope_id,
        harness_version="9.9.9",
        frameworks=(NIST, SOC2),
        trust_categories=("security",),
    )
    first, second = world.service.evaluate(request), world.service.evaluate(request)
    artifact_id = world.service.record(first.document, provenance()).artifact.id
    exported = json.dumps(world.service.export_oscal(artifact_id), sort_keys=True)
    assert exported == json.dumps(oscal_assessment_results(second.document), sort_keys=True)
    assert exported == json.dumps(world.service.export_oscal(artifact_id), sort_keys=True)


def test_only_the_800_53_spine_is_exported_with_content_derived_ids(world: World) -> None:
    artifact_id = recorded(
        world,
        "nist-800-53-rev5",
        "soc2-tsc",
        "fedramp-moderate",
        target_kind="environment",
        trust_categories=("security",),
        inventory=world.inventory.collect([]).data,
    )
    body = json.loads(world.publisher.get(artifact_id).payload)
    registry = body["metadata"]["registry_hash"]
    out = assessment_results(world, artifact_id)
    (result,) = out["results"]
    observations = result["observations"]
    spine = [r for r in body["results"] if r["framework"] in (NIST, MODERATE)]
    assert {r["framework"] for r in body["results"]} == {NIST, SOC2, MODERATE}
    assert len(observations) == len(spine) > 0
    assert {o["title"].split()[0] for o in observations} == {NIST, MODERATE}
    first, observation = spine[0], observations[0]
    assert observation == {
        "uuid": str(
            uuid5(
                NAMESPACE_DNS,
                f"{first['framework']}|{first['control_id']}|{first['verdict']}|{registry}",
            )
        ),
        "title": f"{first['framework']} {first['control_id']}",
        "description": first.get("reason") or first["verdict"],
        "methods": ["TEST" if first["classification"] == "deterministic" else "EXAMINE"],
        "props": [
            {"name": "verdict", "value": first["verdict"]},
            {"name": "classification", "value": first["classification"]},
        ],
    }
    assert {m for o in observations for m in o["methods"]} == {"TEST", "EXAMINE"}
    snapshot = body["metadata"]["target"]["snapshot_id"]
    selected = "fedramp-moderate,nist-800-53-rev5,soc2-tsc"
    assert out["uuid"] == str(uuid5(NAMESPACE_DNS, f"assessment|{registry}|{snapshot}|{selected}"))
    assert result["uuid"] == str(uuid5(NAMESPACE_DNS, f"result|{registry}"))
    assert out["metadata"] == {
        "title": "acme compliance assessment",
        "last-modified": "2026-10-23T09:00:00Z",
        "version": "9.9.9",
        "oscal-version": "1.1.2",
    }


def test_an_assessment_without_a_spine_framework_is_refused(world: World) -> None:
    artifact_id = recorded(world, "soc2-tsc", trust_categories=("security",))
    with pytest.raises(ValidationError, match="spine only; this assessment covers soc2-tsc"):
        world.service.export_oscal(artifact_id)


def test_export_refuses_an_artifact_that_is_not_a_compliance_assessment(world: World) -> None:
    scope = world.service.get_scope(world.declared())
    assert scope.scope_id is not None
    with pytest.raises(IntegrityError, match="not a compliance-assessment"):
        world.service.export_oscal(scope.scope_id)


def test_the_oscal_view_serves_the_door_as_the_oscal_document(world: World) -> None:
    artifact_id = recorded(world, "nist-800-53-rev5")
    insight = InsightService([OscalExport(world.service)], FixedClock(NOW))
    rendered = insight.publish(ViewName.OSCAL, ViewFilter(artifact_id=artifact_id))
    assert isinstance(rendered.model, OscalAssessmentResults)
    assert json.loads(rendered.model.model_dump_json()) == world.service.export_oscal(artifact_id)
    assert "# acme compliance assessment" in rendered.markdown
    assert "nist-800-53-rev5 si-2" in rendered.markdown
    assert insight.refresh(None, ViewFilter()).rendered == {}


def test_the_oscal_view_needs_an_artifact_id(world: World) -> None:
    with pytest.raises(ValidationError, match="name its artifact_id"):
        OscalExport(world.service).build(ViewFilter())


def test_context_serves_the_oscal_view(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="name its artifact_id"):
        Context(Config(home=tmp_path)).services().insight.build(ViewName.OSCAL, ViewFilter())
