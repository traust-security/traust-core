from __future__ import annotations

import json

from tests.v1.services import test_compliance as compliance
from tests.v1.services.test_compliance import World, provenance
from tests.v1.services.test_compliance_calibrate import seeded
from traust_core.v1.models.artifacts import ComplianceAssessmentArtifact
from traust_core.v1.models.compliance import COVERAGE_KEYS
from traust_core.v1.rendering.compliance import assessment_report

engine, uow, seed, world = compliance.engine, compliance.uow, compliance.seed, compliance.world


def test_one_run_report_contains_exact_coverage_and_every_control_with_its_citations(
    world: World,
) -> None:
    evaluated = world.service.evaluate(seeded(world))
    body = json.loads(evaluated.document.payload)
    report = assessment_report(evaluated.document)
    sections = {section.heading: section for section in report.sections}
    assert sections["Target"].table is not None
    target = dict(sections["Target"].table.rows)
    assert target["product"] == body["metadata"]["target"]["product"]
    assert json.loads(target["repos"]) == list(evaluated.scope.repos)
    assert sections["Coverage"].table is not None
    assert sections["Coverage"].table.columns == ("framework", *COVERAGE_KEYS)
    assert sections["Coverage"].table.rows == tuple(
        (framework, *(str(counts[key]) for key in COVERAGE_KEYS))
        for framework, counts in sorted(body["coverage"].items())
    )
    assert {result["verdict"] for result in body["results"]} >= {
        "satisfied",
        "not_satisfied",
        "not_assessed",
    }
    for result in body["results"]:
        control = sections[f"{result['framework']}:{result['control_id']}"]
        assert control.table is not None
        fields = dict(control.table.rows)
        assert fields["verdict"] == result["verdict"]
        assert fields["classification"] == result["classification"]
        assert fields.get("reason") == result.get("reason")
        if evidence := result.get("evidence"):
            citations = sections[f"{control.heading} evidence"].table
            assert citations is not None
            assert citations.rows == tuple(
                (item["kind"], item["locator"], item["sha256"]) for item in evidence
            )


def test_draft_and_recorded_markdown_use_the_same_assessment_not_aggregate_posture(
    world: World,
) -> None:
    evaluated = world.service.evaluate(seeded(world))
    recorded = world.service.record(evaluated.document, provenance())
    assert world.service.export_markdown(recorded.artifact.id) == world.service.render_assessment(
        evaluated.document
    )


def test_skipped_framework_reasons_and_untrusted_control_text_stay_in_their_report_cells(
    world: World,
) -> None:
    request = seeded(world).model_copy(update={"cde_boundary": None})
    evaluated = world.service.evaluate(request)
    body = json.loads(evaluated.document.payload)
    body["results"][0]["reason"] = "audited text\n## forged section\n| fake | row |"
    document = ComplianceAssessmentArtifact.from_document(body)
    report = assessment_report(document)
    skipped = next(
        section for section in report.sections if section.heading == "Skipped frameworks"
    )
    assert skipped.table is not None
    assert dict(skipped.table.rows) == body["metadata"]["skipped_frameworks"]
    markdown = world.service.render_assessment(document).decode()
    assert "\n## forged section\n" not in markdown
    assert "\\| fake \\| row \\|" in markdown
