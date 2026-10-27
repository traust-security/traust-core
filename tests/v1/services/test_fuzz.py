"""A fuzz run recorded as an assessment of kind `fuzz` holding its fuzz report: crashers taken in
as findings through FindingIntake (one naming a finding confirms it), and the validation-fuzz view
over each target's latest run."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services import test_assessment_record as recording
from tests.v1.services.test_assessment_record import WHEN, fixture
from traust_core.v1.context import Context
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.artifacts import FuzzReportArtifact, IsolationReviewArtifact
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.insight import ValidationFuzz, ViewFilter, ViewName
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.rendering.markdown import MarkdownRenderer
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.fuzz import FuzzHarnessReferences
from traust_core.v1.services.lint import LintContext

engine, context = recording.engine, recording.context

BODY: dict[str, Any] = json.loads(fixture("assessments/widget-fuzz-report.json"))
CRASHER: dict[str, Any] = BODY["crashers"][0]


def report(*crashers: dict[str, Any], **changes: Any) -> FuzzReportArtifact:
    return FuzzReportArtifact.from_document({**BODY, "crashers": list(crashers), **changes})


def crasher(label: str, *drop: str, **changes: Any) -> dict[str, Any]:
    return {k: v for k, v in {**CRASHER, "id": label, **changes}.items() if k not in drop}


@pytest.fixture
def ref(engine: Engine) -> UUID:
    with SqlTraustUnitOfWork(engine) as uow:
        saved = Seed(uow).repository_ref(is_default=True)
        uow.commit()
    assert saved.id is not None
    return saved.id


def record(context: Context, doc: FuzzReportArtifact, ref: UUID, at: Any = WHEN) -> Assessment:
    return context.services().assessment.record(
        doc,
        ref,
        AssessmentKind.FUZZ,
        "skill:create-fuzzing",
        "0.1.0",
        Provenance(run_id=uuid4(), source=SourceType.INTERACTIVE, occurred_at=at),
    )


def occurrences(context: Context, assessment: Assessment) -> dict[UUID, str]:
    """Per finding the assessment reported: its title."""
    assert assessment.id is not None
    with SqlTraustUnitOfWork(context.database) as uow:
        found = uow.occurrences.list_for_assessment(assessment.id)
        return {
            f.id: f.title  # type: ignore[misc]
            for f in uow.findings.list_by_ids([o.finding_id for o in found])
        }


def finding_count(context: Context, ref: UUID) -> int:
    with SqlTraustUnitOfWork(context.database) as uow:
        return len(uow.findings.list_for_repository(uow.repository_refs.get(ref).repository_id))


def test_a_fuzz_run_takes_its_crashers_in_as_findings(context: Context, ref: UUID) -> None:
    doc = FuzzReportArtifact.parse(fixture("assessments/widget-fuzz-report.json"))
    assessment = record(context, doc, ref)

    assert assessment.kind == AssessmentKind.FUZZ
    [(finding_id, title)] = occurrences(context, assessment).items()
    assert title == CRASHER["title"]
    view = context.services().findings.list_by_ids([finding_id])[0]
    assert list(view.cwes) == ["CWE-129"]


def test_the_same_run_again_adds_nothing(context: Context, ref: UUID) -> None:
    doc = report(crasher("C-1"))
    first, again = record(context, doc, ref), record(context, doc, ref)
    assert again.id == first.id
    assert finding_count(context, ref) == 1


def test_a_clean_run_records_no_finding(context: Context, ref: UUID) -> None:
    assessment = record(context, report(), ref)
    assert occurrences(context, assessment) == {}
    assert finding_count(context, ref) == 0


def test_a_crasher_naming_a_finding_confirms_it_rather_than_minting_one(
    context: Context, ref: UUID
) -> None:
    first = record(context, report(crasher("C-1")), ref)
    [(finding_id, _)] = occurrences(context, first).items()
    confirming = crasher("C-9", "location", title="reproduced", cwes=[])
    later = record(
        context, report({**confirming, "finding_id": str(finding_id)}), ref, WHEN + timedelta(1)
    )

    assert list(occurrences(context, later)) == [finding_id]
    assert finding_count(context, ref) == 1


def test_a_crasher_confirming_another_repositorys_finding_is_refused(
    context: Context, ref: UUID
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        other = seed.repository_ref(seed.repository(url="https://github.com/org/other"))
        uow.commit()
    assert other.id is not None
    recorded = record(context, report(crasher("C-1")), other.id)
    [finding_id] = occurrences(context, recorded)
    with pytest.raises(ValidationError, match=r"confirms finding .* of repository"):
        record(context, report(crasher("C-2", finding_id=str(finding_id))), ref)
    with SqlTraustUnitOfWork(context.database) as uow:
        assert uow.assessments.list_for_ref(ref) == []


def test_a_crasher_confirming_an_unknown_finding_records_nothing(
    context: Context, ref: UUID
) -> None:
    with pytest.raises(NotFoundError):
        record(context, report(crasher("C-1", finding_id=str(uuid4()))), ref)
    with SqlTraustUnitOfWork(context.database) as uow:
        assert uow.assessments.list_for_ref(ref) == []


def test_a_new_crasher_without_a_location_is_refused(context: Context, ref: UUID) -> None:
    with pytest.raises(ValidationError, match="no usable location"):
        record(context, report(crasher("C-1", "location")), ref)
    assert finding_count(context, ref) == 0


@pytest.mark.parametrize(
    ("doc", "message"),
    [
        (report(crasher("C-1", harness="FuzzMissing")), "does not match any target harness"),
        (report(crasher("C-1"), crasher("C-1")), "crasher id 'C-1' is not unique"),
        (
            report(
                target={
                    **BODY["target"],
                    "harnesses": [BODY["target"]["harnesses"][0]] * 2,
                }
            ),
            "harness name 'FuzzParseRange' is not unique",
        ),
    ],
    ids=["unknown-harness", "duplicate-crasher", "duplicate-harness"],
)
def test_a_report_failing_its_gate_is_refused(
    context: Context, ref: UUID, doc: FuzzReportArtifact, message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        record(context, doc, ref)
    with SqlTraustUnitOfWork(context.database) as uow:
        assert uow.assessments.list_for_ref(ref) == []


def test_the_gate_checks_only_fuzz_reports() -> None:
    other = IsolationReviewArtifact.parse(fixture("assessments/widget-isolation-review.json"))
    with pytest.raises(ValidationError, match="checks fuzz reports"):
        FuzzHarnessReferences().check(other, LintContext())


def view(context: Context, **scope: Any) -> ValidationFuzz:
    model = context.services().insight.build(ViewName.VALIDATION_FUZZ, ViewFilter(**scope))
    assert isinstance(model, ValidationFuzz)
    return model


def test_the_view_is_each_targets_latest_run(context: Context, ref: UUID) -> None:
    record(context, report(crasher("C-1")), ref)
    latest = record(
        context,
        report(
            crasher("C-2", "cvss", severity_proposal="low"),
            crasher("C-3", location={"path": "api/v1/other.go"}),
        ),
        ref,
        WHEN + timedelta(1),
    )
    other_target = record(
        context, report(target={**BODY["target"], "id": "widget-refined"}), ref, WHEN
    )

    model = view(context)

    assert [(t.target, t.assessment_id, t.crashers) for t in model.targets] == [
        ("widget-operator", latest.id, 2),
        ("widget-refined", other_target.id, 0),
    ]
    first = model.targets[0]
    assert (first.engines, dict(first.outcomes), first.execs) == (
        ("go_native",),
        {"crashed": 1, "clean": 1},
        4812330,
    )
    assert (first.lines_covered, first.lines_total, first.gaps) == (812, 1540, 2)
    assert [c.crasher for c in model.crashers] == ["C-3", "C-2"]  # CVSS, then severity
    assert [(g.reason, g.surface) for g in model.gaps] == [
        ("fuzzed_upstream", "pkg/dns"),
        ("fuzzed_upstream", "pkg/dns"),
        ("needs_live_environment", "pkg/webhook"),
        ("needs_live_environment", "pkg/webhook"),
    ]


def test_the_view_as_of_reads_the_run_held_then(context: Context, ref: UUID) -> None:
    first = record(context, report(crasher("C-1")), ref)
    record(context, report(), ref, WHEN + timedelta(1))
    model = view(context, as_of=WHEN + timedelta(hours=1))
    assert [(t.assessment_id, t.crashers) for t in model.targets] == [(first.id, 1)]


def test_a_run_on_a_commit_off_the_default_line_is_in_the_view(context: Context) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        bare = Seed(uow).repository_ref(name=None, kind=None)
        uow.commit()
    assert bare.id is not None
    recorded = record(context, report(crasher("C-1")), bare.id)
    assert [t.assessment_id for t in view(context).targets] == [recorded.id]


def test_an_unmeasured_run_reports_no_coverage_or_execs(context: Context, ref: UUID) -> None:
    harness = {**BODY["target"]["harnesses"][1], "execs": None}
    record(context, report(coverage=None, target={**BODY["target"], "harnesses": [harness]}), ref)
    [target] = view(context).targets
    assert (target.execs, target.lines_covered, target.lines_total) == (None, None, None)


def test_the_view_renders_crashers_targets_and_gaps(context: Context, ref: UUID) -> None:
    record(context, report(crasher("C-1")), ref)
    insight = context.services().insight
    md = MarkdownRenderer().render(insight.report(ViewName.VALIDATION_FUZZ, ViewFilter())).decode()
    assert "1 targets across 1 repositories; 2 harnesses ran, 1 clean, 1 crashed." in md
    assert "1 crashers (0 confirm a recorded finding), 2 surfaces left unfuzzed" in md
    assert "| index_out_of_range | medium | 4.4 | CWE-129 | - |" in md
    assert "| fuzzed_upstream |" in md and "812/1540" in md


def test_an_empty_scope_renders_its_empty_tables(context: Context) -> None:
    md = (
        MarkdownRenderer()
        .render(context.services().insight.report(ViewName.VALIDATION_FUZZ, ViewFilter()))
        .decode()
    )
    assert "0 targets across 0 repositories; 0 harnesses ran. 0 crashers" in md
    assert "_No crashers recorded._" in md and "_No fuzz runs recorded._" in md
    assert "_No gaps recorded._" in md


def test_recording_a_fuzz_run_publishes_the_report_it_holds(context: Context, ref: UUID) -> None:
    doc = report(crasher("C-1"))
    assessment = record(context, doc, ref)
    with SqlTraustUnitOfWork(context.database) as uow:
        repository_id = uow.repository_refs.get(ref).repository_id
    [(owner, held, read)] = context.services().assessment.fuzz_reports([repository_id], WHEN)
    assert (owner, held.id, read.payload) == (repository_id, assessment.id, doc.payload)
