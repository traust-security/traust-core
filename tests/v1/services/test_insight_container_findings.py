from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.test_assessment_record import authored_report
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ValidationError, ViewContractError
from traust_core.v1.models.artifacts import SecurityAuditArtifact
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import FindingState
from traust_core.v1.models.insight import ContainerFindings, FindingTally, ViewFilter, ViewName
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services import insight as insight_module

DAY = timedelta(days=1)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as database:
        yield database


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    context = Context(Config(home=tmp_path), clock=FixedClock(T0 + 20 * DAY))
    context.__dict__["database"] = engine
    return context


def record_container(
    context: Context, ref_id: UUID, image: str, day: int, indices: tuple[int, ...] = (0, 1)
) -> UUID:
    body = json.loads(authored_report().payload)
    body["title"] = f"Container assessment {day}: {image}"
    body["metadata"] = {
        "date": (T0 + day * DAY).date().isoformat(),
        "repository": image,
        "commit": str(day % 10) * 64,
        "audit_profile": "container",
        "scope": image,
    }
    body["findings"] = [body["findings"][i] for i in indices]
    for finding in body["findings"]:
        finding.pop("validation_status", None)
        finding.pop("disposition", None)
        finding.pop("effective_severity", None)
    saved = context.services().assessment.record(
        SecurityAuditArtifact.from_document(body),
        ref_id,
        AssessmentKind.CONTAINER,
        "skill:secure-container-audit",
        "test",
        Provenance(run_id=uuid4(), source=SourceType.INTERACTIVE, occurred_at=T0 + day * DAY),
    )
    assert saved.id is not None
    return saved.id


def test_the_container_rows_cvss_describes_its_own_occurrence(
    context: Context, engine: Engine
) -> None:
    """The row shows the container family's occurrence, so its cvss block must describe
    that occurrence — not the repository-wide latest a plain view would fold. A later
    source-code report scoring the finding 9.8 must not reach the container row's chain."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref()
        uow.commit()
    assert ref.id is not None
    # findings[0] is the report's scored one: cvss 8.1, a high band
    container = record_container(
        context, ref.id, "registry.example:5000/apps/widget@sha256:aaa", 0, (0,)
    )
    (finding_id,) = {
        o.finding_id for o in context.services().findings.occurrences(assessment_id=container)
    }
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        later = seed.assessment(ref, kind="secure-code", occurred_at=T0 + 4 * DAY)
        seed.occurrence(
            uow.findings.get(finding_id),
            later,
            severity="critical",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=Decimal("9.8"),
        )
        uow.commit()
    scope = ViewFilter(assessment_id=container, report_stem="widget-container-audit")
    model = context.services().insight.build(ViewName.CONTAINER_FINDINGS, scope)
    assert isinstance(model, ContainerFindings)
    (row,) = model.findings
    assert row.view.occurrence.assessment_id == container
    assert row.view.cvss is not None
    assert (row.view.cvss.score, row.view.cvss.severity) == (Decimal("8.1"), "high")
    assert row.view.effective_severity == "high"  # the container occurrence's band


def test_container_population_is_cumulative_image_scoped_and_decision_driven(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref()
        uow.commit()
    assert ref.id is not None
    first = record_container(context, ref.id, "registry.example:5000/apps/widget@sha256:aaa", 0)
    second = record_container(context, ref.id, "registry.example:5000/apps/widget:release", 1, (0,))
    empty = record_container(context, ref.id, "registry.example:5000/apps/widget@sha256:ccc", 2, ())
    record_container(context, ref.id, "registry.example:5000/apps/other@sha256:ddd", 3, (2,))
    findings = context.services().findings
    initial = findings.occurrences(assessment_id=first)
    assert len(initial) == 2
    repeated = findings.occurrences(assessment_id=second)[0].finding_id
    absent = next(o.finding_id for o in initial if o.finding_id != repeated)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        code = seed.assessment(ref, kind="secure-code", occurred_at=T0 + 4 * DAY)
        original = uow.findings.get(repeated)
        seed.occurrence(original, code, severity="critical")
        seed.occurrence(
            seed.finding(uow.repositories.get(ref.repository_id)), code, severity="high"
        )
        seed.decision(
            original,
            validity="confirmed",
            resolution="resolved",
            actor="human:analyst@example.com",
            occurred_at=T0 + 5 * DAY,
        )
        uow.commit()
    scope = ViewFilter(assessment_id=empty, report_stem="widget-container-audit")
    rendered = context.services().insight.publish(ViewName.CONTAINER_FINDINGS, scope)
    model = rendered.model
    assert isinstance(model, ContainerFindings)
    assert rendered.stem == "widget-container-audit-findings-current"
    assert model.image_repository == "registry.example:5000/apps/widget"
    assert [r.assessment_id for r in model.reports] == [first, second, empty]
    by_id = {row.view.finding.id: row for row in model.findings}
    assert set(by_id) == {repeated, absent}
    assert len(by_id[repeated].occurrences) == 2
    assert by_id[repeated].view.occurrence.assessment_id == second
    assert by_id[repeated].view.effective_severity == "high"
    assert by_id[repeated].view.state() == FindingState.RESOLVED
    assert by_id[absent].view.state() == FindingState.OPEN
    assert model.total.resolved == 1 and model.total.open.total == 1
    assert len(by_id[repeated].history) == 1
    before_decision = context.services().insight.build(
        ViewName.CONTAINER_FINDINGS, scope.model_copy(update={"as_of": T0 + 3 * DAY})
    )
    assert before_decision.total.open.total == 2
    assert before_decision.total.resolved == 0
    assert all(not row.history for row in before_decision.findings)
    payload = json.loads(model.model_dump_json())
    assert {row["view"]["finding"]["id"] for row in payload["findings"]} == set(map(str, by_id))
    report = context.services().insight.report(ViewName.CONTAINER_FINDINGS, scope)
    table = next(section.table for section in report.sections if section.heading == "Findings")
    assert {row[0]: row[3] for row in table.rows} == {
        str(repeated): "resolved",
        str(absent): "open",
    }


def test_container_scope_rejects_code_anchor_missing_stem_and_future_anchor(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref()
        code = seed.assessment(ref, kind="secure-code", occurred_at=T0)
        uow.commit()
    assert ref.id is not None
    container = record_container(context, ref.id, "registry.example/apps/widget@sha256:aaa", 1, ())
    insight = context.services().insight
    for scope in (
        ViewFilter(assessment_id=container),
        ViewFilter(assessment_id=container, report_stem="widget"),
        ViewFilter(assessment_id=code.id, report_stem="widget-container-audit"),
        ViewFilter(assessment_id=container, report_stem="widget-container-audit", as_of=T0),
    ):
        with pytest.raises(ValidationError):
            insight.build(ViewName.CONTAINER_FINDINGS, scope)


def test_container_scope_rejects_a_source_url_as_image_and_an_out_of_scope_anchor(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref()
        team = seed.team()
        uow.commit()
    assert ref.id is not None and team.id is not None
    source = record_container(context, ref.id, "https://github.com/example-org/widget", 1, ())
    insight = context.services().insight
    with pytest.raises(ValidationError, match="not a source URL"):
        insight.build(
            ViewName.CONTAINER_FINDINGS,
            ViewFilter(assessment_id=source, report_stem="widget-container-audit"),
        )
    image = record_container(context, ref.id, "registry.example/apps/widget@sha256:aaa", 2, ())
    with pytest.raises(ValidationError, match="outside the requested scope"):
        insight.build(
            ViewName.CONTAINER_FINDINGS,
            ViewFilter(
                assessment_id=image, report_stem="widget-container-audit", team_ids=(team.id,)
            ),
        )


def test_container_view_is_single_item_and_left_out_of_a_full_refresh(context: Context) -> None:
    refreshed = context.services().insight.refresh(None, ViewFilter())
    assert ViewName.CONTAINER_FINDINGS not in refreshed.rendered
    assert ViewName.CONTAINER_FINDINGS not in refreshed.failed


def test_container_image_provenance_is_literal_in_published_report_bodies(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        ref = Seed(uow).repository_ref()
        uow.commit()
    assert ref.id is not None
    image = "registry.example/apps/<img src=x onerror=alert(1)> [docs](evil)\n## forged"
    assessment_id = record_container(context, ref.id, image + "@sha256:aaa", 0)
    scope = ViewFilter(assessment_id=assessment_id, report_stem="widget-container-audit")
    insight = context.services().insight
    model = insight.build(ViewName.CONTAINER_FINDINGS, scope)
    assert isinstance(model, ContainerFindings)
    assert model.image_repository == image
    report = insight.report(ViewName.CONTAINER_FINDINGS, scope)
    assert "<img" not in report.sections[0].body
    assert "[docs](evil)" not in report.sections[0].body
    assert "\n## forged" not in report.sections[0].body
    published = insight.publish(ViewName.CONTAINER_FINDINGS, scope)
    assert "<img" not in published.markdown and "<img" not in published.html
    assert "\n## forged" not in published.markdown
    stored = context.services().assessment.report(assessment_id)
    assert stored is not None and stored.metadata.repository == image + "@sha256:aaa"


def test_container_findings_outside_their_contract_are_refused_by_the_build(
    context: Context, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        ref = Seed(uow).repository_ref()
        uow.commit()
    assert ref.id is not None
    anchor = record_container(context, ref.id, "registry.example:5000/apps/widget@sha256:aaa", 0)
    monkeypatch.setattr(insight_module, "_tally", lambda views: FindingTally(hardening=-1))
    scope = ViewFilter(assessment_id=anchor, report_stem="widget-container-audit")
    with pytest.raises(ViewContractError) as error:
        context.services().insight.build(ViewName.CONTAINER_FINDINGS, scope)
    assert "total/hardening" in {issue.path for issue in error.value.issues}
