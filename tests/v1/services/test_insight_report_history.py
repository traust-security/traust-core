from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import timedelta
from decimal import Decimal
from html.parser import HTMLParser
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError as ModelValidationError
from sqlalchemy.engine import Engine

from tests.v1.conftest import CLOCK, SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError, IntegrityError, NotFoundError, ValidationError
from traust_core.v1.models.base import Model
from traust_core.v1.models.insight import (
    ExecutivePanel,
    ExecutiveSummary,
    ReportComparisonTarget,
    ViewFilter,
    ViewName,
)
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects.store import ObjectKey
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpecs
from traust_core.v1.services.insight import InsightService


@pytest.fixture(params=SQL_BACKENDS)
def context(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Context]:
    with contract_db(request.param, tmp_path) as engine:
        ctx = Context(Config(home=tmp_path), clock=CLOCK)
        ctx.__dict__["database"] = engine
        yield ctx


def seed_finding(engine: Engine, *, title: str = "Reported vulnerability") -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/example/{uuid4().hex}")
        ref = seed.repository_ref(repo)
        audit = seed.assessment(ref, occurred_at=T0)
        seed.occurrence(seed.finding(repo, title=title), audit, severity="high")
        uow.commit()


def publisher(context: Context) -> ArtifactPublisher:
    return ArtifactPublisher(
        PublishSpecs(), context.object_store, SqlTraustUnitOfWork(context.database)
    )


class HtmlSurface(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.scripts = 0
        self.csp = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        self.scripts += tag == "script"
        if tag == "meta" and values.get("http-equiv", "").lower() == "content-security-policy":
            self.csp = values.get("content") or ""


@pytest.mark.parametrize(
    "view", [ViewName.SCOREBOARD, ViewName.EXECUTIVE_SUMMARY, ViewName.THREAT_REGISTER]
)
def test_supported_leadership_reports_retain_exact_portable_exports(
    context: Context, view: ViewName
) -> None:
    seed_finding(context.database, title="<script>alert(1)</script>")
    scope = ViewFilter(as_of=T0 + timedelta(days=1))
    insight = context.services().insight
    rendered = insight.publish(view, scope)
    snapshot = insight.capture(view, scope, "Counting methodology at publication")
    original = insight.snapshot_bytes(snapshot.artifact_id)
    reopened = context.services().insight.snapshot(snapshot.artifact_id)
    assert reopened == snapshot
    assert reopened.document.model_json == rendered.model.model_dump_json(indent=2)
    assert reopened.document.markdown == rendered.markdown
    assert reopened.document.html == rendered.html
    assert reopened.document.csv == rendered.csv
    assert json.loads(original)["methodology_note"] == "Counting methodology at publication"
    assert publisher(context).metadata(snapshot.artifact_id).digest == snapshot.digest
    surface = HtmlSurface()
    surface.feed(snapshot.document.html)
    assert surface.scripts == 0
    assert "default-src 'none'" in surface.csp
    assert "<script>alert(1)</script>" not in snapshot.document.html


def test_historical_executive_capture_retains_unavailable_pqc_without_substituting_current_data(
    context: Context,
) -> None:
    seed_finding(context.database)
    scope = ViewFilter(
        as_of=T0 + timedelta(days=1),
        executive_panels=(ExecutivePanel.PQC, ExecutivePanel.ISOLATION),
    )
    insight = context.services().insight
    built = insight.build(ViewName.EXECUTIVE_SUMMARY, scope)
    assert isinstance(built, ExecutiveSummary)
    assert built.pqc is None and built.pqc_unavailable is not None
    assert built.rollup.total.open.high == 1
    assert built.isolation is not None
    assert built.rollup.as_of == built.isolation.threat_register.as_of == scope.as_of
    saved = insight.capture(ViewName.EXECUTIVE_SUMMARY, scope, "Historical evidence only")
    assert saved.document.model_json == built.model_dump_json(indent=2)
    archived = insight.snapshot_bytes(saved.artifact_id)
    replay = insight.compare(saved.artifact_id, ReportComparisonTarget.RECOMPUTED)
    assert replay.changes == ()
    assert insight.snapshot_bytes(saved.artifact_id) == archived


def test_same_time_recomputation_can_change_without_rewriting_the_report(context: Context) -> None:
    seed_finding(context.database)
    insight = context.services().insight
    scope = ViewFilter(as_of=T0 + timedelta(days=1))
    saved = insight.capture(ViewName.SCOREBOARD, scope, "Before late ingestion")
    before = insight.snapshot_bytes(saved.artifact_id)
    assert json.loads(saved.document.model_json)["open"]["high"] == 1

    seed_finding(context.database, title="Late-ingested earlier observation")
    result = context.services().insight.compare(
        saved.artifact_id, ReportComparisonTarget.RECOMPUTED
    )
    changes = {c.path: c for c in result.changes}
    assert (changes["/open/high"].before, changes["/open/high"].after) == (1, 2)
    assert changes["/open/high"].delta == Decimal(1)
    assert result.baseline_artifact_id == saved.artifact_id
    assert result.compared_artifact_id is None
    assert insight.snapshot_bytes(saved.artifact_id) == before
    assert json.loads(insight.snapshot(saved.artifact_id).document.model_json)["open"]["high"] == 1


def test_previous_comparison_and_history_use_reported_not_current_values(context: Context) -> None:
    seed_finding(context.database)
    insight = context.services().insight
    scope = ViewFilter(as_of=T0 + timedelta(days=1))
    first = insight.capture(ViewName.EXECUTIVE_SUMMARY, scope, "Original methodology")
    seed_finding(context.database)
    second = insight.capture(ViewName.EXECUTIVE_SUMMARY, scope, "Expanded population")
    seed_finding(context.database)

    assert second.document.previous_artifact_id == first.artifact_id
    assert second.document.previous_digest == first.digest
    comparison = insight.compare(second.artifact_id)
    change = next(c for c in comparison.changes if c.path == "/rollup/total/open/high")
    assert (change.before, change.after, change.delta) == (1, 2, Decimal(1))
    assert comparison.baseline_artifact_id == first.artifact_id
    assert comparison.compared_artifact_id == second.artifact_id
    history = insight.report_history(ViewName.EXECUTIVE_SUMMARY, scope)
    by_id = {s.artifact_id: json.loads(s.document.model_json) for s in history.model.snapshots}
    assert by_id[first.artifact_id]["rollup"]["total"]["open"]["high"] == 1
    assert by_id[second.artifact_id]["rollup"]["total"]["open"]["high"] == 2
    assert len(insight.history(ViewName.EXECUTIVE_SUMMARY, ViewFilter())) == 2
    assert len(insight.history(ViewName.SCOREBOARD, scope)) == 0
    assert len(insight.history(ViewName.EXECUTIVE_SUMMARY, ViewFilter(categories=("other",)))) == 0


def test_current_comparison_moves_the_data_cut_while_recomputed_keeps_it(context: Context) -> None:
    seed_finding(context.database)
    insight = context.services().insight
    snapshot = insight.capture(
        ViewName.EXECUTIVE_SUMMARY, ViewFilter(as_of=T0 - timedelta(days=1)), "Before observation"
    )
    replay = insight.compare(snapshot.artifact_id, ReportComparisonTarget.RECOMPUTED)
    current = insight.compare(snapshot.artifact_id, ReportComparisonTarget.CURRENT)
    assert replay.changes == ()
    changed = {c.path: c for c in current.changes}
    assert changed["/rollup/total/open/high"].after == 1
    assert changed["/rollup/total/open/high"].before == 0


def test_archive_reads_do_not_require_current_views_or_filter_schema(context: Context) -> None:
    insight = context.services().insight
    saved = insight.capture(ViewName.THREAT_REGISTER, ViewFilter(), "Historical bundle")
    pub = publisher(context)
    row = pub.metadata(saved.artifact_id)
    historical = saved.document.model_copy(update={"filter": {"retired_option": True}})
    result = pub.publish_reference(row.kind.removeprefix("reference:"), historical)
    reader = InsightService((), CLOCK, reports=pub)
    read = reader.snapshot(result.artifact_id)
    assert read.document.filter == {"retired_option": True}
    assert reader.snapshot_bytes(result.artifact_id) == pub.payload(result.artifact_id)
    with pytest.raises(ModelValidationError):
        reader.compare(result.artifact_id, ReportComparisonTarget.RECOMPUTED)


def test_tampered_bundle_is_never_returned_or_used_for_comparison(context: Context) -> None:
    insight = context.services().insight
    saved = insight.capture(ViewName.SCOREBOARD, ViewFilter(), "Original")
    row = publisher(context).metadata(saved.artifact_id)
    context.object_store.put(ObjectKey.parse(row.uri), b'{"tampered":true}')
    with pytest.raises(IntegrityError):
        insight.snapshot(saved.artifact_id)
    with pytest.raises(IntegrityError):
        insight.snapshot_bytes(saved.artifact_id)
    with pytest.raises(IntegrityError):
        insight.compare(saved.artifact_id, ReportComparisonTarget.CURRENT)


def test_broken_previous_digest_is_a_failure_not_a_new_baseline(context: Context) -> None:
    insight = context.services().insight
    first = insight.capture(ViewName.THREAT_REGISTER, ViewFilter(), "First report")
    second = insight.capture(ViewName.THREAT_REGISTER, ViewFilter(), "Second report")
    pub = publisher(context)
    row = pub.metadata(second.artifact_id)
    broken = second.document.model_copy(update={"previous_digest": "0" * 64})
    result = pub.publish_reference(row.kind.removeprefix("reference:"), broken)
    with pytest.raises(IntegrityError):
        insight.compare(result.artifact_id)
    assert insight.snapshot(first.artifact_id).digest == first.digest


def test_report_archive_boundaries_are_explicit(context: Context) -> None:
    insight = context.services().insight
    with pytest.raises(ValidationError):
        insight.capture(ViewName.SCOREBOARD, ViewFilter(), " \n ")
    assert insight.history(ViewName.SCOREBOARD, ViewFilter()) == ()
    with pytest.raises(ValidationError):
        insight.history(ViewName.SCOREBOARD, ViewFilter(), limit=0)
    with pytest.raises(ConfigError):
        InsightService((), CLOCK).history(ViewName.SCOREBOARD, ViewFilter())
    with pytest.raises(NotFoundError):
        insight.snapshot(uuid4())
    saved = insight.capture(ViewName.SCOREBOARD, ViewFilter(), "First")
    with pytest.raises(NotFoundError):
        insight.compare(saved.artifact_id)
    unrelated = publisher(context).publish_reference("unrelated", Model())
    with pytest.raises(ValidationError):
        insight.snapshot(unrelated.artifact_id)


@pytest.mark.parametrize(
    "scope",
    [
        ViewFilter(compare_as_of=T0),
        ViewFilter(first_party_divisor=Decimal("1.6")),
        ViewFilter(reprice_spend=True),
        ViewFilter(workstation_spend=True),
    ],
)
@pytest.mark.parametrize("operation", ["build", "publish", "report"])
def test_view_specific_filters_are_rejected_at_service_boundary(
    context: Context, scope: ViewFilter, operation: str
) -> None:
    with pytest.raises(ValidationError):
        getattr(context.services().insight, operation)(ViewName.SCOREBOARD, scope)


def test_latest_only_view_rejects_replay_without_mutating_its_report(context: Context) -> None:
    insight = context.services().insight
    saved = insight.capture(ViewName.REMEDIATION_INDEX, ViewFilter(), "Current work items")
    original = insight.snapshot_bytes(saved.artifact_id)
    with pytest.raises(ValidationError):
        insight.compare(saved.artifact_id, ReportComparisonTarget.RECOMPUTED)
    assert insight.snapshot_bytes(saved.artifact_id) == original


def test_raw_bundle_read_survives_a_different_bundle_schema(context: Context) -> None:
    insight = context.services().insight
    saved = insight.capture(ViewName.THREAT_REGISTER, ViewFilter(), "Original")
    pub = publisher(context)
    row = pub.metadata(saved.artifact_id)
    incompatible = pub.publish_reference(row.kind.removeprefix("reference:"), Model())
    original = pub.payload(incompatible.artifact_id)
    assert insight.snapshot_bytes(incompatible.artifact_id) == original
    with pytest.raises(IntegrityError):
        insight.snapshot(incompatible.artifact_id)
