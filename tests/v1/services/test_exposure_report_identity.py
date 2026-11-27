"""A report's dependency finding and the impact analysis of the same advisory and package are
one finding (`ExposureKey`); an impact occurrence recorded after the report, carrying neither
places nor CVSS, doesn't hide the report's."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.services.test_exposure_impact import (
    GHSA,
    SAMPLE,
    advisory_id,
    affected_doc,
    one,
    provenance,
    refs,
    service,
)
from tests.v1.services.test_exposure_impact import engine as engine
from traust_core.v1.context import Config, Context
from traust_core.v1.models.artifacts import SecurityAuditArtifact
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.vocabulary import ImpactGovulncheck, SourceType
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

BODY = json.loads(
    (Path(__file__).parents[2] / "fixtures" / "reporting" / "widget-report.json").read_text()
)
BODY["remediation_roadmap"] = [
    {**item, "priority": "p3", "effort": None} for item in BODY["remediation_roadmap"]
]
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"


def _report(path: str = "go.mod") -> SecurityAuditArtifact:
    body = copy.deepcopy(BODY)
    first = body["findings"][0]
    first.update(
        title=f"{GHSA} in google.golang.org/grpc",
        category="supply-chain",
        cwes=["CWE-400"],
        locations=[{"path": path, "lines": "7"}],
        cvss={"vector": VECTOR, "score": 7.5},
        severity="high",
        dependency={
            "advisory": str(GHSA),
            "module": "google.golang.org/grpc",
            "ecosystem": "go",
            "classification": "likely_affected",
            "evidence_level": "manifest",
        },
    )
    body["findings"] = [first]
    for row in body["findings_summary"]:
        row["finding_ids"] = [first["id"]] if row["severity"] == "high" else []
        row["count"] = len(row["finding_ids"])
    body["executive_summary"]["severity_counts"] = {
        k: (1 if k == "high" else 0) for k in body["executive_summary"]["severity_counts"]
    }
    body["remediation_roadmap"] = [{**body["remediation_roadmap"][0], "addresses": [first["id"]]}]
    return SecurityAuditArtifact.from_document(body)


def _services(engine: Engine, tmp_path: Path) -> Any:
    ctx = Context(Config(home=tmp_path))
    ctx.__dict__["database"] = engine
    return ctx.services()


def test_an_impact_after_the_report_is_the_same_finding_and_keeps_its_places_and_score(
    engine: Engine, tmp_path: Path
) -> None:
    [app] = refs(engine, 1)
    assert app.id is not None
    exposure = service(engine)
    exposure.ingest_sbom(SAMPLE, app.id)
    found = advisory_id(exposure)  # the advisory is stored before the report records
    services = _services(engine, tmp_path)
    audit = services.assessment.record(
        _report(),
        app.id,
        AssessmentKind.SECURE_CODE_CANONICAL,
        "skill:secure-code-audit",
        "0.1.0",
        Provenance(
            run_id=uuid4(),
            source=SourceType.INTERACTIVE,
            occurred_at=datetime(2026, 10, 22, 9, tzinfo=UTC),
        ),
    )
    assert audit.id is not None
    impact = exposure.record(
        app.id, affected_doc(one(exposure.prepare(found, app.id))), provenance()
    )
    with SqlTraustUnitOfWork(engine) as uow:
        [reported] = uow.occurrences.list_for_assessment(audit.id)
        occurrences = uow.occurrences.list_for_finding(reported.finding_id)
    assert impact.finding_id == reported.finding_id and len(occurrences) == 2
    [view] = services.findings.list_by_ids([reported.finding_id])
    assert view.occurrence is not None and view.occurrence.assessment_id == impact.assessment_id
    assert [(p.path, p.line_start) for p in view.locations] == [("go.mod", 7)]
    assert view.cvss is not None and view.cvss.vector == VECTOR


def _audit(services: Any, ref: UUID, path: str, day: int) -> UUID:
    saved = services.assessment.record(
        _report(path),
        ref,
        AssessmentKind.SECURE_CODE_CANONICAL,
        "skill:secure-code-audit",
        "0.1.0",
        Provenance(
            run_id=uuid4(),
            source=SourceType.INTERACTIVE,
            occurred_at=datetime(2026, 10, day, 9, tzinfo=UTC),
        ),
    )
    assert saved.id is not None
    return saved.id  # type: ignore[no-any-return]


def test_the_newest_located_occurrence_is_shown_and_only_it_is_read(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two audits, then an impact analysis: the view shows the newer audit's places, read by
    stepping back one occurrence, never by reading the whole history."""
    from traust_core.v1.repositories.traust.assessments import SqlLocationRepository

    [app] = refs(engine, 1)
    assert app.id is not None
    exposure = service(engine)
    exposure.ingest_sbom(SAMPLE, app.id)
    found = advisory_id(exposure)
    services = _services(engine, tmp_path)
    _audit(services, app.id, "go.mod", 20)
    newer = _audit(services, app.id, "vendor/modules.txt", 21)
    exposure.record(app.id, affected_doc(one(exposure.prepare(found, app.id))), provenance())
    with SqlTraustUnitOfWork(engine) as uow:
        [occurrence] = uow.occurrences.list_for_assessment(newer)
    asked: list[list[UUID]] = []
    original = SqlLocationRepository.list_for_occurrences

    def spy(self: Any, ids: Any, **kwargs: Any) -> Any:
        asked.append(list(ids))
        return original(self, ids, **kwargs)

    monkeypatch.setattr(SqlLocationRepository, "list_for_occurrences", spy)
    [view] = services.findings.list_by_ids([occurrence.finding_id])
    assert [p.path for p in view.locations] == ["vendor/modules.txt"]
    assert [len(ids) for ids in asked] == [1, 1] and asked[1] == [occurrence.id]


def test_many_impact_occurrences_cost_two_reads_not_one_per_occurrence(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A located audit followed by many placeless impact occurrences: the view finds the audit's
    places with one ids-only read and one location read, however long the history."""
    from traust_core.v1.repositories.traust.assessments import SqlLocationRepository

    [app] = refs(engine, 1)
    assert app.id is not None
    exposure = service(engine)
    exposure.ingest_sbom(SAMPLE, app.id)
    found = advisory_id(exposure)
    services = _services(engine, tmp_path)
    audit = _audit(services, app.id, "go.mod", 20)
    prepared = one(exposure.prepare(found, app.id))
    reached = prepared.evidence.model_copy(
        update={"govulncheck": ImpactGovulncheck.SYMBOL_REACHABLE}
    )
    for run in range(12):  # distinct analyses: a replayed document adds no occurrence
        doc = prepared.model_copy(update={"evidence": reached}).document(f"1.0.{run}")
        exposure.record(app.id, doc, provenance())
    with SqlTraustUnitOfWork(engine) as uow:
        [occurrence] = uow.occurrences.list_for_assessment(audit)
        history = uow.occurrences.list_for_finding(occurrence.finding_id)
    assert len(history) == 13
    calls: list[str] = []
    for name in ("list_for_occurrences", "located"):
        original = getattr(SqlLocationRepository, name)

        def spy(self: Any, ids: Any, _o: Any = original, _n: str = name, **kw: Any) -> Any:
            calls.append(_n)
            return _o(self, ids, **kw)

        monkeypatch.setattr(SqlLocationRepository, name, spy)
    [view] = services.findings.list_by_ids([occurrence.finding_id])
    assert [p.path for p in view.locations] == ["go.mod"]
    assert calls == ["list_for_occurrences", "located", "list_for_occurrences"]


def _ids(engine: Engine, assessment_id: UUID) -> set[UUID]:
    with SqlTraustUnitOfWork(engine) as uow:
        return {o.finding_id for o in uow.occurrences.list_for_assessment(assessment_id)}
