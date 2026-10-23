"""FindingDecisions.record: a triage as an assessment, its document and one decision per verdict.

Ported from traust's emit_triage_ledger_events (fabdb13): verdict mapping, the auto-accept bar,
the audit valve and the review queue.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import Finding
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore, ObjectKey, ObjectRef
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings.citations import VerdictCitations
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.findings.review import ReviewPolicy
from traust_core.v1.services.ledger import LedgerConfig, LedgerService
from traust_core.v1.services.lint import Lint

NOW = datetime(2026, 10, 23, 9, tzinfo=UTC)
TRIAGE = Path(__file__).parents[3] / "fixtures" / "findings" / "triage"
CHECKOUT = TRIAGE / "canary-target"
PROVENANCE = Provenance(run_id=uuid4(), source=SourceType.TRIAGE_REPORT, occurred_at=NOW)
CLEAN_FP = {
    "verdict": "false_positive",
    "vote_breakdown": {"true_positive": 0, "hardening": 0, "false_positive": 3, "cannot_verify": 0},
    "confidence": 9.0,
    "claimed_severity": "LOW",
    "refute_reasons": ["guard before use"],
    "rationale": "guard exists at entry.c:47 before the fread call.",
    "first_links": ["entry.c:47"],
}


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@dataclass
class Scan:
    assessment_id: Any
    findings: list[Finding]


def scan(engine: Engine, n: int = 3, unreported: int = 0) -> Scan:
    """An assessment reporting n findings, then `unreported` more findings it didn't report."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        assessment = seed.assessment()
        findings = [
            seed.finding(fingerprint=hashlib.sha256(str(uuid4()).encode()).hexdigest())
            for _ in range(n + unreported)
        ]
        for f in findings[:n]:
            seed.occurrence(f, assessment)
        uow.commit()
    return Scan(assessment.id, findings)


def triage(*verdicts: tuple[Finding | None, dict[str, Any]]) -> TriageArtifact:
    doc = json.loads((TRIAGE / "triage-report.json").read_text())
    doc["findings"] = [
        {
            "id": f"f{i:03d}",
            "title": "Unbounded copy in parse_alpha",
            "rationale": "reachable from main at entry.c:53",
            **({"fingerprint": f.fingerprint, "fingerprint_algo": f.fingerprint_algo} if f else {}),
            **v,
        }
        for i, (f, v) in enumerate(verdicts, 1)
    ]
    return TriageArtifact.from_document(doc)


def decisions(
    engine: Engine, objects: InMemoryObjectStore | None = None, **kw: Any
) -> FindingDecisions:
    uow = SqlTraustUnitOfWork(engine)
    return FindingDecisions(
        uow,
        LedgerService(uow, LedgerConfig()) if kw.pop("ledger", False) else None,
        Lint({TriageArtifact: [VerdictCitations()]}),
        FindingPrecedents(uow),
        clock=FixedClock(NOW),
        objects=objects or InMemoryObjectStore(),
        review=ReviewPolicy(**kw),
    )


def pending(engine: Engine, finding: Finding) -> list[tuple[str | None, bool]]:
    with SqlTraustUnitOfWork(engine) as uow:
        return [
            (r.reason, r.decision_id is not None)
            for r in uow.review_items.list_for_finding(finding.id)
            if r.status == "pending"
        ]


def test_each_verdict_becomes_a_decision_or_a_review_item(engine: Engine) -> None:
    s = scan(engine, 5)
    tp, hard, fp, undetermined, manual = s.findings
    doc = triage(
        (tp, {"verdict": "true_positive", "severity": "high"}),
        (
            hard,
            {"verdict": "hardening", "rationale": "accurate CIS gap at deploy/deployment.yaml:19"},
        ),
        (fp, CLEAN_FP),
        (undetermined, {"verdict": "undetermined", "rationale": "cited material not found"}),
        (manual, {"verdict": "true_positive", "verify_verdict": "needs_manual_test"}),
        (None, {"verdict": "duplicate", "duplicate_of": "f001"}),
    )
    made = {
        d.finding_id: d
        for d in decisions(engine).record(s.assessment_id, doc, PROVENANCE, CHECKOUT)
    }

    assert set(made) == {tp.id, hard.id, fp.id}
    assert (made[tp.id].validity, made[tp.id].severity) == ("confirmed", "high")
    assert (made[hard.id].validity, made[hard.id].severity) == ("hardening", None)
    assert made[hard.id].rationale.endswith("an accurate gap with no concrete exploit path)")
    assert (made[fp.id].validity, made[fp.id].auto_accept_tier) == ("false_positive", True)
    assert "refuted: guard before use; exclusion rule none" in made[fp.id].rationale
    assert all(d.actor is None and d.occurred_at == NOW for d in made.values())
    assert pending(engine, undetermined) == [("undetermined_finding", False)]
    assert pending(engine, manual) == [("needs_manual_test", False)]
    assert pending(engine, fp) == [
        ("fp_audit_valve", True)
    ]  # no salt: every auto-accept is audited
    assert pending(engine, tp) == pending(engine, hard) == []


def test_the_triage_is_an_assessment_with_its_document(engine: Engine) -> None:
    s = scan(engine, 1)
    objects = InMemoryObjectStore()
    doc = triage((s.findings[0], {"verdict": "true_positive"}))
    [made] = decisions(engine, objects).record(s.assessment_id, doc, PROVENANCE, CHECKOUT)
    with SqlTraustUnitOfWork(engine) as uow:
        assessment = uow.assessments.get(made.assessment_id)
        [artifact] = uow.artifacts.list_for_assessment(assessment.id)
        triaged = uow.assessments.get(s.assessment_id)
    assert (assessment.kind, assessment.assessor, assessment.status) == (
        "triage",
        "triage",
        "completed",
    )
    assert (assessment.baseline_assessment_id, assessment.repository_ref_id) == (
        triaged.id,
        triaged.repository_ref_id,
    )
    assert (assessment.assessor_version, assessment.occurred_at) == ("0.26.0-abc1234", NOW)
    assert (artifact.kind, made.artifact_id) == ("triage", artifact.id)
    ref = ObjectRef(ObjectKey.parse(artifact.uri), artifact.digest, len(doc.payload))
    assert objects.get(ref) == doc.payload


@pytest.mark.parametrize(
    ("change", "auto"),
    [
        ({}, True),
        ({"vote_breakdown": {**CLEAN_FP["vote_breakdown"], "false_positive": 1}}, False),
        ({"vote_breakdown": {**CLEAN_FP["vote_breakdown"], "hardening": 1}}, False),
        ({"confidence": 7.9}, False),
        ({"claimed_severity": "medium"}, False),
        ({"claimed_severity": "informational"}, True),
        ({"first_links": ["lib/imaginary.c:12"]}, False),  # broken citation: lint not clean
    ],
)
def test_the_auto_accept_bar(engine: Engine, change: dict[str, Any], auto: bool) -> None:
    s = scan(engine, 1)
    [made] = decisions(engine).record(
        s.assessment_id, triage((s.findings[0], {**CLEAN_FP, **change})), PROVENANCE, CHECKOUT
    )
    assert made.auto_accept_tier is auto
    assert pending(engine, s.findings[0]) == ([("fp_audit_valve", True)] if auto else [])


def test_the_audit_valve_queues_exactly_the_findings_the_policy_samples(engine: Engine) -> None:
    s = scan(engine, 40)
    doc = triage(*((f, CLEAN_FP) for f in s.findings))
    made = decisions(engine, valve_salt="s3cret").record(s.assessment_id, doc, PROVENANCE, CHECKOUT)
    sampled = {d.finding_id for d in made if ReviewPolicy("s3cret").needs_signoff(d)}
    queued = {f.id for f in s.findings if pending(engine, f)}
    assert queued == sampled
    for f in s.findings:
        if f.id in queued:
            assert pending(engine, f) == [("fp_audit_valve", True)]


def test_re_recording_changes_nothing(engine: Engine) -> None:
    s = scan(engine, 2)
    doc = triage(
        (s.findings[0], {"verdict": "true_positive"}), (s.findings[1], {"verdict": "undetermined"})
    )
    first = decisions(engine).record(s.assessment_id, doc, PROVENANCE, CHECKOUT)
    again = decisions(engine).record(s.assessment_id, doc, PROVENANCE, CHECKOUT)
    assert [d.id for d in again] == [d.id for d in first]
    assert pending(engine, s.findings[1]) == [("undetermined_finding", False)]
    with SqlTraustUnitOfWork(engine) as uow:
        assert len(uow.artifacts.list_for_assessment(first[0].assessment_id)) == 1


def test_a_verdict_on_a_finding_the_assessment_did_not_report_writes_nothing(
    engine: Engine,
) -> None:
    s = scan(engine, 1, unreported=1)
    stranger = s.findings[1]
    doc = triage(
        (s.findings[0], {"verdict": "true_positive"}),
        (stranger, {"verdict": "true_positive"}),
        (None, {"verdict": "true_positive"}),
    )
    with pytest.raises(ValidationError, match="didn't report: f002, f003"):
        decisions(engine).record(s.assessment_id, doc, PROVENANCE, CHECKOUT)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.decisions.list_for_finding(s.findings[0].id) == []


def test_each_decision_is_proved_on_the_ledger(engine: Engine) -> None:
    s = scan(engine, 1)
    [made] = decisions(engine, ledger=True).record(
        s.assessment_id, triage((s.findings[0], {"verdict": "true_positive"})), PROVENANCE, CHECKOUT
    )
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.events.find_by_decision(made.id) is not None


def test_an_unknown_assessment_is_not_found(engine: Engine) -> None:
    from traust_core.v1.errors import NotFoundError

    with pytest.raises(NotFoundError):
        decisions(engine).record(uuid4(), triage(), PROVENANCE, CHECKOUT)


def test_a_long_rationale_is_stored_whole(engine: Engine) -> None:
    s = scan(engine, 1)
    why = "reachable from main at entry.c:53; " * 40
    doc = triage((s.findings[0], {"verdict": "true_positive", "rationale": why}))
    made = decisions(engine).record(s.assessment_id, doc, PROVENANCE, CHECKOUT)
    with SqlTraustUnitOfWork(engine) as uow:
        stored = uow.decisions.get(made[0].id)
    assert len(why) > 1000
    assert why.strip() in stored.rationale
