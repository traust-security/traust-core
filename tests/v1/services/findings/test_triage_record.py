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
from traust_core.v1.errors import DocumentError, ValidationError
from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import Finding
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore, ObjectKey, ObjectRef
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    PublishSpec,
    PublishSpecs,
)
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
    "claimed_severity": "low",
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
            {
                "verdict": "true_positive",
                "kind": "weakness",
                "severity": None,
                "exclusion_rule": 13,
                "rationale": "accurate CIS gap at deploy/deployment.yaml:19",
            },
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
    assert (made[hard.id].validity, made[hard.id].severity) == ("confirmed", None)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.findings.get(hard.id).kind == "weakness"
    assert "accurate CIS gap at deploy/deployment.yaml:19" in made[hard.id].rationale
    assert "exclusion rule 13" in made[hard.id].rationale
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
    assert pending(engine, s.findings[0]) == [
        ("fp_audit_valve" if auto else "analyst_review", True)
    ]


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


@pytest.mark.parametrize(
    ("existing", "supplied", "expected"),
    [
        (None, None, None),
        ("weakness", None, "weakness"),
        ("vulnerability", None, "vulnerability"),
        (None, "vulnerability", "vulnerability"),
        ("weakness", "vulnerability", "vulnerability"),
        ("vulnerability", "weakness", "weakness"),
    ],
)
def test_explicit_kind_updates_the_finding_and_omission_preserves_it(
    engine: Engine, existing: str | None, supplied: str | None, expected: str | None
) -> None:
    s = scan(engine, 1)
    finding = s.findings[0]
    with SqlTraustUnitOfWork(engine) as uow:
        uow.findings.update(finding.model_copy(update={"kind": existing}))
        uow.commit()
    verdict: dict[str, Any] = {
        "verdict": "true_positive",
        **({"kind": supplied} if supplied else {}),
    }
    if supplied == "weakness":
        verdict["exclusion_rule"] = 13

    [made] = decisions(engine).record(
        s.assessment_id, triage((finding, verdict)), PROVENANCE, CHECKOUT
    )

    assert made.validity == "confirmed"
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.findings.get(finding.id).kind == expected


@pytest.mark.parametrize(
    ("verdict", "verify", "reason"),
    [
        ("undetermined", None, "undetermined_finding"),
        ("true_positive", "needs_manual_test", "needs_manual_test"),
    ],
)
@pytest.mark.parametrize("kind", ["weakness", "vulnerability"])
def test_kind_is_recorded_without_manufacturing_proof_for_review_only_findings(
    engine: Engine, verdict: str, verify: str | None, reason: str, kind: str
) -> None:
    s = scan(engine, 1)
    finding = s.findings[0]
    doc = triage(
        (
            finding,
            {"verdict": verdict, "verify_verdict": verify, "kind": kind, "exclusion_rule": 13}
            if kind == "weakness"
            else {"verdict": verdict, "verify_verdict": verify, "kind": kind},
        )
    )

    assert decisions(engine).record(s.assessment_id, doc, PROVENANCE, CHECKOUT) == []
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.findings.get(finding.id).kind == kind
        assert uow.decisions.list_for_finding(finding.id) == []
    assert pending(engine, finding) == [(reason, False)]
    later_kind = "vulnerability" if kind == "weakness" else "weakness"
    with SqlTraustUnitOfWork(engine) as uow:
        current = uow.findings.get(finding.id)
        uow.findings.update(current.model_copy(update={"kind": later_kind}))
        uow.commit()
    assert decisions(engine).record(s.assessment_id, doc, PROVENANCE, CHECKOUT) == []
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.findings.get(finding.id).kind == later_kind
    assert pending(engine, finding) == [(reason, False)]


def test_false_positive_kind_is_independent_of_validity_and_keeps_autoaccept(
    engine: Engine,
) -> None:
    s = scan(engine, 1)
    finding = s.findings[0]
    [made] = decisions(engine).record(
        s.assessment_id,
        triage((finding, {**CLEAN_FP, "kind": "weakness"})),
        PROVENANCE,
        CHECKOUT,
    )

    assert (made.validity, made.severity, made.auto_accept_tier) == ("false_positive", None, True)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.findings.get(finding.id).kind == "weakness"
    assert pending(engine, finding) == [("fp_audit_valve", True)]


@pytest.mark.parametrize("copied", [False, True])
def test_record_uses_serialized_findings_instead_of_mutable_views(
    engine: Engine, copied: bool
) -> None:
    s = scan(engine, 1, unreported=1)
    finding, stranger = s.findings
    original = triage(
        (finding, {"verdict": "true_positive", "kind": "vulnerability", "severity": "high"})
    )
    document = json.loads(original.payload)
    doc = (
        TriageArtifact(original.payload, document)
        if copied
        else TriageArtifact.from_document(document)
    )
    document["findings"][0].update(
        verdict="hardening",
        kind="weakness",
        fingerprint=stranger.fingerprint,
        severity=None,
    )
    objects = InMemoryObjectStore()

    [made] = decisions(engine, objects).record(s.assessment_id, doc, PROVENANCE, CHECKOUT)

    assert (made.finding_id, made.validity, made.severity) == (finding.id, "confirmed", "high")
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.findings.get(finding.id).kind == "vulnerability"
        assert uow.findings.get(stranger.id).kind is None
        assert uow.decisions.list_for_finding(stranger.id) == []
        [artifact] = uow.artifacts.list_for_assessment(made.assessment_id)
    assert objects.get(objects.stat(ObjectKey.parse(artifact.uri))) == original.payload


@pytest.mark.parametrize("copied", [False, True])
@pytest.mark.parametrize("noncanonical", [{"verdict": "hardening"}, {"claimed_severity": "LOW"}])
def test_noncanonical_payload_cannot_be_hidden_by_a_copied_or_mutated_view(
    engine: Engine, copied: bool, noncanonical: dict[str, str]
) -> None:
    s = scan(engine, 2)
    first, second = s.findings
    source = triage(
        (first, {"verdict": "undetermined", "kind": "weakness"}),
        (second, {"verdict": "true_positive", **noncanonical}),
    )
    document = json.loads(source.payload)
    doc = (
        TriageArtifact(source.payload, document)
        if copied
        else TriageArtifact.from_document(document)
    )
    document["findings"][1].update(verdict="true_positive", claimed_severity="low")
    objects = InMemoryObjectStore()

    with pytest.raises(DocumentError):
        decisions(engine, objects).record(s.assessment_id, doc, PROVENANCE, CHECKOUT)

    with SqlTraustUnitOfWork(engine) as uow:
        source_assessment = uow.assessments.get(s.assessment_id)
        assert uow.assessments.list_for_refs([source_assessment.repository_ref_id], "triage") == []
        assert uow.artifacts.list_for_assessment(s.assessment_id) == []
        for finding in s.findings:
            assert uow.findings.get(finding.id) == finding
            assert uow.decisions.list_for_finding(finding.id) == []
            assert uow.review_items.list_for_finding(finding.id) == []
    assert list(objects.list()) == []


@pytest.mark.parametrize("kind", [None, "hardening", "unknown"])
def test_invalid_serialized_kind_is_rejected_before_recording(
    engine: Engine, kind: str | None
) -> None:
    s = scan(engine, 1)
    original = triage((s.findings[0], {"verdict": "true_positive"}))
    document = json.loads(original.payload)
    document["findings"][0]["kind"] = kind
    doc = TriageArtifact(json.dumps(document).encode(), json.loads(original.payload))
    objects = InMemoryObjectStore()

    with pytest.raises(DocumentError):
        decisions(engine, objects).record(s.assessment_id, doc, PROVENANCE, CHECKOUT)

    with SqlTraustUnitOfWork(engine) as uow:
        source_assessment = uow.assessments.get(s.assessment_id)
        assert uow.assessments.list_for_refs([source_assessment.repository_ref_id], "triage") == []
        assert uow.decisions.list_for_finding(s.findings[0].id) == []
        assert uow.findings.get(s.findings[0].id).kind is None
    assert list(objects.list()) == []


@pytest.mark.parametrize("prepublished", [False, True])
def test_new_hardening_admission_is_refused_even_when_its_bytes_are_prepublished(
    engine: Engine, prepublished: bool
) -> None:
    s = scan(engine, 2)
    doc = triage(
        (s.findings[0], {"verdict": "true_positive", "kind": "weakness", "exclusion_rule": 13}),
        (s.findings[1], {"verdict": "hardening"}),
    )
    objects = InMemoryObjectStore()
    provenance = PROVENANCE
    if prepublished:
        publisher = ArtifactPublisher(
            PublishSpecs(PublishSpec(TriageArtifact)), objects, SqlTraustUnitOfWork(engine)
        )
        published = publisher.publish_ref(doc)
        provenance = PROVENANCE.model_copy(update={"artifact": published})
    before = list(objects.list())

    with pytest.raises(DocumentError):
        decisions(engine, objects).record(s.assessment_id, doc, provenance, CHECKOUT)

    with SqlTraustUnitOfWork(engine) as uow:
        source_assessment = uow.assessments.get(s.assessment_id)
        assert uow.assessments.list_for_refs([source_assessment.repository_ref_id], "triage") == []
        for finding in s.findings:
            assert uow.findings.get(finding.id) == finding
            assert uow.decisions.list_for_finding(finding.id) == []
            assert uow.review_items.list_for_finding(finding.id) == []
        if prepublished:
            assert uow.artifacts.get(published.id).assessment_id is None
    assert list(objects.list()) == before


@pytest.mark.parametrize("stored_validity", ["hardening", "confirmed"])
def test_historical_hardening_replay_preserves_raw_bytes_ids_and_later_kind(
    engine: Engine, stored_validity: str
) -> None:
    s = scan(engine, 1)
    finding = s.findings[0]
    historical = triage((finding, {"verdict": "hardening", "claimed_severity": "LOW"}))
    raw = json.dumps(json.loads(historical.payload), separators=(",", ":")).encode() + b"\n\n"
    objects = InMemoryObjectStore()
    ref = objects.put(ObjectKey.parse(f"triage/{sha256_hex(raw)}.json"), raw)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        source = uow.assessments.get(s.assessment_id)
        run = seed.assessment(
            uow.repository_refs.get(source.repository_ref_id),
            kind="triage",
            assessor="triage",
            assessor_version=historical.triage_context.harness_version,
            baseline_assessment_id=source.id,
            occurred_at=NOW,
        )
        artifact = seed.artifact(run, digest=ref.sha256, kind="triage", uri=str(ref.key))
        original = seed.decision(
            finding,
            assessment_id=run.id,
            artifact_id=artifact.id,
            statement_key="historical-statement-key",
            validity=stored_validity,
            actor=None,
            severity=None,
            rationale="The stored defense-in-depth finding has no concrete exploit path.",
            occurred_at=NOW,
        )
        uow.findings.update(finding.model_copy(update={"kind": "vulnerability"}))
        uow.commit()
    owner = decisions(engine, objects)

    [replayed] = owner.record(s.assessment_id, TriageArtifact.parse(raw), PROVENANCE, CHECKOUT)

    assert (replayed.id, replayed.assessment_id, replayed.artifact_id) == (
        original.id,
        run.id,
        artifact.id,
    )
    assert (replayed.validity, replayed.severity) == ("confirmed", None)
    assert owner.get(original.id).validity == "confirmed"
    with pytest.raises(DocumentError):
        owner.record(s.assessment_id, historical, PROVENANCE, CHECKOUT)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.decisions.get(original.id) == original
        assert uow.findings.get(finding.id).kind == "vulnerability"
        assert uow.artifacts.list_for_assessment(run.id) == [artifact]
        assert uow.assessments.list_for_refs([source.repository_ref_id], "triage") == [run]
    assert objects.get(ref) == raw
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        later = seed.assessment(uow.repository_refs.get(source.repository_ref_id))
        seed.occurrence(finding, later)
        uow.commit()
    with pytest.raises(DocumentError):
        owner.record(later.id, TriageArtifact.parse(raw), PROVENANCE, CHECKOUT)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.assessments.list_for_refs([source.repository_ref_id], "triage") == [run]
        assert uow.decisions.list_for_finding(finding.id) == [original]


@pytest.mark.parametrize("rule", [13, "13"])
def test_confirmed_weakness_keeps_its_kind_rule_and_rationale_without_vulnerability_severity(
    engine: Engine, rule: int | str
) -> None:
    s = scan(engine, 1)
    finding = s.findings[0]
    doc = triage(
        (
            finding,
            {
                "verdict": "true_positive",
                "kind": "weakness",
                "severity": None,
                "exclusion_rule": rule,
                "rationale": "Verified missing defense-in-depth control at entry.c:53.",
            },
        )
    )
    objects = InMemoryObjectStore()

    [made] = decisions(engine, objects, ledger=True).record(
        s.assessment_id, doc, PROVENANCE, CHECKOUT
    )

    assert (made.validity, made.severity) == ("confirmed", None)
    assert "Verified missing defense-in-depth control at entry.c:53." in made.rationale
    assert "weakness" in made.rationale and "exclusion rule 13" in made.rationale
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.findings.get(finding.id).kind == "weakness"
        assert uow.events.find_by_decision(made.id) is not None
        [artifact] = uow.artifacts.list_for_assessment(made.assessment_id)
    stored = TriageArtifact.parse(objects.get(objects.stat(ObjectKey.parse(artifact.uri))))
    assert stored.payload == doc.payload
    assert (stored.findings[0].kind, stored.findings[0].severity) == ("weakness", None)
    assert stored.findings[0].exclusion_rule == rule


@pytest.mark.parametrize(
    "contradiction",
    [
        {"kind": "weakness", "severity": "high", "exclusion_rule": 13},
        {"kind": "weakness", "severity": None},
        {"kind": "weakness", "exclusion_rule": 12},
        {"exclusion_rule": 13},
        {"exclusion_rule": "13"},
        {"kind": "vulnerability", "exclusion_rule": 13},
    ],
)
def test_weakness_contract_contradictions_are_refused_before_any_new_rows(
    engine: Engine, contradiction: dict[str, Any]
) -> None:
    s = scan(engine, 2)
    doc = triage(
        (s.findings[0], {"verdict": "undetermined", "kind": "weakness"}),
        (s.findings[1], {"verdict": "true_positive", **contradiction}),
    )
    objects = InMemoryObjectStore()

    with pytest.raises(DocumentError):
        decisions(engine, objects).record(s.assessment_id, doc, PROVENANCE, CHECKOUT)

    with SqlTraustUnitOfWork(engine) as uow:
        source = uow.assessments.get(s.assessment_id)
        assert uow.assessments.list_for_refs([source.repository_ref_id], "triage") == []
        assert uow.artifacts.list_for_assessment(s.assessment_id) == []
        for finding in s.findings:
            assert uow.findings.get(finding.id) == finding
            assert uow.decisions.list_for_finding(finding.id) == []
            assert uow.review_items.list_for_finding(finding.id) == []
    assert list(objects.list()) == []
