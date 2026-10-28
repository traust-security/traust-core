from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
import sqlalchemy as sa

from tests.v1.repositories.tables.conftest import Seed, saved_id
from tests.v1.services import test_validation as samples
from traust_core.v1.context import Config, Context
from traust_core.v1.context.context import Services
from traust_core.v1.errors import NotFoundError, RepositoryError
from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.findings import CandidateFormat, FindingExternalRef, PrecedentStrength
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.validation import (
    ValidationRecordResult,
)
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.repositories import ObjectKey, ObjectRef
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.validation import ValidationRecords, validation_link

engine = samples.engine
harness = samples.harness
FIXTURES = Path(__file__).parents[3] / "fixtures"


@dataclass(frozen=True)
class World:
    harness: samples.ValidationHarness
    services: Services
    assessment_id: UUID
    finding_id: UUID

    def precedents(self) -> list[UUID]:
        (item,) = self.services.findings.decisions.prepare(self.assessment_id).items
        assert all(p.reason.strength == PrecedentStrength.MACHINE for p in item.precedents)
        return [p.decision.id for p in item.precedents]

    def records(self) -> ValidationRecords:
        return ValidationRecords(SqlTraustUnitOfWork(self.harness.engine), self.harness.objects)


@pytest.fixture
def world(harness: samples.ValidationHarness, tmp_path: Path) -> World:
    with SqlTraustUnitOfWork(harness.engine) as uow:
        seed = Seed(uow)
        cwe = seed.cwe()
        for finding in harness.findings:
            seed.finding_cwe(finding, cwe)
            occurrence = uow.occurrences.find(saved_id(finding), saved_id(harness.source))
            seed.location(occurrence, path="third_party/example/parse.go", symbol="Parse")
        repository = seed.repository(url="https://github.com/example/current")
        target = seed.assessment(seed.repository_ref(repository))
        finding = seed.finding(repository)
        seed.finding_cwe(finding, cwe)
        seed.location(
            seed.occurrence(finding, target), path="vendor/example/parse.go", symbol="Parse"
        )
        uow.commit()
    context = Context(Config(home=tmp_path / "context"), object_store=harness.objects)
    context.__dict__["database"] = harness.engine
    return World(harness, context.services(), saved_id(target), saved_id(finding))


def sound(world: World, **changes: Any) -> ValidationRecordResult:
    observed = (FIXTURES / "validation/rbac-concrete.txt").read_text()
    doc = samples.report(
        world.harness, "refuted", finding={"steps": [samples.probe(observed=observed)]}
    )
    return world.harness.validation.record(
        doc, samples.PROVENANCE, world.harness.bindings(**changes)
    )


def test_recorded_sound_refutation_is_context_while_human_review_stays_pending(
    world: World,
) -> None:
    result = sound(world)
    outcome = result.findings[0]
    assert world.precedents() == [outcome.decision_id]
    source = world.services.findings.get(outcome.finding_id)
    assert source.is_open() and source.disposition.awaiting_signoff
    assert world.services.findings.review.get(outcome.review_item_ids[0]).status == "pending"
    assert (
        world.records()
        .check_refutations([world.harness.decisions.get(outcome.decision_id)])[0]
        .reason
        is None
    )


def test_recording_replay_does_not_duplicate_precedents(world: World) -> None:
    first = sound(world)
    assert sound(world) == first
    assert world.precedents() == [first.findings[0].decision_id]


@pytest.mark.parametrize(
    "fault", ["controls", "differential", "error", "attestation", "inconclusive"]
)
def test_unsound_and_inconclusive_recordings_never_become_precedents(
    world: World, fault: str
) -> None:
    finding: dict[str, Any] = {"steps": [samples.probe()]}
    if fault == "controls":
        finding["steps"] = [samples.probe(controls=[])]
    elif fault == "differential":
        finding["steps"] = [
            samples.probe(differential={"neighbor_action": "get pods", "discriminated": False})
        ]
    elif fault == "error":
        finding["steps"] = [
            samples.probe(observed="Error from server (Forbidden): User cannot get pods")
        ]
    doc = samples.report(
        world.harness,
        "inconclusive" if fault == "inconclusive" else "refuted",
        finding=finding,
        attestation=None if fault == "attestation" else samples.ATTESTATION,
    )
    result = world.harness.validation.record(doc, samples.PROVENANCE, world.harness.bindings())
    assert result.findings[0].decision_id is None
    assert world.precedents() == []


@pytest.mark.parametrize("companion", [False, True], ids=["report", "companion"])
@pytest.mark.parametrize("fault", ["missing", "corrupt"])
def test_unavailable_evidence_is_excluded_with_a_reason(
    world: World,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    companion: bool,
    fault: str,
) -> None:
    result = sound(world)
    artifact_id = (result.evidence_artifact_ids if companion else result.artifact_ids)[0]
    with SqlTraustUnitOfWork(world.harness.engine) as uow:
        artifact = uow.artifacts.get(artifact_id)
    if fault == "corrupt":
        world.harness.objects.put(ObjectKey.parse(artifact.uri), b"corrupted evidence")
    else:
        stat = world.harness.objects.stat

        def missing(key: ObjectKey) -> ObjectRef:
            if str(key) == artifact.uri:
                raise NotFoundError("recorded object unavailable")
            return stat(key)

        monkeypatch.setattr(world.harness.objects, "stat", missing)
    assert world.precedents() == []
    assert "unverifiable-evidence" in caplog.text
    decision = world.harness.decisions.get(result.findings[0].decision_id)
    (check,) = world.records().check_refutations([decision])
    assert (
        check.reason
        == f"unverifiable-evidence:{'IntegrityError' if fault == 'corrupt' else 'NotFoundError'}"
    )


def test_object_store_operational_failures_propagate(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    sound(world)

    def failed(key: ObjectKey) -> ObjectRef:
        raise RepositoryError("object service unavailable")

    monkeypatch.setattr(world.harness.objects, "stat", failed)
    with pytest.raises(RepositoryError, match="object service unavailable"):
        world.precedents()


def test_a_sound_sibling_does_not_qualify_an_inconclusive_decision(world: World) -> None:
    other = {
        "source_id": "f002",
        "source_report": samples.SOURCE_REPORT,
        "verdict": "inconclusive",
        "technique": "replay",
    }
    doc = samples.report(
        world.harness, "refuted", finding={"steps": [samples.probe()]}, additional=(other,)
    )
    result = world.harness.validation.record(doc, samples.PROVENANCE, world.harness.bindings(0, 1))
    with SqlTraustUnitOfWork(world.harness.engine) as uow:
        forged = Seed(uow).decision(
            world.harness.findings[1],
            actor=None,
            validity="false_positive",
            assessment_id=result.assessment_ids[0],
            artifact_id=result.artifact_ids[0],
            occurred_at=samples.NOW,
        )
        uow.commit()
    assert world.precedents() == [result.findings[0].decision_id]
    assert world.records().check_refutations([forged])[0].reason == "not-a-sound-refutation"


@pytest.mark.parametrize(
    "override", ["human-confirmation", "machine-confirmation", "restatement", "not-affected"]
)
def test_superseding_confirmations_and_human_corrections_exclude_the_refutation(
    world: World, override: str
) -> None:
    result = sound(world)
    if override == "machine-confirmation":
        later = samples.PROVENANCE.model_copy(
            update={"run_id": samples.OTHER_RUN_ID, "occurred_at": samples.LATER}
        )
        world.harness.validation.record(
            samples.report(world.harness, finding={"evidence_grade": "E0"}),
            later,
            world.harness.bindings(),
        )
    else:
        with SqlTraustUnitOfWork(world.harness.engine) as uow:
            Seed(uow).decision(
                world.harness.findings[0],
                actor="human:reviewer@example.com",
                validity="not_affected" if override == "not-affected" else "confirmed",
                occurred_at=samples.LATER,
                **(
                    {
                        "restates_id": result.findings[0].decision_id,
                        "ticket": "EXAMPLE-1",
                        "reason": "data_error",
                        "rationale": "The retained confirmation corrects this refutation.",
                    }
                    if override in {"restatement", "not-affected"}
                    else {}
                ),
            )
            uow.commit()
    assert world.precedents() == []


def test_human_precedents_keep_priority_over_validation_context(world: World) -> None:
    machine = sound(world).findings[0].decision_id
    with SqlTraustUnitOfWork(world.harness.engine) as uow:
        human = Seed(uow).decision(
            world.harness.findings[1], actor="human:reviewer@example.com", validity="false_positive"
        )
        uow.commit()
    (item,) = world.services.findings.decisions.prepare(world.assessment_id).items
    assert [(p.decision.id, p.reason.strength) for p in item.precedents] == [
        (human.id, PrecedentStrength.HUMAN),
        (machine, PrecedentStrength.MACHINE),
    ]


def test_batch_reads_shared_evidence_once_and_outside_transactions(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = {
        "source_id": "f002",
        "source_report": samples.SOURCE_REPORT,
        "verdict": "refuted",
        "technique": "replay",
        "steps": [samples.probe()],
    }
    doc = samples.report(
        world.harness, "refuted", finding={"steps": [samples.probe()]}, additional=(other,)
    )
    result = world.harness.validation.record(doc, samples.PROVENANCE, world.harness.bindings(0, 1))
    active = set()
    reads: Counter[str] = Counter()

    def begin(connection: sa.Connection) -> None:
        active.add(connection)

    def finish(connection: sa.Connection) -> None:
        active.discard(connection)

    get = world.harness.objects.get

    def outside(ref: ObjectRef) -> bytes:
        assert not active, "artifact read held a database transaction"
        reads[str(ref.key)] += 1
        return get(ref)

    sa.event.listen(world.harness.engine, "begin", begin)
    sa.event.listen(world.harness.engine, "rollback", finish)
    sa.event.listen(world.harness.engine, "commit", finish)
    monkeypatch.setattr(world.harness.objects, "get", outside)
    try:
        assert set(world.precedents()) == {o.decision_id for o in result.findings}
        assert len(reads) == 2 and set(reads.values()) == {1}
    finally:
        sa.event.remove(world.harness.engine, "begin", begin)
        sa.event.remove(world.harness.engine, "rollback", finish)
        sa.event.remove(world.harness.engine, "commit", finish)


@pytest.mark.parametrize(
    "fault", ["artifact", "grade", "rationale", "actor", "timestamp", "finding"]
)
def test_refutation_must_support_the_exact_decision(world: World, fault: str) -> None:
    result = sound(world)
    original = world.harness.decisions.get(result.findings[0].decision_id)
    changes = {
        "artifact": {"artifact_id": saved_id(world.harness.artifact)},
        "grade": {"evidence_grade": "E0"},
        "rationale": {"rationale": "A different finding was assessed by this run."},
        "actor": {"actor": "machine:unrelated-runner"},
        "timestamp": {"occurred_at": samples.LATER},
        "finding": {"finding_id": saved_id(world.harness.findings[1])},
    }[fault]
    (check,) = world.records().check_refutations([original.model_copy(update=changes)])
    assert check.reason == (
        "finding-binding-mismatch" if fault == "finding" else "decision-evidence-mismatch"
    )


def test_fractional_recording_times_survive_the_evidence_gate(world: World) -> None:
    precise = samples.PROVENANCE.model_copy(
        update={"occurred_at": samples.NOW.replace(microsecond=123456)}
    )
    result = world.harness.validation.record(
        samples.report(world.harness, "refuted", finding={"steps": [samples.probe()]}),
        precise,
        world.harness.bindings(),
    )
    assert world.precedents() == [result.findings[0].decision_id]


def test_scanner_to_recorded_validation_to_triage_uses_producer_supplied_symbols(
    world: World,
) -> None:
    services = world.services
    with SqlTraustUnitOfWork(world.harness.engine) as uow:
        seed = Seed(uow)
        prior = seed.repository_ref(seed.repository(url="https://github.com/example/prior-scanned"))
        current = seed.repository_ref(
            seed.repository(url="https://github.com/example/current-scanned")
        )
        uow.commit()
    raw = (FIXTURES / "findings/scanners/codeql-symbols.sarif").read_bytes()
    provenance = samples.PROVENANCE.model_copy(update={"source": SourceType.VULN_SCAN_REPORT})
    scan, accepted = services.assessment.record_scan(
        saved_id(prior), raw, CandidateFormat.SARIF, provenance
    )
    (item,) = services.findings.decisions.prepare(saved_id(scan)).items
    triage = json.loads(samples.TRIAGE.read_bytes())
    triage["findings"] = [
        {
            "id": "f001",
            "title": item.finding.title,
            "verdict": "undetermined",
            "fingerprint": item.finding.fingerprint,
            "fingerprint_algo": item.finding.fingerprint_algo,
        }
    ]
    assert (
        services.findings.decisions.record(
            saved_id(scan),
            TriageArtifact.from_document(triage),
            provenance,
            FIXTURES / "findings/triage/canary-target",
        )
        == []
    )
    with SqlTraustUnitOfWork(world.harness.engine) as uow:
        source = next(
            a for a in uow.assessments.list_for_ref(saved_id(prior)) if a.kind == "triage"
        )
        (artifact,) = uow.artifacts.list_for_assessment(saved_id(source))
        finding = uow.findings.get(accepted.created[0])
    source_harness = samples.ValidationHarness(
        world.harness.engine,
        world.harness.objects,
        source,
        artifact,
        (finding,),
        services.validation,
        services.findings.decisions,
        services.findings.review,
        world.harness.ledger,
    )
    result = services.validation.record(
        samples.report(source_harness, "refuted", finding={"steps": [samples.probe()]}),
        samples.PROVENANCE,
        source_harness.bindings(),
    )
    incoming, _ = services.assessment.record_scan(
        saved_id(current), raw, CandidateFormat.SARIF, provenance
    )
    (prepared,) = services.findings.decisions.prepare(saved_id(incoming)).items
    assert prepared.locations[0].symbol == "api.Handle"
    assert [(p.decision.id, p.reason.strength) for p in prepared.precedents] == [
        (result.findings[0].decision_id, PrecedentStrength.MACHINE)
    ]


def test_empty_validation_candidates_need_no_io(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected(key: ObjectKey) -> ObjectRef:
        raise AssertionError("unexpected artifact read")

    monkeypatch.setattr(world.harness.objects, "stat", unexpected)
    assert world.records().check_refutations([]) == ()


@pytest.mark.parametrize("irrelevant", ["path", "cwe", "symbol", "human-precedence"])
def test_unnecessary_validation_evidence_is_not_read(
    world: World,
    monkeypatch: pytest.MonkeyPatch,
    irrelevant: str,
) -> None:
    sound(world)
    expected = []
    with SqlTraustUnitOfWork(world.harness.engine) as uow:
        seed = Seed(uow)
        if irrelevant == "human-precedence":
            decision = seed.decision(
                world.harness.findings[0],
                actor="human:reviewer@example.com",
                validity="false_positive",
                occurred_at=samples.LATER,
            )
            expected = [decision.id]
        else:
            repository = seed.repository(url="https://github.com/example/unrelated")
            assessment = seed.assessment(seed.repository_ref(repository))
            finding = seed.finding(repository)
            cwe = (
                seed.cwe(identifier="CWE-999")
                if irrelevant == "cwe"
                else uow.cwes.get(
                    uow.finding_cwes.list_for_finding(world.harness.findings[0].id)[0].cwe_id
                )
            )
            seed.finding_cwe(finding, cwe)
            seed.location(
                seed.occurrence(finding, assessment),
                path="unrelated.go" if irrelevant == "path" else "vendor/example/parse.go",
                symbol="Other" if irrelevant == "symbol" else "Parse",
            )
            world = replace(world, assessment_id=saved_id(assessment))
        uow.commit()

    def unnecessary(key: ObjectKey) -> ObjectRef:
        raise RepositoryError("irrelevant validation evidence was read")

    monkeypatch.setattr(world.harness.objects, "stat", unnecessary)
    (item,) = world.services.findings.decisions.prepare(world.assessment_id).items
    assert [p.decision.id for p in item.precedents] == expected


@pytest.mark.parametrize(
    "fault",
    [
        "soundness",
        "timestamp",
        "source",
        "binding",
        "duplicate-outcome",
        "provenance",
        "missing-report",
        "missing-link",
        "ambiguous-recording",
        "malformed-companion",
    ],
)
def test_retained_evidence_is_verified_beyond_its_stored_outcome(world: World, fault: str) -> None:
    first = sound(world)
    evidence = world.harness.evidence(first).model_dump(mode="json")
    report = samples.report(world.harness, "refuted", finding={"steps": [samples.probe()]})
    if fault == "soundness":
        report = samples.report(
            world.harness, "refuted", finding={"steps": [samples.probe(controls=[])]}
        )
    evidence["report_digest"] = sha256_hex(report.payload)
    if fault == "timestamp":
        evidence["provenance"]["occurred_at"] = samples.LATER.isoformat()
    elif fault == "source":
        evidence["bindings"]["sources"][0]["assessment_id"] = str(world.assessment_id)
    elif fault == "binding":
        evidence["findings"][0]["source_id"] = "unbound"
    elif fault == "duplicate-outcome":
        evidence["findings"].append(evidence["findings"][0])
    elif fault == "provenance":
        evidence["provenance"]["source"] = SourceType.INTERACTIVE
    elif fault == "missing-report":
        evidence["report_digest"] = "0" * 64
    raw = b"{}" if fault == "malformed-companion" else json.dumps(evidence).encode()
    with SqlTraustUnitOfWork(world.harness.engine) as uow:
        seed = Seed(uow)
        ref = uow.repository_refs.get(world.harness.source.repository_ref_id)
        assessment = seed.assessment(
            ref,
            kind="validation",
            occurred_at=samples.NOW,
            baseline_assessment_id=saved_id(world.harness.source),
        )
        primary = world.harness.objects.put(
            ObjectKey.parse(f"test-report/{fault}.json"), report.payload
        )
        artifact = seed.artifact(
            assessment, kind="validation", digest=primary.sha256, uri=str(primary.key)
        )
        companion = world.harness.objects.put(ObjectKey.parse(f"test-evidence/{fault}.json"), raw)
        held = seed.artifact(
            assessment, kind="validation-recording", digest=companion.sha256, uri=str(companion.key)
        )
        if fault == "ambiguous-recording":
            seed.artifact(assessment, kind="validation-recording")
        decision = seed.decision(
            world.harness.findings[0],
            actor=None,
            validity="false_positive",
            assessment_id=saved_id(assessment),
            artifact_id=saved_id(artifact),
            occurred_at=samples.NOW,
        )
        if fault != "missing-link":
            uow.finding_external_refs.add(
                FindingExternalRef(
                    finding_id=decision.finding_id,
                    system="traust.validation",
                    ref=validation_link(saved_id(held), decision.finding_id),
                )
            )
        uow.commit()
    before = samples.snapshot(world.harness.engine)
    (check,) = world.records().check_refutations([decision])
    if fault == "missing-link":
        assert check.reason == "finding-binding-mismatch"
    elif fault == "ambiguous-recording":
        assert check.reason == "missing-or-ambiguous-recording"
    else:
        assert check.reason.startswith("unverifiable-evidence:")
    assert samples.snapshot(world.harness.engine) == before


def test_validation_batch_query_count_does_not_grow_per_finding(world: World) -> None:
    other = {
        "source_id": "f002",
        "source_report": samples.SOURCE_REPORT,
        "verdict": "refuted",
        "technique": "replay",
        "steps": [samples.probe()],
    }
    result = world.harness.validation.record(
        samples.report(
            world.harness, "refuted", finding={"steps": [samples.probe()]}, additional=(other,)
        ),
        samples.PROVENANCE,
        world.harness.bindings(0, 1),
    )
    decisions = [world.harness.decisions.get(o.decision_id) for o in result.findings]
    issued = []

    def record(
        _conn: Any, _cursor: Any, sql: str, _params: Any, _context: Any, _many: bool
    ) -> None:
        issued.append(sql)

    sa.event.listen(world.harness.engine, "before_cursor_execute", record)
    try:
        reader = world.records()
        assert reader.check_refutations(decisions[:1])[0].reason is None
        count = len(issued)
        issued.clear()
        assert all(c.reason is None for c in reader.check_refutations(decisions))
        assert len(issued) == count == 6
    finally:
        sa.event.remove(world.harness.engine, "before_cursor_execute", record)


def test_a_reference_owned_by_another_finding_cannot_bind_the_evidence(world: World) -> None:
    result = sound(world)
    finding_id = result.findings[0].finding_id
    with SqlTraustUnitOfWork(world.harness.engine) as uow:
        (reference,) = uow.finding_external_refs.list_for_findings(
            [finding_id], "traust.validation"
        )
        uow.finding_external_refs.update(
            reference.model_copy(update={"finding_id": saved_id(world.harness.findings[1])})
        )
        second = Seed(uow).decision(
            world.harness.findings[1],
            actor=None,
            validity="false_positive",
            assessment_id=result.assessment_ids[0],
            artifact_id=result.artifact_ids[0],
            occurred_at=samples.NOW,
        )
        uow.commit()
    decisions = [world.harness.decisions.get(result.findings[0].decision_id), second]
    checks = world.records().check_refutations(decisions)
    assert all(check.reason == "finding-binding-mismatch" for check in checks)


def test_large_precedent_batches_bound_the_number_of_query_parameters(world: World) -> None:
    with SqlTraustUnitOfWork(world.harness.engine) as uow:
        seed = Seed(uow)
        source = seed.assessment(
            uow.repository_refs.get(world.harness.source.repository_ref_id), kind="validation"
        )
        repository = seed.repository(url="https://github.com/example/batch")
        decisions = [
            seed.decision(
                seed.finding(repository),
                actor=None,
                validity="false_positive",
                assessment_id=saved_id(source),
            )
            for _ in range(501)
        ]
        uow.commit()
    sizes = []

    def record(
        _conn: Any, _cursor: Any, _sql: str, params: Any, _context: Any, _many: bool
    ) -> None:
        sizes.append(len(params))

    sa.event.listen(world.harness.engine, "before_cursor_execute", record)
    try:
        checks = world.records().check_refutations(decisions)
    finally:
        sa.event.remove(world.harness.engine, "before_cursor_execute", record)
    assert len(checks) == 501
    assert all(check.reason == "missing-or-ambiguous-recording" for check in checks)
    assert max(sizes) <= 501
    assert len(sizes) == 6


@pytest.mark.parametrize("refuted_first", [False, True])
def test_multiple_source_labels_for_one_finding_match_the_decision_not_the_first_outcome(
    world: World,
    refuted_first: bool,
) -> None:
    original = world.harness.findings[0]
    raw = json.loads(samples.TRIAGE.read_bytes())
    raw["findings"] = [
        {
            "id": label,
            "title": original.title,
            "verdict": "undetermined",
            "fingerprint": original.fingerprint,
            "fingerprint_algo": original.fingerprint_algo,
        }
        for label in ("f001", "f002")
    ]
    doc = TriageArtifact.from_document(raw)
    stored = world.harness.objects.put(
        ObjectKey.parse("test-source/repeated-labels.json"), doc.payload
    )
    with SqlTraustUnitOfWork(world.harness.engine) as uow:
        artifact = Seed(uow).artifact(
            world.harness.source, kind="triage", digest=stored.sha256, uri=str(stored.key)
        )
        uow.commit()
    h = replace(world.harness, artifact=artifact, findings=(original, original))
    additional = {
        "source_id": "f002",
        "source_report": samples.SOURCE_REPORT,
        "verdict": "inconclusive" if refuted_first else "refuted",
        "technique": "replay",
        "steps": [samples.probe()],
    }
    report = samples.report(
        h,
        "refuted" if refuted_first else "inconclusive",
        finding={"steps": [samples.probe()]},
        additional=(additional,),
    )
    result = h.validation.record(report, samples.PROVENANCE, h.bindings(0, 1))
    (decision_id,) = [o.decision_id for o in result.findings if o.decision_id is not None]
    assert world.precedents() == [decision_id]


def test_a_human_override_during_evidence_reads_is_seen_before_returning_context(
    world: World,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sound(world)
    get = world.harness.objects.get
    overridden = False

    def override(ref: ObjectRef) -> bytes:
        nonlocal overridden
        if not overridden:
            overridden = True
            with SqlTraustUnitOfWork(world.harness.engine) as uow:
                Seed(uow).decision(
                    world.harness.findings[0],
                    actor="human:reviewer@example.com",
                    validity="confirmed",
                    occurred_at=samples.LATER,
                )
                uow.commit()
        return get(ref)

    monkeypatch.setattr(world.harness.objects, "get", override)
    assert world.precedents() == []
    assert overridden
