from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables import conftest as tables
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.errors import NotFoundError, RepositoryError, ValidationError
from traust_core.v1.models.common import FILE_BYTES_SHA256, CodeHash, CodeSpan, Provenance
from traust_core.v1.models.findings import (
    CandidateFormat,
    FindingCandidate,
    HashUnavailable,
    Label,
    LocationHash,
    PrecedentBasis,
    PrecedentStrength,
)
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.traust.findings.location_hash import SqlLocationHashRepository
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.identity import IdentityPolicy
from traust_core.v1.services.findings.intake import FindingIntake
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.findings.review import ReviewPolicy
from traust_core.v1.services.findings.taxonomy import TaxonomyPolicy
from traust_core.v1.services.lint import Lint

engine = tables.engine
FIXTURES = Path(__file__).parents[3] / "fixtures/findings/scanners"
PROVENANCE = Provenance(run_id=uuid4(), source=SourceType.VULN_SCAN_REPORT, occurred_at=T0)


def scan(source: Path, url: str, sha: str, path: str) -> bytes:
    return subprocess.run(
        [
            sys.executable,
            str(FIXTURES / "hash_claim_scanner.py"),
            str(source),
            "--repository",
            url,
            "--sha",
            sha,
            "--path",
            path,
        ],
        check=True,
        capture_output=True,
    ).stdout


class World:
    def __init__(self, engine: Engine) -> None:
        self.uow = SqlTraustUnitOfWork(engine)
        with self.uow as uow:
            seed = Seed(uow)
            self.prior_repo = seed.repository(url="https://github.com/example/prior")
            self.prior = seed.repository_ref(self.prior_repo)
            self.current_repo = seed.repository(url="https://github.com/example/current")
            self.current = seed.repository_ref(self.current_repo)
            uow.commit()
        self.intake = FindingIntake(self.uow, IdentityPolicy(), TaxonomyPolicy())
        self.scans = AssessmentService(self.uow, self.intake)
        self.precedents = FindingPrecedents(self.uow)
        self.decisions = FindingDecisions(
            self.uow,
            None,
            Lint({}),
            self.precedents,
            clock=FixedClock(T0),
            objects=InMemoryObjectStore(),
            review=ReviewPolicy(),
        )

    def report(self, *, prior: bool, source: Path, hashed: bool = True) -> tuple:
        repo, ref = (self.prior_repo, self.prior) if prior else (self.current_repo, self.current)
        prefix = "vendor" if prior else "third_party"
        raw = scan(source, repo.url, ref.sha, f"{prefix}/example/handler.py")
        if not hashed:
            doc = json.loads(raw)
            del doc["runs"][0]["artifacts"][0]["hashes"]
            raw = json.dumps(doc).encode()
        return self.scans.record_scan(ref.id, raw, CandidateFormat.SARIF, PROVENANCE)

    def adjudicate(self, finding_id: UUID, *, binding: bool = True, **kwargs):
        with self.uow as uow:
            saved = Seed(uow).decision(
                uow.findings.get(finding_id),
                actor="human:analyst@example.com",
                validity="false_positive",
                repository_ref_id=self.prior.id if binding else None,
                **kwargs,
            )
            uow.commit()
            return saved


@pytest.mark.parametrize(
    ("prior_hash", "target_hash", "basis", "reason"),
    [
        (True, True, PrecedentBasis.HASH_BACKED, None),
        (False, True, PrecedentBasis.SYMBOL_ONLY, HashUnavailable.PRIOR),
        (True, False, PrecedentBasis.SYMBOL_ONLY, HashUnavailable.TARGET),
        (False, False, PrecedentBasis.SYMBOL_ONLY, HashUnavailable.BOTH),
    ],
)
def test_executed_scanner_claims_reach_stored_anchors_and_triage(
    engine: Engine,
    prior_hash: bool,
    target_hash: bool,
    basis: PrecedentBasis,
    reason: HashUnavailable | None,
) -> None:
    w = World(engine)
    _, prior = w.report(prior=True, source=FIXTURES / "hash-target.py", hashed=prior_hash)
    decision = w.adjudicate(prior.created[0])
    assessment, _ = w.report(prior=False, source=FIXTURES / "hash-target.py", hashed=target_hash)
    [item] = w.decisions.prepare(assessment.id).items
    [precedent] = item.precedents
    assert precedent.decision.id == decision.id
    assert precedent.reason.strength == PrecedentStrength.HUMAN
    assert (precedent.reason.basis, precedent.reason.unavailable_reason) == (basis, reason)
    serialized = item.model_dump(mode="json")["precedents"][0]["reason"]
    assert serialized["basis"] == basis.value
    with w.uow as uow:
        claims = uow.location_hashes.list_for_locations([item.locations[0].id])
    assert len(claims) == int(target_hash)
    if target_hash:
        assert (
            claims[0].digest
            == hashlib.sha256((FIXTURES / "hash-target.py").read_bytes()).hexdigest()
        )


def test_changed_file_bytes_veto_even_when_the_symbol_and_cwe_agree(
    engine: Engine,
    tmp_path: Path,
) -> None:
    w = World(engine)
    _, prior = w.report(prior=True, source=FIXTURES / "hash-target.py")
    w.adjudicate(prior.created[0])
    changed = tmp_path / "changed.py"
    changed.write_bytes((FIXTURES / "hash-target.py").read_bytes() + b"\n# changed\n")
    assessment, _ = w.report(prior=False, source=changed)
    assert w.decisions.prepare(assessment.id).items[0].precedents == ()


def test_unknown_verdict_binding_is_explicit_symbol_only_context(engine: Engine) -> None:
    w = World(engine)
    _, prior = w.report(prior=True, source=FIXTURES / "hash-target.py")
    w.adjudicate(prior.created[0], binding=False)
    assessment, _ = w.report(prior=False, source=FIXTURES / "hash-target.py")
    [precedent] = w.decisions.prepare(assessment.id).items[0].precedents
    assert precedent.reason.basis == PrecedentBasis.SYMBOL_ONLY
    assert precedent.reason.unavailable_reason == HashUnavailable.BINDING


def test_a_newer_verdict_cannot_borrow_an_older_occurrences_matching_hash(engine: Engine) -> None:
    w = World(engine)
    _, prior = w.report(prior=True, source=FIXTURES / "hash-target.py")
    with w.uow as uow:
        seed = Seed(uow)
        later = seed.repository_ref(w.prior_repo, sha="b" * 40)
        occurrence = seed.occurrence(uow.findings.get(prior.created[0]), seed.assessment(later))
        location = seed.location(occurrence, path="vendor/example/handler.py", symbol="api.handle")
        seed.location_hash(location, digest="b" * 64)
        seed.decision(
            uow.findings.get(prior.created[0]),
            actor="human:analyst@example.com",
            validity="false_positive",
            repository_ref_id=later.id,
        )
        uow.commit()
    assessment, _ = w.report(prior=False, source=FIXTURES / "hash-target.py")
    assert w.decisions.prepare(assessment.id).items[0].precedents == ()


def test_named_and_bare_refs_to_one_commit_have_compatible_bindings(engine: Engine) -> None:
    w = World(engine)
    _, prior = w.report(prior=True, source=FIXTURES / "hash-target.py")
    with w.uow as uow:
        seed = Seed(uow)
        bare = seed.repository_ref(w.prior_repo, name=None, kind=None, sha=w.prior.sha)
        seed.decision(
            uow.findings.get(prior.created[0]),
            actor="human:analyst@example.com",
            validity="false_positive",
            repository_ref_id=bare.id,
        )
        uow.commit()
    assessment, _ = w.report(prior=False, source=FIXTURES / "hash-target.py")
    [precedent] = w.decisions.prepare(assessment.id).items[0].precedents
    assert precedent.reason.basis == PrecedentBasis.HASH_BACKED


def test_contradictory_duplicate_claims_roll_back_the_whole_scan(engine: Engine) -> None:
    w = World(engine)
    raw = json.loads(
        scan(FIXTURES / "hash-target.py", w.current_repo.url, w.current.sha, "handler.py")
    )
    run = raw["runs"][0]
    conflicting = json.loads(json.dumps(run))
    conflicting["artifacts"][0]["hashes"]["sha-256"] = "b" * 64
    raw["runs"].append(conflicting)
    with pytest.raises(ValidationError, match="conflicting hashes"):
        w.scans.record_scan(
            w.current.id, json.dumps(raw).encode(), CandidateFormat.SARIF, PROVENANCE
        )
    with w.uow as uow:
        assert uow.assessments.list_for_ref(w.current.id) == []


def test_retries_and_later_reports_do_not_enrich_historical_locations(engine: Engine) -> None:
    w = World(engine)
    assessment, accepted = w.report(prior=True, source=FIXTURES / "hash-target.py", hashed=False)
    _, retry = w.report(prior=True, source=FIXTURES / "hash-target.py", hashed=True)
    assert retry.created == ()
    with w.uow as uow:
        occurrence = uow.occurrences.find(accepted.created[0], assessment.id)
        locations = uow.locations.list_for_occurrence(occurrence.id)
        assert uow.location_hashes.list_for_locations([loc.id for loc in locations]) == []
    raw = scan(
        FIXTURES / "hash-target.py", w.prior_repo.url, w.prior.sha, "vendor/example/handler.py"
    )
    later, _ = w.scans.record_scan(
        w.prior.id,
        raw,
        CandidateFormat.SARIF,
        PROVENANCE.model_copy(update={"occurred_at": T0 + timedelta(days=1)}),
    )
    with w.uow as uow:
        new = uow.occurrences.find(accepted.created[0], later.id)
        assert (
            len(
                uow.location_hashes.list_for_locations(
                    [loc.id for loc in uow.locations.list_for_occurrence(new.id)]
                )
            )
            == 1
        )


@pytest.mark.parametrize("same_digest", [False, True])
def test_unrelated_schemes_never_confirm_a_match(engine: Engine, same_digest: bool) -> None:
    w = World(engine)
    with w.uow as uow:
        seed = Seed(uow)
        cwe = seed.cwe(identifier="CWE-117")
        finding = seed.finding(w.prior_repo)
        seed.finding_cwe(finding, cwe)
        occurrence = seed.occurrence(finding, seed.assessment(w.prior))
        location = seed.location(occurrence, path="vendor/example/handler.py", symbol="api.handle")
        digest = hashlib.sha256((FIXTURES / "hash-target.py").read_bytes()).hexdigest()
        seed.location_hash(
            location, algorithm="other-scope/v1", digest=digest if same_digest else "b" * 64
        )
        uow.commit()
    w.adjudicate(finding.id)
    assessment, _ = w.report(prior=False, source=FIXTURES / "hash-target.py")
    assert w.decisions.prepare(assessment.id).items[0].precedents == ()


def test_candidate_claim_validation_is_atomic_before_intake_writes(engine: Engine) -> None:
    w = World(engine)
    with w.uow as uow:
        assessment = Seed(uow).assessment(w.current)
        uow.commit()
    base = FindingCandidate(
        label=Label("first"),
        repository_id=w.current_repo.id,
        title="log input",
        cwes=("CWE-117",),
        reported_severity="high",
        locations=(
            CodeSpan(
                path="handler.py",
                symbol="api.handle",
                hashes=(CodeHash(algorithm=FILE_BYTES_SHA256, digest="a" * 64),),
            ),
        ),
    )
    other = base.model_copy(
        update={
            "label": Label("second"),
            "locations": (
                CodeSpan(
                    path="handler.py",
                    symbol="api.handle",
                    hashes=(CodeHash(algorithm=FILE_BYTES_SHA256, digest="b" * 64),),
                ),
            ),
        }
    )
    with pytest.raises(ValidationError, match="conflicting hashes"):
        w.intake.accept(assessment.id, [base, other])
    with w.uow as uow:
        assert uow.occurrences.list_for_assessment(assessment.id) == []


@pytest.mark.parametrize("fault", ["path", "symbol", "cwe"])
def test_equal_hashes_never_create_an_unrelated_precedent(engine: Engine, fault: str) -> None:
    w = World(engine)
    _, prior = w.report(prior=True, source=FIXTURES / "hash-target.py")
    w.adjudicate(prior.created[0])
    raw = json.loads(
        scan(
            FIXTURES / "hash-target.py",
            w.current_repo.url,
            w.current.sha,
            "third_party/example/handler.py",
        )
    )
    run = raw["runs"][0]
    if fault == "path":
        run["artifacts"][0]["location"]["uri"] = "other.py"
    elif fault == "symbol":
        run["results"][0]["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] = "api.other"
    else:
        run["tool"]["driver"]["rules"][0]["properties"]["tags"] = ["CWE-79"]
    assessment, _ = w.scans.record_scan(
        w.current.id, json.dumps(raw).encode(), CandidateFormat.SARIF, PROVENANCE
    )
    assert w.decisions.prepare(assessment.id).items[0].precedents == ()


def test_confirmation_still_overrides_a_hash_backed_refutation(engine: Engine) -> None:
    w = World(engine)
    _, prior = w.report(prior=True, source=FIXTURES / "hash-target.py")
    w.adjudicate(prior.created[0])
    with w.uow as uow:
        Seed(uow).decision(
            uow.findings.get(prior.created[0]),
            actor="human:analyst@example.com",
            validity="confirmed",
            repository_ref_id=w.prior.id,
            occurred_at=T0 + timedelta(days=1),
            statement_key="later-confirmation",
        )
        uow.commit()
    assessment, _ = w.report(prior=False, source=FIXTURES / "hash-target.py")
    assert w.decisions.prepare(assessment.id).items[0].precedents == ()


def test_missing_producer_binding_is_observable_as_an_unavailable_target_claim(
    engine: Engine,
) -> None:
    w = World(engine)
    _, prior = w.report(prior=True, source=FIXTURES / "hash-target.py")
    w.adjudicate(prior.created[0])
    raw = json.loads(
        scan(
            FIXTURES / "hash-target.py",
            w.current_repo.url,
            w.current.sha,
            "third_party/example/handler.py",
        )
    )
    del raw["runs"][0]["versionControlProvenance"]
    assessment, _ = w.scans.record_scan(
        w.current.id, json.dumps(raw).encode(), CandidateFormat.SARIF, PROVENANCE
    )
    [item] = w.decisions.prepare(assessment.id).items
    [precedent] = item.precedents
    assert precedent.reason.basis == PrecedentBasis.SYMBOL_ONLY
    assert precedent.reason.unavailable_reason == HashUnavailable.TARGET
    with w.uow as uow:
        assert uow.location_hashes.list_for_locations([item.locations[0].id]) == []


def test_a_known_mismatch_cannot_fall_back_to_an_unhashed_location_in_the_same_function(
    engine: Engine,
) -> None:
    w = World(engine)
    _, prior = w.report(prior=True, source=FIXTURES / "hash-target.py")
    w.adjudicate(prior.created[0])
    with w.uow as uow:
        seed = Seed(uow)
        assessment = seed.assessment(w.current)
        finding = seed.finding(w.current_repo)
        seed.finding_cwe(finding, uow.cwes.find_by_identifier("CWE-117"))
        occurrence = seed.occurrence(finding, assessment)
        location = seed.location(
            occurrence, path="third_party/example/handler.py", symbol="api.handle"
        )
        seed.location_hash(location, digest="b" * 64)
        seed.location(
            occurrence,
            path="third_party/example/handler.py",
            symbol="api.handle",
            line_start=20,
            line_end=20,
        )
        uow.commit()
    assert w.decisions.prepare(assessment.id).items[0].precedents == ()


def test_hash_write_failure_rolls_back_the_scanner_assessment_and_its_locations(
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    w = World(engine)
    written = []

    def failed(self: SqlLocationHashRepository, record: LocationHash) -> LocationHash:
        written.append(record.location_id)
        raise RepositoryError("hash storage unavailable")

    monkeypatch.setattr(SqlLocationHashRepository, "add", failed)
    with pytest.raises(RepositoryError, match="hash storage unavailable"):
        w.report(prior=False, source=FIXTURES / "hash-target.py")
    assert len(written) == 1
    with w.uow as uow:
        assert uow.assessments.list_for_ref(w.current.id) == []
        with pytest.raises(NotFoundError):
            uow.locations.get(written[0])


def test_triage_checks_later_candidate_pages_before_applying_the_precedent_limit(
    engine: Engine,
) -> None:
    w = World(engine)
    assessment, _ = w.report(prior=False, source=FIXTURES / "hash-target.py")
    locations = []
    findings = {}
    with w.uow as uow:
        seed = Seed(uow)
        cwe = uow.cwes.find_by_identifier("CWE-117")
        for _ in range(270):
            finding = seed.finding(w.prior_repo)
            seed.finding_cwe(finding, cwe)
            location = seed.location(
                seed.occurrence(finding, seed.assessment(w.prior)),
                path="vendor/example/handler.py",
                symbol="api.handle",
            )
            locations.append(location)
            findings[location.id] = finding
            seed.decision(
                finding,
                actor=None,
                validity="false_positive",
                assessment_id=seed.assessment(w.prior, kind="triage").id,
            )
        last = max(locations, key=lambda loc: loc.id)
        digest = hashlib.sha256((FIXTURES / "hash-target.py").read_bytes()).hexdigest()
        for location in locations:
            seed.location_hash(location, digest=digest if location.id == last.id else "b" * 64)
        uow.commit()
    sizes = []

    def record(_conn, _cursor, sql, params, _context, _many) -> None:
        if sql.lstrip().startswith("SELECT"):
            sizes.append(len(params))

    sa.event.listen(engine, "before_cursor_execute", record)
    try:
        [precedent] = w.decisions.prepare(assessment.id).items[0].precedents
    finally:
        sa.event.remove(engine, "before_cursor_execute", record)
    assert precedent.decision.finding_id == findings[last.id].id
    assert precedent.reason.basis == PrecedentBasis.HASH_BACKED
    assert max(sizes) <= 501
    assert len(sizes) < 40
