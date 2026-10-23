from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import CandidateFormat, PrecedentStrength
from traust_core.v1.models.vocabulary import FindingOrigin, SourceType
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.identity import IdentityPolicy
from traust_core.v1.services.findings.intake import FindingIntake
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.findings.review import ReviewPolicy
from traust_core.v1.services.findings.taxonomy import TaxonomyPolicy
from traust_core.v1.services.lint import Lint

engine = table_fixtures.engine
SCANNER = Path(__file__).parents[3] / "fixtures/findings/scanners/codeql-symbols.sarif"


@pytest.mark.parametrize(
    ("symbol", "cwe", "unknown_function", "matches"),
    [
        ("api.Handle", "CWE-117", False, True),
        ("api.Other", "CWE-117", False, False),
        (None, "CWE-117", False, False),
        ("api.Handle", "CWE-79", False, False),
        ("api.Handle", "CWE-117", True, False),
    ],
)
def test_scanner_intake_produces_precedents_in_triage_preparation(
    engine: Engine, symbol: str | None, cwe: str, unknown_function: bool, matches: bool
) -> None:
    uow = SqlTraustUnitOfWork(engine)
    with uow:
        seed = Seed(uow)
        prior_ref = seed.repository_ref(seed.repository(url="https://github.com/example/prior"))
        new_ref = seed.repository_ref(seed.repository(url="https://github.com/example/current"))
        uow.commit()
    scans = AssessmentService(uow, FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()))
    provenance = Provenance(run_id=uuid4(), source=SourceType.INTERACTIVE, occurred_at=T0)
    raw = SCANNER.read_bytes()
    _, accepted = scans.record_scan(
        prior_ref.id, raw, CandidateFormat.SARIF, FindingOrigin.VULN_SCAN, provenance
    )
    with uow:
        verdict = Seed(uow).decision(
            uow.findings.get(accepted.created[0]),
            actor="human:analyst@example.com",
            validity="false_positive",
            rationale="The argument is validated before reaching the logger.",
        )
        uow.commit()

    doc = json.loads(raw)
    run = doc["runs"][0]
    location = run["results"][0]["locations"][0]
    location["physicalLocation"]["artifactLocation"]["uri"] = (
        "third_party/example.com/logger/handler.go"
    )
    location["logicalLocations"] = (
        [{"kind": "function", "fullyQualifiedName": symbol}] if symbol else []
    )
    if unknown_function:
        location["logicalLocations"].append({"kind": "function", "decoratedName": "_Z5Otherv"})
    run["tool"]["driver"]["rules"][0]["properties"]["tags"] = [f"external/cwe/{cwe.lower()}"]
    assessment, _ = scans.record_scan(
        new_ref.id,
        json.dumps(doc).encode(),
        CandidateFormat.SARIF,
        FindingOrigin.VULN_SCAN,
        provenance,
    )
    triage = FindingDecisions(
        uow,
        None,
        Lint({}),
        FindingPrecedents(uow),
        clock=FixedClock(T0),
        objects=InMemoryObjectStore(),
        review=ReviewPolicy(),
    )
    [item] = triage.prepare(assessment.id).items
    assert item.locations[0].symbol == (None if unknown_function else symbol)
    assert [p.decision.id for p in item.precedents] == ([verdict.id] if matches else [])
    if matches:
        [precedent] = item.precedents
        assert precedent.reason.strength == PrecedentStrength.HUMAN
        assert (precedent.reason.path, precedent.reason.symbol) == (
            "example.com/logger/handler.go",
            "api.Handle",
        )
