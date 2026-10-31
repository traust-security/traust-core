"""Precedents keyed on location (vendor-normalized path + symbol) and a shared CWE."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.findings import Cwe, Finding, Location, PrecedentStrength
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects.store import InMemoryObjectStore
from traust_core.v1.services.findings.precedents import FindingPrecedents, vendor_path
from traust_core.v1.services.findings.records import FindingRecords
from traust_core.v1.services.validation import ValidationRecords

PERSON, ENGINE = "human:analyst@example.com", None


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def seed(engine: Engine) -> Iterator[Seed]:
    with SqlTraustUnitOfWork(engine) as uow:
        yield Seed(uow)


class World:
    """A finding to triage, vendored in one repository, and prior findings elsewhere."""

    def __init__(self, seed: Seed) -> None:
        self.seed = seed
        self.xss = seed.cwe()
        self.finding, self.locations = self.reported("vendor/github.com/acme/w/parse.go", "Parse")

    def reported(
        self, path: str, symbol: str | None, cwe: Cwe | None = None
    ) -> tuple[Finding, tuple[Location, ...]]:
        finding = self.seed.finding(self.seed.repository())
        self.seed.finding_cwe(finding, cwe or self.xss)
        occurrence = self.seed.occurrence(finding, self.seed.assessment(kind="vuln-scan"))
        return finding, (self.seed.location(occurrence, path=path, symbol=symbol),)

    def prior(
        self, path: str, symbol: str | None, *verdicts: dict[str, Any], cwe: Cwe | None = None
    ) -> Finding:
        finding, _ = self.reported(path, symbol, cwe)
        for i, v in enumerate(verdicts):
            self.seed.decision(finding, occurred_at=T0 + timedelta(days=i), **v)
        return finding

    def precedents(self, limit: int = 5) -> list[tuple[Finding | None, PrecedentStrength]]:
        found = FindingPrecedents(
            self.seed.uow,
            validation=ValidationRecords(
                self.seed.uow,
                InMemoryObjectStore(),
                findings=FindingRecords(self.seed.uow),
            ),
        ).for_locations(self.finding.id, self.locations, limit)
        return [(p.decision.finding_id, p.reason.strength) for p in found]


def fp(actor: str | None = PERSON, **kw: Any) -> dict[str, Any]:
    return {
        "actor": actor,
        "validity": "false_positive",
        "rationale": "the sink is unreachable",
        **kw,
    }


def test_a_person_s_verdict_on_the_same_function_in_another_vendored_copy(seed: Seed) -> None:
    w = World(seed)
    other = w.prior("third_party/github.com/acme/w/parse.go", "Parse", fp())
    [precedent] = FindingPrecedents(seed.uow).for_locations(w.finding.id, w.locations, 5)
    assert (precedent.decision.finding_id, precedent.reason.strength) == (
        other.id,
        PrecedentStrength.HUMAN,
    )
    assert (precedent.reason.path, precedent.reason.symbol) == (
        "github.com/acme/w/parse.go",
        "Parse",
    )


def test_another_function_in_the_same_file_is_not_a_precedent(seed: Seed) -> None:
    w = World(seed)
    w.prior("vendor/github.com/acme/w/parse.go", "Render", fp())
    assert w.precedents() == []


def test_no_shared_cwe_or_no_symbol_is_not_a_precedent(seed: Seed) -> None:
    w = World(seed)
    w.prior("vendor/github.com/acme/w/parse.go", "Parse", fp(), cwe=seed.cwe())
    w.prior("vendor/github.com/acme/w/parse.go", None, fp())
    assert w.precedents() == []
    assert FindingPrecedents(seed.uow).for_locations(w.finding.id, (), 5) == []


def test_a_person_s_verdict_no_longer_standing_is_not_a_precedent(seed: Seed) -> None:
    w = World(seed)
    w.prior(
        "vendor/github.com/acme/w/parse.go",
        "Parse",
        fp(),
        {"actor": PERSON, "validity": "confirmed"},
    )
    assert w.precedents() == []


def test_machine_refutations_count_from_triage_and_verification_only(seed: Seed) -> None:
    w = World(seed)
    triaged = w.prior(
        "vendor/github.com/acme/w/parse.go",
        "Parse",
        fp(ENGINE, assessment_id=seed.assessment(kind="triage").id),
    )
    w.prior(
        "vendor/github.com/acme/w/parse.go",
        "Parse",
        fp(ENGINE, assessment_id=seed.assessment(kind="validation").id),
    )
    assert w.precedents() == [(triaged.id, PrecedentStrength.MACHINE)]


def test_validation_precedents_without_an_evidence_reader_refuse(seed: Seed) -> None:
    w = World(seed)
    w.prior(
        "vendor/github.com/acme/w/parse.go",
        "Parse",
        fp(ENGINE, assessment_id=seed.assessment(kind="validation").id),
    )
    with pytest.raises(ConfigError, match="validation precedents need an evidence reader"):
        FindingPrecedents(seed.uow).for_locations(w.finding.id, w.locations, 5)


def test_a_contested_machine_refutation_is_not_a_precedent(seed: Seed) -> None:
    w = World(seed)
    scan = seed.assessment(kind="triage").id
    w.prior(
        "vendor/github.com/acme/w/parse.go",
        "Parse",
        {"actor": None, "validity": "confirmed", "assessment_id": scan},
        fp(ENGINE, assessment_id=scan),
    )
    assert w.precedents() == []


def test_people_first_then_newest_up_to_the_limit(seed: Seed) -> None:
    w = World(seed)
    scan = seed.assessment(kind="triage").id
    machine = w.prior("vendor/github.com/acme/w/parse.go", "Parse", fp(ENGINE, assessment_id=scan))
    old = w.prior("vendor/github.com/acme/w/parse.go", "Parse", fp())
    new = w.prior(
        "vendor/github.com/acme/w/parse.go",
        "Parse",
        {"actor": PERSON, "validity": "confirmed"},
        fp(),
    )
    human = PrecedentStrength.HUMAN
    assert w.precedents() == [
        (new.id, human),
        (old.id, human),
        (machine.id, PrecedentStrength.MACHINE),
    ]
    assert w.precedents(limit=1) == [(new.id, human)]


@pytest.mark.parametrize(
    ("path", "normalized"),
    [
        ("vendor/github.com/acme/w/parse.go", "github.com/acme/w/parse.go"),
        ("./a/third_party/x/vendor/y/z.go", "y/z.go"),
        ("node_modules/lib/index.js", "lib/index.js"),
        ("src/app/main.go", "src/app/main.go"),
        ("vendorized/main.go", "vendorized/main.go"),
        (None, ""),
    ],
)
def test_vendor_path(path: str | None, normalized: str) -> None:
    assert vendor_path(path) == normalized


def test_canonical_weakness_and_historical_hardening_remain_human_precedents(seed: Seed) -> None:
    w = World(seed)
    canonical = w.prior(
        "vendor/github.com/acme/w/parse.go",
        "Parse",
        {"actor": PERSON, "validity": "confirmed"},
    )
    seed.uow.findings.update(canonical.model_copy(update={"kind": "weakness"}))
    historical = w.prior(
        "vendor/github.com/acme/w/parse.go",
        "Parse",
        {"actor": PERSON, "validity": "hardening"},
    )
    picked = FindingPrecedents(seed.uow).for_locations(w.finding.id, w.locations, 5)
    assert {row.decision.finding_id for row in picked} == {canonical.id, historical.id}
    assert all(row.reason.strength == PrecedentStrength.HUMAN for row in picked)
    assert all(row.decision.validity == "confirmed" for row in picked)
