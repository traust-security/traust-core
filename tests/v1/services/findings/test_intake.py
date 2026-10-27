"""FindingIntake.accept on SQLite and Postgres: an assessment's reported findings become rows."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pydantic
import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.models.findings import CweId, ExposureKey, FindingCandidate, Label
from traust_core.v1.models.integrity import FingerprintInput
from traust_core.v1.models.inventory import Repository, RepositoryRef
from traust_core.v1.models.vocabulary import Severity
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@dataclass
class Target:
    repository: Repository
    ref: RepositoryRef


@pytest.fixture
def target(engine: Engine) -> Target:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url="https://github.com/example/operator")
        ref = seed.repository_ref(repo)
        for cwe in ("CWE-89", "CWE-79", "CWE-306"):
            seed.cwe(identifier=cwe)
        uow.commit()
    return Target(repo, ref)


def intake(engine: Engine) -> FindingIntake:
    return FindingIntake(SqlTraustUnitOfWork(engine), IdentityPolicy(), TaxonomyPolicy())


def audit(engine: Engine, target: Target) -> UUID:
    with SqlTraustUnitOfWork(engine) as uow:
        made = Seed(uow).assessment(target.ref, kind="secure-code")
        uow.commit()
    assert made.id is not None
    return made.id


def candidate(target: Target, label: str = "OPERATOR-abcdef0-001", **kw: Any) -> FindingCandidate:
    values: dict[str, Any] = {
        "label": Label(label),
        "repository_id": target.repository.id,
        "title": "SQL injection in the reconcile handler",
        "rule": "go.sql.injection",
        "cwes": (CweId("CWE-89"),),
        "category": "injection",
        "locations": (
            CodeSpan(path=RepoPath("controllers/reconcile.go"), line=41),
            CodeSpan(path=RepoPath("controllers/db.go"), line=12),
        ),
        "reported_severity": Severity.HIGH,
    }
    return FindingCandidate(**{**values, **kw})


def rows(engine: Engine, finding_id: UUID) -> dict[str, Any]:
    with SqlTraustUnitOfWork(engine) as uow:
        occurrences = uow.occurrences.list_for_finding(finding_id)
        return {
            "finding": uow.findings.get(finding_id),
            "occurrences": occurrences,
            "locations": [
                (loc.path, loc.line_start, loc.line_end)
                for o in occurrences
                for loc in uow.locations.list_for_occurrence(o.id)  # type: ignore[arg-type]
            ],
            "cwes": [
                uow.cwes.get(fc.cwe_id).identifier
                for fc in uow.finding_cwes.list_for_finding(finding_id)
            ],
            "labels": [
                (fl.taxonomy, fl.label) for fl in uow.finding_labels.list_for_finding(finding_id)
            ],
        }


def test_a_new_finding_gets_its_occurrence_locations_cwes_and_category(
    engine: Engine, target: Target
) -> None:
    run = audit(engine, target)
    result = intake(engine).accept(run, [candidate(target)])
    finding_id = result.findings[Label("OPERATOR-abcdef0-001")]
    assert result.created == (finding_id,)
    got = rows(engine, finding_id)
    assert got["finding"].title == "SQL injection in the reconcile handler"
    assert (got["finding"].fingerprint_algo, len(got["finding"].fingerprint)) == ("v3", 64)
    (occurrence,) = got["occurrences"]
    assert (occurrence.assessment_id, occurrence.severity, occurrence.rule) == (
        run,
        "high",
        "go.sql.injection",
    )
    assert sorted(got["locations"]) == [
        ("controllers/db.go", 12, 12),
        ("controllers/reconcile.go", 41, 41),
    ]
    assert got["cwes"] == ["CWE-89"]
    assert got["labels"] == [("category", "injection")]


def test_accepting_the_same_report_again_adds_nothing(engine: Engine, target: Target) -> None:
    run = audit(engine, target)
    first = intake(engine).accept(run, [candidate(target)])
    again = intake(engine).accept(run, [candidate(target)])
    assert again.findings == first.findings
    assert again.created == ()
    got = rows(engine, first.findings[Label("OPERATOR-abcdef0-001")])
    assert (len(got["occurrences"]), len(got["locations"]), got["cwes"], len(got["labels"])) == (
        1,
        2,
        ["CWE-89"],
        1,
    )


def test_a_later_scan_matches_by_fingerprint_and_adds_its_own_occurrence(
    engine: Engine, target: Target
) -> None:
    first = intake(engine).accept(audit(engine, target), [candidate(target)])
    rescan = audit(engine, target)
    later = intake(engine).accept(
        rescan,
        [
            candidate(
                target,
                label="OPERATOR-1234567-004",
                title="retitled by the rescan",
                reported_severity=Severity.CRITICAL,
            )
        ],
    )
    finding_id = first.findings[Label("OPERATOR-abcdef0-001")]
    assert later.findings == {Label("OPERATOR-1234567-004"): finding_id}
    assert later.created == ()
    got = rows(engine, finding_id)
    assert [o.severity for o in got["occurrences"]] == ["high", "critical"]
    assert got["finding"].title == "SQL injection in the reconcile handler"


def test_same_place_and_weakness_reported_twice_in_one_report_is_one_finding(
    engine: Engine, target: Target
) -> None:
    result = intake(engine).accept(
        audit(engine, target),
        [candidate(target, label="A-001"), candidate(target, label="A-002", title="duplicate")],
    )
    assert result.findings[Label("A-001")] == result.findings[Label("A-002")]
    assert len(result.created) == 1
    assert len(rows(engine, result.created[0])["occurrences"]) == 1


@pytest.mark.parametrize("reverse", [False, True])
def test_duplicate_fingerprints_reconcile_unknown_and_explicit_kind(
    engine: Engine, target: Target, reverse: bool
) -> None:
    reported = [
        candidate(target, label="A-001"),
        candidate(target, label="A-002", kind="weakness"),
    ]
    if reverse:
        reported.reverse()
    service = intake(engine)
    run = audit(engine, target)
    result = service.accept(run, reported)
    finding_id = result.findings[Label("A-001")]
    assert result.findings[Label("A-002")] == finding_id
    assert result.created == (finding_id,)
    assert rows(engine, finding_id)["finding"].kind == "weakness"
    assert service.accept(run, reported).created == ()


@pytest.mark.parametrize("stored_kind", [None, "vulnerability"])
@pytest.mark.parametrize("reverse", [False, True])
def test_duplicate_batch_does_not_reclassify_a_previously_stored_finding(
    engine: Engine, target: Target, stored_kind: str | None, reverse: bool
) -> None:
    service = intake(engine)
    original = service.accept(audit(engine, target), [candidate(target, kind=stored_kind)])
    finding_id = original.created[0]
    stored = rows(engine, finding_id)["finding"]
    reported = [
        candidate(target, label="A-001"),
        candidate(target, label="A-002", kind="weakness"),
    ]
    if reverse:
        reported.reverse()
    result = service.accept(audit(engine, target), reported)
    assert set(result.findings.values()) == {finding_id}
    assert result.created == ()
    assert rows(engine, finding_id)["finding"] == stored


def test_a_different_weakness_at_the_same_place_is_a_different_finding(
    engine: Engine, target: Target
) -> None:
    result = intake(engine).accept(
        audit(engine, target),
        [candidate(target, label="A-001"), candidate(target, label="A-002", cwes=("CWE-79",))],
    )
    assert len(set(result.findings.values())) == 2


def test_owasp_llm_categories_are_labels_once_each(engine: Engine, target: Target) -> None:
    llm = candidate(target, owasp_llm_references=("LLM05", "LLM06", "LLM05"))
    run = intake(engine)
    created = run.accept(audit(engine, target), [llm]).created[0]
    run.accept(audit(engine, target), [llm])  # re-reporting adds no second label
    assert sorted(rows(engine, created)["labels"]) == [
        ("category", "injection"),
        ("owasp-llm", "LLM05"),
        ("owasp-llm", "LLM06"),
    ]
    with SqlTraustUnitOfWork(engine) as uow:
        assert [fl.finding_id for fl in uow.finding_labels.list_with("owasp-llm", "LLM06")] == [
            created
        ]


def test_an_unknown_owasp_llm_category_is_refused(target: Target) -> None:
    with pytest.raises(pydantic.ValidationError):
        candidate(target, owasp_llm_references=("LLM11",))


def test_a_finding_without_category_gets_no_label(engine: Engine, target: Target) -> None:
    result = intake(engine).accept(audit(engine, target), [candidate(target, category=None)])
    assert rows(engine, result.created[0])["labels"] == []


def test_a_file_level_location_has_no_line(engine: Engine, target: Target) -> None:
    spans = (CodeSpan(path=RepoPath("deploy/role.yaml")),)
    result = intake(engine).accept(audit(engine, target), [candidate(target, locations=spans)])
    assert rows(engine, result.created[0])["locations"] == [("deploy/role.yaml", None, None)]


def test_an_empty_report_records_nothing(engine: Engine, target: Target) -> None:
    assert intake(engine).accept(audit(engine, target), []).findings == {}


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"reported_severity": None}, "no severity"),
        ({"cwes": ("CWE89",)}, "not CWE identifiers"),
        ({"locations": ()}, "no usable location"),
        ({"repository_id": uuid4()}, "examined"),
    ],
)
def test_an_invalid_candidate_rolls_back_the_whole_report(
    engine: Engine, target: Target, change: dict[str, Any], message: str
) -> None:
    run = audit(engine, target)
    batch = [candidate(target, label="GOOD-001"), candidate(target, label="BAD-002", **change)]
    with pytest.raises(ValidationError, match=message):
        intake(engine).accept(run, batch)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.findings.list_for_repository(target.repository.id) == []  # type: ignore[arg-type]
        assert uow.occurrences.list_for_assessment(run) == []


def test_an_unknown_assessment_is_not_found(engine: Engine, target: Target) -> None:
    with pytest.raises(NotFoundError):
        intake(engine).accept(uuid4(), [candidate(target)])


def test_match_finds_an_accepted_report_entry_by_fingerprint(
    engine: Engine, target: Target
) -> None:
    accepted = intake(engine).accept(audit(engine, target), [candidate(target)])
    entry = {
        "id": "OPERATOR-abcdef0-001",
        "cwes": ["CWE-89"],
        "locations": [{"path": "controllers/db.go"}, {"path": "./controllers/reconcile.go"}],
    }
    reported = FingerprintInput.from_report(entry, target.repository.url)
    found = intake(engine).match(target.repository.id, reported)  # type: ignore[arg-type]
    assert found == accepted.findings[Label("OPERATOR-abcdef0-001")]


def test_match_of_an_entry_never_accepted_is_none(engine: Engine, target: Target) -> None:
    reported = FingerprintInput.from_report(
        {"cwes": ["CWE-79"], "locations": [{"path": "web/view.go"}]}, target.repository.url
    )
    assert intake(engine).match(target.repository.id, reported) is None  # type: ignore[arg-type]


def test_match_refuses_an_entry_without_a_location(engine: Engine, target: Target) -> None:
    reported = FingerprintInput.from_report({"cwes": ["CWE-79"]}, target.repository.url)
    with pytest.raises(ValidationError, match="no usable location"):
        intake(engine).match(target.repository.id, reported)  # type: ignore[arg-type]


def test_a_well_formed_cwe_outside_the_catalog_is_recorded_once(
    engine: Engine, target: Target
) -> None:
    first = intake(engine).accept(audit(engine, target), [candidate(target, cwes=("CWE-1333",))])
    intake(engine).accept(
        audit(engine, target),
        [
            candidate(
                target,
                label="B-001",
                cwes=("CWE-1333",),
                locations=(CodeSpan(path=RepoPath("x.go")),),
            )
        ],
    )
    assert rows(engine, first.created[0])["cwes"] == ["CWE-1333"]
    with SqlTraustUnitOfWork(engine) as uow:
        cwe = uow.cwes.find_by_identifier("CWE-1333")
        assert cwe is not None
        assert (cwe.abstraction, cwe.mapping_usage, cwe.catalog_version) == (None, None, None)
        assert len(uow.finding_cwes.list_for_cwe(cwe.id)) == 2  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "symbols", [(None, "Handle"), ("Handle", None), ("Handle", "Handle"), (None, None)]
)
@pytest.mark.parametrize("line", [None, 41])
@pytest.mark.parametrize("separate_candidates", [False, True])
def test_duplicate_location_ranges_preserve_the_supplied_symbol(
    engine: Engine,
    target: Target,
    symbols: tuple[str | None, ...],
    line: int | None,
    separate_candidates: bool,
) -> None:
    run = audit(engine, target)
    spans = tuple(CodeSpan(path="handler.go", line=line, symbol=s) for s in symbols)
    reports = (
        [candidate(target, label=f"A-{i}", locations=(span,)) for i, span in enumerate(spans)]
        if separate_candidates
        else [candidate(target, locations=spans)]
    )
    first = intake(engine).accept(run, reports)
    again = intake(engine).accept(run, reports)
    assert again.findings == first.findings
    assert again.created == ()
    with SqlTraustUnitOfWork(engine) as uow:
        [occurrence] = uow.occurrences.list_for_assessment(run)
        [location] = uow.locations.list_for_occurrence(occurrence.id)
    assert (location.path, location.line_start, location.line_end, location.symbol) == (
        "handler.go",
        line,
        line,
        "Handle" if "Handle" in symbols else None,
    )


@pytest.mark.parametrize("separate_candidates", [False, True])
@pytest.mark.parametrize("symbols", [("Handle", "Other"), ("Other", "Handle")])
def test_conflicting_location_symbols_roll_back_the_whole_intake(
    engine: Engine, target: Target, separate_candidates: bool, symbols: tuple[str, str]
) -> None:
    run = audit(engine, target)
    spans = tuple(CodeSpan(path="handler.go", line=41, symbol=s) for s in symbols)
    reports = (
        [candidate(target, label=f"BAD-{i}", locations=(span,)) for i, span in enumerate(spans)]
        if separate_candidates
        else [candidate(target, label="BAD-001", locations=spans)]
    )
    with pytest.raises(ValidationError, match=r"conflicting symbols at handler\.go:41"):
        intake(engine).accept(run, [candidate(target), *reports])
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.findings.list_for_repository(target.repository.id) == []
        assert uow.occurrences.list_for_assessment(run) == []
        assert uow.locations.list_with_symbols(["Handle", "Other"]) == []


def test_a_later_scan_adds_a_symbol_without_rewriting_earlier_locations(
    engine: Engine, target: Target
) -> None:
    earlier = audit(engine, target)
    original = candidate(target, locations=(CodeSpan(path="handler.go", line=41),))
    accepted = intake(engine).accept(earlier, [original])
    with SqlTraustUnitOfWork(engine) as uow:
        [old_occurrence] = uow.occurrences.list_for_assessment(earlier)
        [old_location] = uow.locations.list_for_occurrence(old_occurrence.id)
    later = audit(engine, target)
    enriched = original.model_copy(
        update={"locations": (CodeSpan(path="handler.go", line=41, symbol="Handle"),)}
    )
    rescanned = intake(engine).accept(later, [enriched])
    assert rescanned.findings == accepted.findings
    assert rescanned.created == ()
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.locations.list_for_occurrence(old_occurrence.id) == [old_location]
        [new_occurrence] = uow.occurrences.list_for_assessment(later)
        [new_location] = uow.locations.list_for_occurrence(new_occurrence.id)
    assert old_location.symbol is None
    assert new_location.symbol == "Handle"


def exposure(engine: Engine, identifier: str = "GHSA-m425-mq94-257g") -> ExposureKey:
    with SqlTraustUnitOfWork(engine) as uow:
        advisory = Seed(uow).advisory(identifier=identifier)
        uow.commit()
    assert advisory.id is not None
    return ExposureKey(
        advisory_id=advisory.id,
        advisory=identifier,
        ecosystem="go",
        package="google.golang.org/grpc",
    )


def test_a_dependency_finding_is_known_by_advisory_and_package_without_a_location(
    engine: Engine, target: Target
) -> None:
    key = exposure(engine)
    dependency = candidate(target, cwes=(), locations=(), category=None, exposure=key)
    first = intake(engine).accept(audit(engine, target), [dependency])
    later = intake(engine).accept(
        audit(engine, target), [dependency.model_copy(update={"title": "x"})]
    )
    finding_id = first.findings[dependency.label]
    assert later.findings[dependency.label] == finding_id and later.created == ()
    finding = rows(engine, finding_id)["finding"]
    assert (finding.fingerprint_algo, finding.advisory_id, finding.advisory_match) == (
        "exposure-v1",
        key.advisory_id,
        "confirmed",
    )
    assert len(rows(engine, finding_id)["occurrences"]) == 2


def test_another_advisory_on_the_same_package_is_another_finding(
    engine: Engine, target: Target
) -> None:
    one, other = exposure(engine), exposure(engine, "GHSA-other-0000-0000")
    found = intake(engine).accept(
        audit(engine, target),
        [
            candidate(target, label="a", cwes=(), locations=(), exposure=one),
            candidate(target, label="b", cwes=(), locations=(), exposure=other),
        ],
    )
    assert found.findings[Label("a")] != found.findings[Label("b")]


def test_a_report_finding_carries_its_owasp_llm_categories(target: Target) -> None:
    from tests.v1.services.reporting.documents import valid_report
    from traust_core.v1.models.artifacts import ReportArtifact

    doc = valid_report()
    doc["findings"][0]["owasp_llm_references"] = ["LLM01"]
    found = FindingCandidate.of_report(
        ReportArtifact.from_document(doc).findings, target.repository.id
    )
    assert found[0].owasp_llm_references == ("LLM01",)
    assert all(f.owasp_llm_references == () for f in found[1:])
