"""`AssessmentService.record` of a container or RPM audit or a vuln-scan: the document's findings
are taken in as findings of the assessment through FindingIntake, as `record_audit` does."""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Any
from uuid import UUID

import pytest

from tests.v1.services import test_assessment_record as recording
from tests.v1.services.test_assessment_record import REPORT, fixture, provenance, record
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.artifacts import SecurityAuditArtifact, VulnFindingsArtifact
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs
from traust_core.v1.services.assessment import AssessmentService

engine, context, ref = recording.engine, recording.context, recording.ref

DESCRIPTION = "The image runs its entrypoint as root, so a process escape lands with uid 0 rights."


def finding(label: str, path: str, lines: str | None = None, **changes: Any) -> dict[str, Any]:
    location = {"path": path} | ({"lines": lines} if lines else {})
    return {
        "id": label,
        "title": f"{label} runs as root",
        "severity": "high",
        "cwes": ["CWE-250"],
        "locations": [location],
        "description": DESCRIPTION,
        "remediation": "Set a non-root USER in the image.",
        **changes,
    }


def report(*findings: dict[str, Any]) -> SecurityAuditArtifact:
    return SecurityAuditArtifact.from_document(
        {**json.loads(REPORT.payload), "findings": list(findings)}
    )


AUDIT = report(
    finding("WIDGET-1", "Dockerfile", "12-14", category="insecure-workload-config"),
    finding("WIDGET-2", "usr/lib/widget/plugin.so", severity="low", cwes=["CWE-276", "CWE-732"]),
)


def taken(context: Any, assessment: Assessment) -> dict[str, tuple[str, str, int | None]]:
    """Per finding title: its occurrence's severity and first location on this assessment."""
    assert assessment.id is not None
    with SqlTraustUnitOfWork(context.database) as uow:
        occurrences = uow.occurrences.list_for_assessment(assessment.id)
        findings = {f.id: f for f in uow.findings.list_by_ids([o.finding_id for o in occurrences])}
        out = {}
        for o in occurrences:
            assert o.id is not None
            (place,) = uow.locations.list_for_occurrences([o.id])
            out[findings[o.finding_id].title] = (o.severity, place.path, place.line_start)
    return out


@pytest.mark.parametrize("kind", [AssessmentKind.CONTAINER, AssessmentKind.RPM])
def test_a_container_or_rpm_audit_takes_its_report_findings_in(
    context: Any, ref: UUID, kind: AssessmentKind
) -> None:
    assessment = record(context, AUDIT, ref, kind)
    assert taken(context, assessment) == {
        "WIDGET-1 runs as root": ("high", "Dockerfile", 12),
        "WIDGET-2 runs as root": ("low", "usr/lib/widget/plugin.so", None),
    }


def test_the_report_states_cwes_and_category_on_the_findings(context: Any, ref: UUID) -> None:
    assessment = record(context, AUDIT, ref, AssessmentKind.CONTAINER)
    assert assessment.id is not None
    views = context.services().findings.list_by_ids(
        [o.finding_id for o in _occurrences(context, assessment.id)]
    )
    assert {v.finding.title: (sorted(v.cwes), v.label("category")) for v in views} == {
        "WIDGET-1 runs as root": (["CWE-250"], "insecure-workload-config"),
        "WIDGET-2 runs as root": (["CWE-276", "CWE-732"], None),
    }


def _occurrences(context: Any, assessment_id: UUID) -> list[Any]:
    with SqlTraustUnitOfWork(context.database) as uow:
        return uow.occurrences.list_for_assessment(assessment_id)


def test_recording_the_same_run_again_adds_no_finding(context: Any, ref: UUID) -> None:
    first = record(context, AUDIT, ref, AssessmentKind.CONTAINER)
    again = record(context, AUDIT, ref, AssessmentKind.CONTAINER)
    assert again.id == first.id
    assert first.id is not None
    assert len(_occurrences(context, first.id)) == 2


def test_the_same_finding_in_a_later_audit_is_the_same_finding(context: Any, ref: UUID) -> None:
    first = record(context, AUDIT, ref, AssessmentKind.CONTAINER)
    later = record(
        context, report(finding("WIDGET-9", "Dockerfile", "30")), ref, AssessmentKind.RPM
    )
    assert first.id is not None and later.id is not None
    (rerun,) = _occurrences(context, later.id)
    assert rerun.finding_id in {o.finding_id for o in _occurrences(context, first.id)}


@pytest.mark.parametrize("kind", [AssessmentKind.BENCHMARK_AUDIT], ids=str)
def test_other_report_kinds_record_the_document_only(
    context: Any, ref: UUID, kind: AssessmentKind
) -> None:
    assessment = record(context, AUDIT, ref, kind)
    assert assessment.id is not None
    assert _occurrences(context, assessment.id) == []


def test_a_report_with_no_findings_takes_nothing_in(context: Any, ref: UUID) -> None:
    assessment = record(context, REPORT, ref, AssessmentKind.CONTAINER)
    assert assessment.id is not None
    assert _occurrences(context, assessment.id) == []


@pytest.mark.parametrize("root", [".", "./", "/"])
def test_a_finding_intake_refuses_records_nothing(context: Any, ref: UUID, root: str) -> None:
    doc = report(finding("WIDGET-1", "Dockerfile"), finding("ROOT", root))
    with pytest.raises(ValidationError, match="no usable location"):
        record(context, doc, ref, AssessmentKind.CONTAINER)
    with SqlTraustUnitOfWork(context.database) as uow:
        assert uow.assessments.list_for_ref(ref) == []


def test_recording_findings_needs_intake(context: Any, ref: UUID) -> None:
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(SecurityAuditArtifact)))
    service = AssessmentService(SqlTraustUnitOfWork(context.database), publisher=publisher)
    with pytest.raises(ConfigError, match="needs finding intake"):
        service.record(AUDIT, ref, AssessmentKind.CONTAINER, "skill:test", "0.1.0", provenance())
    with SqlTraustUnitOfWork(context.database) as uow:
        assert uow.assessments.list_for_ref(ref) == []


SCAN = json.loads(fixture("assessments/widget-vuln-findings.json"))


def scan(*findings: dict[str, Any], **changes: Any) -> VulnFindingsArtifact:
    return VulnFindingsArtifact.from_document({**SCAN, "findings": list(findings), **changes})


def scanned(label: str, file: str, line: int | None, **changes: Any) -> dict[str, Any]:
    return {
        "id": label,
        "file": file,
        "line": line,
        "category": "auth-bypass",
        "severity": "high",
        "confidence": 0.9,
        "title": f"{label} skips its ownership check",
        "description": DESCRIPTION,
        "recommendation": "Check ownership before returning the record.",
        **changes,
    }


VULN = scan(
    scanned("REPO-abcdef0-001", "auth.py", 41, cwe="CWE-862"),
    scanned("REPO-abcdef0-002", "debug.py", None, severity="low", category="info-leak"),
)


def test_a_vuln_scan_takes_its_findings_in(context: Any, ref: UUID) -> None:
    assessment = record(context, VULN, ref, AssessmentKind.VULN_SCAN_CANONICAL)
    assert taken(context, assessment) == {
        "REPO-abcdef0-001 skips its ownership check": ("high", "auth.py", 41),
        "REPO-abcdef0-002 skips its ownership check": ("low", "debug.py", None),
    }
    assert assessment.id is not None
    views = context.services().findings.list_by_ids(
        [o.finding_id for o in _occurrences(context, assessment.id)]
    )
    assert {v.finding.title: (list(v.cwes), v.label("category")) for v in views} == {
        "REPO-abcdef0-001 skips its ownership check": (["CWE-862"], "auth-bypass"),
        "REPO-abcdef0-002 skips its ownership check": ([], "info-leak"),
    }


@pytest.mark.parametrize(
    ("doc", "count"),
    [
        (scan(), 0),
        (scan(known_findings=[{"title": "old", "matches_baseline_id": "WIDGET-1"}]), 0),
        (VULN, 2),
    ],
    ids=["clean", "known-only", "two"],
)
def test_a_vuln_scan_takes_in_only_its_new_findings_once(
    context: Any, ref: UUID, doc: VulnFindingsArtifact, count: int
) -> None:
    first = record(context, doc, ref, AssessmentKind.VULN_SCAN_CANONICAL)
    again = record(context, doc, ref, AssessmentKind.VULN_SCAN_CANONICAL)
    assert again.id == first.id and first.id is not None
    assert len(_occurrences(context, first.id)) == count


def test_a_vuln_scan_finding_intake_refuses_records_nothing(context: Any, ref: UUID) -> None:
    doc = scan(scanned("REPO-abcdef0-001", "auth.py", 3), scanned("REPO-abcdef0-002", ".", 1))
    with pytest.raises(ValidationError, match="no usable location"):
        record(context, doc, ref, AssessmentKind.VULN_SCAN_CANONICAL)
    with SqlTraustUnitOfWork(context.database) as uow:
        assert uow.assessments.list_for_ref(ref) == []


def test_a_vuln_scan_kind_holding_a_report_is_refused(context: Any, ref: UUID) -> None:
    with pytest.raises(ValidationError, match="holds a vuln-findings document"):
        record(context, AUDIT, ref, AssessmentKind.VULN_SCAN_CANONICAL)


def test_recording_a_vuln_scan_needs_intake(context: Any, ref: UUID) -> None:
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(VulnFindingsArtifact)))
    service = AssessmentService(SqlTraustUnitOfWork(context.database), publisher=publisher)
    with pytest.raises(ConfigError, match="needs finding intake"):
        service.record(
            VULN, ref, AssessmentKind.VULN_SCAN_CANONICAL, "skill:test", "0.1.0", provenance()
        )


def _store_advisory(context: Any, identifier: str, *aliases: str) -> UUID:
    from traust_core.v1.models.dependencies import Advisory

    with SqlTraustUnitOfWork(context.database) as uow:
        canonical = uow.advisories.get_or_add(Advisory(identifier=identifier))
        assert canonical.id is not None
        for alias in aliases:
            uow.advisories.get_or_add(Advisory(identifier=alias, alias_of_id=canonical.id))
        uow.commit()
    return canonical.id


def _dependency_finding(label: str, advisory: str) -> dict[str, Any]:
    return finding(
        label,
        "go.mod",
        title=f"{advisory} in google.golang.org/grpc",
        category="supply-chain",
        cwes=["CWE-1395"],
        dependency={
            "advisory": advisory,
            "module": "google.golang.org/grpc",
            "ecosystem": "go",
            "installed_version": "v1.56.0",
            "classification": "likely_affected",
            "evidence_level": "manifest",
        },
    )


def test_a_report_dependency_on_a_stored_advisory_is_the_exposure_finding(
    context: Any, ref: UUID
) -> None:
    """A report finding whose dependency names a stored advisory is identified the way an
    impact analysis identifies its dependency finding: (repository, advisory, package)."""
    canonical = _store_advisory(context, "GHSA-m425-mq94-257g", "CVE-2023-44487")
    first = record(
        context,
        report(_dependency_finding("GRPC-1", "GHSA-m425-mq94-257g")),
        ref,
        AssessmentKind.CONTAINER,
    )
    # a later audit names the CVE alias, at another path: still the same finding
    alias = _dependency_finding("GRPC-9", "CVE-2023-44487")
    alias["locations"] = [{"path": "vendor/modules.txt"}]
    second = record(context, report(alias), ref, AssessmentKind.CONTAINER)
    [a] = _occurrences(context, first.id)
    [b] = _occurrences(context, second.id)
    assert a.finding_id == b.finding_id
    with SqlTraustUnitOfWork(context.database) as uow:
        found = uow.findings.get(a.finding_id)
    assert (found.advisory_id, found.fingerprint_algo) == (canonical, "exposure-v1")


def test_a_report_dependency_on_an_unknown_advisory_keeps_its_report_identity(
    context: Any, ref: UUID
) -> None:
    assessment = record(
        context,
        report(_dependency_finding("GRPC-1", "GHSA-xxxx-yyyy-zzzz")),
        ref,
        AssessmentKind.CONTAINER,
    )
    [o] = _occurrences(context, assessment.id)
    with SqlTraustUnitOfWork(context.database) as uow:
        found = uow.findings.get(o.finding_id)
    assert found.advisory_id is None and found.fingerprint_algo != "exposure-v1"


def _link_packages(context: Any, advisory_id: UUID, *packages: tuple[str, str]) -> None:
    """The stored advisory names each (ecosystem, name) package."""
    from traust_core.v1.models.dependencies import AdvisoryPackage, Package

    with SqlTraustUnitOfWork(context.database) as uow:
        for ecosystem, name in packages:
            stored = uow.packages.get_or_add(Package(ecosystem=ecosystem, name=name))
            assert stored.id is not None
            uow.advisory_packages.get_or_add(
                AdvisoryPackage(advisory_id=advisory_id, package_id=stored.id)
            )
        uow.commit()


def _finding_of(context: Any, assessment: Assessment) -> Any:
    assert assessment.id is not None
    [o] = _occurrences(context, assessment.id)
    with SqlTraustUnitOfWork(context.database) as uow:
        return uow.findings.get(o.finding_id)


def _with_dependency(label: str, path: str, **dependency: Any) -> dict[str, Any]:
    entry = _dependency_finding(label, "GHSA-m425-mq94-257g")
    entry["locations"] = [{"path": path}]
    entry["dependency"] = {"advisory": "GHSA-m425-mq94-257g", **dependency}
    return entry


@pytest.mark.parametrize(
    ("ecosystem", "spellings"),
    [
        ("pypi", ("Requests", "requests")),
        ("pypi", ("zope.interface", "Zope_Interface")),
        ("npm", ("Lodash", "lodash")),
    ],
)
def test_equivalent_package_spellings_are_one_exposure_finding(
    context: Any, ref: UUID, ecosystem: str, spellings: tuple[str, str]
) -> None:
    """The package is keyed as core stores it (`package_name`), so a report's spelling and an
    impact analysis's stored name land on one finding."""
    from traust_core.v1.models.dependencies import Advisory
    from traust_core.v1.services.findings.exposures import exposure_key

    _store_advisory(context, "GHSA-m425-mq94-257g")
    first, second = (
        _finding_of(
            context,
            record(
                context,
                report(_with_dependency(f"DEP-{i}", path, module=name, ecosystem=ecosystem)),
                ref,
                AssessmentKind.CONTAINER,
            ),
        )
        for i, (name, path) in enumerate(zip(spellings, ("a/manifest", "b/manifest"), strict=True))
    )
    assert first.id == second.id and first.fingerprint_algo == "exposure-v1"
    advisory = Advisory(id=first.advisory_id, identifier="GHSA-m425-mq94-257g")
    assert len({exposure_key(advisory, ecosystem, name) for name in spellings}) == 1


def test_an_omitted_ecosystem_is_the_one_the_stored_advisory_names(context: Any, ref: UUID) -> None:
    """The contract lets a report omit `ecosystem`; when the stored advisory names the module
    in exactly one ecosystem, that is the finding's exposure identity."""
    canonical = _store_advisory(context, "GHSA-m425-mq94-257g")
    _link_packages(context, canonical, ("go", "google.golang.org/grpc"))
    bare = _finding_of(
        context,
        record(
            context,
            report(_with_dependency("DEP-1", "go.mod", module="google.golang.org/grpc")),
            ref,
            AssessmentKind.CONTAINER,
        ),
    )
    stated = _finding_of(
        context,
        record(
            context,
            report(
                _with_dependency(
                    "DEP-2", "vendor/x", module="google.golang.org/grpc", ecosystem="go"
                )
            ),
            ref,
            AssessmentKind.CONTAINER,
        ),
    )
    assert bare.id == stated.id and bare.fingerprint_algo == "exposure-v1"


@pytest.mark.parametrize("names", [(), (("npm", "widget"), ("pypi", "widget"))])
def test_an_ecosystem_the_advisory_cant_settle_is_never_guessed(
    context: Any, ref: UUID, names: tuple[tuple[str, str], ...]
) -> None:
    """No stored package, or the module named in two ecosystems: the report identity stays."""
    canonical = _store_advisory(context, "GHSA-m425-mq94-257g")
    _link_packages(context, canonical, *names)
    found = _finding_of(
        context,
        record(
            context,
            report(_with_dependency("DEP-1", "package.json", module="widget")),
            ref,
            AssessmentKind.CONTAINER,
        ),
    )
    assert found.advisory_id is None and found.fingerprint_algo != "exposure-v1"


def test_a_vuln_scans_advisory_score_is_kept_on_the_occurrence_and_view(
    context: Any, ref: UUID
) -> None:
    """traust-contracts#190: a vuln-scan finding's `cvss` is taken in as a report's is, so the
    occurrence holds it and the finding view shows it (risk weight and SLA read it)."""
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    doc = scan(
        scanned(
            "REPO-abcdef0-003",
            "go.mod",
            3,
            category="supply-chain",
            severity="critical",
            cvss={"vector": vector, "score": 9.8},
            dependency={"advisory": "CVE-2024-0001", "module": "golang.org/x/net"},
        )
    )
    assessment = record(context, doc, ref, AssessmentKind.VULN_SCAN_CANONICAL)
    assert assessment.id is not None
    [occurrence] = _occurrences(context, assessment.id)
    assert (occurrence.cvss_vector, occurrence.cvss_score) == (vector, Decimal("9.8"))
    [view] = context.services().findings.list_by_ids([occurrence.finding_id])
    assert view.cvss is not None and view.cvss.vector == vector


def test_a_vuln_scan_dependency_on_a_stored_advisory_is_the_exposure_finding(
    context: Any, ref: UUID
) -> None:
    """A vuln-scan finding's `dependency` (traust-contracts#190) is identified as a report's is:
    the same advisory and package in one repository is one finding across both kinds."""
    _store_advisory(context, "GHSA-m425-mq94-257g")
    audit = _finding_of(
        context,
        record(
            context,
            report(
                _with_dependency("DEP-1", "go.mod", module="google.golang.org/grpc", ecosystem="go")
            ),
            ref,
            AssessmentKind.CONTAINER,
        ),
    )
    scanned_finding = scanned(
        "REPO-abcdef0-009",
        "vendor/modules.txt",
        2,
        category="supply-chain",
        dependency={
            "advisory": "GHSA-m425-mq94-257g",
            "module": "google.golang.org/grpc",
            "ecosystem": "go",
        },
    )
    swept = _finding_of(
        context, record(context, scan(scanned_finding), ref, AssessmentKind.VULN_SCAN_CANONICAL)
    )
    assert swept.id == audit.id and swept.fingerprint_algo == "exposure-v1"


@pytest.mark.parametrize("kind", [AssessmentKind.CONTAINER, AssessmentKind.VULN_SCAN_CANONICAL])
def test_a_vector_without_a_score_is_scored_at_intake(
    context: Any, ref: UUID, kind: AssessmentKind
) -> None:
    """D14: a producer reports the vector; intake computes cvss_score from it with Core's
    calculator (the data model's `cvss_score`, computed from `cvss_vector` at intake)."""
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    entry = (
        finding("VEC-1", "Dockerfile", cvss={"vector": vector})
        if kind is AssessmentKind.CONTAINER
        else scanned("REPO-abcdef0-010", "go.mod", 3, cvss={"vector": vector})
    )
    doc = report(entry) if kind is AssessmentKind.CONTAINER else scan(entry)
    assessment = record(context, doc, ref, kind)
    assert assessment.id is not None
    [occurrence] = _occurrences(context, assessment.id)
    assert (occurrence.cvss_vector, occurrence.cvss_score) == (vector, Decimal("7.5"))


def test_a_stated_score_that_differs_from_the_vector_is_still_refused(
    context: Any, ref: UUID
) -> None:
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    with pytest.raises(ValidationError, match="not what its vector computes"):
        record(
            context,
            report(finding("VEC-2", "Dockerfile", cvss={"vector": vector, "score": 9.8})),
            ref,
            AssessmentKind.CONTAINER,
        )


def test_a_later_entry_s_vector_scores_the_shared_occurrence(context: Any, ref: UUID) -> None:
    """Two entries with one fingerprint are one append-only occurrence: the first entry with a
    vector supplies its CVSS, even when an unscored entry comes before it."""
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    doc = report(
        finding("DUP-1", "Dockerfile"),
        finding("DUP-2", "Dockerfile", cvss={"vector": vector}),
    )
    assessment = record(context, doc, ref, AssessmentKind.CONTAINER)
    assert assessment.id is not None
    [occurrence] = _occurrences(context, assessment.id)
    assert (occurrence.cvss_vector, occurrence.cvss_score) == (vector, Decimal("7.5"))


def test_a_score_only_entry_keeps_its_own_score(context: Any, ref: UUID) -> None:
    """Only an entry with no CVSS at all takes a same-fingerprint entry's vector; a score-only
    entry's stated score is never overwritten."""
    from traust_core.v1.models.findings import FindingCandidate
    from traust_core.v1.models.integrity import Fingerprint
    from traust_core.v1.services.findings.intake import _scored_per_fingerprint

    base = FindingCandidate.model_validate(
        {
            "label": "S-1",
            "repository_id": "00000000-0000-0000-0000-000000000001",
            "title": "t",
            "description": "d",
            "reported_severity": "high",
        }
    )
    score_only = base.model_copy(update={"cvss_score": Decimal("5.0")})
    unprefixed = base.model_copy(update={"label": "S-2", "cvss_vector": "AV:N/AC:L"})
    bare = base.model_copy(update={"label": "S-3"})
    key = Fingerprint("v3", "a" * 64)
    out = _scored_per_fingerprint([score_only, unprefixed, bare], [key, key, key])
    assert (out[0].cvss_vector, out[0].cvss_score) == (None, Decimal("5.0"))
    assert (out[2].cvss_vector, out[2].cvss_score) == ("AV:N/AC:L", None)
