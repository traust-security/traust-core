"""Advisory fleet exports retain native evidence and every commit/package verdict."""

from __future__ import annotations

import json
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.services.test_exposure_impact import (
    AT,
    GHSA,
    GRPC,
    Lookup,
    engine,
    refs,
    sbom,
    service,
)
from tests.v1.services.test_exposure_reads import reads
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.artifacts import ImpactAnalysisArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    ImpactEvidence,
    ImpactExport,
    Version,
)
from traust_core.v1.models.vocabulary import (
    ImpactClassification,
    ImpactGovulncheck,
    ImpactManifestScan,
    SourceType,
)

__all__ = ["engine"]


def source(day: int = 0) -> Provenance:
    return Provenance(
        run_id=uuid4(), source=SourceType("impact_report"), occurred_at=AT + timedelta(days=day)
    )


def test_export_retains_every_classification_and_the_complete_native_documents(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    exposure = reads(engine)
    known = exposure.find_advisory(GHSA)
    assert known is not None and known.advisory_id is not None
    evidence = (
        ImpactEvidence(
            govulncheck=ImpactGovulncheck.SYMBOL_REACHABLE,
            govulncheck_trace=("app.main", "grpc.Serve"),
        ),
        ImpactEvidence(
            manifest_scan=ImpactManifestScan.MODULE_PINNED_IN_RANGE,
            needs_manual_trace=True,
            notes="Configuration-dependent call path",
        ),
        ImpactEvidence(),
        ImpactEvidence(govulncheck=ImpactGovulncheck.PACKAGE_IMPORTED_NOT_OBSERVED),
        ImpactEvidence(l1_version_in_range=False),
        ImpactEvidence(l1_depends_on=False),
    )
    documents = {}
    payloads = {}
    subjects = {}
    for day, (ref, observed) in enumerate(zip(refs(engine, len(evidence)), evidence, strict=True)):
        assert ref.id is not None
        exposure.ingest_sbom(sbom(("google.golang.org/grpc", "v1.56.2")), ref.id)
        [prepared] = exposure.prepare(known.advisory_id, ref.id)
        prepared = prepared.model_copy(
            update={"evidence": observed, "products": ("example-product",)}
        )
        doc = prepared.document("1.0.0", "HTTP/2 stream handling")
        recorded = exposure.record(ref.id, doc, source(day))
        documents[recorded.artifact_id] = json.loads(doc.payload)
        payloads[recorded.artifact_id] = doc.payload
        subjects[recorded.artifact_id] = ref.sha

    def offline(self: Lookup, identifier: AdvisoryIdentifier) -> None:
        pytest.fail(f"Export must not refresh {identifier}")

    monkeypatch.setattr(Lookup, "record", offline)
    exported = exposure.export_impacts(AdvisoryIdentifier("GO-2023-2153"))
    assert (exported.advisory_id, exported.advisory, exported.generated_at) == (
        known.advisory_id,
        GHSA,
        AT,
    )
    assert exported.commits == exported.analyses == len(evidence)
    assert exported.classifications == {verdict: 1 for verdict in ImpactClassification}
    assert {row.classification for row in exported.repos} == set(ImpactClassification)
    for row in exported.repos:
        native = documents[row.artifact_id]
        assert row.document == native
        assert (
            ImpactAnalysisArtifact.from_document(row.document).payload == payloads[row.artifact_id]
        )
        assert row.repo == native["repos"][0]["repo"]
        assert row.evidence == ImpactEvidence.model_validate(native["repos"][0]["evidence"])
        assert row.ecosystem is not None
        assert row.evidence.classification(row.ecosystem) == row.classification
        assert row.repository_url == row.repo.replace("repo:", "https://", 1)
        assert row.sha == subjects[row.artifact_id]
        assert (row.finding_id is not None) == (row.classification == ImpactClassification.AFFECTED)
    assert ImpactExport.model_validate_json(exported.model_dump_json()) == exported
    with pytest.raises(NotFoundError):
        exposure.export_impacts(AdvisoryIdentifier("CVE-2023-44487"))


@pytest.mark.parametrize(
    "arrays",
    [
        {},
        {"govulncheck_trace": None, "l4_packages_found": None},
        {"govulncheck_trace": [], "l4_packages_found": []},
        {
            "govulncheck_trace": ["app.main", "grpc.Serve"],
            "l4_packages_found": ["google.golang.org/grpc"],
        },
    ],
    ids=["absent", "unmeasured", "measured-empty", "measured-values"],
)
def test_export_preserves_native_evidence_array_presence(
    engine: Engine, arrays: dict[str, list[str] | None]
) -> None:
    exposure = reads(engine)
    [ref] = refs(engine, 1)
    assert ref.id is not None
    exposure.ingest_sbom(sbom(("google.golang.org/grpc", "v1.56.2")), ref.id)
    known = exposure.find_advisory(GHSA)
    assert known is not None and known.advisory_id is not None
    [prepared] = exposure.prepare(known.advisory_id, ref.id)
    native = json.loads(prepared.document("1.0.0").payload)
    native["repos"][0]["evidence"].update(arrays)
    document = ImpactAnalysisArtifact.from_document(native)
    recorded = exposure.record(ref.id, document, source())
    [exported] = exposure.export_impacts(GHSA).repos
    expected = ImpactEvidence.model_validate(native["repos"][0]["evidence"])
    assert exported.artifact_id == recorded.artifact_id
    assert exported.document == native
    assert ImpactAnalysisArtifact.from_document(exported.document).payload == document.payload
    assert exported.evidence == expected
    assert exported.evidence.model_fields_set == expected.model_fields_set
    trace = arrays.get("govulncheck_trace")
    packages = arrays.get("l4_packages_found")
    assert exported.evidence.govulncheck_trace == (None if trace is None else tuple(trace))
    assert exported.evidence.l4_packages_found == (None if packages is None else tuple(packages))


def test_export_keeps_distinct_modules_and_versions_and_latest_evidence_for_each(
    engine: Engine,
) -> None:
    second = GRPC.affected[0].model_copy(update={"name": "example.org/transport"})
    advisory = GRPC.model_copy(update={"affected": (*GRPC.affected, second)})
    exposure = service(engine, advisory)
    [ref] = refs(engine, 1)
    assert ref.id is not None
    exposure.ingest_sbom(
        sbom(
            ("google.golang.org/grpc", "v1.56.2"),
            ("google.golang.org/grpc", "v1.56.1"),
            (second.name, "v1.56.2"),
        ),
        ref.id,
    )
    known = exposure.find_advisory(GHSA)
    assert known is not None and known.advisory_id is not None
    prepared = exposure.prepare(known.advisory_id, ref.id)
    assert len(prepared) == 3
    originals = {}
    for item in prepared:
        doc = item.document("1.0.0")
        recorded = exposure.record(ref.id, doc, source())
        originals[(doc.metadata.module, doc.repos[0].version)] = recorded.artifact_id
    updated = prepared[0].model_copy(update={"evidence": ImpactEvidence(notes="Reviewed again")})
    latest_doc = updated.document("1.0.0")
    latest = exposure.record(ref.id, latest_doc, source(1))
    originals[(latest_doc.metadata.module, latest_doc.repos[0].version)] = latest.artifact_id

    exported = exposure.export_impacts(GHSA)
    assert (exported.commits, exported.analyses) == (1, 3)
    assert {(row.module, row.version): row.artifact_id for row in exported.repos} == originals
    assert {row.version for row in exported.repos} == {Version("v1.56.1"), Version("v1.56.2")}
    retained = next(row for row in exported.repos if row.artifact_id == latest.artifact_id)
    assert retained.evidence.notes == "Reviewed again"


def test_export_distinguishes_unknown_advisory_from_known_without_analyses(engine: Engine) -> None:
    exposure = reads(engine)
    known = exposure.find_advisory(GHSA)
    assert known is not None
    exported = exposure.export_impacts(GHSA)
    assert (exported.commits, exported.analyses, exported.repos) == (0, 0, ())
    assert all(count == 0 for count in exported.classifications.values())
    with pytest.raises(NotFoundError):
        exposure.export_impacts(AdvisoryIdentifier("CVE-2099-9999"))
    with pytest.raises(ValidationError):
        exposure.export_impacts(AdvisoryIdentifier("../invalid"))
