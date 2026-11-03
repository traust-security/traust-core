from __future__ import annotations

import json
from uuid import uuid4

from fastapi.testclient import TestClient

from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.services.test_exposure_impact import GHSA, GRPC, Lookup, provenance, refs, sbom
from traust_core.v1.context import Context
from traust_core.v1.models.dependencies import ImpactEvidence
from traust_core.v1.models.vocabulary import ImpactGovulncheck, ImpactManifestScan
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def test_rest_export_retains_recorded_native_documents_and_alias_identity(
    context: Context, client: TestClient
) -> None:
    context.clock = FixedClock(context.clock.now())
    context.advisories = Lookup(GRPC)  # type: ignore[assignment]
    exposure = context.services().exposure
    known = exposure.find_advisory(GHSA)
    assert known is not None and known.advisory_id is not None
    documents = {}
    for ref, evidence in zip(
        refs(context.database, 2),
        (
            ImpactEvidence(
                govulncheck=ImpactGovulncheck.SYMBOL_REACHABLE,
                govulncheck_trace=("app.main", "grpc.Serve"),
            ),
            ImpactEvidence(
                manifest_scan=ImpactManifestScan.MODULE_PINNED_IN_RANGE,
                notes="Deployment configuration needs review",
            ),
        ),
        strict=True,
    ):
        assert ref.id is not None
        exposure.ingest_sbom(sbom(("google.golang.org/grpc", "v1.56.2")), ref.id)
        [prepared] = exposure.prepare(known.advisory_id, ref.id)
        prepared = prepared.model_copy(update={"evidence": evidence})
        doc = prepared.document("1.0.0", "HTTP/2 stream handling")
        recorded = exposure.record(ref.id, doc, provenance())
        documents[str(recorded.artifact_id)] = json.loads(doc.payload)
    context.advisories = None
    response = client.get(
        f"/v1/advisories/{known.advisory_id}/impact-report", headers=bearer(context)
    )
    assert response.status_code == 200
    body = response.json()
    same_as_in_process(body, exposure.export_impacts(known.advisory_id))
    assert (body["commits"], body["analyses"]) == (2, 2)
    assert {row["classification"] for row in body["repos"]} == {"affected", "likely_affected"}
    assert {row["artifact_id"]: row["document"] for row in body["repos"]} == documents
    with SqlTraustUnitOfWork(context.database) as uow:
        alias = uow.advisories.find_by_identifier("GO-2023-2153")
        assert alias is not None and alias.alias_of_id == known.advisory_id
        assert uow.advisories.find_by_identifier("CVE-2023-44487") is None
    aliased = client.get(f"/v1/advisories/{alias.id}/impact-report", headers=bearer(context))
    assert aliased.status_code == 200
    assert aliased.json() == body


def test_rest_export_keeps_authentication_and_unknown_advisory_boundaries(
    context: Context, client: TestClient
) -> None:
    path = f"/v1/advisories/{uuid4()}/impact-report"
    assert client.get(path).status_code == 401
    missing = client.get(path, headers=bearer(context))
    assert missing.status_code == 404
    assert missing.headers["content-type"] == "application/problem+json"
    assert missing.json()["status"] == 404
