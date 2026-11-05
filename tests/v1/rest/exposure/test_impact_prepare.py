from __future__ import annotations

import json
from uuid import uuid4

from fastapi.testclient import TestClient

from tests.v1.rest.conftest import bearer
from tests.v1.services.test_exposure_impact import Lookup, refs
from traust_core.v1.context import Context
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    AdvisoryRecord,
    AffectedPackage,
    AffectedSpan,
    Version,
)
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.clock import FixedClock


def test_rest_prepare_returns_every_ecosystem_package_and_installed_version(
    context: Context,
    client: TestClient,
) -> None:
    context.clock = FixedClock(context.clock.now())
    record = AdvisoryRecord(
        identifier=AdvisoryIdentifier("GHSA-aaaa-bbbb-cccc"),
        affected=(
            AffectedPackage(
                ecosystem=Ecosystem.GO,
                name="lib",
                spans=(
                    AffectedSpan(introduced=Version("1.0.0"), fixed=Version("1.1.0")),
                    AffectedSpan(introduced=Version("2.0.0"), fixed=Version("2.2.0")),
                ),
            ),
            AffectedPackage(
                ecosystem=Ecosystem.NPM,
                name="lib",
                spans=(AffectedSpan(introduced=Version("9.0.0"), fixed=Version("9.1.0")),),
            ),
        ),
        source="https://osv.test/fixture",
    )
    context.advisories = Lookup(record)  # type: ignore[assignment]
    exposure = context.services().exposure
    known = exposure.find_advisory(record.identifier)
    assert known is not None and known.advisory_id is not None
    [ref] = refs(context.database, 1)
    assert ref.id is not None
    exposure.ingest_sbom(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {"purl": "pkg:golang/lib@1.0.5"},
                    {"purl": "pkg:golang/lib@2.0.5"},
                    {"purl": "pkg:npm/lib@9.0.5"},
                ],
            }
        ).encode(),
        ref.id,
    )
    expected = exposure.prepare(known.advisory_id, ref.id)
    response = client.get(
        f"/v1/advisories/{known.advisory_id}/impact-inputs",
        params={"repository_ref_id": str(ref.id)},
        headers=bearer(context),
    )
    assert response.status_code == 200
    assert response.json() == [item.model_dump(mode="json") for item in expected]
    documents = [item.document("1") for item in expected]
    assert {
        (doc.metadata.ecosystem, doc.repos[0].version, doc.metadata.fixed_version)
        for doc in documents
    } == {("go", "1.0.5", "1.1.0"), ("go", "2.0.5", "2.2.0"), ("npm", "9.0.5", "9.1.0")}
    schema = client.get("/openapi.json").json()
    result = schema["paths"]["/v1/advisories/{advisory_id}/impact-inputs"]["get"]["responses"]
    result_schema = result["200"]["content"]["application/json"]["schema"]
    assert result_schema["type"] == "array"
    assert result_schema["items"]["$ref"].endswith("/ImpactInput")


def test_rest_prepare_preserves_authentication_and_missing_advisory_boundaries(
    context: Context,
    client: TestClient,
) -> None:
    path = f"/v1/advisories/{uuid4()}/impact-inputs"
    params = {"repository_ref_id": str(uuid4())}
    assert client.get(path, params=params).status_code == 401
    response = client.get(path, params=params, headers=bearer(context))
    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["status"] == 404
