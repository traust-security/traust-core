from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest

from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services import test_code_facts as recorded
from traust_core.v1.context.documents import yaml_documents_with_lines
from traust_core.v1.errors import ConflictError, NotFoundError, ValidationError
from traust_core.v1.models.code_facts import CodeFactKind, PackageFacts, PackageModule
from traust_core.v1.models.common import CodeSpan, Provenance, ToolRequest
from traust_core.v1.models.vocabulary import Ecosystem, InterfaceRole, SourceType
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.providers.package_facts import PackageIndex
from traust_core.v1.services.code_facts import CodeFactsService
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

engine = recorded.engine
facts = recorded.facts


def services(facts: recorded.Facts) -> tuple[CodeFactsService, ExposureService]:
    portfolio = PortfolioService(facts.uow, PortfolioPolicy())
    exposure = ExposureService(
        facts.uow,
        FindingIntake(facts.uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry[FeedProvider]("feed"),
        objects=facts.store,
        portfolio=portfolio,
    )
    service = CodeFactsService(
        facts.assessments,
        facts.publisher,
        portfolio=portfolio,
        exposure=exposure,
        package_index=PackageIndex(yaml_documents_with_lines),
    )
    return service, exposure


def provenance() -> Provenance:
    return Provenance(run_id=uuid4(), source=SourceType.INTERACTIVE, occurred_at=T0)


def sbom(name: str, version: str = "v1.0.0") -> bytes:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "components": [
                {
                    "type": "library",
                    "name": name,
                    "version": version,
                    "purl": f"pkg:golang/{name}@{version}",
                }
            ],
        }
    ).encode()


def test_checkout_fleet_records_reference_facts_and_all_reverse_interface_roles(
    facts: recorded.Facts,
    tmp_path: Path,
) -> None:
    service, exposure = services(facts)
    with facts.uow as uow:
        seed = Seed(uow)
        consumer = seed.repository_ref(seed.repository(url="https://github.com/example/consumer"))
        uow.commit()
    assert consumer.id is not None
    owner, client = tmp_path / "owner", tmp_path / "client"
    owner.mkdir()
    client.mkdir()
    (owner / "go.mod").write_text("module example.test/library\n")
    (owner / "api.go").write_text("package api\nfunc Serve() {}\nfunc hidden() {}\n")
    (owner / "crd.yaml").write_text("""apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata: {name: widgets.widgets.example.test}
spec:
  group: widgets.example.test
  names: {kind: Widget, plural: widgets}
  scope: Namespaced
""")
    (client / "go.mod").write_text("module example.test/client\n")
    (client / "main.go").write_text("""package client
import (
 "example.test/library/api"
)
var version = GroupVersion{Group: "widgets.example.test"}
""")
    (client / "rbac.yaml").write_text("""apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: reader}
rules:
  - apiGroups: [widgets.example.test]
    resources: [widgets]
    verbs: [get, list]
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata: {name: admission}
webhooks:
  - name: check.example.test
    rules:
      - apiGroups: [widgets.example.test]
        resources: [widgets]
        operations: [CREATE]
""")
    result = service.collect_fleet(
        [facts.ref_id, consumer.id],
        provenance(),
        checkouts={
            facts.ref_id: ToolRequest(workspace=owner),
            consumer.id: ToolRequest(workspace=client),
        },
    )
    assert {r.repository_ref_id for r in result} == {facts.ref_id, consumer.id}
    reader = CodeFactsService(
        facts.assessments,
        facts.publisher,
        portfolio=PortfolioService(facts.uow, PortfolioPolicy()),
    )
    interfaces = reader.crd_consumers([facts.ref_id, consumer.id], "widgets.example.test")
    assert {r.fact.role for r in interfaces} == {
        InterfaceRole.OWNER,
        InterfaceRole.CONSUMER,
        InterfaceRole.RBAC,
        InterfaceRole.WEBHOOK,
    }
    assert {r.artifact_id for r in interfaces} == {r.artifact_id for r in result}
    exports = reader.exports_of([facts.ref_id])
    assert [r.fact.name for r in exports] == ["Serve"]
    imports = reader.imports_package([facts.ref_id, consumer.id], "example.test/library")
    assert [(r.repository_ref_id, r.fact.package) for r in imports] == [
        (consumer.id, "example.test/library/api"),
    ]
    assert reader.imports_package([consumer.id], "example.test/lib") == []
    exposure.ingest_sbom(sbom("example.test/library"), consumer.id)
    with facts.uow as uow:
        repository_id = uow.repository_refs.get(facts.ref_id).repository_id
    [coupling] = exposure.internal_coupling([repository_id])
    assert coupling.consumer_repository_ids == (consumer.repository_id,)
    assert [p.name for p in coupling.packages] == ["example.test/library"]
    assert coupling.packages[0].source_repository_id == repository_id


def test_producing_repository_is_idempotent_conflicts_roll_back_and_fan_in_deduplicates(
    facts: recorded.Facts,
) -> None:
    _, exposure = services(facts)
    with facts.uow as uow:
        seed = Seed(uow)
        consumer = seed.repository_ref(seed.repository(url="https://github.com/example/consumer"))
        same_repository = seed.repository_ref(
            uow.repositories.get(consumer.repository_id),
            name="release",
            sha="b" * 40,
        )
        other = seed.repository_ref(
            seed.repository(url="https://github.com/example/other-producer")
        )
        producer = uow.repository_refs.get(facts.ref_id)
        uow.commit()
    module = PackageModule(
        ecosystem="go",
        name="example.test/library",
        location=CodeSpan(path="go.mod", line=1),
    )
    first = exposure.record_package_sources(facts.ref_id, [module])
    assert exposure.record_package_sources(facts.ref_id, [module]) == first
    assert consumer.id is not None and same_repository.id is not None and other.id is not None
    exposure.ingest_sbom(sbom(module.name), consumer.id)
    exposure.ingest_sbom(sbom(module.name), same_repository.id)
    exposure.ingest_sbom(sbom(module.name), facts.ref_id)
    with pytest.raises(ConflictError):
        exposure.record_package_sources(other.id, [module])
    [coupling] = exposure.internal_coupling([producer.repository_id])
    assert coupling.consumer_repository_ids == (consumer.repository_id,)
    assert set(coupling.consumer_repository_ref_ids) == {consumer.id, same_repository.id}
    assert exposure.internal_coupling([other.repository_id]) == []


def test_shipped_module_reads_image_sbom_and_filters_version(facts: recorded.Facts) -> None:
    _, exposure = services(facts)
    image = exposure.ingest_image_sbom(
        sbom("example.test/library"),
        "sha256:" + "a" * 64,
        repository_ref_id=facts.ref_id,
    )
    [shipped] = exposure.ships_module(Ecosystem.GO, "example.test/library")
    assert shipped.image_id == image.id
    assert shipped.repository_ref_id == facts.ref_id
    assert shipped.dependency.version == "v1.0.0"
    assert exposure.ships_module(Ecosystem.GO, "example.test/library", "v2.0.0") == []
    with pytest.raises(NotFoundError):
        exposure.ships_module(Ecosystem.NPM, "example.test/library")


def test_measured_empty_and_unmeasured_are_distinct(
    facts: recorded.Facts,
    tmp_path: Path,
) -> None:
    service, _ = services(facts)
    with pytest.raises(NotFoundError):
        service.crd_consumers([facts.ref_id], "widgets.example.test")
    service.collect_checkout(facts.ref_id, ToolRequest(workspace=tmp_path), provenance())
    assert service.crd_consumers([facts.ref_id], "widgets.example.test") == []
    result = service.collect(facts.ref_id, [CodeFactKind.PACKAGES])
    assert result.facts[0].detail == PackageFacts()


def test_unparseable_interface_manifests_are_not_reported_as_clean(
    facts: recorded.Facts,
    tmp_path: Path,
) -> None:
    service, _ = services(facts)
    (tmp_path / "broken.yaml").write_text("apiVersion: [\n")
    with pytest.raises(ValidationError):
        service.collect_checkout(facts.ref_id, ToolRequest(workspace=tmp_path), provenance())
    with pytest.raises(NotFoundError):
        service.collect(facts.ref_id, [CodeFactKind.INTERFACES])
