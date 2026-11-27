from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer
from tests.v1.services.test_exposure_coverage import NO_LODASH, checkout
from tests.v1.services.test_exposure_sweep import FakeSbomTool, engine
from traust_core.v1 import contracts
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ViewContractError
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.insight import ReportFormat, ViewFilter, ViewName
from traust_core.v1.providers.syft import SyftSbom
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.identity import IdentityConfig
from traust_core.v1.services.insight import DependencyReachView

__all__ = ["engine"]


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path / "rest", identity=IdentityConfig(trust_local=True)))
    ctx.__dict__["database"] = engine
    return ctx


def test_v1_http_reach_beside_scan_bound_coverage(
    context: Context, client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref(is_default=True)
        seed.assessment(ref, kind=AssessmentKind.REPO_STATE)
        uow.commit()
    assert ref.id is not None
    empty = b'{"bomFormat":"CycloneDX","components":[]}'
    tool = FakeSbomTool(raw=empty)
    monkeypatch.setattr(SyftSbom, "acquire", lambda self, request: tool.acquire(request))
    monkeypatch.setattr(SyftSbom, "check", lambda self: tool.check())
    headers = bearer(context)
    services = context.services()
    reader = DependencyReachView(services.exposure, services.portfolio)
    cases: dict[str, Any] = {}
    dependencies = f"/v1/refs/{ref.id}/dependencies"

    def render_report() -> str:
        return services.insight.render(
            ViewName.DEPENDENCY_REACH, ViewFilter(), ReportFormat.MARKDOWN
        ).body

    def capture(case: str, unmeasured: int, without_scan: int, unresolved: dict[str, int]) -> None:
        wire = services.insight.build(ViewName.DEPENDENCY_REACH, ViewFilter()).model_dump(
            mode="json"
        )
        model, gaps = reader.with_coverage(ViewFilter())
        assert model.model_dump(mode="json") == wire
        assert set(wire) == {"repositories", "unmeasured", "ecosystems", "shared"}
        assert (wire["repositories"], wire["unmeasured"]) == (1, unmeasured)
        coverage = gaps.model_dump(mode="json")
        assert coverage == {
            "coverage_unknown": without_scan,
            "unresolved_manifest": unresolved,
            "ecosystem_coverage_unknown": {},
        }
        contracts.validate_view(ViewName.DEPENDENCY_REACH, wire)
        with pytest.raises(ViewContractError):
            contracts.validate_view(ViewName.DEPENDENCY_REACH, {**wire, "coverage": coverage})
        cases[case] = {"reach": wire, "coverage": coverage}

    capture("never-scanned", 1, 1, {})
    assert cases["never-scanned"]["reach"]["shared"] == []
    assert client.get(dependencies, headers=headers).status_code == 404
    report = render_report()
    assert "Repositories without scan-backed manifest coverage (coverage_unknown): 1" in report
    assert "No manifests recorded" in report

    services.exposure.ingest_sbom(empty, ref.id)
    capture("document-only", 0, 1, {})

    tree = tmp_path / "checkout"
    tree.mkdir()
    services.exposure.ingest_dependencies(ref.id, tree)
    capture("measured-empty", 0, 0, {})
    assert cases["document-only"]["reach"] == cases["measured-empty"]["reach"]
    rows = client.get(dependencies, headers=headers)
    assert rows.status_code == 200 and rows.json() == []
    report = render_report()
    assert "No manifest packages observed" in report
    assert "Unknown manifest coverage" not in report

    checkout(tree, locked=False)
    services.exposure.ingest_dependencies(ref.id, tree)
    capture("partial-empty", 0, 0, {"npm": 1})
    assert cases["partial-empty"]["reach"] == cases["measured-empty"]["reach"]

    tool.raw = NO_LODASH
    locked = tree / "locked"
    locked.mkdir()
    (locked / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0"}}}'
    )
    services.exposure.ingest_dependencies(ref.id, tree)
    capture("partial-positive", 0, 0, {"npm": 1})
    assert cases["partial-positive"]["reach"]["shared"] == [
        {"ecosystem": "npm", "name": "left-pad", "repositories": 1}
    ]
    rows = client.get(dependencies, headers=headers)
    assert rows.status_code == 200
    [row] = rows.json()
    assert (row["package"]["name"], row["dependency"]["version"]) == ("left-pad", "1.3.0")
    report = render_report()
    assert "npm: unresolved manifests in 1 repository." in report
    assert "| npm | left-pad | 1 |" in report
    (tmp_path / "i8-reach-cases.json").write_text(json.dumps(cases, indent=2) + "\n")
