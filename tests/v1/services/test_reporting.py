"""ReportingService: the doors over a report document a caller holds."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import (
    ArtifactDocument,
    CloudConfigAuditArtifact,
    ReportArtifact,
    SecurityAuditArtifact,
    TriageArtifact,
)
from traust_core.v1.providers.sources import WorkspaceFiles
from traust_core.v1.services.reporting import RenderFormat, ReportingService

FIXTURES = Path(__file__).parents[2] / "fixtures"
REPORT = FIXTURES / "reporting" / "widget-report.json"
CLOUD = FIXTURES / "cloud_config" / "myrepo-cloud-config-audit.json"
TRIAGE = FIXTURES / "findings" / "triage" / "triage-report.json"
THREAT_MODEL = FIXTURES / "assessments" / "widget-threat-model.json"
ATTACK = FIXTURES / "insight" / "attack"
TOOL_URI = "https://tool.example/traust"


@pytest.fixture
def reporting(tmp_path: Path) -> ReportingService:
    (tmp_path / "traust.yaml").write_text(
        f"home: {tmp_path / 'home'}\nlocations:\n  sarif_tool_uri: {TOOL_URI}\n"
    )
    return Context.from_file(tmp_path / "traust.yaml").services().reporting


def _without(path: Path, key: str) -> bytes:
    document = json.loads(path.read_bytes())
    del document[key]
    return json.dumps(document).encode()


@pytest.mark.parametrize(
    ("payload", "artifact", "issues"),
    [
        (REPORT.read_bytes(), ReportArtifact, []),
        (REPORT.read_bytes(), SecurityAuditArtifact, []),
        (CLOUD.read_bytes(), CloudConfigAuditArtifact, []),
        (TRIAGE.read_bytes(), TriageArtifact, []),
        (_without(REPORT, "findings"), ReportArtifact, [("$", "'findings' is a required")]),
        (b"{not json", ReportArtifact, [("$", "not JSON")]),
        (b"[]", ReportArtifact, [("$", "[] is not of type 'object'")]),
    ],
    ids=["report", "role-alias", "cloud-config", "triage", "missing", "not-json", "not-object"],
)
def test_validate_returns_the_contract_issues(
    reporting: ReportingService,
    payload: bytes,
    artifact: type[ArtifactDocument],
    issues: list[tuple[str, str]],
) -> None:
    got = reporting.validate(payload, artifact)
    assert [(i.path, i.message[: len(m)]) for i, (_, m) in zip(got, issues, strict=True)] == issues


def test_validate_against_the_wrong_artifact_reports_issues(reporting: ReportingService) -> None:
    assert reporting.validate(TRIAGE.read_bytes(), ReportArtifact)


def test_lint_runs_the_rules_registered_for_the_document(reporting: ReportingService) -> None:
    document = json.loads(CLOUD.read_bytes())
    clean = reporting.lint(CloudConfigAuditArtifact.from_document(document))
    flagged = next(f for f in document["findings"] if f.get("status") != "suppressed")
    flagged.update(status="suppressed", rationale="")
    dirty = reporting.lint(CloudConfigAuditArtifact.from_document(document))
    assert clean.passed
    assert {(v.rule, v.item) for v in dirty.violations} == {
        ("cloud-config.citations", flagged["id"])
    }


def test_lint_of_a_document_no_rule_covers_passes(reporting: ReportingService) -> None:
    assert reporting.lint(ReportArtifact.parse(REPORT.read_bytes())).passed


def test_lint_rules_that_need_the_checkout_say_so(
    reporting: ReportingService, tmp_path: Path
) -> None:
    triage = TriageArtifact.parse(TRIAGE.read_bytes())
    with pytest.raises(ValidationError, match="needs the target checkout"):
        reporting.lint(triage)
    assert reporting.lint(triage, WorkspaceFiles(tmp_path)).violations


@pytest.mark.parametrize(
    ("format", "starts"), [(RenderFormat.MARKDOWN, "# "), (RenderFormat.HTML, "<!DOCTYPE html>")]
)
def test_render_a_triage_document(
    reporting: ReportingService, format: RenderFormat, starts: str
) -> None:
    triage = TriageArtifact.parse(TRIAGE.read_bytes())
    rendered = reporting.render(triage, format)
    assert rendered.startswith(starts)
    assert "Act on these" in rendered


@pytest.mark.parametrize(
    "document", [CloudConfigAuditArtifact.parse(CLOUD.read_bytes())], ids=["cloud-config"]
)
def test_render_refuses_a_document_without_a_view(
    reporting: ReportingService, document: ArtifactDocument
) -> None:
    with pytest.raises(ValidationError, match="no report view"):
        reporting.render(document, RenderFormat.MARKDOWN)


# core's SARIF vocabulary (SarifExport) in place of the legacy exporter's
RENAMES = [
    ('"name": "traust-engine"', '"name": "traust"'),
    ('"harness/', '"traust/'),
    ('"harnessFindingId/v1"', '"traustFindingId/v1"'),
    ('"harnessFingerprint/v1"', '"traustFingerprint/v1"'),
    ("Harness finding category: ", "Finding category: "),
    (
        "harness disposition ledger: validity=false_positive (countersigned per ledger; "
        "see properties.disposition)",
        "traust disposition: validity=false_positive",
    ),
    (
        "harness disposition ledger: resolution=risk_accepted (see properties.disposition)",
        "traust disposition: resolution=risk_accepted",
    ),
]


def _legacy(name: str) -> dict[str, Any]:
    text = (FIXTURES / "reporting" / name).read_text()
    for old, new in RENAMES:
        text = text.replace(old, new)
    return json.loads(text)


@pytest.mark.parametrize(
    ("document", "legacy"),
    [
        (ReportArtifact.parse(REPORT.read_bytes()), "widget-report.sarif"),
        (CloudConfigAuditArtifact.parse(CLOUD.read_bytes()), "myrepo-cloud-config-audit.sarif"),
    ],
    ids=["report", "cloud-config"],
)
def test_sarif_matches_the_legacy_exporter(
    reporting: ReportingService,
    document: ReportArtifact | CloudConfigAuditArtifact,
    legacy: str,
) -> None:
    assert reporting.sarif(document) == _legacy(legacy)


def test_sarif_omits_the_tool_uri_when_unset() -> None:
    sarif = ReportingService((), None).sarif(ReportArtifact.parse(REPORT.read_bytes()))
    assert "informationUri" not in sarif["runs"][0]["tool"]["driver"]


def test_sarif_reports_are_the_sweep_over_a_results_tree(
    reporting: ReportingService, tmp_path: Path
) -> None:
    (tmp_path / "r").mkdir()
    (tmp_path / "r" / "r-security-audit.json").write_text("{}")
    assert reporting.sarif_reports(tmp_path) == [tmp_path / "r" / "r-security-audit.json"]


def test_ctx_reporting_never_opens_the_record_store(tmp_path: Path) -> None:
    home = tmp_path / "home"
    ctx = Context(Config(home=home))
    assert [r.file_path for r in ctx.reporting.validate_reports(REPORT)] == [str(REPORT)]
    document = ReportArtifact.parse(REPORT.read_bytes())
    assert ctx.reporting.render(document, RenderFormat.MARKDOWN).startswith("# ")
    assert "database" not in ctx.__dict__
    assert not home.exists()


def test_services_hand_out_ctx_reporting(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path / "home"))
    assert ctx.services().reporting is ctx.reporting


def test_registering_the_attack_catalog_rebuilds_ctx_reporting(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path / "home"))
    before = ctx.reporting
    ctx.register_attack_catalog(ATTACK / "attack-techniques.json", ATTACK / "attack-mapping.json")
    assert ctx.reporting is not before
