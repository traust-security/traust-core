from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.services.test_pqc import (
    AT,
    CHECKOUT,
    PROVENANCE,
    REPORT,
    URL,
    FakeScanner,
    World,
    engine,  # noqa: F401
    report,
)
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import (
    ArtifactDocument,
    PqcReadinessArtifact,
    ReportArtifact,
    VerificationArtifact,
)
from traust_core.v1.models.assessment import ASSESSMENT_COMPLETED, Assessment, AssessmentKind
from traust_core.v1.models.insight import ViewFilter
from traust_core.v1.models.pqc import PqcFilter
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import AssessmentLog
from traust_core.v1.services.insight import PqcPortfolioView, PqcView

FIXTURES = Path(__file__).parents[2] / "fixtures"
MARKDOWN = """# Readiness

### Fix now
- `pkg/server/tls.go:88` — Remove the classical-only group pin
  Action: Allow hybrid key exchange
  Playbook: remediation/hybrid.md
### Upgrade
- Upgrade the TLS provider
  Action: Upgrade OpenSSL to a supported release
### Waiting on upstream
- Provider has no roadmap — blocked on Example Vendor

## Scores
| Domain | Facts | Score |
|---|---|---|
| VULN | F0001 | 50 |
"""


def test_bootstrap_crypto_discovery_has_no_readiness_prerequisite(engine: Engine) -> None:  # noqa: F811
    world = World(engine, None)
    measured = world.ref()
    world.ref(url=f"{URL}-missing", sbom=None)
    view = PqcPortfolioView(world.pqc, world.code_facts, world.portfolio)
    scope = view.build(ViewFilter()).scopes[0]
    assert scope.repositories == ()
    assert {(p.package, p.provider): p.repositories for p in scope.packages} == {
        (f.package or f.provider or "", f.provider): 1 for f in world.code_facts.packages(measured)
    }
    assert scope.without_sbom == 1
    assert scope.campaign.sweep.model_dump() == {
        "total": 2,
        "assessed": 0,
        "pending": 2,
        "current": 0,
        "stale": 0,
        "unmeasured": 2,
        "repositories": 2,
        "without_commit": 0,
        "unreachable": 0,
        "access_requests": 0,
        "unobserved": 2,
    }
    assert world.pqc.list_readiness(PqcFilter()) == []
    assert world.pqc.scoped_refs(PqcFilter(repository_ref_ids=())) == []


def test_sweep_progress_distinguishes_readiness_from_pack_freshness(
    engine: Engine,  # noqa: F811
) -> None:
    scanner = FakeScanner()
    world = World(engine, scanner)
    ref = world.ref()
    world.pqc.prescan(ref, CHECKOUT)
    current = world.pqc.campaign(PqcFilter()).sweep
    assert (current.current, current.assessed, current.pending) == (1, 0, 1)
    scanner.pack = scanner.pack.model_copy(update={"rules_sha256": "cd" * 32})
    stale = world.pqc.campaign(PqcFilter()).sweep
    assert (stale.current, stale.stale, stale.assessed) == (0, 1, 0)
    assert world.pqc.find(ref) is None


def test_repair_derives_actions_and_clock_without_changing_posture(engine: Engine) -> None:  # noqa: F811
    world = World(engine, None)
    body = json.loads(report().payload)
    body.pop("remediations")
    original = PqcReadinessArtifact.from_document(body)
    repaired = world.pqc.repair(original, MARKDOWN)
    result = json.loads(repaired.report.payload)
    assert {k: v for k, v in result.items() if k != "remediations"} == body
    assert [r["category"] for r in result["remediations"]] == [
        "fix-now",
        "upgrade",
        "waiting-on-upstream",
        "deadline",
    ]
    action, upgrade, waiting, deadline = result["remediations"]
    assert (action["action"], action["locations"], action["recipe"]) == (
        "Allow hybrid key exchange",
        ["pkg/server/tls.go:88"],
        "remediation/hybrid.md",
    )
    assert upgrade["target"] == "Upgrade OpenSSL to a supported release"
    assert waiting["blocked_on"] == "Example Vendor"
    assert "blocked_external" not in waiting
    assert deadline["deadline"] == 2035
    assert deadline["remediation_effort"] is None
    assert len({r["id"] for r in result["remediations"]}) == 4
    assert all("-f1b2984-REM-" in r["id"] for r in result["remediations"])
    assert json.loads(original.payload) == body
    assert "Facts" not in repaired.markdown and "F0001" not in repaired.markdown
    assert "remediation/hybrid.md" not in repaired.markdown
    assert all(domain in repaired.markdown for domain in ("VULN", "AGIL", "PQCA", "HNDL"))
    again = world.pqc.repair(repaired.report, repaired.markdown)
    assert (again.report.payload, again.markdown, again.changed) == (
        repaired.report.payload,
        repaired.markdown,
        False,
    )


def test_repair_preserves_authored_actions_and_refuses_invalid_new_writes(
    engine: Engine,  # noqa: F811
) -> None:
    world = World(engine, None)
    original = report()
    refreshed = world.pqc.repair(original, "# Minimal\n", derive=False)
    assert refreshed.report.payload == original.payload
    assert "### What the domains mean" in refreshed.markdown
    body = json.loads(original.payload)
    body.pop("remediations")
    body["do_next"][0]["who"] = "app"
    body["do_next"][0]["locations"] = []
    with pytest.raises(ValidationError):
        world.pqc.repair(PqcReadinessArtifact.from_document(body), MARKDOWN)
    assert world.pqc.list_readiness(PqcFilter()) == []


def _record(world: World, ref: UUID, doc: ArtifactDocument, kind: AssessmentKind) -> None:
    from traust_core.v1.models.integrity import sha256_hex

    published = world.publisher.publish_artifact(doc)
    AssessmentLog(SqlTraustUnitOfWork(world.engine)).add(
        Assessment(
            repository_ref_id=ref,
            kind=kind,
            status=ASSESSMENT_COMPLETED,
            assessor="fixture",
            assessor_version="1",
            occurred_at=AT,
        ),
        published.artifact_id,
        sha256_hex(doc.payload),
    )


def test_both_views_include_workflow_findings_and_real_regression_membership(
    engine: Engine,  # noqa: F811
) -> None:
    world = World(engine, None)
    ref = world.ref()
    other = world.ref(url=f"{URL}-other")
    world.pqc.record(ref, report(), PROVENANCE)
    audit = json.loads((FIXTURES / "reporting/widget-report.json").read_text())
    audit["findings"][0].update(
        id="REGULAR-0123456-001",
        pqc_classification="shor-signature",
        remediation_effort="s",
    )
    audit_doc = ReportArtifact.from_document(audit)
    _record(world, ref, audit_doc, AssessmentKind.SECURE_CODE_CANONICAL)
    _record(world, ref, audit_doc, AssessmentKind.SECURE_CODE_CANONICAL)
    verification = json.loads((FIXTURES / "remediation/verification-report.json").read_text())
    verification["regressions"][0].update(
        pqc_classification="pqc-blocker-config",
    )
    _record(
        world, ref, VerificationArtifact.from_document(verification), AssessmentKind.VERIFICATION
    )
    views = [PqcView(world.pqc), PqcPortfolioView(world.pqc, world.code_facts, world.portfolio)]
    for view in views:
        model = view.build(ViewFilter())
        workflow = model.scopes[0].campaign.workflow_findings
        assert workflow.model_dump() == {
            "total": 2,
            "by_classification": {"pqc-blocker-config": 1, "shor-signature": 1},
            "by_effort": {"s": 1, "unclassified": 1},
            "repos": 1,
            "pqc_regressions": 1,
        }
        assert model.scopes[0].campaign.sweep.assessed == 1
        assert any(
            s.table
            and s.table.rows
            == (
                ("pqc-blocker-config", "1"),
                ("shor-signature", "1"),
            )
            for s in view.report(model, AT).sections
        )
    only_other = world.pqc.campaign(PqcFilter(repository_ref_ids=(other,)))
    assert only_other.workflow_findings.total == 0
    assert only_other.sweep.pending == 1


def test_historical_effort_can_be_rendered_but_is_not_guessed_into_a_new_write(
    engine: Engine,  # noqa: F811
) -> None:
    world = World(engine, None)
    historical = PqcReadinessArtifact.from_document(REPORT)
    refreshed = world.pqc.repair(historical, "# Minimal\n", derive=False)
    assert refreshed.report.payload == historical.payload
    assert "moderate" in refreshed.markdown
    missing = json.loads(historical.payload)
    missing.pop("remediations")
    with pytest.raises(ValidationError):
        world.pqc.repair(PqcReadinessArtifact.from_document(missing), MARKDOWN)
    assert json.loads(historical.payload) == REPORT


def test_force_repair_covers_existing_primitives_and_preserves_unknown_vendor_evidence(
    engine: Engine,  # noqa: F811
) -> None:
    world = World(engine, None)
    original = report()
    markdown = (
        "### Upgrade\n- Replace RSA-2048 signing\n"
        "### Waiting on upstream\n- Await the provider roadmap\n"
        "## Unrelated\n- Not a remediation\n"
    )
    repaired = world.pqc.repair(original, markdown, force=True)
    actions = json.loads(repaired.report.payload)["remediations"]
    assert [a["category"] for a in actions] == ["upgrade", "waiting-on-upstream"]
    assert actions[1]["blocked_on"] == "Await the provider roadmap"
    assert "blocked_external" not in actions[1]
    assert json.loads(repaired.report.payload)["scores"] == json.loads(original.payload)["scores"]
