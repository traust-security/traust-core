from traust_core.v1.services.findings import (
    FindingDecisions,
    FindingIntake,
    FindingPrecedents,
    FindingReview,
    FindingService,
    IdentityPolicy,
    RatingPolicy,
    TransitionPolicy,
)


def test_finding_service_wires_its_parts_and_policies() -> None:
    findings = FindingService(None)  # type: ignore[arg-type]
    assert isinstance(findings.intake, FindingIntake)
    assert isinstance(findings.decisions, FindingDecisions)
    assert isinstance(findings.review, FindingReview)
    assert isinstance(findings.precedents, FindingPrecedents)
    assert isinstance(findings.identity, IdentityPolicy)
    assert isinstance(findings.transitions, TransitionPolicy)
    assert isinstance(findings.rating, RatingPolicy)
    assert findings.intake._identity is findings.identity
    assert findings.decisions._transitions is findings.transitions
