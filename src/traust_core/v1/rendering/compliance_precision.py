from __future__ import annotations

from traust_core.v1.models.detection_quality import ComplianceCalibration
from traust_core.v1.rendering.markdown import markdown_table, markdown_text


def compliance_precision_markdown(report: ComplianceCalibration) -> str:
    lines = [
        "# Compliance field precision",
        "",
        f"Framework: {markdown_text(report.framework)}. Assessments: {report.assessments}. "
        f"Demotion review gate: precision ≤ {report.gate:.3f}.",
        "",
        "Population: distinct recorded compliance documents for this framework. "
        "A firing is an automatic not-satisfied check or its attributed human override; "
        "a dismissal is a human override reversing that automatic verdict. "
        "Flagged checks require review, not automatic demotion.",
        "",
    ]
    if not report.assessments:
        lines += ["No assessments recorded; field precision is unmeasured.", ""]
    elif not report.checks:
        lines += ["No automatic check firings; field precision is unmeasured.", ""]
    else:
        lines += markdown_table(
            ("Check", "Fired", "Dismissed", "Precision", "Demotion review"),
            [
                (
                    check.check_id,
                    str(check.fired),
                    str(check.dismissed),
                    "unmeasured" if check.precision is None else f"{check.precision:.3f}",
                    "flagged" if check.flagged else "not flagged",
                )
                for check in report.checks
            ],
        )
        lines += [""]
    return "\n".join(lines)
