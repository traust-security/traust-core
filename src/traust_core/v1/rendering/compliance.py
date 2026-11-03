from __future__ import annotations

import json
from datetime import datetime

from pydantic import JsonValue

from traust_core.v1.models.artifacts import ComplianceAssessmentArtifact
from traust_core.v1.models.compliance import COVERAGE_KEYS
from traust_core.v1.rendering.markdown import Report, Section, Table


def assessment_report(document: ComplianceAssessmentArtifact) -> Report:
    """The target, coverage and every control of one draft or recorded assessment."""
    body = json.loads(document.payload)
    metadata = body["metadata"]

    def value(item: JsonValue) -> str:
        return item if isinstance(item, str) else json.dumps(item, sort_keys=True)

    target = metadata["target"]
    sections = [
        Section(
            heading="Target",
            table=Table(
                columns=("field", "value"),
                rows=tuple((key, value(item)) for key, item in sorted(target.items())),
            ),
        ),
        Section(
            heading="Coverage",
            body="Coverage describes assessed evidence, not an overall compliance score.",
            table=Table(
                columns=("framework", *COVERAGE_KEYS),
                rows=tuple(
                    (framework, *(str(counts[key]) for key in COVERAGE_KEYS))
                    for framework, counts in sorted(body["coverage"].items())
                ),
            ),
        ),
    ]
    if skipped := metadata.get("skipped_frameworks"):
        sections.append(
            Section(
                heading="Skipped frameworks",
                table=Table(columns=("framework", "reason"), rows=tuple(sorted(skipped.items()))),
            )
        )
    for result in body["results"]:
        sections.append(
            Section(
                heading=f"{result['framework']}:{result['control_id']}",
                table=Table(
                    columns=("field", "value"),
                    rows=tuple(
                        (key, value(item))
                        for key, item in result.items()
                        if key not in {"framework", "control_id", "evidence"}
                    ),
                ),
            )
        )
        if evidence := result.get("evidence"):
            sections.append(
                Section(
                    heading=f"{result['framework']}:{result['control_id']} evidence",
                    table=Table(
                        columns=("kind", "locator", "sha256"),
                        rows=tuple(
                            (item["kind"], item["locator"], item["sha256"]) for item in evidence
                        ),
                    ),
                )
            )
    return Report(
        title="Compliance assessment",
        generated_at=datetime.fromisoformat(metadata["generated_at"].replace("Z", "+00:00")),
        sections=tuple(sections),
        sources=(
            f"scope:{metadata['scope_id']}",
            f"registry:sha256:{metadata['registry_hash']}",
            f"harness:{metadata['harness_version']}",
        ),
    )
