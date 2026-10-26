"""AuditScope.of_report: the reviewed line count and companion lanes a code audit's report states,
read as the legacy router read them (traust build_rescan_worklist._report_meta)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests.v1.services.test_assessment_population import report
from traust_core.v1.models.artifacts import ReportArtifact
from traust_core.v1.models.assessment import AuditScope


def scoped(loc: Any = None, additional: dict[str, Any] | None = None) -> AuditScope:
    doc = json.loads(report(additional))
    if loc is not None:
        doc["metadata"]["loc_reviewed"] = loc
    return AuditScope.of_report(ReportArtifact.from_document(doc))


@pytest.mark.parametrize(
    ("loc", "additional", "lines"),
    [
        (None, None, None),
        (2400, None, 2400),
        ("2400", None, 2400),
        ("about 2k", None, None),
        (0, None, None),
        (0, {"lines_reviewed": 900}, 900),
        (None, {"loc_reviewed": 12.0}, 12),
        (None, {"lines_of_code": 77}, 77),
        (None, {"lines_reviewed": True, "lines_of_code": 5}, 5),
        (None, {"lines_reviewed": -3}, None),
        (300, {"lines_reviewed": 900}, 300),
    ],
    ids=[
        "unstated",
        "integer",
        "digit string",
        "prose string",
        "zero",
        "zero then legacy key",
        "legacy float",
        "legacy lines_of_code",
        "boolean is not a count",
        "negative",
        "metadata wins",
    ],
)
def test_lines_reviewed_reads_the_first_positive_count(
    loc: Any, additional: dict[str, Any] | None, lines: int | None
) -> None:
    assert scoped(loc, additional).lines_reviewed == lines


def test_companion_lanes_come_from_the_additional_block() -> None:
    assert scoped(additional={"companion_lanes": ["cloud-config-audit"]}).companion_lanes == (
        "cloud-config-audit",
    )
    assert scoped().companion_lanes == ()
