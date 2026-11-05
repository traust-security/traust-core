from __future__ import annotations

import json
from pathlib import Path

import pytest

from traust_core.v1.errors import DocumentError, NotFoundError, ServiceError
from traust_core.v1.models.critical_misses import CriticalInstrument
from traust_core.v1.providers.critical_miss_campaign import CriticalMissCampaignReader

_FIXTURE = Path(__file__).parents[2] / "fixtures/reporting/widget-report.json"


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_delta_fragments_votes_confidence_and_original_ids_are_preserved(tmp_path: Path) -> None:
    write_json(
        tmp_path / "b-lite/widget-w2-delta.json",
        {
            "slug": "widget",
            "deltas": [
                {"title": "Medium", "severity": "medium"},
                {
                    "title": "Critical",
                    "severity": "critical (CVSS 9.9)",
                    "file": "a.py",
                    "rationale": "Untrusted input reaches a sink: CWE-78",
                },
            ],
        },
    )
    write_json(
        tmp_path / "matrix/widget-delta-wave3.json",
        {
            "slug": "widget",
            "deltas": [{"title": "Matrix", "severity": "critical"}],
        },
    )
    write_json(
        tmp_path / "triage/fast-track-triage.json",
        {
            "findings": [
                {
                    "source": "b-lite/widget-w2-delta.json#1",
                    "orig_id": "WIDGET-original-005",
                    "verdict": "true_positive",
                    "confidence": 9,
                    "vote_breakdown": {"true_positive": 3, "false_positive": 0},
                }
            ]
        },
    )
    campaign = CriticalMissCampaignReader(tmp_path).read()
    assert [(c.instrument, c.source_key) for c in campaign.candidates] == [
        (CriticalInstrument.B_LITE, "b-lite/widget-w2-delta.json#0"),
        (CriticalInstrument.B_LITE, "b-lite/widget-w2-delta.json#1"),
        (CriticalInstrument.MATRIX, "matrix/widget-delta-wave3.json#0"),
    ]
    assert campaign.candidates[1].cwe == "CWE-78"
    [triage] = campaign.triage
    assert (triage.true_positive_votes, triage.false_positive_votes, triage.confidence) == (3, 0, 9)
    assert (triage.source_key, triage.original_id) == (
        "b-lite/widget-w2-delta.json#1",
        "WIDGET-original-005",
    )


@pytest.mark.parametrize("shape", ["rows", "candidates"])
def test_legacy_and_oracle_replay_exports_retain_unknown_presence(
    tmp_path: Path, shape: str
) -> None:
    write_json(
        tmp_path / "cve-replay/candidates.json",
        {
            shape: [
                {
                    "repository": "https://github.com/example/widget",
                    "advisory_id": "CVE-2026-1234",
                    "severity": "critical",
                    "summary": "An injection (CWE-78)",
                    "present_at_audit": None,
                    "audit_verdict": "unclear",
                }
            ]
        },
    )
    [candidate] = CriticalMissCampaignReader(tmp_path).read().candidates
    assert candidate.present_at_audit is None
    assert candidate.audit_verdict == "unclear"
    assert candidate.advisory_id == "CVE-2026-1234"
    assert candidate.slug == "https://github.com/example/widget"


def test_samples_resolve_baseline_and_current_through_typed_artifacts(tmp_path: Path) -> None:
    baseline = tmp_path / "reports/widget-security-audit.json"
    current = tmp_path / "reports/widget-findings-current.json"
    doc = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    doc["findings"][0]["dependency"] = {"advisory": "CVE-2026-1234", "module": "widget"}
    write_json(baseline, doc)
    doc["findings"][0]["disposition"] = {
        "validity": "false_positive",
        "resolution": "open",
        "last_updated": "2026-10-20T00:00:00Z",
        "events": [],
        "refuted_awaiting_signoff": True,
    }
    doc["findings"][0]["validation_status"] = "false_positive"
    write_json(current, doc)
    write_json(
        tmp_path / "wave2-sample.json",
        [
            {
                "slug": "widget",
                "report": "reports/widget-findings-current.json",
            }
        ],
    )
    [reports] = CriticalMissCampaignReader(tmp_path).read().repositories
    assert reports.baseline_source == str(baseline)
    assert reports.current_source == str(current)
    assert reports.baseline[0].original_id == "WIDGET-0123456-001"
    assert reports.baseline[0].paths == ("pkg/db/query.go", "pkg/db/other.go")
    assert reports.current[1].validity == "false_positive"
    assert reports.current[2].validity == "confirmed"
    assert reports.current[0].refuted_awaiting_signoff is True
    assert reports.baseline[0].advisory_ids == ("CVE-2026-1234",)


def test_missing_baseline_and_current_are_explicit_unresolved_sources(tmp_path: Path) -> None:
    write_json(
        tmp_path / "wave-sample.json",
        [
            {
                "slug": "widget",
                "report": "missing/widget-findings-current.json",
            }
        ],
    )
    [reports] = CriticalMissCampaignReader(tmp_path).read().repositories
    assert reports.baseline_source is None and reports.current_source is None
    assert reports.baseline == () and reports.current == ()


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("b-lite/widget-delta.json", b"not json"),
        ("b-lite/widget-delta.json", b'{"deltas": "not an array"}'),
        ("wave-triage.json", b'{"findings": [{"vote_breakdown": {"true_positive": -1}}]}'),
        ("cve-replay/candidates.json", b'{"rows":[{"present_at_audit":"true"}]}'),
        ("wave-sample.json", b'{"slug":"not an array"}'),
    ],
)
def test_malformed_sources_raise_typed_document_errors(
    tmp_path: Path,
    name: str,
    payload: bytes,
) -> None:
    source = tmp_path / name
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(payload)
    with pytest.raises(DocumentError) as raised:
        CriticalMissCampaignReader(tmp_path).read()
    assert raised.value.document == str(source)
    assert raised.value.issues
    assert raised.value.__cause__ is not None


def test_malformed_baseline_is_not_misreported_as_uningested(tmp_path: Path) -> None:
    write_json(tmp_path / "widget-security-audit.json", {"findings": []})
    write_json(
        tmp_path / "wave-sample.json",
        [
            {
                "slug": "widget",
                "report": "widget-findings-current.json",
            }
        ],
    )
    with pytest.raises(DocumentError) as raised:
        CriticalMissCampaignReader(tmp_path).read()
    assert raised.value.document == str(tmp_path / "widget-security-audit.json")


def test_missing_campaign_is_a_typed_not_found(tmp_path: Path) -> None:
    with pytest.raises(NotFoundError, match="critical-miss campaign"):
        CriticalMissCampaignReader(tmp_path / "missing").read()


def test_provider_io_failure_retains_the_source_and_cause(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "b-lite/widget-delta.json"
    write_json(source, {"deltas": []})

    def denied(path: Path) -> bytes:
        raise PermissionError(str(path))

    monkeypatch.setattr(Path, "read_bytes", denied)
    with pytest.raises(ServiceError) as raised:
        CriticalMissCampaignReader(tmp_path).read()
    assert str(source) in str(raised.value)
    assert isinstance(raised.value.__cause__, PermissionError)
