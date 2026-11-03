from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path
from unittest.mock import Mock

import pytest

from traust_core.v1.context.documents import yaml_documents
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.sbom_formats import PURL_ECOSYSTEMS, parse_sbom
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.impact import GovulncheckAnalyzer, SourceScanAnalyzer
from traust_core.v1.providers.language_coverage import (
    LanguageCoverageCatalog,
    ReachabilityReviewFile,
)
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.syft import LANGUAGE_MANIFESTS


@pytest.mark.parametrize(
    ("language", "ecosystem"),
    [
        ("Go", "go"),
        ("Python", "pypi"),
        ("JavaScript", "npm"),
        ("TypeScript", "npm"),
        ("TSX", "npm"),
        ("Java", "maven"),
        ("Kotlin", "maven"),
        ("Scala", "maven"),
        ("Rust", "cargo"),
        ("Ruby", "ruby"),
        ("C#", "nuget"),
        ("F#", "nuget"),
        ("Swift", None),
        ("PHP", None),
        ("Fortran", None),
        ("C", None),
        ("Shell", None),
    ],
)
def test_dependency_support_requires_retained_manifests_and_native_ingestion(
    language: str, ecosystem: str | None
) -> None:
    assert LanguageCoverageCatalog(()).dependency_ecosystem(language) == ecosystem


def test_only_actually_wired_symbol_tier_engines_claim_reachability() -> None:
    clock = FixedClock(datetime(2026, 11, 3, tzinfo=UTC))
    source_only = LanguageCoverageCatalog((SourceScanAnalyzer(clock),))
    process = Mock(spec=ProcessRunner)
    wired = LanguageCoverageCatalog(
        (GovulncheckAnalyzer(process, clock), SourceScanAnalyzer(clock))
    )
    assert source_only.reachability_engines("Go") == ()
    assert wired.reachability_engines("Go") == ("govulncheck",)
    assert wired.reachability_engines("Python") == ()
    assert wired.reachability_engines("Java") == ()
    process.run.assert_not_called()


def test_syft_checkout_filter_removal_removes_the_coverage_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("traust_core.v1.providers.syft.MANIFESTS", ("go.mod",))
    assert LanguageCoverageCatalog(()).dependency_ecosystem("Java") is None


def test_no_dependency_exceptions_have_reasons_and_are_not_package_support() -> None:
    catalog = LanguageCoverageCatalog(())
    assert catalog.canonical_language("BASH") == "Shell"
    assert catalog.no_dependencies_reason("BASH") is not None
    assert catalog.no_dependencies_reason("YAML") is not None
    assert catalog.no_dependencies_reason("Swift") is None
    assert catalog.dependency_ecosystem("BASH") is None
    assert catalog.reachability_engines("BASH") == ()


@pytest.mark.parametrize("language", ["PHP", "Swift", "Elixir", "Dart"])
def test_discoverable_manifest_does_not_claim_support_when_core_discards_its_packages(
    language: str,
) -> None:
    package_type, manifests = LANGUAGE_MANIFESTS[language]
    assert manifests
    assert package_type not in PURL_ECOSYSTEMS
    sbom = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "components": [{"purl": f"pkg:{package_type}/example@1.0.0", "version": "1.0.0"}],
        }
    ).encode()
    assert parse_sbom(sbom).entries == ()
    assert parse_sbom(sbom).skipped == 1
    assert LanguageCoverageCatalog(()).dependency_ecosystem(language) is None


@pytest.mark.parametrize("configured", [False, True])
def test_absent_review_reference_is_not_a_review(tmp_path: Path, configured: bool) -> None:
    path = tmp_path / "reachability-watch.yaml" if configured else None
    assert ReachabilityReviewFile(path, yaml_documents).read() is None


@pytest.mark.parametrize("quoted", [False, True])
def test_reads_actual_human_date_and_legacy_watch_fields(tmp_path: Path, quoted: bool) -> None:
    path = tmp_path / "reachability-watch.yaml"
    stamp = '"2026-08-01"' if quoted else "2026-08-01"
    path.write_text(
        f"reviewed: {stamp}\nreview_cadence_days: 92\nreviewer: reviewer@example.com\n"
        "watch:\n  - id: symbol-data\n    question: Does the feed supply symbol data?\n"
        "    checked: 2026-08-01\n    last_answer: Not yet\n"
        "    on_fire: Revisit the engine pilot\n",
        encoding="utf-8",
    )
    review = ReachabilityReviewFile(path, yaml_documents).read()
    assert review is not None
    assert review.reviewed == date(2026, 8, 1)
    assert review.review_cadence_days == 92
    assert review.reviewer == "reviewer@example.com"
    assert review.watch[0].checked == date(2026, 8, 1)
    assert review.watch[0].last_answer == "Not yet"


@pytest.mark.parametrize(
    "text",
    [
        "",
        "[",
        "[]",
        "watch: []",
        "reviewed: invalid",
        "reviewed: 2026-08-01\nreview_cadence_days: 0",
        "reviewed: 2026-08-01\nreview_cadence_days: -1",
        "reviewed: 2026-08-01\nreview_cadence_days: true",
        "reviewed: 2026-08-01\n---\nreviewed: 2026-09-01",
        "reviewed: 2026-08-01\nwatch: [not-a-question]",
    ],
)
def test_malformed_review_is_a_config_error_not_a_missing_reference(
    tmp_path: Path, text: str
) -> None:
    path = tmp_path / "reachability-watch.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError):
        ReachabilityReviewFile(path, yaml_documents).read()


def test_reading_an_unreviewed_template_does_not_create_a_review(tmp_path: Path) -> None:
    path = tmp_path / "reachability-watch.yaml"
    path.write_text("reviewed: null\nreview_cadence_days: 92\nwatch: []\n", encoding="utf-8")
    before = path.read_bytes()
    review = ReachabilityReviewFile(path, yaml_documents).read()
    assert review is not None and review.reviewed is None
    assert path.read_bytes() == before
