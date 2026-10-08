from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.v1.services.test_storage import TRIAGE
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.analysis_results import ResultKind, Subject
from traust_core.v1.models.artifacts import ARTIFACT_FOR_KIND
from traust_core.v1.repositories import InMemoryObjectStore, LocalObjectStore, ObjectKey
from traust_core.v1.repositories.analysis_results import (
    AnalysisResultsRepository,
    ResultsLayout,
    ResultsRepository,
)

REPO = Subject(tree="findings", product="openshift", repo_dir="oc", base="oc")
FLAT = Subject(tree="findings", repo_dir="org__repo", base="org__repo")
LAYOUT = ResultsLayout()


@pytest.mark.parametrize(
    ("subject", "kind", "key"),
    [
        (REPO, ResultKind.SECURITY_AUDIT, "findings/openshift/oc/oc-security-audit.json"),
        (REPO, ResultKind.FINDINGS_LAYER, "findings/openshift/oc/oc-findings-layer.json"),
        (FLAT, ResultKind.TRIAGE, "findings/org__repo/org__repo-triage.json"),
        (
            Subject(tree="findings", repo_dir="oc", base="oc__release-4.14"),
            ResultKind.THREAT_MODEL_MD,
            "findings/oc/oc__release-4.14-threat-model.md",
        ),
        (
            Subject(tree="findings", repo_dir=".github", base=".github"),
            ResultKind.REMEDIATION_VERIFICATION,
            "findings/.github/.github-remediation-verification.json",
        ),
    ],
)
def test_layout_round_trips_todays_convention(subject: Subject, kind: ResultKind, key: str) -> None:
    assert str(LAYOUT.key_for(subject, kind)) == key
    assert LAYOUT.parse(ObjectKey.parse(key)) == (subject, kind)


@pytest.mark.parametrize(
    "key", ["findings/oc-triage.json", "a/b/c/d/x-triage.json", "findings/oc/notes.txt"]
)
def test_layout_ignores_keys_outside_the_convention(key: str) -> None:
    assert LAYOUT.parse(ObjectKey.parse(key)) is None


@pytest.fixture(params=["memory", "local"])
def results(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[ResultsRepository]:
    store = LocalObjectStore(tmp_path / "ar") if request.param == "local" else InMemoryObjectStore()
    yield AnalysisResultsRepository(store, ARTIFACT_FOR_KIND)


def test_put_then_get(results: ResultsRepository) -> None:
    results.put(REPO, ResultKind.TRIAGE, TRIAGE)
    assert results.exists(REPO, ResultKind.TRIAGE)
    assert results.get(REPO, ResultKind.TRIAGE) == TRIAGE


def test_document_is_validated_against_its_contract_schema(results: ResultsRepository) -> None:
    with pytest.raises(ValidationError):
        results.put(REPO, ResultKind.TRIAGE, b'{"findings": []}')
    assert not results.exists(REPO, ResultKind.TRIAGE)


def test_kinds_without_a_schema_are_stored_as_is(results: ResultsRepository) -> None:
    results.put(REPO, ResultKind.SECURITY_AUDIT_MD, b"# audit")
    assert results.get(REPO, ResultKind.SECURITY_AUDIT_MD) == b"# audit"


def test_find_by_kind_and_tree(results: ResultsRepository) -> None:
    results.put(REPO, ResultKind.TRIAGE, TRIAGE)
    results.put(FLAT, ResultKind.TRIAGE, TRIAGE)
    results.put(REPO, ResultKind.SECURITY_AUDIT_MD, b"# audit")
    assert sorted(s.key for s in results.find(ResultKind.TRIAGE, "findings")) == [
        "findings/openshift/oc/oc",
        "findings/org__repo/org__repo",
    ]
