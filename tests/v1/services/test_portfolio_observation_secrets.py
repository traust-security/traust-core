import logging
from dataclasses import dataclass

import pytest

from tests.v1.observation_support import NOW, observer, repository_id_for
from traust_core.v1.errors import ServiceError
from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Readiness, Result
from traust_core.v1.services.observation import GITLEAKS, TRIPWIRE_QUOTA_RESERVE

RID = repository_id_for(None, "test")
PATCH = "+++ b/settings.py\n+KEY = 'AKIA-one'\n+OTHER = 'AKIA-two'\n"


def _observation(line: int) -> dict:
    return {
        "id": "gitleaks/aws-access-token",
        "title": "AWS access token",
        "severity": "high",
        "cwes": [],
        "locations": [{"path": "change.patch", "lines": str(line)}],
        "description": "AWS access token",
        "remediation": "",
        "category": "aws-access-token",
    }


def adapter_result(hits: int) -> AdapterResultArtifact:
    return AdapterResultArtifact.from_document(
        {
            "target": "change",
            "scanned_at": "2026-10-23T00:00:00Z",
            "metadata": {"tool": "gitleaks", "scanner_version": "8.30.0"},
            "findings": [_observation(n) for n in range(1, hits + 1)],
        }
    )


@dataclass
class ContractModel:
    """traust-contracts' AdapterResult as traust-engine's scanners return it."""

    document: dict

    def to_dict(self) -> dict:
        return self.document


class FakeGitleaks:
    name = GITLEAKS

    def __init__(self, ready=True, fails=False, wrap=None):
        self.ready, self.fails, self.wrap = ready, fails, wrap or (lambda result: result)
        self.scanned: list[str] = []

    def check(self):
        return Readiness(ready=self.ready, detail="" if self.ready else "gitleaks not on PATH")

    def acquire(self, request):
        if self.fails:
            raise ServiceError("gitleaks over the patch: exit 2")
        text = (request.workspace / "change.patch").read_text(encoding="utf-8")
        self.scanned.append(text)
        found = adapter_result(text.count("AKIA"))
        return Result(self.wrap(found), Acquisition(provider=self.name, acquired_at=NOW))


def registry(*tools):
    registered = ProviderRegistry("tool")
    for tool in tools:
        registered.register(tool.name, lambda tool=tool: tool)
    return registered


def github(tool, remaining=TRIPWIRE_QUOTA_RESERVE + 50, patch=PATCH, **changes):
    service, portfolio, _, _, source = observer(tools=registry(tool), **changes)
    source.remaining, source.patch = remaining, patch
    return service, portfolio, source


def test_secret_hits_in_the_github_patch_are_stored_and_read_back():
    tool = FakeGitleaks()
    service, portfolio, source = github(tool)
    service.record_forge_facts(repository_id=RID)
    assert service.repo_state(repository_id=RID).secret_hits == 2
    assert portfolio.forge_facts(RID).secret_hits == 2
    assert tool.scanned == [PATCH]
    assert source.calls.count("compare_patch") == 1


def test_a_gitlab_patch_comes_with_the_compare_at_no_extra_call():
    tool = FakeGitleaks()
    service, _, source = github(tool, repo_url="https://gitlab.com/o/repo")
    source.comparison_data = {**source.comparison_data, "patch": PATCH}
    service.record_forge_facts(repository_id=RID)
    assert service.repo_state(repository_id=RID).secret_hits == 2
    assert "compare_patch" not in source.calls


def test_observation_event_is_committed_once_without_url_or_patch(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service, _, _ = github(FakeGitleaks())
    with caplog.at_level(logging.INFO, logger="traust_core.v1.services.portfolio"):
        first = service.record_forge_facts(repository_id=RID)
        service.record_forge_facts(repository_id=RID)
    events = [
        r.getMessage() for r in caplog.records if r.name == "traust_core.v1.services.portfolio"
    ]
    assert first.status == ComparisonStatus.OK
    assert len(events) == 1 and str(first.repository_id) in events[0]
    assert "duration_ms=" in events[0]
    assert "https://" not in caplog.text and "AKIA" not in caplog.text


def test_metadata_only_change_logs_one_committed_event_without_url(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service, portfolio, _, _, source = observer()
    service.record_forge_facts(repository_id=service.repository_id)
    caplog.clear()
    source.info_data = {**source.info_data, "visibility": "private"}
    with caplog.at_level(logging.INFO, logger="traust_core.v1.services.portfolio"):
        service.record_forge_facts(repository_id=service.repository_id)
    events = [
        r.getMessage() for r in caplog.records if r.name == "traust_core.v1.services.portfolio"
    ]
    assert portfolio.get_repository(service.repository_id).public is False
    assert len(events) == 1 and "metadata" in events[0]
    assert str(service.repository_id) in events[0] and "duration_ms=" in events[0]
    assert "https://" not in caplog.text


def test_metadata_only_event_is_discarded_on_outer_rollback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service, portfolio, _, _, source = observer()
    service.record_forge_facts(repository_id=service.repository_id)
    source.info_data = {**source.info_data, "visibility": "private"}
    with caplog.at_level(logging.INFO, logger="traust_core.v1.services.portfolio"):
        with portfolio._uow:
            service.record_forge_facts(repository_id=service.repository_id)
            assert "metadata updated" not in caplog.text
        assert "metadata updated" not in caplog.text
    assert portfolio.get_repository(service.repository_id).public is True


def test_a_clean_patch_is_zero_hits_not_unscanned():
    service, _, _ = github(FakeGitleaks(), patch="+++ b/x.py\n+x = 1\n")
    service.record_forge_facts(repository_id=RID)
    assert service.repo_state(repository_id=RID).secret_hits == 0


def test_the_engine_adapter_model_is_read_through_the_adapter_result_contract():
    model = FakeGitleaks(wrap=lambda result: ContractModel(dict(result._document)))
    service, _, _ = github(model)
    service.record_forge_facts(repository_id=RID)
    assert service.repo_state(repository_id=RID).secret_hits == 2


@pytest.mark.parametrize(
    ("tools", "remaining", "patch", "diagnostic", "fetched"),
    [
        (registry(), 500, PATCH, "stage=registration error_type=ConfigError", 0),
        (None, 500, PATCH, "stage=registration error_type=ConfigError", 0),
        (
            registry(FakeGitleaks(ready=False)),
            500,
            PATCH,
            "stage=readiness error_type=ConfigError",
            0,
        ),
        (registry(FakeGitleaks(fails=True)), 500, PATCH, "stage=scan error_type=ServiceError", 1),
        (
            registry(FakeGitleaks()),
            TRIPWIRE_QUOTA_RESERVE + 1,
            PATCH,
            "stage=patch error_type=SourceError",
            0,
        ),
        (registry(FakeGitleaks()), 500, "", "stage=patch error_type=ValidationError", 1),
        (
            registry(FakeGitleaks(wrap=lambda _: b"[]")),
            500,
            PATCH,
            "stage=scan error_type=IntegrityError",
            1,
        ),
    ],
    ids=[
        "not registered",
        "no tool registry",
        "not ready",
        "scanner failed",
        "quota at the reserve",
        "empty patch",
        "unexpected result",
    ],
)
def test_an_unscanned_patch_is_none_and_says_why(
    caplog, tools, remaining, patch, diagnostic, fetched
):
    service, portfolio, _, _, source = observer(tools=tools)
    source.remaining, source.patch = remaining, patch
    with caplog.at_level(logging.WARNING, "traust_core.v1.services.observation"):
        facts = service.record_forge_facts(repository_id=RID)
    assert facts.status == ComparisonStatus.OK
    assert service.repo_state(repository_id=RID).secret_hits is None
    assert portfolio.forge_facts(RID).secret_hits is None
    assert source.calls.count("compare_patch") == fetched
    assert any("not scanned" in r.message and diagnostic in r.message for r in caplog.records)


def test_scanner_failure_does_not_log_exception_text_or_repository_url(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "synthetic-only-never-a-real-credential"

    class LeakyScanner(FakeGitleaks):
        def acquire(self, request: object) -> None:
            raise ServiceError(f"scanner refused: {secret}")

    service, _, _ = github(LeakyScanner())
    with caplog.at_level(logging.WARNING, "traust_core.v1.services.observation"):
        service.record_forge_facts(repository_id=RID)
    assert "not scanned" in caplog.text
    assert secret not in caplog.text
    assert "https://" not in caplog.text


def test_a_change_with_no_first_party_lines_is_not_scanned(caplog):
    tool = FakeGitleaks()
    service, _, source = github(tool)
    vendored = [{"filename": "vendor/x.go", "changes": 10}]
    source.comparison_data = {"ok": True, "ahead_by": 1, "truncated": False, "files": vendored}
    with caplog.at_level(logging.WARNING, "traust_core.v1.services.observation"):
        service.record_forge_facts(repository_id=RID)
    assert service.repo_state(repository_id=RID).secret_hits is None
    assert (tool.scanned, source.calls.count("compare_patch")) == ([], 0)
    assert not [r for r in caplog.records if "not scanned" in r.message]


def test_an_unchanged_repository_is_not_scanned():
    tool = FakeGitleaks()
    service, _, source = github(tool)
    source.info_data = {**source.info_data, "pushed_at": "2026-08-01T00:00:00Z"}
    service.record_forge_facts(repository_id=RID)
    assert service.repo_state(repository_id=RID).secret_hits is None
    assert tool.scanned == []
