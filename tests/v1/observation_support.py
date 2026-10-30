from __future__ import annotations

import json
import shutil
import tempfile
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid5

from tests.v1.conftest import _sqlite_template
from traust_core.v1.models.artifacts import AdapterResultArtifact, ReportArtifact, RepoStateArtifact
from traust_core.v1.models.inventory import Repository
from traust_core.v1.models.observation import ComparisonStatus, ObservationTarget
from traust_core.v1.models.values import GitSha
from traust_core.v1.models.vocabulary import Severity
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Readiness, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.sources import (
    ChangedFile,
    Comparison,
    Quota,
    RepoInfo,
    RepoTree,
    SourceError,
)
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects.store import InMemoryObjectStore
from traust_core.v1.repositories.sql import create_database_engine
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpec, PublishSpecs
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.observation import GITLEAKS, TRIPWIRE_QUOTA_RESERVE
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService, RepoStateQuery

REFERENCE = json.loads(
    (Path(__file__).parents[1] / "fixtures/observations/reference.json").read_text()
)
_UNSET = object()
NOW = datetime.fromisoformat(REFERENCE["now"])
HOSTS = {"github.com": "github", "gitlab.com": "gitlab"}
HEAD = "b" * 40


def repository_id_for(repo_url: str | None, repo_key: str) -> UUID:
    """A stable repository id per fixture repo (the model supplies real UUIDs)."""
    return uuid5(NAMESPACE_URL, repo_url or f"key:{repo_key}")


class CleanGitleaks:
    """The support's default scanner: gitleaks over the change's patch, finding nothing."""

    name = GITLEAKS

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def acquire(self, request: object) -> Result[AdapterResultArtifact]:
        return Result(
            AdapterResultArtifact.from_document(
                {
                    "target": "change",
                    "scanned_at": "2026-10-23T00:00:00Z",
                    "metadata": {"tool": GITLEAKS, "scanner_version": "8.30.0"},
                    "findings": [],
                }
            ),
            Acquisition(provider=self.name, acquired_at=NOW),
        )


def default_tools() -> ProviderRegistry[CleanGitleaks]:
    """The registry a real observation runs with: gitleaks registered and ready."""
    registered = ProviderRegistry("tool")
    scanner = CleanGitleaks()
    registered.register(scanner.name, lambda: scanner)
    return registered


class FakeSource:
    name = "fake"

    def __init__(self, info=None, comparison=None, quota=None, tree=None):
        self.info_data = info if info is not None else REFERENCE["cases"][0]["info"]
        self.comparison_data = (
            comparison if comparison is not None else REFERENCE["cases"][0]["compare"]
        )
        # Above the tripwire reserve so the patch fetch (the secret scan) is not deferred.
        self.remaining = TRIPWIRE_QUOTA_RESERVE + 50 if quota is None else quota
        self.tree_data = tree if tree is not None else {"ok": True, "paths": [], "truncated": False}
        self.patch = "+++ b/x.py\n+x = 1\n"
        self.calls = []

    def result(self, data):
        return Result(data, Acquisition(provider="fake", acquired_at=NOW))

    def info(self, repo):
        self.calls.append("info")
        data = {k: v for k, v in self.info_data.items() if k not in ("ok", "head")}
        if not self.info_data["ok"]:
            raise SourceError(data.get("error") or "source failed", ComparisonStatus(data["kind"]))
        return self.result(RepoInfo(repo=repo, **data))

    def head(self, repo, branch):
        self.calls.append("head")
        return self.result(GitSha(self.info_data.get("head", HEAD)))

    def compare(self, repo, baseline, branch):
        self.calls.append("compare")
        data = self.comparison_data
        if not data["ok"]:
            raise SourceError(data.get("error") or "source failed", ComparisonStatus(data["kind"]))
        return self.result(
            Comparison(
                ahead_by=data["ahead_by"],
                truncated=data["truncated"],
                files=tuple(ChangedFile(**f) for f in data["files"]),
                patch=data.get("patch"),
            )
        )

    def compare_patch(self, repo, baseline):
        self.calls.append("compare_patch")
        return self.result(self.patch)

    def tree(self, repo, ref):
        self.calls.append("tree")
        data = self.tree_data
        if not data["ok"]:
            raise SourceError(data.get("error") or "source failed", ComparisonStatus(data["kind"]))
        return self.result(RepoTree(paths=tuple(data["paths"]), truncated=data["truncated"]))

    def quota(self, repo):
        self.calls.append("quota")
        return self.result(Quota(remaining=self.remaining))


class FixedOpenCounts:
    """The finding_status view double: N open critical/high findings for a repo."""

    def __init__(self) -> None:
        self.counts: dict[UUID, int] = {}

    def open_count(self, repository_id: UUID, severities: Sequence[Severity]) -> int:
        if Severity.CRITICAL not in severities and Severity.HIGH not in severities:
            return 0
        return self.counts.get(repository_id, 0)


class FixedBaselineAssessment(AssessmentService):
    """Records into the database; the audit an observation measures against is fixed."""

    def __init__(self, uow, target, clock):
        publisher = ArtifactPublisher(
            PublishSpecs(PublishSpec(ReportArtifact)), InMemoryObjectStore(), uow
        )
        super().__init__(uow, clock=clock, publisher=publisher)
        self.target = target

    def observation_target(self, **kwargs):
        return self.target


def observer(case=None, tools=_UNSET, **changes):
    case = case or REFERENCE["cases"][0]
    data = {**case["repo"], **changes}
    live = data.pop("live_crit_high", 0)
    repo_key = data.pop("repo_key")
    repo_url = data.pop("repo_url", None)
    uow = _contract_db()
    with uow:
        repository = uow.repositories.add(
            Repository(url=repo_url or f"https://github.com/{repo_key}", public=False)
        )
        uow.commit()
    target = ObservationTarget(repository_id=repository.id, repo_url=repo_url, **data)
    clock = FixedClock(NOW)
    assessment = FixedBaselineAssessment(uow, target, clock)
    counts = FixedOpenCounts()
    counts.counts[target.repository_id] = live
    sources = FakeSource(case["info"], case["compare"])
    service = PortfolioService(
        uow,
        PortfolioPolicy(),
        assessment=assessment,
        sources=sources,
        clock=clock,
        hosts=HOSTS,
        publisher=ArtifactPublisher(
            PublishSpecs(PublishSpec(RepoStateArtifact)), InMemoryObjectStore(), uow
        ),
        tools=default_tools() if tools is _UNSET else tools,
    )
    harness = _Harness(
        service,
        RepoStateQuery(
            service,
            assessment,
            counts,  # stands in for FindingService.open_count
            PortfolioPolicy(),
            clock=clock,
            hosts=HOSTS,
        ),
    )
    return harness, service, assessment, counts, sources


class _Harness:
    """Exposes both the observation write path and the composite read."""

    def __init__(self, service, query):
        self._service, self.query = service, query

    @property
    def repository_id(self) -> UUID:
        return self._service._assessment.target.repository_id

    def record_forge_facts(self, **kwargs):
        return self._service.record_forge_facts(**kwargs)

    def repo_state(self, **kwargs):
        return self.query.repo_state(**kwargs)


def _contract_db() -> SqlTraustUnitOfWork:
    """A fresh SQLite contract database (a copy of the session template)."""
    path = Path(tempfile.mkdtemp(prefix="traust-observe-")) / "contract.db"
    shutil.copyfile(_sqlite_template(), path)
    return SqlTraustUnitOfWork(create_database_engine(f"sqlite:///{path}"))
