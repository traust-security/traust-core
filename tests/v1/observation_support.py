from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from traust_core.v1.models.portfolio import ComparisonStatus, ObservationTarget
from traust_core.v1.providers.base import Provenance, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.sources import ChangedFile, Comparison, Quota, RepoInfo, SourceError
from traust_core.v1.repositories.assessment import InMemoryAssessmentUnitOfWork
from traust_core.v1.repositories.findings import FindingCountRecord, InMemoryFindingUnitOfWork
from traust_core.v1.repositories.portfolio import InMemoryPortfolioUnitOfWork
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

REFERENCE = json.loads(
    (Path(__file__).parents[1] / "fixtures/observations/reference.json").read_text()
)
NOW = datetime.fromisoformat(REFERENCE["now"])
HOSTS = {"github.com": "github", "gitlab.com": "gitlab"}


class FakeSource:
    def __init__(self, info=None, comparison=None, quota=100):
        self.info_data = info if info is not None else REFERENCE["cases"][0]["info"]
        self.comparison_data = (
            comparison if comparison is not None else REFERENCE["cases"][0]["compare"]
        )
        self.remaining = quota
        self.calls = []

    def result(self, data):
        return Result(data, Provenance(provider="fake", acquired_at=NOW))

    def info(self, repo):
        self.calls.append("info")
        data = {k: v for k, v in self.info_data.items() if k != "ok"}
        if not self.info_data["ok"]:
            raise SourceError(data.get("error") or "source failed", ComparisonStatus(data["kind"]))
        return self.result(RepoInfo(repo=repo, **data))

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
            )
        )

    def quota(self, repo):
        self.calls.append("quota")
        return self.result(Quota(remaining=self.remaining))


class FixedBaselineAssessment(AssessmentService):
    def __init__(self, target, clock):
        super().__init__(InMemoryAssessmentUnitOfWork(), clock=clock)
        self.target = target

    def observation_target(self, **kwargs):
        return self.target


def observer(case=None, *, uow=None, **changes):
    case = case or REFERENCE["cases"][0]
    data = {**case["repo"], **changes}
    live = data.pop("live_crit_high", 0)
    target = ObservationTarget(**data)
    clock = FixedClock(NOW)
    assessment = FixedBaselineAssessment(target, clock)
    findings = InMemoryFindingUnitOfWork(
        [FindingCountRecord(repo_key=target.repo_key, severity="high") for _ in range(live)]
    )
    sources = FakeSource(case["info"], case["compare"])
    portfolio = uow or InMemoryPortfolioUnitOfWork()
    service = PortfolioService(
        portfolio,
        PortfolioPolicy(),
        assessment=assessment,
        findings=findings,
        sources=sources,
        clock=clock,
        hosts=HOSTS,
    )
    return service, portfolio, assessment, findings, sources
