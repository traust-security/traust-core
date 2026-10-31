"""`regression_pairs` on SQLite and Postgres: a confirmed fix's pre- and post-fix files.

Pairing rules ported from traust harnessing/mine-ledger/scripts/emit_rule_drafts.py and
recall-benchmark bootstrap_benchmark_targets.py (traust fabdb13).
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.findings.test_reads import service as finding_service
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.detection_quality import (
    PairFile,
    PairSkip,
    RegressionPairFilter,
    RegressionPairs,
)
from traust_core.v1.models.inventory import Repository, RepositoryRef
from traust_core.v1.providers.base import Acquisition, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.sources import CheckoutProviderName, CheckoutRequest, Workspace
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpecs
from traust_core.v1.services.detection_quality import DetectionQualityService

PRE, FIX = "a" * 40, "b" * 40
REPO = "https://github.com/org/repo-a"
GONE = "https://github.com/org/gone"
VULN = 'exec.Command("sh", "-c", input)\n'
SAFE = 'exec.Command("ls", input)\n'


@dataclass
class FakeCheckouts:
    """A checkout seam over a fixed tree: (repo, sha, path) -> text, serving each order's kept
    paths as a workspace; a repository that 404s raises."""

    files: Mapping[tuple[str, str, str], str]
    orders: list[CheckoutRequest] = field(default_factory=list)

    def checkout(self, request: CheckoutRequest) -> Result[Workspace]:
        self.orders.append(request)
        if str(request.repo) == GONE:
            raise NotFoundError("HTTP 404")
        repo, sha = str(request.repo), str(request.ref)
        path = Path(tempfile.mkdtemp(prefix="pair-"))
        for (r, s, rel), text in self.files.items():
            if r == repo and s == sha and (request.keep is None or rel in request.keep):
                file = path / rel
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(text)
        return Result(
            Workspace(
                repo=request.repo, sha=request.ref, path=path, provider=CheckoutProviderName.MIRROR
            ),
            Acquisition(provider=CheckoutProviderName.MIRROR, acquired_at=T0),
        )

    def release(self, workspace: Workspace) -> None:
        shutil.rmtree(workspace.path, ignore_errors=True)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@dataclass
class Ledger:
    engine: Engine
    uow: SqlTraustUnitOfWork
    seed: Seed
    repos: dict[str, tuple[Repository, RepositoryRef, RepositoryRef]] = field(default_factory=dict)

    def finding(
        self,
        path: str = "cmd/run.go",
        cwe: str = "CWE-78",
        *,
        repo: str = REPO,
        validity: str | None = "confirmed",
        resolved: bool = True,
        fixed: bool = True,
        reported_before: bool = True,
    ) -> UUID:
        """A finding reported on PRE (or only on FIX), judged, then resolved by a verification of
        FIX that names FIX as the fix commit (or names none)."""
        seed = self.seed
        with self.uow as uow:
            if repo not in self.repos:
                r = seed.repository(url=repo)
                refs = seed.repository_ref(r, sha=PRE), seed.repository_ref(r, sha=FIX)
                self.repos[repo] = (r, *refs)
            r, pre, fix = self.repos[repo]
            cwe_row = uow.cwes.find_by_identifier(cwe) or seed.cwe(identifier=cwe)
            f = seed.finding(r, title=f"{cwe} in {path}")
            seed.finding_cwe(f, cwe_row)
            audit = seed.assessment(pre if reported_before else fix, occurred_at=T0)
            seed.location(seed.occurrence(f, audit), path=path)
            if validity:
                seed.decision(f, validity=validity, actor="human:alice@example.com")
            if resolved:
                verify = seed.assessment(fix, kind="verification", occurred_at=T0 + timedelta(1))
                seed.decision(
                    f,
                    validity=None,
                    resolution="resolved",
                    assessment_id=verify.id,
                    fixed_repository_ref_id=fix.id if fixed else None,
                    actor=None,
                    rationale="Commit bbbbbbb quotes the argument",
                    occurred_at=T0 + timedelta(1),
                )
            uow.commit()
        assert f.id is not None
        return f.id

    def pairs(self, forge: FakeCheckouts, **kw: Any) -> RegressionPairs:
        uow = SqlTraustUnitOfWork(self.engine)
        service = DetectionQualityService(
            uow,
            finding_service(self.engine),
            ArtifactPublisher(PublishSpecs(), InMemoryObjectStore(), uow),
            clock=FixedClock(T0),
            checkouts=forge,  # type: ignore[arg-type]
        )
        return service.regression_pairs(RegressionPairFilter(**kw))


@pytest.fixture
def ledger(engine: Engine) -> Ledger:
    uow = SqlTraustUnitOfWork(engine)
    return Ledger(engine, uow, Seed(uow))


def tree(files: Mapping[str, tuple[str | None, str | None]]) -> dict[tuple[str, str, str], str]:
    """path -> (pre-fix text, fix text); None: absent on that commit."""
    return {
        (REPO, sha, path): text
        for path, (before, after) in files.items()
        for sha, text in ((PRE, before), (FIX, after))
        if text is not None
    }


def test_a_confirmed_fix_pairs_its_pre_and_post_fix_files(ledger: Ledger) -> None:
    finding_id = ledger.finding()
    result = ledger.pairs(FakeCheckouts(tree({"cmd/run.go": (VULN, SAFE)})))
    (pair,) = result.pairs
    assert (pair.finding_id, pair.pre_fix_sha, pair.fix_sha) == (finding_id, PRE, FIX)
    assert pair.files == (PairFile(path="cmd/run.go", before=VULN, after=SAFE),)
    assert (pair.language, pair.cwes, pair.rationale) == (
        "go",
        ("CWE-78",),
        "Commit bbbbbbb quotes the argument",
    )
    assert pair.id.startswith("repo-a-cwe-78-fp-")
    assert pair.rule_id == f"harness-go-regression-{pair.id}"
    assert pair.rule_severity == "ERROR"
    assert result.skipped == ()


@pytest.mark.parametrize(
    "kw",
    [
        pytest.param({"fixed": False}, id="resolved-with-no-fix-commit"),
        pytest.param({"resolved": False}, id="not-resolved"),
        pytest.param({"validity": "false_positive"}, id="false-positive"),
        pytest.param({"validity": None}, id="never-confirmed"),
        pytest.param({"reported_before": False}, id="only-seen-on-the-fix-commit"),
    ],
)
def test_only_confirmed_fixes_seen_before_the_fix_commit_pair(
    ledger: Ledger, kw: dict[str, Any]
) -> None:
    ledger.finding(**kw)
    forge = FakeCheckouts(tree({"cmd/run.go": (VULN, SAFE)}))
    assert ledger.pairs(forge) == RegressionPairs()
    assert forge.orders == []


@pytest.mark.parametrize(
    ("path", "files", "reason"),
    [
        ("cmd/run.go", tree({"cmd/run.go": (VULN, VULN)}), PairSkip.UNCHANGED),
        ("cmd/run.go", tree({"cmd/run.go": (None, SAFE)}), PairSkip.NO_PRE_IMAGE),
        ("chart/values.yaml", {}, PairSkip.UNRULEABLE),
    ],
)
def test_a_fix_with_nothing_to_calibrate_is_skipped_with_its_reason(
    ledger: Ledger, path: str, files: dict[tuple[str, str, str], str], reason: PairSkip
) -> None:
    finding_id = ledger.finding(path)
    result = ledger.pairs(FakeCheckouts(files))
    assert result.pairs == ()
    assert [(s.finding_id, s.reason) for s in result.skipped] == [(finding_id, reason)]


def test_a_path_the_fix_deleted_pairs_with_no_post_fix_file(ledger: Ledger) -> None:
    ledger.finding()
    (pair,) = ledger.pairs(FakeCheckouts(tree({"cmd/run.go": (VULN, None)}))).pairs
    assert pair.files == (PairFile(path="cmd/run.go", before=VULN, after=None),)


def test_an_unreadable_repository_is_skipped_loudly_and_the_rest_still_pair(
    ledger: Ledger,
) -> None:
    gone = ledger.finding(repo=GONE)
    ledger.finding()
    result = ledger.pairs(FakeCheckouts(tree({"cmd/run.go": (VULN, SAFE)})))
    assert len(result.pairs) == 1
    (skip,) = result.skipped
    assert (skip.finding_id, skip.reason, skip.detail) == (gone, PairSkip.UNREADABLE, "HTTP 404")
    assert result.skipped_by_reason == {"unreadable": 1}
    assert result.model_dump(mode="json")["skipped_by_reason"] == {"unreadable": 1}


def test_cwe_limit_and_staged_drafts_narrow_before_any_checkout(ledger: Ledger) -> None:
    first = ledger.finding("cmd/a.go")
    second = ledger.finding("cmd/b.go")
    ledger.finding("cmd/c.go", "CWE-22")
    files = tree({"cmd/a.go": (VULN, SAFE), "cmd/b.go": (VULN, SAFE), "cmd/c.go": (VULN, SAFE)})
    assert [p.finding_id for p in ledger.pairs(FakeCheckouts(files), limit=1).pairs] == [first]
    assert [p.cwes for p in ledger.pairs(FakeCheckouts(files), cwe="cwe-22").pairs] == [("CWE-22",)]
    staged = ledger.pairs(FakeCheckouts(files), limit=1).pairs[0].id
    forge = FakeCheckouts(files)
    result = ledger.pairs(forge, limit=1, staged=frozenset({staged}))
    assert [p.finding_id for p in result.pairs] == [second]
    assert [(s.finding_id, s.reason) for s in result.skipped] == [(first, PairSkip.STAGED)]
    assert all("cmd/a.go" not in (order.keep or ()) for order in forge.orders)


def test_pairs_are_deterministic_across_runs(ledger: Ledger) -> None:
    for path in ("cmd/a.go", "cmd/b.go"):
        ledger.finding(path)
    files = tree({"cmd/a.go": (VULN, SAFE), "cmd/b.go": (VULN, SAFE)})
    assert ledger.pairs(FakeCheckouts(files)) == ledger.pairs(FakeCheckouts(files))


def test_an_empty_ledger_has_no_pairs(ledger: Ledger) -> None:
    assert ledger.pairs(FakeCheckouts({})) == RegressionPairs()
