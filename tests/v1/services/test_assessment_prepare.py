"""AssessmentService.prepare: what an assessment starts from, and diff mode's scope (vuln-scan).

Ported from traust's tests/test_resolve_baseline.py and tests/test_build_diff_packet.py; the
baselines come from assessment rows instead of findings.db, the anchors from tiny git repos.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from tests.v1.conftest import CLOCK, commit_all, git
from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.errors import ConfigError, ServiceError, ValidationError
from traust_core.v1.models.assessment import (
    Assessment,
    AssessmentKind,
    DiffRefused,
    DiffRequest,
    DiffResolution,
)
from traust_core.v1.models.inventory import Repository, RepositoryRef
from traust_core.v1.models.observation import CHURN_FULL_LINES
from traust_core.v1.providers.checkout import GitCheckout
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.symbols import CTAGS_BINARIES, SymbolIndex
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services import assessment as assessment_module
from traust_core.v1.services.assessment import AssessmentService, clusters, touches
from traust_core.v1.services.findings import (
    FindingDecisions,
    FindingIntake,
    FindingPrecedents,
    FindingReview,
    FindingService,
    IdentityPolicy,
    RatingPolicy,
    ReviewPolicy,
    TaxonomyPolicy,
)
from traust_core.v1.services.findings.rating import RatingConfig
from traust_core.v1.services.lint import Lint

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed

NOW = T0 + timedelta(days=30)
URL = "https://github.com/acme/widget"
SECURE_CODE = AssessmentKind.SECURE_CODE.value


def findings(uow: SqlTraustUnitOfWork) -> FindingService:
    precedents = FindingPrecedents(uow)
    return FindingService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        FindingDecisions(
            uow,
            None,
            Lint({}),
            precedents,
            clock=FixedClock(NOW),
            objects=InMemoryObjectStore(),
            review=ReviewPolicy(),
        ),
        FindingReview(uow, ReviewPolicy()),
        precedents,
        RatingPolicy(RatingConfig()),
        InMemoryObjectStore(),
    )


def service(uow: SqlTraustUnitOfWork, **kw: Any) -> AssessmentService:
    wired: dict[str, Any] = {
        "findings": findings(uow),
        "git": GitCheckout(ProcessRunner(("git",))),
        "symbols": SymbolIndex(ProcessRunner(CTAGS_BINARIES), CLOCK),
    }
    return AssessmentService(uow, clock=FixedClock(NOW), **{**wired, **kw})


@dataclass
class Widget:
    """A checkout with its repository rows: the audited base commit and the current head."""

    path: Path
    base: str
    repository: Repository
    audited: RepositoryRef
    seed: Seed

    def head(self) -> RepositoryRef:
        sha = git(self.path, "rev-parse", "HEAD")
        found = self.seed.uow.repository_refs.find(self.repository.id, "main", sha)
        return found or self.seed.repository_ref(self.repository, sha=sha, is_default=True)

    def audit(self, **kw: Any) -> Assessment:
        ref = kw.pop("ref", self.audited)
        return self.seed.assessment(ref, **{"kind": SECURE_CODE, "occurred_at": T0, **kw})

    def finding(self, audit: Assessment, path: str, title: str = "SQL injection") -> Any:
        found = self.seed.finding(self.repository, title=title)
        self.seed.location(self.seed.occurrence(found, audit), path=path)
        return found


@pytest.fixture
def widget(tmp_path: Path, seed: Seed) -> Widget:
    """22 first-party files at the base commit (20 pkg files, internal/auth/login.go, go.mod),
    plus vendor/ and a README that don't count."""
    r = tmp_path / "widget"
    r.mkdir()
    git(r, "init", "-q")
    for i in range(20):
        (r / f"pkg{i % 4}").mkdir(exist_ok=True)
        (r / f"pkg{i % 4}" / f"file{i}.go").write_text(f"package p{i % 4}\n// f{i}\n")
    (r / "internal" / "auth").mkdir(parents=True)
    (r / "internal" / "auth" / "login.go").write_text("package auth\n// login\n")
    (r / "go.mod").write_text("module widget\n")
    (r / "vendor").mkdir()
    (r / "vendor" / "dep.go").write_text("package dep\n")
    (r / "README.md").write_text("# widget\n")
    base = commit_all(r, "base")
    repository = seed.repository(url=URL)
    audited = seed.repository_ref(repository, sha=base, is_default=True)
    return Widget(r, base, repository, audited, seed)


def advance(w: Widget) -> RepositoryRef:
    """3 of 22 first-party files change (under the 30% rule): one sensitive, one manifest."""
    (w.path / "pkg0" / "file0.go").write_text("package p0\n// changed\nvar X=1\n")
    with (w.path / "internal" / "auth" / "login.go").open("a") as f:
        f.write("func Login() {}\n")
    (w.path / "go.mod").write_text("module widget\n\nrequire x v1\n")
    commit_all(w.path, "change")
    return w.head()


def test_without_diff_the_input_is_the_repository_findings_and_latest_threat_model(
    uow: SqlTraustUnitOfWork, widget: Widget
) -> None:
    audit = widget.audit()
    known = widget.finding(audit, "pkg0/file0.go")
    old = widget.audit(kind=AssessmentKind.THREAT_MODEL.value, occurred_at=T0 - timedelta(days=9))
    widget.seed.artifact(old, kind="threat-model")
    model = widget.audit(kind=AssessmentKind.THREAT_MODEL.value)
    md, js = (widget.seed.artifact(model, kind=k) for k in ("threat-model-md", "threat-model"))
    widget.audit(kind=AssessmentKind.THREAT_MODEL.value, status="degraded", occurred_at=NOW)

    prepared = service(uow).prepare(widget.audited.id, AssessmentKind.THREAT_MODEL)

    assert prepared.kind == AssessmentKind.THREAT_MODEL
    assert (prepared.subject.sha, prepared.subject.repository_url) == (widget.base, URL)
    assert prepared.prepared_at == NOW
    assert [v.finding.id for v in prepared.findings.baseline] == [known.id]
    assert {a.id for a in prepared.threat_model} == {md.id, js.id}
    assert prepared.diff is None


def test_without_a_threat_model_or_findings_the_input_is_empty(
    uow: SqlTraustUnitOfWork, widget: Widget
) -> None:
    prepared = service(uow).prepare(widget.audited.id, AssessmentKind.SECURE_CODE)
    assert (prepared.findings.baseline, prepared.threat_model, prepared.diff) == ((), (), None)


def test_the_diff_scope_measures_the_change_since_the_baseline(
    uow: SqlTraustUnitOfWork, widget: Widget
) -> None:
    audit = widget.audit()
    touched = widget.finding(audit, "internal/auth/login.go")
    widget.finding(audit, "pkg3/file3.go", "unrelated")
    head = advance(widget)

    prepared = service(uow).prepare(
        head.id, AssessmentKind.VULN_SCAN, DiffRequest(checkout=widget.path)
    )

    scope = prepared.diff
    assert scope is not None
    assert (scope.anchor, scope.resolution) == (widget.base, DiffResolution.AUTO)
    assert scope.baseline_assessment_id == audit.id
    files = {f.path: f for c in scope.clusters for f in c.files}
    assert set(files) == {"pkg0/file0.go", "internal/auth/login.go", "go.mod"}
    assert files["internal/auth/login.go"].sensitive
    assert not files["pkg0/file0.go"].sensitive
    assert files["internal/auth/login.go"].added >= 1
    assert "+func Login() {}" in (files["internal/auth/login.go"].hunks or "")
    assert scope.deps_manifests_changed
    assert scope.changed_lines == sum(f.added + f.deleted for f in files.values())
    assert scope.sensitive_lines >= 1
    assert scope.first_party_files == 22
    assert 0 < scope.changed_ratio <= 0.30
    by_name = {c.name: c for c in scope.clusters}
    assert set(by_name) == {"pkg0", "internal", "(root)"}
    assert [v.finding.id for v in by_name["internal"].baseline] == [touched.id]
    assert by_name["pkg0"].baseline == ()
    assert len(prepared.findings.baseline) == 2
    assert scope.omitted == ()


def test_vendored_and_markdown_changes_are_out_of_scope(
    uow: SqlTraustUnitOfWork, widget: Widget
) -> None:
    widget.audit()
    (widget.path / "vendor" / "dep.go").write_text("package dep\n// changed\n")
    (widget.path / "README.md").write_text("# widget\nchanged\n")
    (widget.path / "pkg1" / "file1.go").write_text("package p1\n// changed\n")
    commit_all(widget.path, "mixed change")

    scope = (
        service(uow)
        .prepare(widget.head().id, AssessmentKind.VULN_SCAN, DiffRequest(checkout=widget.path))
        .diff
    )

    assert scope is not None
    assert [f.path for c in scope.clusters for f in c.files] == ["pkg1/file1.go"]
    assert not scope.deps_manifests_changed


def test_the_baseline_is_the_freshest_completed_default_branch_code_audit(
    uow: SqlTraustUnitOfWork, widget: Widget
) -> None:
    widget.audit(occurred_at=T0 - timedelta(days=60))
    fresh = widget.audit()
    branch = widget.seed.repository_ref(
        widget.repository, name="feature", sha=widget.base, is_default=False
    )
    widget.audit(ref=branch, occurred_at=T0 + timedelta(days=1))
    widget.audit(kind=AssessmentKind.VULN_SCAN.value, occurred_at=T0 + timedelta(days=2))
    widget.audit(status="degraded", occurred_at=T0 + timedelta(days=3))
    head = advance(widget)

    scope = (
        service(uow)
        .prepare(head.id, AssessmentKind.VULN_SCAN, DiffRequest(checkout=widget.path))
        .diff
    )

    assert scope is not None
    assert scope.baseline_assessment_id == fresh.id


def test_a_named_baseline_overrides_resolution(uow: SqlTraustUnitOfWork, widget: Widget) -> None:
    named = widget.audit(occurred_at=T0 - timedelta(days=60))
    widget.audit()
    head = advance(widget)

    scope = (
        service(uow)
        .prepare(
            head.id,
            AssessmentKind.VULN_SCAN,
            DiffRequest(checkout=widget.path, baseline_assessment_id=named.id),
        )
        .diff
    )

    assert scope is not None
    assert (scope.baseline_assessment_id, scope.resolution) == (named.id, DiffResolution.OVERRIDE)


def test_since_anchors_the_diff_without_a_baseline(
    uow: SqlTraustUnitOfWork, widget: Widget
) -> None:
    head = advance(widget)

    prepared = service(uow).prepare(
        head.id, AssessmentKind.VULN_SCAN, DiffRequest(checkout=widget.path, since=widget.base)
    )

    assert prepared.diff is not None
    assert (prepared.diff.anchor, prepared.diff.resolution) == (
        widget.base,
        DiffResolution.OVERRIDE,
    )
    assert prepared.diff.baseline_assessment_id is None


def test_a_baseline_of_another_repository_is_rejected(
    uow: SqlTraustUnitOfWork, widget: Widget
) -> None:
    other = widget.seed.assessment(kind=SECURE_CODE)
    with pytest.raises(ValidationError, match="another repository"):
        service(uow).prepare(
            advance(widget).id,
            AssessmentKind.VULN_SCAN,
            DiffRequest(checkout=widget.path, baseline_assessment_id=other.id),
        )


def test_since_must_be_a_sha(widget: Widget) -> None:
    with pytest.raises(ValueError, match="pattern"):
        DiffRequest(checkout=widget.path, since="main")


def _wide(w: Widget) -> None:
    for i in range(8):  # 8 of 22 first-party files: 36%
        (w.path / f"pkg{i % 4}" / f"file{i}.go").write_text(f"package p{i % 4}\n// rewritten\n")
    commit_all(w.path, "wide change")


def _big(w: Widget) -> None:
    lines = "\n".join(f"// l{i}" for i in range(CHURN_FULL_LINES + 1000))
    (w.path / "pkg0" / "big.go").write_text(f"package p0\n{lines}\n")
    commit_all(w.path, "big change")


@pytest.mark.parametrize(
    ("change", "audit", "since", "reason"),
    [
        (advance, False, None, "no valid HEAD code-audit baseline resolvable for " + URL),
        (advance, False, "deadbeef" * 5, "not reachable in the clone"),
        (_wide, True, None, "8/22 (36%) of first-party files changed"),
        (_big, True, None, f">= {CHURN_FULL_LINES}"),
    ],
)
def test_a_diff_that_cannot_stand_in_for_the_baseline_is_refused(
    uow: SqlTraustUnitOfWork,
    widget: Widget,
    change: Any,
    audit: bool,
    since: str | None,
    reason: str,
) -> None:
    if audit:
        widget.audit()
    change(widget)
    with pytest.raises(DiffRefused) as refused:
        service(uow).prepare(
            widget.head().id,
            AssessmentKind.VULN_SCAN,
            DiffRequest(checkout=widget.path, since=since),
        )
    assert reason in refused.value.reason
    assert refused.value.recommend == "full-audit"


def test_a_directory_that_is_not_a_checkout_is_refused(
    uow: SqlTraustUnitOfWork, widget: Widget, tmp_path: Path
) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(DiffRefused, match="not a git checkout"):
        service(uow).prepare(
            widget.audited.id, AssessmentKind.VULN_SCAN, DiffRequest(checkout=plain)
        )


def test_hunks_past_the_per_file_cap_are_truncated_with_a_marker(
    uow: SqlTraustUnitOfWork, widget: Widget, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(assessment_module, "MAX_FILE_HUNK_BYTES", 50)
    widget.audit()
    scope = (
        service(uow)
        .prepare(advance(widget).id, AssessmentKind.VULN_SCAN, DiffRequest(checkout=widget.path))
        .diff
    )
    assert scope is not None
    file = scope.clusters[0].files[0]
    assert file.truncated
    assert "truncated at 50 bytes" in (file.hunks or "")


def test_files_past_the_total_cap_are_listed_not_embedded(
    uow: SqlTraustUnitOfWork, widget: Widget, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(assessment_module, "MAX_TOTAL_HUNK_BYTES", 1)
    widget.audit()
    scope = (
        service(uow)
        .prepare(advance(widget).id, AssessmentKind.VULN_SCAN, DiffRequest(checkout=widget.path))
        .diff
    )
    assert scope is not None
    files = [f for c in scope.clusters for f in c.files]
    assert sum(f.hunks is not None for f in files) == 1  # the cap is checked before each file
    skipped = [f.path for f in files if f.hunks is None]
    assert all(any(p in o and "byte cap" in o for o in scope.omitted) for p in skipped)


@pytest.fixture
def caller(tmp_path: Path, seed: Seed) -> Widget:
    r = tmp_path / "r"
    (r / "pkg").mkdir(parents=True)
    (r / "cmd").mkdir()
    git(r, "init", "-q")
    (r / "pkg" / "auth.go").write_text(
        'package pkg\n\nfunc CheckToken(t string) bool {\n\treturn t != ""\n}\n'
    )
    (r / "cmd" / "main.go").write_text(
        'package main\n\nimport "r/pkg"\n\nfunc main() {\n\t_ = pkg.CheckToken("x")\n}\n'
    )
    for i in range(3):
        (r / "cmd" / f"pad{i}.go").write_text("package main\n")
    base = commit_all(r, "base")
    with (r / "pkg" / "auth.go").open("a") as f:
        f.write("\nfunc CheckSession(s string) bool {\n\treturn len(s) > 4\n}\n")
    commit_all(r, "change")
    repository = seed.repository(url=URL)
    w = Widget(
        r, base, repository, seed.repository_ref(repository, sha=base, is_default=True), seed
    )
    w.audit()
    return w


def test_callers_of_the_changed_files_symbols_come_with_context(
    uow: SqlTraustUnitOfWork, caller: Widget
) -> None:
    scope = (
        service(uow)
        .prepare(caller.head().id, AssessmentKind.VULN_SCAN, DiffRequest(checkout=caller.path))
        .diff
    )
    assert scope is not None
    (cluster,) = scope.clusters
    assert [(c.symbol, c.defined_in, c.path, c.line) for c in cluster.callers] == [
        ("CheckToken", "pkg/auth.go", "cmd/main.go", 6)
    ]
    assert '6: \t_ = pkg.CheckToken("x")' in cluster.callers[0].context
    assert scope.callers_note is None


def test_caller_caps_are_listed_in_omitted(
    uow: SqlTraustUnitOfWork, caller: Widget, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(assessment_module, "MAX_CALLERS", 0)
    monkeypatch.setattr(assessment_module, "MAX_SYMBOLS_PER_FILE", 1)
    scope = (
        service(uow)
        .prepare(caller.head().id, AssessmentKind.VULN_SCAN, DiffRequest(checkout=caller.path))
        .diff
    )
    assert scope is not None
    assert scope.clusters[0].callers == ()
    assert any("1 symbol(s) beyond the per-file cap" in o for o in scope.omitted)
    assert any("caller cap (0) reached at pkg/auth.go:CheckToken" in o for o in scope.omitted)


class _BrokenIndex(SymbolIndex):
    def enumerate(self, request: Any) -> Any:
        raise ServiceError("ctags exited 1")


def test_a_failed_symbol_index_says_callers_were_skipped(
    uow: SqlTraustUnitOfWork, caller: Widget
) -> None:
    broken = _BrokenIndex(ProcessRunner(CTAGS_BINARIES), CLOCK)
    scope = (
        service(uow, symbols=broken)
        .prepare(caller.head().id, AssessmentKind.VULN_SCAN, DiffRequest(checkout=caller.path))
        .diff
    )
    assert scope is not None
    assert scope.callers_note is not None
    assert scope.callers_note.startswith("skipped: symbol index build failed")
    assert scope.clusters[0].callers == ()


@pytest.mark.parametrize(
    ("missing", "diff", "needs"),
    [("findings", False, "finding reads"), ("git", True, "checkout reader")],
)
def test_prepare_without_its_wiring_raises(
    uow: SqlTraustUnitOfWork, widget: Widget, missing: str, diff: bool, needs: str
) -> None:
    request = DiffRequest(checkout=widget.path) if diff else None
    with pytest.raises(ConfigError, match=needs):
        service(uow, **{missing: None}).prepare(
            widget.audited.id, AssessmentKind.VULN_SCAN, request
        )


def test_diff_mode_without_the_symbol_index_raises(
    uow: SqlTraustUnitOfWork, widget: Widget
) -> None:
    widget.audit()
    with pytest.raises(ConfigError, match="symbol index"):
        service(uow, symbols=None).prepare(
            advance(widget).id, AssessmentKind.VULN_SCAN, DiffRequest(checkout=widget.path)
        )


def test_clusters_group_by_top_level_directory() -> None:
    got = dict(clusters(["pkg/a.go", "pkg/b.go", "cmd/main.go", "go.mod"]))
    assert got == {"pkg": ["pkg/a.go", "pkg/b.go"], "cmd": ["cmd/main.go"], "(root)": ["go.mod"]}


def test_clusters_cap_at_five_with_the_smallest_merged_into_other() -> None:
    paths = [f"d{i}/f.go" for i in range(8)] + ["d0/g.go"]
    got = clusters(paths)
    assert len(got) == 5
    assert got[0][0] == "d0"
    assert dict(got)["other"] == ["d4/f.go", "d5/f.go", "d6/f.go", "d7/f.go"]
    assert sorted(p for _, ps in got for p in ps) == sorted(paths)
    assert clusters([]) == []


@pytest.mark.parametrize(
    ("location", "touched"),
    [
        ("internal/auth/login.go", True),
        ("./pkg0/file0.go", True),
        ("widget/internal/auth/login.go", True),
        ("login.go", True),
        ("pkg3/file3.go", False),
        ("internal/auth/login.go.orig", False),
    ],
)
def test_a_location_touches_a_changed_path_allowing_for_a_root_prefix(
    location: str, touched: bool
) -> None:
    assert touches(location, ["internal/auth/login.go", "pkg0/file0.go"]) is touched
