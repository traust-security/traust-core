"""Fork detection (the fork advisory-lag pre-scan's stage 1): pure-local, no network. Ported from
traust tests/test_run_fork_advisory_lag.py; git config is written, never run."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.code_facts import ForkLagFact, ForkSignalKind
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.fork_lag import (
    ForkDetector,
    detect,
    module_identity,
    parse_remote_url,
)
from traust_core.v1.providers.tools import ToolRequest


def _git_config(remotes: dict[str, str]) -> str:
    return "[core]\n\tbare = false\n" + "".join(
        f'[remote "{name}"]\n\turl = {url}\n\tfetch = +refs/heads/*:refs/remotes/{name}/*\n'
        for name, url in remotes.items()
    )


def _mk_repo(
    tmp_path: Path, module: str, origin: str | None = None, name: str = "target", **remotes: str
) -> Path:
    repo = tmp_path / name
    (repo / ".git").mkdir(parents=True)
    (repo / "go.mod").write_text(f"module {module}\n\ngo 1.21\n")
    all_remotes = ({"origin": origin} if origin else {}) | remotes
    (repo / ".git" / "config").write_text(_git_config(all_remotes))
    return repo


def test_gomod_module_path_fork_detection(tmp_path):
    repo = _mk_repo(
        tmp_path, "github.com/coredns/coredns", "https://github.com/openshift/coredns.git"
    )
    fact = detect(repo)
    [up] = fact.upstreams
    assert (up.identity, up.package, up.ecosystem) == (
        "github.com/coredns/coredns",
        "github.com/coredns/coredns",
        Ecosystem.GO,
    )
    ev = up.evidence[0]
    assert (ev.file, ev.line) == ("go.mod", 1)
    assert "coredns/coredns" in ev.quote
    assert [s.type for s in fact.signals] == [ForkSignalKind.GO_MOD_MODULE_PATH]
    assert fact.fork_detected and fact.network == "skipped"


def test_version_constant_resolves_tracked_version(tmp_path):
    repo = _mk_repo(
        tmp_path, "github.com/coredns/coredns", "https://github.com/openshift/coredns.git"
    )
    (repo / "coremain").mkdir()
    (repo / "coremain" / "version.go").write_text(
        'package coremain\n\nconst (\n\tCoreVersion = "1.11.1"\n\tGoVersion = "1.21.5"\n)\n'
    )
    [up] = detect(repo).upstreams
    assert up.tracked_version == "1.11.1"  # GoVersion is not the upstream's version
    assert any(e.file == "coremain/version.go" and e.line == 4 for e in up.evidence)


def test_shallowest_version_file_wins(tmp_path):
    repo = _mk_repo(
        tmp_path, "github.com/coredns/coredns", "https://github.com/openshift/coredns.git"
    )
    (repo / "VERSION").write_text("v2.0.0\n")
    (repo / "pkg").mkdir()
    (repo / "pkg" / "version.txt").write_text("1.0.0\n")
    (repo / "notes").mkdir()
    (repo / "notes" / "VERSION").write_text("not a version\n")
    assert detect(repo).upstreams[0].tracked_version == "2.0.0"


def test_replace_directive_fork(tmp_path):
    repo = _mk_repo(
        tmp_path, "github.com/openshift/router", "https://github.com/openshift/router.git"
    )
    (repo / "go.mod").write_text(
        "module github.com/openshift/router\n\ngo 1.21\n\n"
        "require github.com/coredns/coredns v1.11.1\n\n"
        "replace github.com/coredns/coredns => github.com/openshift/coredns v1.11.2\n"
    )
    fact = detect(repo)
    assert [s.type for s in fact.signals] == [ForkSignalKind.GO_MOD_REPLACE]
    [up] = fact.upstreams
    assert (up.identity, up.tracked_version) == ("github.com/coredns/coredns", "1.11.2")
    assert up.evidence[0].file == "go.mod"


def test_replace_block_takes_the_required_version_and_skips_local_paths(tmp_path):
    repo = _mk_repo(
        tmp_path, "github.com/openshift/router", "https://github.com/openshift/router.git"
    )
    (repo / "go.mod").write_text(
        "module github.com/openshift/router\n\n"
        "require (\n\tgithub.com/coredns/coredns v1.11.1\n)\n\n"
        "replace (\n"
        "\tgithub.com/coredns/coredns => github.com/openshift/coredns // pinned fork\n"
        "\tgithub.com/foo/bar => ../bar\n"
        "\tgithub.com/same/thing => github.com/same/thing v1.0.0\n"
        ")\n"
    )
    [up] = detect(repo).upstreams
    assert (up.identity, up.tracked_version) == ("github.com/coredns/coredns", "1.11.1")


def test_vendored_project_detection(tmp_path):
    repo = _mk_repo(
        tmp_path, "github.com/openshift/thing", "https://github.com/openshift/thing.git"
    )
    vend = repo / "third_party" / "coredns"
    vend.mkdir(parents=True)
    (vend / "go.mod").write_text("module github.com/coredns/coredns\n")
    (vend / "version.go").write_text('package coredns\n\nvar Version = "1.10.0"\n')
    (vend / "plugin").mkdir()
    (vend / "plugin" / "go.mod").write_text("module github.com/coredns/coredns/plugin\n")
    fact = detect(repo)
    vendored = [s for s in fact.signals if s.type is ForkSignalKind.VENDORED_PROJECT]
    assert [s.scope for s in vendored] == ["third_party/coredns"]  # never below a project root
    [up] = fact.upstreams
    assert (up.identity, up.tracked_version) == ("github.com/coredns/coredns", "1.10.0")
    assert any(e.file == "third_party/coredns/go.mod" for e in up.evidence)


def test_vendored_npm_project(tmp_path):
    repo = _mk_repo(
        tmp_path, "github.com/openshift/thing", "https://github.com/openshift/thing.git"
    )
    vend = repo / "vendor" / "left-pad"
    vend.mkdir(parents=True)
    (vend / "package.json").write_text('{"name": "left-pad", "version": "v1.3.0"}')
    (repo / "vendor" / "broken").mkdir()
    (repo / "vendor" / "broken" / "package.json").write_text("{not json")
    [up] = detect(repo).upstreams
    assert (up.identity, up.ecosystem, up.tracked_version) == ("left-pad", Ecosystem.NPM, "1.3.0")


def test_git_remote_on_another_org_names_the_root_module(tmp_path):
    repo = _mk_repo(
        tmp_path,
        "github.com/openshift/coredns",
        "https://github.com/openshift/coredns.git",
        name="coredns",
        upstream="git@github.com:coredns/coredns.git",
    )
    fact = detect(repo)
    [signal] = fact.signals
    assert signal.type is ForkSignalKind.GIT_REMOTE
    assert signal.evidence[0].file == ".git/config"
    [up] = fact.upstreams
    assert (up.identity, up.package) == (
        "github.com/coredns/coredns",
        "github.com/openshift/coredns",
    )


def test_worktree_reads_the_common_git_config(tmp_path):
    main = _mk_repo(
        tmp_path,
        "github.com/openshift/coredns",
        "https://github.com/openshift/coredns.git",
        name="main",
        upstream="https://github.com/coredns/coredns",
    )
    gitdir = main / ".git" / "worktrees" / "wt"
    gitdir.mkdir(parents=True)
    (gitdir / "commondir").write_text("../..\n")
    wt = tmp_path / "wt"
    wt.mkdir()
    (wt / ".git").write_text(f"gitdir: {gitdir}\n")
    (wt / "go.mod").write_text("module github.com/openshift/coredns\n")
    [up] = detect(wt).upstreams
    assert up.identity == "github.com/coredns/coredns"


def test_directory_identity_when_there_is_no_origin(tmp_path):
    (tmp_path / "openshift").mkdir()
    repo = _mk_repo(tmp_path / "openshift", "github.com/coredns/coredns", name="coredns")
    [signal] = detect(repo).signals
    assert signal.detail.endswith("checkout directory is openshift/coredns")


def test_checkout_container_directory_is_not_a_fork_org(tmp_path):
    (tmp_path / "src").mkdir()
    repo = _mk_repo(tmp_path / "src", "github.com/coredns/coredns", name="coredns")
    assert detect(repo) == ForkLagFact()


def test_non_fork_repo(tmp_path):
    repo = _mk_repo(
        tmp_path, "github.com/openshift/foo", "https://github.com/openshift/foo.git", name="foo"
    )
    (repo / "VERSION").write_text("1.0.0\n")  # versions only count once an identity exists
    assert detect(repo) == ForkLagFact()
    assert not detect(repo).fork_detected


def test_vanity_module_path_is_not_a_fork(tmp_path):
    repo = _mk_repo(
        tmp_path,
        "k8s.io/kubernetes",
        "https://github.com/kubernetes/kubernetes.git",
        name="kubernetes",
    )
    assert detect(repo).upstreams == ()


@pytest.mark.parametrize(
    ("url", "identity"),
    [
        ("https://github.com/openshift/coredns.git", ("github.com", "openshift", "coredns")),
        ("git@GitHub.com:coredns/coredns.git", ("github.com", "coredns", "coredns")),
        ("ssh://git@gitlab.com/group/proj/", ("gitlab.com", "group", "proj")),
        ("not a url", None),
    ],
)
def test_parse_remote_url(url, identity):
    assert parse_remote_url(url) == identity


@pytest.mark.parametrize(
    ("module", "identity"),
    [
        ("k8s.io/api", ("github.com", "kubernetes", "api")),
        ("google.golang.org/grpc", ("github.com", "grpc", "grpc-go")),
        ("github.com/a/b/v2", ("github.com", "a", "b")),
        ("example/local", None),
    ],
)
def test_module_identity(module, identity):
    assert module_identity(module) == identity


def test_enumerator_returns_one_fact(tmp_path):
    at = datetime(2026, 10, 25, tzinfo=UTC)
    repo = _mk_repo(tmp_path, "github.com/a/b", "https://github.com/a/b.git", name="b")
    result = ForkDetector(FixedClock(at)).enumerate(ToolRequest(workspace=repo))
    assert result.data == [ForkLagFact()]
    assert (result.acquisition.provider, result.acquisition.acquired_at) == ("fork-detector", at)


def test_missing_workspace_is_refused(tmp_path):
    with pytest.raises(ValidationError, match="not a directory"):
        detect(tmp_path / "absent")
