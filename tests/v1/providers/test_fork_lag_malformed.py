from __future__ import annotations

from pathlib import Path

from traust_core.v1.providers.fork_lag import detect


def test_invalid_vendored_version_does_not_hide_other_projects(tmp_path: Path) -> None:
    broken = tmp_path / "vendor" / "broken"
    good = tmp_path / "vendor" / "good"
    broken.mkdir(parents=True)
    good.mkdir()
    (broken / "package.json").write_text('{"name":"broken","version":123}')
    (good / "package.json").write_text('{"name":"good","version":"1.2.3"}')

    try:
        fact = detect(tmp_path)
    except AttributeError:
        fact = None

    assert fact is not None, "malformed vendored version aborted fork detection"
    assert [up.identity for up in fact.upstreams] == ["good"]


def test_vendored_project_with_go_and_npm_manifests_names_both_upstreams(tmp_path: Path) -> None:
    project = tmp_path / "vendor" / "dual"
    project.mkdir(parents=True)
    (project / "go.mod").write_text("module github.com/example/lib\n")
    (project / "package.json").write_text('{"name":"@example/lib","version":"1.2.3"}')

    fact = detect(tmp_path)

    assert {up.identity for up in fact.upstreams} == {"github.com/example/lib", "@example/lib"}
