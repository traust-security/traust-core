"""Locations resolve exactly as traust-engine's `locations` module (and traust's `inputs_dir`)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from traust_core.v1.context import Config, Locations
from traust_core.v1.errors import ConfigError

# Expected values were produced by running traust-engine's `locations` accessors (and traust's
# `context.inputs_dir`) over the same files; "error" = the engine raised DeploymentConfigMissing.
ACCESSORS = (
    "analysis_results_dir",
    "workspace_dir",
    "inputs_dir",
    "progress_tracker_dir",
    "feeds_cache_dir",
    "rule_drafts_dir",
    "portfolio_graph_db",
    "findings_db",
)
# Accessors absent from a row return None.
PARITY = [
    (
        "absent",
        None,
        {
            "workspace_dir": "error",
            "inputs_dir": "error",
        },
    ),
    (
        "absolute",
        (
            "workspace: {abs}/ws\n"
            "analysis_results: {abs}/ar\n"
            "progress_tracker: {abs}/pt\n"
            "feeds_cache: {abs}/fc\n"
        ),
        {
            "analysis_results_dir": "{root}/abs/ar",
            "workspace_dir": "{root}/abs/ws",
            "inputs_dir": "{root}/abs/ws/inputs",
            "progress_tracker_dir": "{root}/abs/pt",
            "feeds_cache_dir": "{root}/abs/fc",
            "rule_drafts_dir": "{root}/abs/pt/metrics/rule-mining/rule-drafts",
            "portfolio_graph_db": "{root}/abs/ar/graph/portfolio-graph.db",
            "findings_db": "{root}/abs/ar/graph/findings.db",
        },
    ),
    (
        "relative",
        ("workspace: ws\nanalysis_results: ./ar\nprogress_tracker: ../pt\nfeeds_cache: a/../fc\n"),
        {
            "analysis_results_dir": "{root}/cfg/home/ar",
            "workspace_dir": "{root}/cfg/home/ws",
            "inputs_dir": "{root}/cfg/home/ws/inputs",
            "progress_tracker_dir": "{root}/cfg/pt",
            "feeds_cache_dir": "{root}/cfg/home/fc",
            "rule_drafts_dir": "{root}/cfg/pt/metrics/rule-mining/rule-drafts",
            "portfolio_graph_db": "{root}/cfg/home/ar/graph/portfolio-graph.db",
            "findings_db": "{root}/cfg/home/ar/graph/findings.db",
        },
    ),
    (
        "file_uri",
        (
            "workspace: file://{abs}/ws\n"
            "analysis_results: file://{abs}/ar\n"
            "progress_tracker: file://{abs}/pt\n"
        ),
        {
            "analysis_results_dir": "{root}/abs/ar",
            "workspace_dir": "{root}/abs/ws",
            "inputs_dir": "{root}/abs/ws/inputs",
            "progress_tracker_dir": "{root}/abs/pt",
            "rule_drafts_dir": "{root}/abs/pt/metrics/rule-mining/rule-drafts",
            "portfolio_graph_db": "{root}/abs/ar/graph/portfolio-graph.db",
            "findings_db": "{root}/abs/ar/graph/findings.db",
        },
    ),
    (
        "remote",
        (
            "workspace: s3://b/ws\n"
            "analysis_results: s3://b/ar\n"
            "progress_tracker: gs://b/pt\n"
            "feeds_cache: az://b/fc\n"
        ),
        {
            "workspace_dir": "error",
            "inputs_dir": "error",
        },
    ),
    (
        "overrides",
        (
            "analysis_results: {abs}/ar\n"
            "portfolio_graph: pg/graph.db\n"
            "progress_tracker: {abs}/pt\n"
            "rule_drafts: s3://b/drafts\n"
        ),
        {
            "analysis_results_dir": "{root}/abs/ar",
            "workspace_dir": "error",
            "inputs_dir": "error",
            "progress_tracker_dir": "{root}/abs/pt",
            "portfolio_graph_db": "{root}/cfg/home/pg/graph.db",
            "findings_db": "{root}/abs/ar/graph/findings.db",
        },
    ),
    (
        "defaults_only",
        ("analysis_results: {abs}/ar\nprogress_tracker: {abs}/pt\n"),
        {
            "analysis_results_dir": "{root}/abs/ar",
            "workspace_dir": "error",
            "inputs_dir": "error",
            "progress_tracker_dir": "{root}/abs/pt",
            "rule_drafts_dir": "{root}/abs/pt/metrics/rule-mining/rule-drafts",
            "portfolio_graph_db": "{root}/abs/ar/graph/portfolio-graph.db",
            "findings_db": "{root}/abs/ar/graph/findings.db",
        },
    ),
    (
        "inputs_relative",
        ("workspace: {abs}/ws\ninputs: inv\n"),
        {
            "workspace_dir": "{root}/abs/ws",
            "inputs_dir": "{root}/cfg/home/inv",
        },
    ),
    (
        "inputs_file_relative",
        ("workspace: {abs}/ws\ninputs: file://inv\n"),
        {
            "workspace_dir": "{root}/abs/ws",
            "inputs_dir": "{root}/cfg/home/inv",
        },
    ),
    (
        "inputs_absolute",
        "inputs: {abs}/inv\n",
        {
            "workspace_dir": "error",
            "inputs_dir": "{root}/abs/inv",
        },
    ),
    (
        "unknown_key",
        ("workspace: {abs}/ws\nsomething_else: 3\n"),
        {
            "workspace_dir": "{root}/abs/ws",
            "inputs_dir": "{root}/abs/ws/inputs",
        },
    ),
    (
        "empty_strings",
        ("workspace: ''\nanalysis_results: ''\n"),
        {
            "workspace_dir": "error",
            "inputs_dir": "error",
        },
    ),
]


@pytest.mark.parametrize(("text", "expected"), [c[1:] for c in PARITY], ids=[c[0] for c in PARITY])
def test_locations_match_the_engine(tmp_path: Path, text: str | None, expected: dict) -> None:
    root = tmp_path.resolve()
    home = root / "cfg" / "home"
    home.mkdir(parents=True)
    inline = "" if text is None else "locations:\n" + textwrap.indent(text, "  ")
    (home / "traust.yaml").write_text(inline.format(abs=root / "abs"))
    locations = Config.from_file(home / "traust.yaml").locations
    for accessor in ACCESSORS:
        want = expected.get(accessor)
        if want == "error":
            with pytest.raises(ConfigError, match="not configured"):
                getattr(locations, accessor)()
        else:
            got = getattr(locations, accessor)()
            shown = None if got is None else str(got).replace(str(root), "{root}")
            assert shown == want, accessor


@pytest.mark.parametrize(
    "text",
    ["locations:\n", "locations:\n  workspace: 5\n", "locations:\n  - a\n", "locations: [\n"],
    ids=["empty", "not-a-string", "not-a-mapping", "not-yaml"],
)
def test_an_invalid_locations_file_is_a_config_error(tmp_path: Path, text: str) -> None:
    (tmp_path / "traust.yaml").write_text(text)
    with pytest.raises(ConfigError, match=r"traust\.yaml"):
        Config.from_file(tmp_path / "traust.yaml")


def test_remote_inputs_is_refused_not_replaced_by_the_workspace(tmp_path: Path) -> None:
    locations = Locations(workspace=str(tmp_path), inputs="s3://bucket/inputs")
    with pytest.raises(ConfigError, match="inputs not configured"):
        locations.inputs_dir()


def test_require_names_the_missing_location() -> None:
    with pytest.raises(ConfigError, match=r"^progress_tracker not configured"):
        Locations.require(Locations().progress_tracker_dir(), "progress_tracker")
    assert Locations.require(Path("/x"), "x") == Path("/x")


def test_the_mirror_cache_defaults_under_the_home_and_resolves_like_the_rest(
    tmp_path: Path,
) -> None:
    # Unlike the locations above it has a default; the engine has no counterpart for it.
    assert Locations().mirror_cache_dir(tmp_path) == tmp_path / "mirrors"
    assert Locations(mirror_cache="m").mirror_cache_dir(tmp_path) == tmp_path / "m"
    assert Locations(mirror_cache=str(tmp_path / "m")).mirror_cache_dir(tmp_path) == tmp_path / "m"
    with pytest.raises(ConfigError, match="mirror_cache must be a local path"):
        Locations(mirror_cache="s3://bucket/m").mirror_cache_dir(tmp_path)
