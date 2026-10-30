"""`Context.preflight`: every unmet requirement of the enabled assets at once, each with its
fix; the same door the engine's start gate and `traust doctor` call."""

from __future__ import annotations

from pathlib import Path

import pydantic
import pytest
import yaml

from traust_core.v1.context import Config, Context
from traust_core.v1.context.home import TRAUST_CONFIG_HOME_ENV
from traust_core.v1.errors import PreflightError
from traust_core.v1.models.artifacts import SlaPolicyArtifact
from traust_core.v1.models.operations import Requirement
from traust_core.v1.providers.base import Readiness
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    PublishSpec,
    PublishSpecs,
)

FIXTURES = Path(__file__).parents[2] / "fixtures"
MODEL_REGISTRY = FIXTURES / "operations" / "model-registry.yaml"
SLA_POLICY = FIXTURES / "insight" / "sla-policy.yaml"

TOOLS = """
tools:
  - name: not-a-real-tool
    expected: "9.9.9"
    version_cmd: [not-a-real-tool, --version]
"""

FEEDS = """
version: 1
sources:
  deps_dev:
    tier: live
    url_template: https://dd.test/v3/systems/{ident}
"""

# Every key the completeness audit warns about is set; `home` keeps the database in tmp_path.
COMPLETE = """
home: {store}
locations:
  workspace: ws
  analysis_results: results
  progress_tracker: tracker
ledger:
  public_key_path: /keys/ledger.pub
"""


def context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    traust_yaml: str | None = COMPLETE,
    tools: bool = True,
    feeds: bool = True,
    model_registry: bool = True,
) -> Context:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    if traust_yaml is not None:
        (home / "traust.yaml").write_text(traust_yaml.format(store=tmp_path / "store"))
    if model_registry:
        (home / "model-registry.yaml").write_bytes(MODEL_REGISTRY.read_bytes())
    monkeypatch.setenv(TRAUST_CONFIG_HOME_ENV, str(home))
    ctx = Context(Config.from_home(home))
    if tools:
        ctx.register_toolchain(
            _write(tmp_path, "external-tools.yaml", TOOLS),
            _write(tmp_path, "safe-exec-profiles.yaml", "profiles: {}\n"),
        )
    if feeds:
        ctx.register_feeds(_write(tmp_path, "feeds.yaml", FEEDS))
    if model_registry:
        ctx.register_model_catalog(home / "model-registry.yaml")
    return ctx


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text)
    return path


def gaps(error: PreflightError) -> list[str]:
    return str(error).splitlines()[1:]


def test_a_complete_home_with_every_requirement_met_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = context(tmp_path, monkeypatch)
    monkeypatch.setenv("NVD_API_KEY", "synthetic-only")
    record_sla_policy(ctx)
    ctx.preflight(
        [
            Requirement(config=("ledger",), facts=("sla-policy",), feeds=("deps_dev",)),
            Requirement(config=("model-registry",), secrets=("NVD_API_KEY",)),
        ]
    )
    ctx.preflight([])


def test_every_gap_is_listed_at_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = context(tmp_path, monkeypatch, traust_yaml=COMPLETE.replace("  workspace: ws\n", ""))
    with pytest.raises(PreflightError) as caught:
        ctx.preflight(
            [
                Requirement(tools=("not-a-real-tool",), config=("review",)),
                Requirement(facts=("sla-policy",), feeds=("osv",)),
                Requirement(secrets=("NVD_API_KEY",)),
            ]
        )
    lines = gaps(caught.value)
    assert lines == [
        "- not-a-real-tool: not found on PATH "
        "(install it at the external-tools.yaml pin, not-a-real-tool >= 9.9.9)",
        "- config: `review` is not set -- set it in traust.yaml (copy traust.example.yaml "
        "to start)",
        "- facts: sla-policy is not recorded -- record one (InsightService.record_sla_policy)",
        "- feeds: osv is not an enabled source -- enable it in the feeds registry "
        "(Context.register_feeds)",
        "- secrets: $NVD_API_KEY is not set",
        "- traust.yaml: locations.workspace unset",
    ]


def test_requirements_of_several_assets_are_checked_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = context(tmp_path, monkeypatch)
    with pytest.raises(PreflightError) as caught:
        ctx.preflight(
            [
                Requirement(tools=("not-a-real-tool",), config=("review",)),
                Requirement(tools=("not-a-real-tool",), config=("review", "campaign")),
            ]
        )
    assert gaps(caught.value) == [
        "- not-a-real-tool: not found on PATH "
        "(install it at the external-tools.yaml pin, not-a-real-tool >= 9.9.9)",
        "- config: `campaign` is not set -- set it in traust.yaml (copy traust.example.yaml "
        "to start)",
        "- config: `review` is not set -- set it in traust.yaml (copy traust.example.yaml "
        "to start)",
    ]


def test_a_config_requirement_names_the_unset_traust_yaml_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = context(tmp_path, monkeypatch)
    with pytest.raises(PreflightError, match="`review` is not set"):
        ctx.preflight([Requirement(config=("review",))])
    ctx.preflight([Requirement(config=("ledger",))])


def test_a_model_registry_requirement_names_the_register_door(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = context(tmp_path, monkeypatch, model_registry=False)
    with pytest.raises(PreflightError, match="model-registry is not registered"):
        ctx.preflight([Requirement(config=("model-registry",))])


def test_a_fact_requirement_names_the_record_door(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = context(tmp_path, monkeypatch)
    with pytest.raises(PreflightError, match="sla-policy is not recorded"):
        ctx.preflight([Requirement(facts=("sla-policy",))])
    record_sla_policy(ctx)
    ctx.preflight([Requirement(facts=("sla-policy",))])


def record_sla_policy(ctx: Context) -> None:
    publisher = ArtifactPublisher(
        PublishSpecs(PublishSpec(SlaPolicyArtifact)),
        ctx.object_store,
        SqlTraustUnitOfWork(ctx.database),
    )
    publisher.publish_artifact(
        SlaPolicyArtifact.from_document(yaml.safe_load(SLA_POLICY.read_text()))
    )


def test_a_feed_requirement_names_the_source_and_its_reachability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = context(tmp_path, monkeypatch)
    with pytest.raises(PreflightError, match="osv is not an enabled source"):
        ctx.preflight([Requirement(feeds=("osv",))])
    monkeypatch.setattr(
        ctx.feed_sources.get("deps_dev"),
        "check",
        lambda: Readiness(ready=False, detail="could not reach dd.test"),
    )
    with pytest.raises(PreflightError, match="deps_dev is not reachable -- could not reach"):
        ctx.preflight([Requirement(feeds=("deps_dev",))])


def test_a_secret_requirement_names_the_environment_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = context(tmp_path, monkeypatch)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    with pytest.raises(PreflightError, match=r"\$NVD_API_KEY is not set"):
        ctx.preflight([Requirement(secrets=("NVD_API_KEY",))])


def test_the_home_audit_is_part_of_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = context(tmp_path, monkeypatch, traust_yaml=None, model_registry=False)
    with pytest.raises(PreflightError, match=r"model-registry\.yaml"):
        ctx.preflight([])
    ctx = context(
        tmp_path,
        monkeypatch,
        traust_yaml=COMPLETE.replace("ledger:\n  public_key_path: /keys/ledger.pub\n", ""),
    )
    with pytest.raises(PreflightError, match=r"ledger\.public_key_path unset"):
        ctx.preflight([])


@pytest.mark.parametrize(
    "fields",
    [
        {"config": ("storage",)},
        {"facts": ("org-chart",)},
        {"tools": ("gitleaks", "gitleaks")},
        {"secrets": ("",)},
    ],
    ids=["unknown config key", "unknown fact", "duplicate tool", "empty secret"],
)
def test_an_unknown_or_empty_requirement_is_rejected(fields: dict[str, tuple[str, ...]]) -> None:
    with pytest.raises(pydantic.ValidationError):
        Requirement(**fields)
