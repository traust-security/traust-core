"""Recording the SLA policy through Context on SQLite and Postgres: a run's own policy wins, then
the newest recorded one, then the registered default."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
import yaml
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError, DocumentError
from traust_core.v1.models.artifacts import SlaPolicyArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.services.insight import InsightService

POLICY = Path(__file__).parents[2] / "fixtures" / "insight" / "sla-policy.yaml"


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0))
    ctx.__dict__["database"] = engine
    return ctx


def policy(name: str, **changes: Any) -> SlaPolicyArtifact:
    doc = {**yaml.safe_load(POLICY.read_text()), "policy_name": name, **changes}
    return SlaPolicyArtifact.from_document(doc)


def provenance() -> Provenance:
    return Provenance(run_id=uuid4(), source=SourceType.INTERACTIVE, occurred_at=T0)


def shown(context: Context) -> str:
    return context.services().insight.build(ViewName.SLA, ViewFilter()).policy_name  # type: ignore[attr-defined]


def test_the_default_holds_until_a_policy_is_recorded(context: Context) -> None:
    context.register_default_sla_policy(POLICY)
    assert shown(context) == "example-sla-policy"
    context.services().insight.record_sla_policy(policy("first"), provenance())
    assert shown(context) == "first"
    context.services().insight.record_sla_policy(policy("second"), provenance())
    assert shown(context) == "second"


def test_a_runs_own_policy_wins_over_the_recorded_one(context: Context) -> None:
    context.register_default_sla_policy(POLICY)
    context.services().insight.record_sla_policy(policy("recorded"), provenance())
    context.register_sla_policy(POLICY)
    assert shown(context) == "example-sla-policy"


def test_re_recording_the_same_policy_adds_nothing(context: Context) -> None:
    insight = context.services().insight
    first = insight.record_sla_policy(policy("same"), provenance())
    again = insight.record_sla_policy(policy("same"), provenance())
    assert first.artifact_id == again.artifact_id
    assert len(context.services().artifacts.history(SlaPolicyArtifact, 10)) == 1


def test_a_recorded_policy_alone_builds_the_view(context: Context) -> None:
    context.services().insight.record_sla_policy(policy("recorded"), provenance())
    assert shown(context) == "recorded"


def test_an_invalid_policy_cannot_be_recorded() -> None:
    with pytest.raises(DocumentError):
        policy("bad", clock_start="whenever")


@pytest.mark.parametrize("contents", [None, "policy_name: [", "policy_name: incomplete\n"])
def test_an_unusable_default_is_an_error_when_sla_is_requested(
    context: Context, tmp_path: Path, contents: str | None
) -> None:
    path = tmp_path / "default.yaml"
    if contents is not None:
        path.write_text(contents)
    context.register_default_sla_policy(path)
    with pytest.raises(ConfigError, match="SLA policy"):
        shown(context)


@pytest.mark.parametrize("contents", [None, "policy_name: [", "policy_name: incomplete\n"])
@pytest.mark.parametrize("recorded", [False, True])
def test_a_policy_override_does_not_require_a_usable_default(
    context: Context, tmp_path: Path, contents: str | None, recorded: bool
) -> None:
    path = tmp_path / "default.yaml"
    if contents is not None:
        path.write_text(contents)
    context.register_default_sla_policy(path)
    if recorded:
        context.services().insight.record_sla_policy(policy("recorded"), provenance())
    else:
        context.register_sla_policy(POLICY)
    assert shown(context) == ("recorded" if recorded else "example-sla-policy")


def test_registering_another_default_replaces_the_loaded_policy(
    context: Context, tmp_path: Path
) -> None:
    context.register_default_sla_policy(POLICY)
    assert shown(context) == "example-sla-policy"
    path = tmp_path / "replacement.yaml"
    path.write_bytes(policy("replacement").payload)
    context.register_default_sla_policy(path)
    assert shown(context) == "replacement"


def test_recording_without_an_artifact_store_is_a_config_error() -> None:
    with pytest.raises(ConfigError, match="no artifact store"):
        InsightService([], FixedClock(T0)).record_sla_policy(policy("x"), provenance())
