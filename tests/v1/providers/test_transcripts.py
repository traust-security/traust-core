"""Claude Code transcripts read as traust's `metrics collect-spend --append` and traust-engine's
`attribute_spend` read them: usage per request, the skill inferred from the session's signals."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.providers.test_model_catalog import REGISTRY
from tests.v1.repositories.tables.conftest import T0
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ServiceError
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.operations import SpendDimension, SpendFilter
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.transcripts import SessionTranscripts, detect_skill

PROJECTS = Path(__file__).parents[2] / "fixtures" / "operations" / "transcripts"
WORKSPACE = Path("/work/example-repo")
SKILLS = {"triage", "secure-code-audit", "validate-findings"}


@pytest.fixture
def transcripts() -> SessionTranscripts:
    return SessionTranscripts(PROJECTS)


def test_project_dirs_are_the_slugs_under_the_workspace(transcripts: SessionTranscripts) -> None:
    assert transcripts.project_dirs(WORKSPACE) == [PROJECTS / "-work-example-repo"]
    assert transcripts.project_dirs(Path("/work")) == [PROJECTS / "-work-example-repo"]
    assert transcripts.project_dirs(Path("/nowhere")) == []


def test_no_projects_dir_means_no_project_dirs(tmp_path: Path) -> None:
    assert SessionTranscripts(tmp_path / "absent").project_dirs(WORKSPACE) == []


def test_usages_follow_each_sessions_skill_signals_in_order(
    transcripts: SessionTranscripts,
) -> None:
    usages = list(transcripts.usages(transcripts.project_dirs(WORKSPACE), SKILLS))
    first, second = "1a2b3c4d-0000-4000-8000-000000000001", "1a2b3c4d-0000-4000-8000-000000000002"
    assert [
        (u.session, u.occurred_at.isoformat(), u.model, u.skill, u.tokens_in, u.tokens_out)
        for u in usages
    ] == [
        (first, "2026-10-05T08:00:00+00:00", "claude-opus-5-5", None, 100, 10),
        (first, "2026-10-05T08:02:00+00:00", "claude-opus-5-5", "triage", 200, 20),
        (first, "2026-10-05T08:05:00+00:00", "claude-opus-5-5", "secure-code-audit", 10, 5),
        (first, "2026-10-06T09:00:00+00:00", "claude-haiku-5-5", "secure-code-audit", 300, 30),
        (second, "2026-10-05T10:00:00+00:00", "claude-opus-5-5", None, 50, 5),
        (second, "2026-10-05T10:01:00+00:00", "claude-opus-5-5", "validate-findings", 10, 5),
        (second, "2026-10-05T10:02:00+00:00", "claude-opus-5-5", "validate-findings", 60, 6),
        (second, "2026-10-05T10:03:00+00:00", "claude-opus-5-5", "triage", 10, 5),
    ]
    assert (usages[1].cache_read, usages[1].cache_creation) == (1000, 50)
    assert {u.provider for u in usages} == {"anthropic"}


def test_with_no_known_skills_every_usage_is_unattributed(transcripts: SessionTranscripts) -> None:
    usages = transcripts.usages(transcripts.project_dirs(WORKSPACE), set())
    assert {u.skill for u in usages} == {None}


def test_source_names_the_workspace(transcripts: SessionTranscripts) -> None:
    source = transcripts.source(WORKSPACE, SKILLS)
    assert source.name == "sessions:/work/example-repo"
    assert len(source.usages) == 8


def test_an_unreadable_transcript_is_a_service_error(tmp_path: Path) -> None:
    (tmp_path / "-w" / "s.jsonl").mkdir(parents=True)
    with pytest.raises(ServiceError, match=r"cannot read transcript .*s\.jsonl"):
        list(SessionTranscripts(tmp_path).usages([tmp_path / "-w"], SKILLS))


@pytest.mark.parametrize(
    ("record", "skill"),
    [
        (
            {
                "message": {
                    "content": [{"type": "tool_use", "name": "Skill", "input": {"skill": "triage"}}]
                }
            },
            "triage",
        ),
        (
            {
                "message": {
                    "content": [
                        {"type": "tool_use", "name": "Skill", "input": {"skill": "p:triage "}}
                    ]
                }
            },
            "triage",
        ),
        (
            {
                "message": {
                    "content": [{"type": "tool_use", "name": "Skill", "input": {"skill": "other"}}]
                }
            },
            None,
        ),
        (
            {"message": {"content": "<command-name>secure-code-audit</command-name>"}},
            "secure-code-audit",
        ),
        ({"message": {"content": "read harnessing/triage/SKILL.md"}}, "triage"),
        ({"message": {"content": "read skills/4-triage/triage/SKILL.md"}}, "triage"),
        ({"message": {"content": "read docs/triage/SKILL.md"}}, None),
        (
            {"message": {"content": "<command-name>/triage</command-name> then skills/x/SKILL.md"}},
            "triage",
        ),
        ({"message": None}, None),
        ({}, None),
    ],
)
def test_detect_skill_takes_the_strongest_signal_naming_a_known_skill(
    record: dict, skill: str | None
) -> None:
    assert detect_skill(record, SKILLS) == skill


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def test_collected_transcripts_split_by_skill_losslessly(
    engine: Engine, tmp_path: Path, transcripts: SessionTranscripts
) -> None:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0 + timedelta(days=3)))
    ctx.__dict__["database"] = engine
    ctx.__dict__["session_transcripts"] = transcripts
    ctx.register_model_catalog(REGISTRY)
    spend = ctx.services().spend
    window = TimeWindow(start=T0, end=datetime(2026, 10, 8, tzinfo=UTC))
    source = ctx.session_transcripts.source(WORKSPACE, SKILLS)
    assert spend.collect(source, window) == 5
    assert spend.collect(source, window) == 0
    split = spend.attribute_by(SpendFilter(window=window), SpendDimension.SKILL)
    assert split.lossless
    assert {r.key for r in split.rows} == {"triage", "secure-code-audit", "validate-findings"}
    assert split.total.events == 5
    assert split.unattributed.cost_usd == Decimal("0.0009")  # 150 in at $4, 15 out at $20 per Mtok
