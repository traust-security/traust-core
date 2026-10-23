import json

import pytest

from tests.v1.observation_support import NOW
from traust_core.v1.context.observation import command_source
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import ProcessResult, ProcessRunner


def test_batch_source_respects_the_supplied_host_allowlist_and_clock(monkeypatch):
    calls = []

    def run(self, argv, **kwargs):
        calls.append(tuple(argv))
        return ProcessResult(tuple(argv), 0, b"{}", b"", 0)

    monkeypatch.setattr(ProcessRunner, "run", run)
    source = command_source({"github.com": "github"}, clock=FixedClock(NOW))
    with pytest.raises(ValidationError):
        source.info(HttpsRepoUrl("example.com", "o/r"))
    assert calls == []
    assert source.info(HttpsRepoUrl("github.com", "o/r")).acquisition.acquired_at == NOW
    assert len(calls) == 1


def test_observation_door_reads_the_contract_tables(tmp_path, monkeypatch):
    from datetime import UTC, datetime

    from tests.v1.conftest import contract_db
    from tests.v1.repositories.tables.conftest import Seed
    from traust_core.v1.context.config import Config, DatabaseConfig
    from traust_core.v1.context.context import Context
    from traust_core.v1.models.assessment import AssessmentKind
    from traust_core.v1.providers.clock import FixedClock
    from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

    with contract_db("sqlite", tmp_path) as engine:
        pass  # schema applied to a fresh sqlite file; reuse the same path
    url = str(engine.url)
    engine.dispose()
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url="https://github.com/org/door")
        ref = seed.repository_ref(repository=repo, sha="c" * 40)
        seed.assessment(
            ref=ref,
            kind=AssessmentKind.SECURE_CODE,
            occurred_at=datetime(2026, 9, 1, tzinfo=UTC),
        )
        uow.commit()
    engine.dispose()

    config = Config(database=DatabaseConfig(url=url))
    context = Context(config, clock=FixedClock(NOW))
    answers = {
        "repos/org/door": {
            "pushed_at": "2026-08-01T00:00:00Z",
            "archived": False,
            "default_branch": "main",
            "visibility": "private",
            "fork": True,
            "parent": "org/upstream",
        },
        "repos/org/door/branches/main": {"sha": "d" * 40},
    }
    calls = []

    def run(self, argv, **kwargs):
        calls.append(argv[2])
        return ProcessResult(tuple(argv), 0, json.dumps(answers[argv[2]]).encode(), b"", 0)

    monkeypatch.setattr(ProcessRunner, "run", run)
    with context.repository_observation() as obs:
        facts = obs.service.record_forge_facts(repository_id=repo.id)
        assert facts.repository_id == repo.id
    with context.repository_observation() as obs:
        state = obs.query.repo_state(repository_id=repo.id)
        assert state.repository_id == repo.id
        assert state.exposure == "public-internal"
        assert obs.service.forge_facts(repo.id).head == "d" * 40
        obs.service.record_forge_facts(repository_id=repo.id)
    assert calls.count("repos/org/door/branches/main") == 1
