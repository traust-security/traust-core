from datetime import timedelta, timezone

import pytest

from tests.v1.conftest import SQL_BACKENDS, storage_db
from tests.v1.observation_support import observer
from traust_core.v1.repositories.portfolio import (
    InMemoryPortfolioUnitOfWork,
    SqlPortfolioUnitOfWork,
    metadata,
)
from traust_core.v1.repositories.sql import schema_drift


@pytest.fixture(params=["memory", *SQL_BACKENDS])
def uow(request, tmp_path):
    if request.param == "memory":
        yield InMemoryPortfolioUnitOfWork()
    else:
        with storage_db(request.param, tmp_path) as engine:
            assert schema_drift(engine, metadata) == []
            yield SqlPortfolioUnitOfWork(engine)


def facts(**changes):
    service, _, _, _, _ = observer()
    row = service.record_forge_facts(repo_key="test")
    return row.model_copy(update=changes)


def test_committed_facts_round_trip_and_unmeasured_stays_none(uow):
    row = facts(changed_lines=None, sensitive_changed=None, deps_only=False, ahead_by=0)
    with uow:
        uow.portfolio.save_forge_facts(row)
        uow.commit()
    with uow:
        assert uow.portfolio.forge_facts(row.identity) == row
        assert uow.portfolio.forge_facts_by_key(row.repo_key) == row
        assert uow.portfolio.forge_facts("missing") is None


def test_uncommitted_insert_and_update_roll_back(uow):
    row = facts()
    with uow:
        uow.portfolio.save_forge_facts(row)
    with uow:
        assert uow.portfolio.forge_facts(row.identity) is None
        uow.portfolio.save_forge_facts(row)
        uow.commit()
    with uow:
        uow.portfolio.save_forge_facts(row.model_copy(update={"changed_lines": 99}))
    with uow:
        assert uow.portfolio.forge_facts(row.identity) == row


def test_missing_urls_do_not_collapse_and_repair_retires_old_identity(uow):
    a = facts(identity="key:a", repo_key="a", repo=None)
    b = facts(identity="key:b", repo_key="b", repo=None)
    with uow:
        uow.portfolio.save_forge_facts(a)
        uow.portfolio.save_forge_facts(b)
        uow.commit()
    fixed = facts(repo_key="a")
    with uow:
        assert uow.portfolio.forge_facts_by_key("a") == a
        assert uow.portfolio.forge_facts_by_key("b") == b
        uow.portfolio.save_forge_facts(fixed)
        uow.commit()
    with uow:
        assert uow.portfolio.forge_facts("key:a") is None
        assert uow.portfolio.forge_facts_by_key("a") == fixed
        assert uow.portfolio.forge_facts_by_key("b") == b


def test_later_observation_replaces_filing_but_older_observation_does_not(uow):
    old = facts()
    new = facts(repo_key="new-filing", observed_at=old.observed_at + timedelta(hours=1))
    with uow:
        uow.portfolio.save_forge_facts(old)
        uow.portfolio.save_forge_facts(new)
        uow.portfolio.save_forge_facts(old)
        uow.commit()
    with uow:
        assert uow.portfolio.forge_facts(old.identity) == new
        assert uow.portfolio.forge_facts_by_key(old.repo_key) is None


def test_state_assembly_from_sql_requeries_findings(uow):
    service, _, _, findings, source = observer(uow=uow, live_crit_high=5)
    service.record_forge_facts(repo_key="test")
    assert service.repo_state(repo_key="test").risk_tier == "P0"
    calls = list(source.calls)
    findings.findings.rows.clear()
    assert service.repo_state(repo_key="test").risk_tier == "P2"
    assert source.calls == calls


def test_older_identity_repair_does_not_erase_newer_observation(uow):
    current = facts(identity="key:a", repo_key="a", repo=None)
    stale = facts(repo_key="a", observed_at=current.observed_at - timedelta(hours=1))
    with uow:
        uow.portfolio.save_forge_facts(current)
        uow.portfolio.save_forge_facts(stale)
        uow.commit()
    with uow:
        assert uow.portfolio.forge_facts_by_key("a") == current
        assert uow.portfolio.forge_facts(stale.identity) is None


def test_observation_order_compares_instants_not_timezone_strings(uow):
    old = facts()
    new_time = (old.observed_at + timedelta(hours=1)).astimezone(timezone(timedelta(hours=-5)))
    new = facts(observed_at=new_time, changed_lines=99)
    with uow:
        uow.portfolio.save_forge_facts(old)
        uow.portfolio.save_forge_facts(new)
        uow.commit()
    with uow:
        assert uow.portfolio.forge_facts(old.identity) == new
