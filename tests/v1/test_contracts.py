import re
import tomllib
from pathlib import Path

import pytest
import sqlalchemy as sa

from tests.v1.conftest import apply_contract_db
from traust_core.v1 import contracts
from traust_core.v1.errors import ConfigError, DocumentError
from traust_core.v1.repositories import create_database_engine

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("name", ["traust-contracts", "traust-ledger"])
def test_contracts_dependency_is_pinned_to_a_commit(name: str) -> None:
    deps = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["dependencies"]
    pin = next(d for d in deps if d.startswith(f"{name} @ git+"))
    assert re.fullmatch(r"[0-9a-f]{40}", pin.rsplit("@", 1)[1])


def test_schema_gate_is_exact_and_reports_paths() -> None:
    with pytest.raises(DocumentError) as err:
        contracts.validate("triage", {"findings": [{"id": "x"}]})
    paths = {i.path for i in err.value.issues}
    assert "$" in paths or any(p.startswith("findings/0") for p in paths)


def test_config_gate_validates_a_pack_and_reports_paths() -> None:
    contracts.validate_config("pack", {"pack": "p", "assets": {"a": {"trigger": {"every": "1d"}}}})
    with pytest.raises(DocumentError) as err:
        contracts.validate_config("pack", {"pack": "p", "assets": {"a": {"trigger": {"x": 1}}}})
    assert any(i.path.startswith("assets/a/trigger") for i in err.value.issues)


def test_an_unknown_config_schema_is_a_config_error() -> None:
    with pytest.raises(ConfigError):
        contracts.validate_config("no-such-config", {})


def test_database_ddl_applies_every_namespace_on_sqlite(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path}/c.db")
    apply_contract_db(engine)
    names = set(sa.inspect(engine).get_table_names())
    assert {"repository", "ops_run_order", "ledger_events"} <= names
