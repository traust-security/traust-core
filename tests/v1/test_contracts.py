import tomllib
from pathlib import Path

import pytest
import sqlalchemy as sa

from tests.v1.conftest import apply_contract_ddl
from traust_core.v1 import contracts
from traust_core.v1.errors import DocumentError
from traust_core.v1.repositories import create_database_engine, schema_drift

ROOT = Path(__file__).resolve().parents[2]


def test_contracts_dependency_is_pinned_to_a_commit() -> None:
    source = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["uv"]["sources"]
    assert len(source["traust-contracts"]["rev"]) == 40


def test_schema_gate_is_exact_and_reports_paths() -> None:
    with pytest.raises(DocumentError) as err:
        contracts.validate("triage", {"findings": [{"id": "x"}]})
    paths = {i.path for i in err.value.issues}
    assert "$" in paths or any(p.startswith("findings/0") for p in paths)


@pytest.mark.parametrize("area", ["storage", "ledger"])
def test_contract_ddl_applies_on_sqlite(area: str, tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path}/c.db")
    apply_contract_ddl(engine, area)
    assert sa.inspect(engine).get_table_names()


def test_schema_drift_flags_disagreements(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path}/c.db")
    apply_contract_ddl(engine, "ledger")
    wrong = sa.MetaData()
    sa.Table("layers", wrong, sa.Column("not_in_ddl", sa.Text))
    problems = schema_drift(engine, wrong)
    assert any("not_in_ddl: missing in database" in p for p in problems)
    assert any("not declared in Table" in p for p in problems)
