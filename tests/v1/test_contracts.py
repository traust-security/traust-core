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


def test_an_unknown_view_schema_is_a_config_error() -> None:
    with pytest.raises(ConfigError):
        contracts.validate_view("no-such-view", {})


def test_database_ddl_applies_every_namespace_on_sqlite(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path}/c.db")
    apply_contract_db(engine)
    names = set(sa.inspect(engine).get_table_names())
    assert {"repository", "ops_run_order", "ledger_events"} <= names


def _scan(**advisory: object) -> dict[str, object]:
    finding = {
        "id": "REPO-abcdef0-001",
        "file": "go.mod",
        "line": 3,
        "category": "supply-chain",
        "severity": "critical",
        "confidence": 0.9,
        "title": "Vulnerable golang.org/x/net",
        "description": "golang.org/x/net v0.20.0 is in the advisory's affected range.",
        "recommendation": "Upgrade golang.org/x/net past the fixed version.",
        **advisory,
    }
    return {
        "target": "example/repo",
        "scanned_at": "2026-01-01T00:00:00Z",
        "focus_areas": ["dependencies"],
        "metadata": {
            "repo": "repo",
            "repo_slug": "REPO",
            "scanned_ref": "abcdef0",
            "harness_version": "0.1.0",
            "baseline": None,
            "baseline_findings": 0,
        },
        "findings": [finding],
        "summary": {
            "total": 1,
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "known": 0,
            "low_confidence": 0,
        },
    }


def test_a_vuln_scan_finding_carries_an_advisorys_cvss_and_dependency() -> None:
    """traust-contracts#190: vuln-scan records an advisory's score and dependency evidence as
    data, in the report finding's shapes, and the gate still refuses a malformed block."""
    advisory = {
        "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
        "dependency": {
            "advisory": "CVE-2024-0001",
            "module": "golang.org/x/net",
            "ecosystem": "go",
            "installed_version": "v0.20.0",
            "classification": "likely_affected",
            "evidence_level": "manifest",
            "impact_artifact": "impact row: repo@abcdef0",
        },
    }
    assert contracts.schema_errors("vuln-findings", _scan(**advisory)) == []
    assert contracts.schema_errors("vuln-findings", _scan(dependency={"advisory": "x"})) != []
