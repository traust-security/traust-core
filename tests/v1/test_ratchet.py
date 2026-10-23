from pathlib import Path

import pytest

from traust_core.v1.checks import compare, scan, scan_source


def _kinds(source: str) -> set[str]:
    return {kind for _, kind in scan_source(source)}


def test_connect_is_flagged() -> None:
    assert "connect" in _kinds("import sqlite3\nsqlite3.connect('db')\n")
    assert "connect" in _kinds("from sqlite3 import connect\nconnect('db')\n")


def test_subprocess_import_is_flagged() -> None:
    assert "subprocess" in _kinds("import subprocess\n")
    assert "subprocess" in _kinds("from subprocess import run\nrun(['ls'])\n")


def test_env_access_is_flagged() -> None:
    assert "env" in _kinds("import os\nos.environ['X']\n")
    assert "env" in _kinds("import os\nos.getenv('X')\n")
    assert "env" in _kinds("import os\nos.environ.get('X')\n")


def test_json_write_is_flagged() -> None:
    assert "json-write" in _kinds("import json\njson.dump(d, f)\n")
    src = "import json\nfrom pathlib import Path\nPath('x').write_text(json.dumps(d))\n"
    assert "json-write" in _kinds(src)


def test_clock_is_flagged() -> None:
    assert "clock" in _kinds("from datetime import datetime\ndatetime.now()\n")
    assert "clock" in _kinds("import datetime\ndatetime.datetime.utcnow()\n")


def test_http_import_is_flagged() -> None:
    assert "http" in _kinds("import requests\n")
    assert "http" in _kinds("import httpx\n")
    assert "http" in _kinds("import urllib.request\n")


def test_docstring_mentioning_a_kind_does_not_count() -> None:
    assert _kinds('"""This module avoids sqlite3.connect and os.getenv."""\nx = 1\n') == set()


def test_repository_file_is_exempt_from_connect(tmp_path: Path) -> None:
    repo = tmp_path / "repositories" / "sql.py"
    repo.parent.mkdir(parents=True)
    repo.write_text("import sqlite3\nsqlite3.connect('db')\n")
    assert [h.kind for h in scan([tmp_path])] == []


def test_provider_file_is_exempt_from_http(tmp_path: Path) -> None:
    provider = tmp_path / "providers" / "feeds.py"
    provider.parent.mkdir(parents=True)
    provider.write_text("import httpx\n")
    service = tmp_path / "services" / "vex.py"
    service.parent.mkdir(parents=True)
    service.write_text("import httpx\n")
    assert [h.path for h in scan([tmp_path])] == [service.as_posix()]


def test_new_hit_fails_against_empty_baseline(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text("import subprocess\n")
    result = compare(scan([tmp_path]), baseline={})
    assert not result.ok
    assert [h.kind for h in result.new] == ["subprocess"]


def test_dropped_count_is_shrinkable(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text("x = 1\n")
    baseline = {(tmp_path / "m.py").as_posix(): {"subprocess": 2}}
    result = compare(scan([tmp_path]), baseline)
    assert not result.ok
    assert result.shrinkable[0][1:] == ("subprocess", 2, 0)


def test_matching_baseline_passes(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text("import subprocess\n")
    hits = scan([tmp_path])
    baseline = {(tmp_path / "m.py").as_posix(): {"subprocess": 1}}
    assert compare(hits, baseline).ok


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


def test_keyword_and_concatenated_json_writes_are_caught():
    from traust_core.v1.checks import scan_source

    hits = scan_source(
        "import json\n"
        "from pathlib import Path\n"
        'Path("/tmp/x").write_text(json.dumps({"a": 1}) + "\\n")\n'
        'Path("/tmp/x").write_text(data=json.dumps({"a": 1}))\n'
    )
    assert [kind for _, kind in hits] == ["json-write", "json-write"]


def test_os_environ_copy_is_caught():
    from traust_core.v1.checks import scan_source

    hits = scan_source("import os\n\nsettings = os.environ.copy()\n")
    assert [kind for _, kind in hits] == ["env"]


def test_a_pr_cannot_raise_its_own_baseline(tmp_path):
    import json

    from traust_core.v1.checks.ratchet import main

    root = tmp_path / "roots"
    root.mkdir()
    reference = tmp_path / "ref.json"
    baseline = tmp_path / "baseline.json"
    reference.write_text(json.dumps({"src/a.py": {"env": 1}}))
    baseline.write_text(json.dumps({"src/a.py": {"env": 2}}))

    assert main([str(root), "--baseline", str(baseline), "--reference", str(reference)]) == 1


def test_reference_check_passes_when_the_baseline_only_shrinks(tmp_path):
    import json

    from traust_core.v1.checks.ratchet import main

    root = tmp_path / "roots"
    root.mkdir()
    reference = tmp_path / "ref.json"
    baseline = tmp_path / "baseline.json"
    reference.write_text(json.dumps({"src/a.py": {"env": 1}}))
    baseline.write_text(json.dumps({"src/a.py": {"env": 0}}))

    assert main([str(root), "--baseline", str(baseline), "--reference", str(reference)]) == 0


def _consumer_kinds(source: str) -> list[str]:
    from traust_core.v1.checks.ratchet import CONSUMER_RULES

    return [kind for _, kind in scan_source(source, CONSUMER_RULES)]


def test_consumer_flags_contracts_and_database_imports():
    assert _consumer_kinds("from traust_contracts.v1 import ops\n") == ["contracts"]
    assert _consumer_kinds("import sqlite3\nimport sqlalchemy.orm\nfrom psycopg import sql\n") == [
        "database",
        "database",
        "database",
    ]


def test_consumer_allows_core_context_models_and_errors_only():
    allowed = (
        "from traust_core.v1.context import Context\n"
        "from traust_core.v1 import context\n"
        "from traust_core.v1.models.findings import Finding\n"
        "import traust_core.v1.errors\n"
    )
    assert _consumer_kinds(allowed) == []
    flagged = (
        "from traust_core.v1.services.insight import SarifExport\n"
        "from traust_core.v1.repositories import contract\n"
        "import traust_core\n"
    )
    assert _consumer_kinds(flagged) == ["core-internal"] * 3


def test_one_hit_per_import_statement():
    assert _consumer_kinds("from traust_contracts.v1 import ops, storage\n") == ["contracts"]


def test_consumer_allows_engine_adapters_only():
    assert _consumer_kinds("from traust_engine.adapters import osv\n") == []
    assert _consumer_kinds("from traust_engine.corpus import migrate\n") == ["engine-internal"]
    assert _consumer_kinds("from traust_engine import HarnessEngine\n") == ["engine-internal"]


def test_engine_modules_may_import_each_other(tmp_path):
    from traust_core.v1.checks.ratchet import CONSUMER_RULES

    own = tmp_path / "src" / "traust_engine" / "corpus" / "m.py"
    own.parent.mkdir(parents=True)
    own.write_text("from traust_engine.reporting import x\n")
    assert scan([tmp_path], CONSUMER_RULES) == []


def test_consumer_flags_state_file_names_but_not_docstrings():
    src = (
        '"""Reads findings.db."""\n'
        'DB = "graph/findings.db"\n'
        'path = f"{base}-findings-current.json"\n'
        'GRAPH = "portfolio-graph.db"\n'
    )
    assert _consumer_kinds(src) == ["state-file"] * 3


def test_core_rules_are_unchanged_without_the_flag():
    assert _kinds("import sqlite3\nfrom traust_contracts.v1 import ops\n") == set()
    assert _consumer_kinds("import subprocess\nimport os\nos.getenv('X')\n") == []


def test_cli_consumer_rules_fail_a_new_contracts_import(tmp_path, capsys):
    from traust_core.v1.checks.ratchet import main

    (tmp_path / "m.py").write_text("from traust_contracts.v1 import ops\n")
    baseline = tmp_path / "baseline.json"
    assert main([str(tmp_path), "--rules", "consumer", "--baseline", str(baseline)]) == 1
    assert "contracts → use core's domain services" in capsys.readouterr().out


def test_only_engine_tool_adapters_may_import_core_providers(tmp_path):
    from traust_core.v1.checks.ratchet import CONSUMER_RULES

    source = (
        "from traust_core.v1.providers.base import Acquisition, Readiness, Result\n"
        "from traust_core.v1.providers.process import ProcessRunner\n"
        "from traust_core.v1.services.assessment import AssessmentService\n"
    )
    files = {
        "traust-engine/src/traust_engine/adapters/cloud_config.py": [3],
        "traust-engine/src/traust_engine/ops/loop.py": [1, 2, 3],
        "traust/src/traust/cli/audit.py": [1, 2, 3],
    }
    for rel in files:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(source)
    hits = scan([tmp_path], CONSUMER_RULES)
    assert {rel: [h.line for h in hits if h.path.endswith(rel)] for rel in files} == files
    assert {h.kind for h in hits} == {"core-internal"}
