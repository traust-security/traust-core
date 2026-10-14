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
