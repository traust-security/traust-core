"""Sanitizer discovery: static, executes nothing. Ported from traust
tests/test_probe_sanitizers.py (discovery); probing stays with the probe tool."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.code_facts import SanitizerFact
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.sanitizers import SanitizerDiscovery
from traust_core.v1.providers.tools import ToolRequest

AT = datetime(2026, 10, 25, tzinfo=UTC)


def discover(root) -> list[SanitizerFact]:
    result = SanitizerDiscovery(FixedClock(AT)).enumerate(ToolRequest(workspace=root))
    assert result.acquisition.provider == "sanitizer-discovery"
    assert result.acquisition.acquired_at == AT
    assert all(isinstance(f, SanitizerFact) for f in result.data)
    return result.data  # type: ignore[return-value]


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "util.py").write_text(
        "def sanitize_jinja(value):\n"
        "    return value.replace('{{', '').replace('{%', '')\n"
        "\n"
        "def sanitize_label(value):\n"
        "    return ''.join(c for c in value if c.isalnum())\n"
        "\n"
        "def validate_name(value):\n"
        "    raise RuntimeError('needs app context')\n"
        "\n"
        "def unrelated_helper(a, b):\n"
        "    return a + b\n"
    )
    return tmp_path


def test_discovery_finds_sanitizer_shapes(repo):
    names = {c.function for c in discover(repo)}
    assert names == {"sanitize_jinja", "sanitize_label", "validate_name"}


def test_discovery_skips_multi_arg_and_tests(repo, tmp_path):
    (tmp_path / "util_test.py").write_text("def sanitize_ignored(v):\n    return v\n")
    (tmp_path / "conftest.py").write_text("def sanitize_fixture(v):\n    return v\n")
    names = {c.function for c in discover(repo)}
    assert names.isdisjoint({"unrelated_helper", "sanitize_ignored", "sanitize_fixture"})


def test_discovery_records_location(repo):
    [cand] = [c for c in discover(repo) if c.function == "sanitize_jinja"]
    assert (cand.path, cand.line, cand.arg, cand.is_method) == ("util.py", 1, "value", False)


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("class A:\n    def escape(self, v):\n        return v\n", [("escape", "v", True)]),
        ("class A:\n    def clean(cls, v, f=0):\n        return v\n", [("clean", "v", True)]),
        ("def quote(v, w):\n    return v\n", []),
        ("def strip_all(v, w=1, x=2):\n    return v\n", [("strip_all", "v", False)]),
        ("def mask():\n    return 1\n", []),
        ("async def _redact(v):\n    return v\n", [("_redact", "v", False)]),
        ("def formatter(v):\n    return v\n", []),
    ],
)
def test_one_required_value_argument_is_the_probe_convention(tmp_path, source, expected):
    (tmp_path / "m.py").write_text(source)
    assert [(c.function, c.arg, c.is_method) for c in discover(tmp_path)] == expected


def test_skipped_dirs_and_unparseable_files_are_ignored(tmp_path):
    for d in ("site-packages", "vendor", ".venv"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "m.py").write_text("def sanitize(v):\n    return v\n")
    (tmp_path / "broken.py").write_text("def sanitize(:\n")
    assert discover(tmp_path) == []


def test_missing_workspace_is_refused(tmp_path):
    with pytest.raises(ValidationError, match="not a directory"):
        discover(tmp_path / "absent")
