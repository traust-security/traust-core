"""CodeSpan.parse, ported from traust tests/test_check_location_paths.py (the location gate)."""

from __future__ import annotations

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.common import CodeSpan


@pytest.mark.parametrize(
    ("raw", "path", "line"),
    [
        ("src/app.go", "src/app.go", None),
        ("src/app.go:42", "src/app.go", 42),
        ("src/app.go:42-60", "src/app.go", 42),
        ("./SECURITY.md", "SECURITY.md", None),
        ("repo:maintenance", "repo:maintenance", None),
        ("  deploy/k8s.yaml:7  ", "deploy/k8s.yaml", 7),
        ("C:weird:name", "C:weird:name", None),
    ],
)
def test_parse_keeps_the_path_and_the_first_line(raw: str, path: str, line: int | None) -> None:
    span = CodeSpan.parse(raw)
    assert (span.path, span.line) == (path, line)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (".", "repo root"),
        ("/", "repo root"),
        ("./", "repo root"),
        ("/.", "repo root"),
        ("/./", "repo root"),
        ("./:12", "repo root"),
        ("", "repo root"),
        ("src/a.go\nmore prose", "newline"),
        ("x" * 201, "over 200"),
    ],
)
def test_parse_refuses_what_is_not_an_artifact(raw: str, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        CodeSpan.parse(raw)
