from __future__ import annotations

from uuid import UUID

import pytest

from traust_core.v1.models.findings import Location
from traust_core.v1.services.findings.classification import CodeFindingPolicy


@pytest.mark.parametrize(
    ("locations", "expected"),
    [
        ((("src/app.GO", None),), True),
        ((("deploy/config.yaml", "yaml"),), False),
        ((("Dockerfile", "dockerfile"),), False),
        ((("settings.json", None),), False),
        ((("unknown", None),), False),
        ((("bin/tool", " Bash "),), True),
        ((("src/app", "go"),), True),
        ((("config.yaml", "yaml"), ("lib/server.rs", "rust")), True),
        ((), False),
    ],
)
def test_only_explicit_source_path_or_language_qualifies(
    locations: tuple[tuple[str, str | None], ...], expected: bool
) -> None:
    spans = tuple(
        Location(occurrence_id=UUID(int=1), path=path, language=language)
        for path, language in locations
    )
    assert CodeFindingPolicy().includes(spans) is expected


def test_source_vocabulary_is_tunable_without_changing_cwe_classification() -> None:
    source = Location(occurrence_id=UUID(int=1), path="component.wat")
    assert not CodeFindingPolicy().includes((source,))
    assert CodeFindingPolicy(extensions=frozenset({"wat"})).includes((source,))
