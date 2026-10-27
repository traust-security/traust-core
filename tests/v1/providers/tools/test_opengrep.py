from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.providers.tools import opengrep
from traust_core.v1.providers.tools.opengrep import SupplementalPack

SHA = "b" * 40


def test_fork_supplement_pin_constants() -> None:
    assert "opengrep-rules" in opengrep.FORK_RULES_REPO
    assert len(opengrep.FORK_RULES_SHA) == 40


@pytest.mark.parametrize(
    ("source", "want"),
    [
        (f"https://github.com/o/r@{SHA}", ("https://github.com/o/r", SHA)),
        (opengrep.FORK_RULES_REPO, (opengrep.FORK_RULES_REPO, opengrep.FORK_RULES_SHA)),
        (opengrep.FORK_RULES_REPO + "/", (opengrep.FORK_RULES_REPO + "/", opengrep.FORK_RULES_SHA)),
    ],
)
def test_a_pinned_rules_source_is_its_https_url_and_commit(
    source: str, want: tuple[str, str]
) -> None:
    assert opengrep.pinned_rules_source(source) == want


@pytest.mark.parametrize(
    ("source", "match"),
    [
        ("https://github.com/o/r@main", "ref must be a 40-hex commit"),
        ("https://github.com/o/r", "ref must be a 40-hex commit"),
        (f"https://github.com/o/r@{SHA[:12]}", "ref must be a 40-hex commit"),
        (f"http://github.com/o/r@{SHA}", "https:// URLs only"),
        (f"git@github.com:o/r@{SHA}", "https:// URLs only"),
    ],
)
def test_an_unpinned_or_non_https_rules_source_is_refused(source: str, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        opengrep.pinned_rules_source(source)


def test_a_pinned_source_is_cached_by_repository_name_and_short_commit() -> None:
    dest = opengrep.rules_cache_dir("https://github.com/o/argus-observe-rules", SHA)
    assert dest == opengrep.CACHE_ROOT / f"argus-observe-rules-{SHA[:12]}"


def test_only_argus_nests_its_rules(tmp_path: Path) -> None:
    argus = "https://github.com/o/argus-observe-rules/"
    assert opengrep.rules_root("https://github.com/o/r", tmp_path) == tmp_path
    assert opengrep.rules_root(argus, tmp_path) == tmp_path / "rules"
    (tmp_path / "rules" / "languages").mkdir(parents=True)
    assert opengrep.rules_root(argus, tmp_path) == tmp_path / "rules" / "languages"


def _packs(**overrides: Any) -> dict[str, Any]:
    pack = {"enabled": True, "source": f"https://x/y@{SHA}", "rules": ["r1", "r2"]}
    return {"p": {**pack, **overrides}}


def test_reads_enabled_packs() -> None:
    assert opengrep.supplemental_packs(_packs()) == [
        SupplementalPack("p", f"https://x/y@{SHA}", ("r1", "r2"))
    ]


@pytest.mark.parametrize(
    "packs",
    [_packs(enabled=False), _packs(rules=[]), _packs(source=None), {"p": "not a mapping"}, {}],
)
def test_a_disabled_ruleless_or_sourceless_pack_is_off(packs: dict[str, Any]) -> None:
    assert opengrep.supplemental_packs(packs) == []
