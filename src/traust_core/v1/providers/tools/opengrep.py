"""Where opengrep keeps pinned git rule packs: the source form `URL[@SHA]` and its clone cache."""

from __future__ import annotations

import re
from pathlib import Path

CACHE_ROOT = Path.home() / ".cache" / "traust-engine"
FORK_RULES_REPO = "https://github.com/opengrep/opengrep-rules"
FORK_RULES_SHA = "f1d2b562b414783763fd02a6ed2736eaed622efa"  # 2026-07 pin


def pinned_rules_source(src: str) -> tuple[str, str]:
    """A git rules source `URL[@SHA]` as (https URL, 40-hex SHA); ValueError otherwise."""
    # Split only on a trailing ref, not the git@ host.
    m = re.match(
        r"^(?P<url>.+?)@(?P<ref>[A-Za-z0-9._/-]+)$",
        src.replace("://", "\x00", 1).replace("git@", "\x01", 1),
    )
    if m and "/" not in m.group("ref"):
        url = m.group("url").replace("\x00", "://", 1).replace("\x01", "git@", 1)
        ref = m.group("ref")
    else:
        url, ref = (src, (FORK_RULES_SHA if src.rstrip("/") == FORK_RULES_REPO else "HEAD"))
    # A movable branch, tag or HEAD would change what the scan reports under the same source.
    if not re.fullmatch(r"[0-9a-f]{40}", ref):
        raise ValueError(
            f"rules source {src!r}: ref must be a 40-hex commit "
            "SHA (movable refs change scan results silently)"
        )
    if not url.startswith("https://"):
        raise ValueError(f"rules source {src!r}: https:// URLs only")
    return url, ref


def rules_cache_dir(url: str, ref: str) -> Path:
    """Where a pinned git rules source is cloned."""
    return CACHE_ROOT / f"{Path(url).name}-{ref[:12]}"


def rules_root(url: str, dest: Path) -> Path:
    """The rules subtree of a cloned pack: argus nests its rules (beside a tests/ tree of
    deliberately vulnerable fixtures) under rules/languages/."""
    if not url.rstrip("/").endswith("argus-observe-rules"):
        return dest
    nested = dest / "rules" / "languages"
    return nested if nested.is_dir() else dest / "rules"
