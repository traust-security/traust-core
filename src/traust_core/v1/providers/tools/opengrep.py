"""Where opengrep keeps pinned git rule packs (the source form `URL[@SHA]` and its clone cache),
and the supplemental packs the rule-pack allowlist enables."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from traust_core.v1.errors import ValidationError

CACHE_ROOT = Path.home() / ".cache" / "traust-engine"
FORK_RULES_REPO = "https://github.com/opengrep/opengrep-rules"
FORK_RULES_SHA = "f1d2b562b414783763fd02a6ed2736eaed622efa"  # 2026-07 pin


@dataclass(frozen=True, slots=True)
class SupplementalPack:
    """An external pack the allowlist enables, and the only rule ids of it that may report."""

    name: str
    source: str
    rules: tuple[str, ...]


def pinned_rules_source(src: str) -> tuple[str, str]:
    """A git rules source `URL[@SHA]` as (https URL, 40-hex SHA)."""
    # split only on a trailing ref, never on the git@ host
    m = re.match(
        r"^(?P<url>.+?)@(?P<ref>[A-Za-z0-9._/-]+)$",
        src.replace("://", "\x00", 1).replace("git@", "\x01", 1),
    )
    if m and "/" not in m.group("ref"):
        url = m.group("url").replace("\x00", "://", 1).replace("\x01", "git@", 1)
        ref = m.group("ref")
    else:
        url, ref = (src, (FORK_RULES_SHA if src.rstrip("/") == FORK_RULES_REPO else "HEAD"))
    # a movable ref would change what the scan reports while the report still names the source
    if not re.fullmatch(r"[0-9a-f]{40}", ref):
        raise ValidationError(
            f"rules source {src!r}: ref must be a 40-hex commit "
            "SHA (movable refs change scan results silently)"
        )
    if not url.startswith("https://"):
        raise ValidationError(f"rules source {src!r}: https:// URLs only")
    return url, ref


def rules_cache_dir(url: str, ref: str) -> Path:
    """Where a pinned git rules source is cloned."""
    return CACHE_ROOT / f"{Path(url).name}-{ref[:12]}"


def rules_root(url: str, dest: Path) -> Path:
    """The rules subtree of a cloned pack: argus nests its rules under rules/languages/."""
    if not url.rstrip("/").endswith("argus-observe-rules"):
        return dest
    nested = dest / "rules" / "languages"
    return nested if nested.is_dir() else dest / "rules"


def supplemental_packs(packs: Mapping[str, Any]) -> list[SupplementalPack]:
    """The allowlist's enabled packs that name a source and at least one rule: an enabled pack
    with no rules would mean every rule, the wholesale enablement this forbids."""
    out = []
    for name, cfg in packs.items():
        if not isinstance(cfg, dict) or not cfg.get("enabled"):
            continue
        rules = tuple(str(r) for r in (cfg.get("rules") or []) if r)
        if rules and (src := cfg.get("source")):
            out.append(SupplementalPack(name, str(src), rules))
    return out
