"""The holder count of a shared, read-only worktree: written atomically, and never read as
zero when it can't be read, so a torn or missing count keeps the tree rather than removing it
from under a holder."""

from __future__ import annotations

import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)


def read_holders(refs_file: Path) -> int | None:
    """The tree's recorded holder count; None when the count is missing or unreadable."""
    try:
        holders = int(refs_file.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    return holders if holders >= 0 else None


def write_holders(refs_file: Path, holders: int) -> None:
    """Replace the count in one rename: a crash leaves the old count or the new, never half."""
    staged = refs_file.with_name(f"{refs_file.name}.tmp")
    with staged.open("w", encoding="utf-8") as out:
        out.write(f"{holders}\n")
        out.flush()
        os.fsync(out.fileno())
    staged.replace(refs_file)


def acquire(refs_file: Path) -> None:
    """One more holder of an existing tree; an unknown count counts as one live holder."""
    holders = read_holders(refs_file)
    if holders is None:
        log.warning("shared tree count %s is unreadable; counting one unknown holder", refs_file)
        holders = 1
    write_holders(refs_file, holders + 1)


def release(refs_file: Path) -> bool:
    """One holder fewer; True when none remain and the tree may go. An unknown count keeps it."""
    holders = read_holders(refs_file)
    if holders is None:
        log.warning("shared tree count %s is unreadable; keeping the tree", refs_file)
        return False
    remaining = holders - 1
    if remaining > 0:
        write_holders(refs_file, remaining)
        return False
    refs_file.unlink(missing_ok=True)
    return True
