"""The worklist windows' process memo: a short-lived memory of a scope's folded views.

Every sorted window and every filtered count folds the requested repositories before it
answers, and the fold is Python — the GIL serializes it. Twenty readers arriving at once
for one scope therefore paid twenty sequential folds (the stampede: 20 same-scope windows
at 18.6s wall, p50 12.2s), and nothing was shared between them: `FindingService.shared()`
memoized a build's one fleet read, but only inside one request.

This memo is owned by the `Context` — one per process, outliving the per-request
services — and keyed by one repository, not by the requested scope. A reader asks for
the repositories it holds and folds only the ones nobody has folded, so the readers of
one scope cost one fold and the readers of overlapping scopes (the 20-user shape:
ninety-five of a hundred repositories in common) pay only for the repositories they add.

The burst is the hard case: twenty readers call `take` before any of them has deposited.
The fill lock closes it — one reader fills at a time, and every reader takes again once
it holds the lock, so the second reader finds the first's deposit instead of repeating
its fold. A reader waits only for a fill that holds a repository it wants: a fill of an
unrelated scope never queues it, so a burst with nothing to share (twenty disjoint
scopes) folds exactly as it did before the memo. The wait is bounded, too — a fill that
runs long never queues the process behind it.

The memory is bounded and the freshness is traded, never assumed:

- an entry serves for `ttl` seconds (shorter than the consumers' own window cache, so a
  record written through core never waits on this memo longer than a person's glance),
- at most `repositories` entries are held (a repository can hold its window views
  and its census views), least recently served evicted first,
- a fold that raises deposits nothing — the next reader folds it, never a half view,
- the entries are frozen models, so a served view cannot be mutated under another reader.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Collection, Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime
from uuid import UUID

from traust_core.v1.models.findings import FindingView

# How long a folded repository serves a second reader: the worklist's own freshness, half
# the minute the consumers cache, so a decision recorded through core is visible on the
# refresh after a person's glance rather than after a build cadence.
WINDOW_TTL_SECONDS = 15.0
# The repository entries one process remembers: the 20-user lane touches ~2,000 of the
# estate's 3,687, and a 100-repository scope's views cost a few megabytes, so the cap is
# the working set of a busy lane rather than the estate. A repository can hold two entries
# (the window's full views and the count's census views), so the cap is entries, not
# repositories. Eviction is least-recently-served.
WINDOW_REPOSITORIES = 4_096
# How long a reader waits for a fill that holds a repository it wants before folding on
# its own: long enough for a scope's whole fold (a 100-repository scope folds in one to
# two seconds) so the burst shares it, bounded so a pathological fold never queues the
# process behind it. A reader whose scope cannot share a fill never waits at all.
WINDOW_FILL_WAIT_SECONDS = 10.0


class WindowMemo:
    """Folded views by (repository, as_of), with a short TTL and one fill at a time."""

    def __init__(
        self,
        *,
        ttl: float = WINDOW_TTL_SECONDS,
        repositories: int = WINDOW_REPOSITORIES,
        fill_wait: float = WINDOW_FILL_WAIT_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl
        self._repositories = max(1, repositories)
        self._fill_wait = fill_wait
        self._clock = clock
        self._lock = threading.Lock()
        self._fill = threading.Lock()
        self._in_flight: dict[UUID, int] = {}
        self._entries: OrderedDict[
            tuple[UUID, datetime | None, bool], tuple[float, tuple[FindingView, ...]]
        ] = OrderedDict()
        # Diagnostics: the folds this process ran and the repositories it served from the
        # memo — what a stampede's logs count (one fold and N-1 hits is the fix).
        self.folds = 0
        self.folded_repositories = 0
        self.served = 0

    def take(
        self, repository_ids: Sequence[UUID], as_of: datetime | None, *, census: bool = False
    ) -> tuple[dict[UUID, tuple[FindingView, ...]], list[UUID]]:
        """The repositories the memo holds fresh, and the ones it holds none of (or holds
        stale) — the caller folds only the latter. `census` names the flavour: the views a
        tally counts carry no locations or cwes and cost about half, so a count never pays
        for the window's weight (and the two never serve each other's rows)."""
        now = self._clock()
        held: dict[UUID, tuple[FindingView, ...]] = {}
        missing: list[UUID] = []
        with self._lock:
            for repository_id in repository_ids:
                key = (repository_id, as_of, census)
                entry = self._entries.get(key)
                if entry is None or now - entry[0] >= self._ttl:
                    missing.append(repository_id)
                    continue
                self._entries.move_to_end(key)
                held[repository_id] = entry[1]
            self.served += len(held)
        return held, missing

    def deposit(
        self,
        repository_id: UUID,
        as_of: datetime | None,
        views: tuple[FindingView, ...],
        *,
        census: bool = False,
    ) -> None:
        """Remember one repository's complete folded views, replacing any older entry."""
        with self._lock:
            key = (repository_id, as_of, census)
            self._entries[key] = (self._clock(), views)
            self._entries.move_to_end(key)
            while len(self._entries) > self._repositories:
                self._entries.popitem(last=False)

    def record_fold(self, repositories: int) -> None:
        """Count one fold of `repositories` repositories, for the logs the scoreboard reads."""
        with self._lock:
            self.folds += 1
            self.folded_repositories += repositories

    @contextmanager
    def fill(self, repository_ids: Sequence[UUID]) -> Iterator[bool]:
        """One reader fills at a time: yields whether this reader holds the fill lock.

        A reader waits only for a fill that can save it work — one already folding a
        repository the reader wants; a fill of an unrelated scope is not worth a queue,
        so that reader takes the lock if it is free and otherwise folds without it. The
        wait is bounded: a fill that runs long never queues the process behind it, and a
        reader that gives up takes whatever is deposited and folds the rest itself."""
        held, wait = self._claim(repository_ids)
        if not held and wait:
            held = self._fill.acquire(timeout=self._fill_wait)
            if held:
                with self._lock:
                    self._register(repository_ids)
        try:
            yield held
        finally:
            if held:
                with self._lock:
                    self._forget(repository_ids)
                self._fill.release()

    def _claim(self, repository_ids: Sequence[UUID]) -> tuple[bool, bool]:
        """Take the fill lock if it is free, else say whether an in-flight fill holds a
        repository this reader wants — the one case waiting can save it work. The claim
        and the registration share one critical section, so a reader of a burst never
        misses the fill that has just started (it waits) and never queues behind a fill
        that cannot help it (it folds its own)."""
        with self._lock:
            if self._fill.acquire(blocking=False):
                self._register(repository_ids)
                return True, False
            return False, any(r in self._in_flight for r in repository_ids)

    def _register(self, repository_ids: Sequence[UUID]) -> None:
        for repository_id in repository_ids:
            self._in_flight[repository_id] = self._in_flight.get(repository_id, 0) + 1

    def _forget(self, repository_ids: Sequence[UUID]) -> None:
        for repository_id in repository_ids:
            remaining = self._in_flight.get(repository_id, 0) - 1
            if remaining > 0:
                self._in_flight[repository_id] = remaining
            else:
                self._in_flight.pop(repository_id, None)

    def clear(self) -> None:
        """Forget every folded repository (a test seam, and the door a writer would use)."""
        with self._lock:
            self._entries.clear()
            self.served = 0

    def held(self) -> int:
        """How many repositories the memo holds (the bound, observable)."""
        with self._lock:
            return len(self._entries)


def memo_keys(repository_ids: Collection[UUID]) -> Sequence[UUID]:
    """A scope's repositories in first-seen order, each once — the keys the memo is asked
    for, however a consumer spelled (or repeated) the scope."""
    return tuple(dict.fromkeys(repository_ids))
