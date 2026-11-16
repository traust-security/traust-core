"""The unreachable disposition (foundry plan repo-unreachable): the gone-class counting
rules, the planner's exclusion, and the doors — the URL correction's identity continuity
and the verify that clears.

The counting rules under test, from the plan's resolved decisions:
- only the gone-class counts (the forge 404/410 word, the empty answer, the transport's
  positive unreachable word); the transient classes never count
- two consecutive gone-class failures flip the disposition
- the count resets after a success
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from tests.v1.observation_support import NOW, observer
from traust_core.v1.errors import ConflictError
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.inventory import (
    GoneReason,
    Repository,
    RepositoryDisposition,
    RepositoryFilter,
)
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.services.portfolio import GONE_STREAK_THRESHOLD

HOSTS = {"github.com": "github", "gitlab.com": "gitlab"}


def _gone(
    kind: str = "error",
    *,
    liveness: str = "missing",
    error: str = "404",
    canonical_url: str | None = None,
) -> dict:
    gone = {"ok": False, "kind": kind, "liveness": liveness, "error": error}
    if canonical_url:
        gone["canonical_url"] = canonical_url
    return gone


def _unreachable(error: str = "name or service not known") -> dict:
    return {"ok": False, "kind": "unreachable", "endpoint_unreachable": True, "error": error}


def _transient(kind: str = "unreachable", error: str = "timed out") -> dict:
    """A failure that says nothing about the repository: no liveness word, no transport
    word — the classes the plan's transient lane owns."""
    return {"ok": False, "kind": kind, "error": error}


def _healthy() -> dict:
    """The forge's healthy answer: the repository is there, on its default branch."""
    return {
        "ok": True,
        "pushed_at": "2026-10-01T12:00:00Z",
        "archived": False,
        "default_branch": "main",
        "visibility": "public",
        "fork": False,
        "parent": None,
    }


def _empty() -> dict:
    """The forge answers 200, the repository has no commits: no default branch."""
    return {
        "ok": True,
        "pushed_at": None,
        "archived": False,
        "default_branch": None,
        "visibility": "public",
        "fork": False,
        "parent": None,
    }


def _repository(service, repository_id):
    with service._uow as uow:
        return uow.repositories.get(repository_id)


def _observe(service, repository_id, *, minutes: int = 1):
    """One observation with the clock moved on: the liveness snapshot is append-only, so
    consecutive observations of the same repository need distinct times."""
    service._clock = FixedClock(NOW + timedelta(minutes=minutes))
    return service.record_forge_facts(repository_id=repository_id)


def _set_source(service, sources, info):
    sources.info_data = info


class _SwappingSource:
    """The source whose answers change between observations: the streak counts across
    calls, so the double swaps what the forge says per call."""

    def __init__(self, sources):
        self._sources = sources

    def say(self, info) -> None:
        self._sources.info_data = info


# The counting rules ----------------------------------------------------------------------


def test_one_gone_failure_does_not_flip_the_disposition():
    harness, service, _, _, sources = observer()
    _set_source(service, sources, _gone())
    _observe(service, harness.repository_id)
    repository = _repository(service, harness.repository_id)
    assert repository.disposition is None
    assert repository.gone_streak == 1


def test_two_consecutive_gone_failures_flip_the_disposition():
    harness, service, _, _, sources = observer()
    _set_source(service, sources, _gone())
    _observe(service, harness.repository_id, minutes=1)
    _observe(service, harness.repository_id, minutes=2)
    repository = _repository(service, harness.repository_id)
    assert repository.disposition == RepositoryDisposition.REPO_UNREACHABLE
    assert repository.disposition_reason == GoneReason.GONE
    assert repository.disposition_evidence == "404"
    assert repository.disposition_at is not None


def test_transient_failures_never_count():
    harness, service, _, _, sources = observer()
    _set_source(service, sources, _transient())
    for i in range(GONE_STREAK_THRESHOLD + 3):
        _observe(service, harness.repository_id, minutes=i + 1)
    repository = _repository(service, harness.repository_id)
    assert repository.disposition is None
    assert repository.gone_streak == 0


def test_a_transient_failure_between_gone_failures_does_not_reset_the_count():
    """Only a success resets: a timeout between two gone-class failures leaves them
    consecutive in their class (the plan's resolved decision: the count resets after a
    success, and the transient classes get nothing)."""
    harness, service, _, _, sources = observer()
    swap = _SwappingSource(sources)
    swap.say(_gone())
    _observe(service, harness.repository_id, minutes=1)
    swap.say(_transient())
    _observe(service, harness.repository_id, minutes=2)
    assert _repository(service, harness.repository_id).gone_streak == 1
    swap.say(_gone())
    service.record_forge_facts(repository_id=harness.repository_id)
    repository = _repository(service, harness.repository_id)
    assert repository.disposition == RepositoryDisposition.REPO_UNREACHABLE


def test_a_success_resets_the_count():
    harness, service, _, _, sources = observer()
    swap = _SwappingSource(sources)
    swap.say(_gone())
    _observe(service, harness.repository_id, minutes=1)
    swap.say(_healthy())
    _observe(service, harness.repository_id, minutes=2)
    repository = _repository(service, harness.repository_id)
    assert repository.disposition is None
    assert repository.gone_streak == 0


def test_a_success_clears_a_flipped_disposition():
    """The verify's rule, landed from the other side: the only observations a
    dispositioned repository can receive are deliberate (it is planned nothing), and a
    successful one clears the disposition."""
    harness, service, _, _, sources = observer()
    swap = _SwappingSource(sources)
    swap.say(_gone())
    _observe(service, harness.repository_id, minutes=1)
    _observe(service, harness.repository_id, minutes=2)
    assert _repository(service, harness.repository_id).disposition is not None
    swap.say(
        {
            "ok": True,
            "pushed_at": "2026-10-01T12:00:00Z",
            "archived": False,
            "default_branch": "main",
            "visibility": "public",
            "fork": False,
            "parent": None,
        }
    )
    _observe(service, harness.repository_id, minutes=3)
    repository = _repository(service, harness.repository_id)
    assert repository.disposition is None
    assert repository.disposition_reason is None
    assert repository.disposition_evidence is None
    assert repository.disposition_at is None
    assert repository.gone_streak == 0


# The reason taxonomy ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("info", "reason"),
    [
        (_gone(liveness="missing"), GoneReason.GONE),
        (_gone(liveness="moved", canonical_url="https://github.com/else/where"), GoneReason.GONE),
        (_gone(liveness="disabled"), GoneReason.GONE),
        (_empty(), GoneReason.EMPTY),
        (_unreachable(), GoneReason.UNREACHABLE),
    ],
    ids=["missing", "moved", "disabled", "empty", "nxdomain"],
)
def test_the_flip_carries_the_gone_class_reason(info, reason):
    harness, service, _, _, sources = observer()
    _set_source(service, sources, info)
    _observe(service, harness.repository_id, minutes=1)
    _observe(service, harness.repository_id, minutes=2)
    repository = _repository(service, harness.repository_id)
    assert repository.disposition == RepositoryDisposition.REPO_UNREACHABLE
    assert repository.disposition_reason == reason


def test_a_flipped_repository_holds_with_the_new_evidence_on_a_later_gone_class():
    harness, service, _, _, sources = observer()
    swap = _SwappingSource(sources)
    swap.say(_gone(error="first 404"))
    _observe(service, harness.repository_id, minutes=1)
    _observe(service, harness.repository_id, minutes=2)
    swap.say(_unreachable(error="NXDOMAIN: no such host"))
    _observe(service, harness.repository_id, minutes=3)
    repository = _repository(service, harness.repository_id)
    assert repository.disposition == RepositoryDisposition.REPO_UNREACHABLE
    assert repository.disposition_reason == GoneReason.UNREACHABLE
    assert repository.disposition_evidence == "NXDOMAIN: no such host"


# The planner's exclusion -----------------------------------------------------------------


def test_the_planners_universe_skips_dispositioned_repositories():
    harness, service, _, _, sources = observer()
    _set_source(service, sources, _gone())
    _observe(service, harness.repository_id, minutes=1)
    _observe(service, harness.repository_id, minutes=2)
    universe = service.list_repositories(
        RepositoryFilter(dispositioned=False), PageRequest(limit=100)
    )
    worklist = service.list_repositories(
        RepositoryFilter(dispositioned=True), PageRequest(limit=100)
    )
    everyone = service.list_repositories(RepositoryFilter(), PageRequest(limit=100))
    assert harness.repository_id not in {r.id for r in universe.items}
    assert {r.id for r in worklist.items} == {harness.repository_id}
    assert {r.id for r in everyone.items} >= {harness.repository_id}


# The URL-correction door -----------------------------------------------------------------


def _url(raw: str) -> HttpsRepoUrl:
    return HttpsRepoUrl.parse(raw, HOSTS)


def test_the_url_correction_preserves_identity_through_the_upstream_edge():
    """The moved case: the repository keeps its row (every finding and ref stays
    attached, so the fingerprints chain across the move), and the vacated URL's row
    carries the upstream link — the same edge the fork resolution reads — so anything
    still holding the old URL follows the edge to the repository."""
    harness, service, _, _, _sources = observer()
    from traust_core.v1.models.values import GitSha

    line = service.mark_default_branch(harness.repository_id, GitSha("a" * 40), "main")
    repository = _repository(service, harness.repository_id)
    old_url = repository.url
    moved = service.correct_repository_url(
        harness.repository_id, _url("https://github.com/moved/relocated")
    )
    assert moved.id == repository.id  # the identity: same row, same findings
    assert moved.url == "https://github.com/moved/relocated"
    # the subject chain survives: the default line the repository's runs work on
    assert line.id == service.inventory.default_line(harness.repository_id).id
    with service._uow as uow:
        tombstone = uow.repositories.find_by_url(old_url)
        assert tombstone is not None and tombstone.id is not None
        assert tombstone.upstream_id == repository.id  # the move's record
        # the fork resolution's own read of the edge: the vacated self is provably the
        # repository's own, and public — never a foreign or private push target
        mirror = service.inventory.private_mirror(repository.id)
        assert mirror is None or (mirror.id == tombstone.id and tombstone.public)


def test_the_url_correction_resets_the_streak_and_holds_the_disposition():
    harness, service, _, _, sources = observer()
    _set_source(service, sources, _gone())
    _observe(service, harness.repository_id, minutes=1)
    _observe(service, harness.repository_id, minutes=2)
    moved = service.correct_repository_url(
        harness.repository_id, _url("https://github.com/moved/relocated")
    )
    assert moved.disposition == RepositoryDisposition.REPO_UNREACHABLE  # holds: verify clears
    assert moved.gone_streak == 0  # the failures counted against the old URL die with it


def test_the_url_correction_refuses_an_occupied_destination():
    harness, service, _, _, _sources = observer()
    with service._uow as uow:
        other = uow.repositories.add(Repository(url="https://github.com/other/seat", public=True))
        uow.commit()
    with pytest.raises(ConflictError, match="already"):
        service.correct_repository_url(harness.repository_id, _url(str(other.url)))


def test_the_url_correction_is_idempotent_for_the_same_url():
    harness, service, _, _, _sources = observer()
    repository = _repository(service, harness.repository_id)
    again = service.correct_repository_url(harness.repository_id, _url(repository.url))
    assert again.id == repository.id and again.url == repository.url
    with service._uow as uow:
        assert uow.repositories.find_by_url(repository.url).id == repository.id


# The verify door -------------------------------------------------------------------------


def test_the_verify_clears_the_disposition_on_success():
    harness, service, _, _, sources = observer()
    swap = _SwappingSource(sources)
    swap.say(_gone())
    _observe(service, harness.repository_id, minutes=1)
    _observe(service, harness.repository_id, minutes=2)
    swap.say(
        {
            "ok": True,
            "pushed_at": "2026-10-01T12:00:00Z",
            "archived": False,
            "default_branch": "main",
            "visibility": "public",
            "fork": False,
            "parent": None,
        }
    )
    facts = service.verify_repository(harness.repository_id)
    assert facts.status in (ComparisonStatus.OK, ComparisonStatus.NEVER_AUDITED)
    repository = _repository(service, harness.repository_id)
    assert repository.disposition is None


def test_the_verify_holds_the_disposition_with_the_new_evidence():
    harness, service, _, _, sources = observer()
    swap = _SwappingSource(sources)
    swap.say(_gone(error="first 404"))
    _observe(service, harness.repository_id, minutes=1)
    _observe(service, harness.repository_id, minutes=2)
    swap.say(_gone(error="still 404"))
    service.verify_repository(harness.repository_id)
    repository = _repository(service, harness.repository_id)
    assert repository.disposition == RepositoryDisposition.REPO_UNREACHABLE
    assert repository.disposition_evidence == "still 404"


def test_the_verify_holds_untouched_on_a_transient_failure():
    harness, service, _, _, sources = observer()
    swap = _SwappingSource(sources)
    swap.say(_gone(error="the flip"))
    _observe(service, harness.repository_id, minutes=1)
    _observe(service, harness.repository_id, minutes=2)
    before = _repository(service, harness.repository_id)
    swap.say(_transient(error="a timeout"))
    facts = service.verify_repository(harness.repository_id)
    assert facts.status == ComparisonStatus.UNREACHABLE
    after = _repository(service, harness.repository_id)
    assert after.disposition == before.disposition
    assert after.disposition_evidence == before.disposition_evidence
    assert after.gone_streak == before.gone_streak


# The Qodo #474 rounds: the observation's own staging, the transient words, and the
# correction's downstream invariants.


def test_a_failed_later_read_never_clears_the_disposition():
    """The repository read answered (the repo is alive) but the branch read failed: the
    observation did not complete, so it is a failure — never a success that clears."""
    harness, service, _, _, sources = observer()
    swap = _SwappingSource(sources)
    swap.say(_gone())
    _observe(service, harness.repository_id, minutes=1)
    _observe(service, harness.repository_id, minutes=2)
    assert _repository(service, harness.repository_id).disposition is not None
    # info answers healthy, the head read times out: a failed observation.
    swap.say({**_healthy(), "head_error": "timed out", "head_kind": "unreachable"})
    _observe(service, harness.repository_id, minutes=3)
    repository = _repository(service, harness.repository_id)
    assert repository.disposition == RepositoryDisposition.REPO_UNREACHABLE
    assert repository.gone_streak == 2  # neither counted nor reset


def test_a_later_reads_transport_failure_never_counts_gone():
    """The repository read answered and a later read failed unreachable: the host was
    just there, so the failure says nothing repository-level — no flip across two."""
    harness, service, _, _, sources = observer()
    swap = _SwappingSource(sources)
    swap.say({**_healthy(), "head_error": "no route to host", "head_unreachable": True})
    _observe(service, harness.repository_id, minutes=1)
    _observe(service, harness.repository_id, minutes=2)
    repository = _repository(service, harness.repository_id)
    assert repository.disposition is None
    assert repository.gone_streak == 0


def test_the_github_empty_repository_flips_with_reason_empty():
    """GitHub reports a default branch for a repository with no commits; the branch read
    then answers 404/409 — the empty signature, not a transient error."""
    harness, service, _, _, sources = observer()
    swap = _SwappingSource(sources)
    swap.say({**_healthy(), "head_error": "Git Repository is empty", "head_empty": True})
    _observe(service, harness.repository_id, minutes=1)
    _observe(service, harness.repository_id, minutes=2)
    repository = _repository(service, harness.repository_id)
    assert repository.disposition == RepositoryDisposition.REPO_UNREACHABLE
    assert repository.disposition_reason == GoneReason.EMPTY


def test_the_flip_timestamp_survives_later_failed_verifies():
    """disposition_at records when the repository left the planner's universe, not when
    it was last seen gone: the refresh carries the reason and evidence, never the time."""
    harness, service, _, _, sources = observer()
    swap = _SwappingSource(sources)
    swap.say(_gone(error="the flip"))
    _observe(service, harness.repository_id, minutes=1)
    _observe(service, harness.repository_id, minutes=2)
    flipped = _repository(service, harness.repository_id)
    assert flipped.disposition_at is not None
    swap.say(_gone(error="still gone"))
    _observe(service, harness.repository_id, minutes=3)
    held = _repository(service, harness.repository_id)
    assert held.disposition_at == flipped.disposition_at
    assert held.disposition_evidence == "still gone"


def test_an_observation_for_a_vacated_url_counts_for_neither_side():
    """A correction landing mid-observation: the answer belongs to the URL the row no
    longer carries, so it neither counts nor clears."""
    harness, service, _, _, sources = observer()
    _set_source(service, sources, _gone())
    facts = service.record_forge_facts(repository_id=harness.repository_id)
    service.correct_repository_url(
        harness.repository_id, _url("https://github.com/moved/relocated")
    )
    # The in-flight observation lands after the correction committed.
    service._count_toward_disposition(harness.repository_id, facts, observed_url=facts.repo_url)
    repository = _repository(service, harness.repository_id)
    assert repository.url == "https://github.com/moved/relocated"
    assert repository.gone_streak == 0  # the correction reset it; the stale answer added nothing


def test_the_url_branch_applies_the_dispositioned_predicate():
    harness, service, _, _, sources = observer()
    _set_source(service, sources, _gone())
    _observe(service, harness.repository_id, minutes=1)
    _observe(service, harness.repository_id, minutes=2)
    url = _repository(service, harness.repository_id).url
    active = service.list_repositories(
        RepositoryFilter(url=url, dispositioned=False), PageRequest(limit=10)
    )
    gone = service.list_repositories(
        RepositoryFilter(url=url, dispositioned=True), PageRequest(limit=10)
    )
    assert active.items == ()
    assert [r.id for r in gone.items] == [harness.repository_id]


def test_the_tombstone_is_dispositioned_at_creation():
    """The vacated URL is known gone — the person just corrected away from it — so its
    row never re-enters the planner's universe to burn two observations proving it."""
    harness, service, _, _, _sources = observer()
    old_url = _repository(service, harness.repository_id).url
    service.correct_repository_url(
        harness.repository_id, _url("https://github.com/moved/relocated")
    )
    universe = service.list_repositories(
        RepositoryFilter(dispositioned=False), PageRequest(limit=100)
    )
    assert old_url not in {r.url for r in universe.items}
    tombstone = service.find_repository(old_url)
    assert tombstone is not None and tombstone.disposition == (
        RepositoryDisposition.REPO_UNREACHABLE
    )
    assert tombstone.disposition_reason == GoneReason.GONE
    assert tombstone.upstream_id == harness.repository_id


# The Qodo #474 second round: the undo, and the alias row set.


def test_a_mistaken_correction_can_be_undone_by_moving_back():
    """A correction back to the URL the repository vacated reclaims its own
    tombstone rather than conflicting with it: the repository returns home (where its
    findings' stamps match directly again), and the tombstone follows the URL being
    left — recording the new vacated one."""
    harness, service, _, _, _sources = observer()
    home = _repository(service, harness.repository_id).url
    service.correct_repository_url(harness.repository_id, _url("https://github.com/wrong/typo"))
    moved = _repository(service, harness.repository_id)
    assert moved.url == "https://github.com/wrong/typo"

    back = service.correct_repository_url(harness.repository_id, _url(home))
    assert back.id == harness.repository_id and back.url == home
    with service._uow as uow:
        # The tombstone followed the typo'd URL: it is vacated now.
        tombstone = uow.repositories.find_by_url("https://github.com/wrong/typo")
        assert tombstone is not None and tombstone.id is not None
        assert tombstone.upstream_id == harness.repository_id
        assert tombstone.disposition == RepositoryDisposition.REPO_UNREACHABLE
        assert home not in {
            row.url for row in uow.repositories.list_by_upstream(harness.repository_id)
        }
        # The undo left exactly one row at the home URL: the repository itself.
        assert uow.repositories.find_by_url(home).id == harness.repository_id


def test_prior_urls_answer_vacated_rows_not_forks():
    """The alias set is the correction's vacated-URL rows, recognized by the
    correction's own signature — a fork or mirror sharing the upstream edge is not a
    place the repository's findings were stamped."""
    harness, service, _, _, _sources = observer()
    repository = _repository(service, harness.repository_id)
    with service._uow.write() as uow:
        mirror = uow.repositories.get_or_add(
            Repository(url="https://github.com/example/mirror", public=False)
        )
        uow.repositories.update(mirror.model_copy(update={"upstream_id": repository.id}))
        uow.commit()
    assert service.inventory.prior_urls(harness.repository_id) == ()
    service.correct_repository_url(
        harness.repository_id, _url("https://github.com/moved/relocated")
    )
    prior = service.inventory.prior_urls(harness.repository_id)
    assert prior == (repository.url,)
