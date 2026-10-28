"""1 · Inventory repositories: natural-key lookups and the temporal ownership reads."""

from __future__ import annotations

from datetime import timedelta

import sqlalchemy as sa

from tests.v1.repositories.tables.conftest import (
    SHA,
    T0,
    Seed,
    apart,
    repository_for,
    same_rows,
)

B = "b" * 40


def test_lookups_by_natural_key(seed: Seed) -> None:
    u = seed.uow
    product = seed.product(slug="ocp")
    release = seed.release(product, version="4.22")
    repo = seed.repository(url="https://github.com/org/x")
    team = seed.team(name="core")
    assert u.products.find_by_slug("ocp") == product
    assert u.releases.find(product.id, "4.22") == release
    assert u.repositories.find_by_url("https://github.com/org/x") == repo
    assert u.teams.find_by_name("core") == team
    assert u.products.find_by_slug("nope") is None
    assert u.releases.find(product.id, "9.9") is None


def test_releases_and_components_list_by_parent(seed: Seed) -> None:
    u = seed.uow
    product, other = seed.product(), seed.product()
    r1, r2 = seed.release(product), seed.release(product)
    seed.release(other)
    ref = seed.repository_ref()
    c1, c2 = seed.component(r1, ref), seed.component(r2, ref)
    assert same_rows(u.releases.list_for_product(product.id), [r1, r2])
    assert u.components.list_for_release(r1.id) == [c1]
    assert same_rows(u.components.list_for_ref(ref.id), [c1, c2])
    assert u.components.find(r2.id, ref.id) == c2


def test_ref_lookup_separates_named_and_bare_commits(seed: Seed) -> None:
    u = seed.uow
    repo = seed.repository()
    main = seed.repository_ref(repo, name="main", sha=SHA)
    bare = seed.repository_ref(repo, name=None, kind=None, sha=B)
    assert u.repository_refs.find(repo.id, "main", SHA) == main
    assert u.repository_refs.find(repo.id, None, B) == bare
    assert u.repository_refs.find(repo.id, None, SHA) is None
    assert u.repository_refs.find(repo.id, "main", B) is None
    assert same_rows(u.repository_refs.list_for(repo.id), [main, bare])


def test_default_ref_is_the_latest_recorded_default(seed: Seed) -> None:
    u = seed.uow
    repo = seed.repository()
    assert u.repository_refs.default(repo.id) is None
    seed.repository_ref(repo, name="dev", sha=SHA)
    first = seed.repository_ref(repo, name="main", sha=SHA, is_default=True)
    assert u.repository_refs.default(repo.id) == first
    u.commit()  # a later scan, a later transaction
    apart()
    later = seed.repository_ref(repo, name="main", sha=B, is_default=True)
    assert u.repository_refs.default(repo.id) == later


def test_refs_carrying_a_manifest_sbom(seed: Seed) -> None:
    sbom = seed.sbom()
    ref = seed.repository_ref(manifest_sbom_id=sbom.id)
    seed.repository_ref()
    assert seed.uow.repository_refs.list_for_manifest_sbom(sbom.id) == [ref]


def test_ownership_current_and_as_of(seed: Seed) -> None:
    u = seed.uow
    repo, platform, core = seed.repository(), seed.team(), seed.team()
    day = timedelta(days=1)
    old = seed.ownership(repo, platform, valid_from=T0, valid_to=T0 + 10 * day)
    new = seed.ownership(repo, core, valid_from=T0 + 10 * day)
    assert u.ownerships.current(repo.id) == [new]
    assert u.ownerships.as_of(repo.id, T0 - day) == []
    assert u.ownerships.as_of(repo.id, T0) == [old]  # valid_from is inclusive
    assert u.ownerships.as_of(repo.id, T0 + 10 * day) == [new]  # valid_to is exclusive
    assert u.ownerships.list_for_team(platform.id) == [old]


def test_closing_ownership_moves_it_out_of_current(seed: Seed) -> None:
    u = seed.uow
    owned = seed.ownership()
    closed = u.ownerships.update(owned.model_copy(update={"valid_to": T0 + timedelta(days=3)}))
    assert u.ownerships.current(owned.repository_id) == []
    assert u.ownerships.as_of(owned.repository_id, T0 + timedelta(days=1)) == [closed]


def test_archived_is_unknown_until_observed(seed: Seed) -> None:
    repos = seed.uow.repositories
    unobserved, archived = seed.repository(), seed.repository(archived=True)
    assert repos.get(unobserved.id).archived is None
    assert repos.get(archived.id).archived is True
    assert repos.update(unobserved.model_copy(update={"archived": False})).archived is False


def test_products_list_by_slug_after_a_position(seed: Seed) -> None:
    u = seed.uow
    b, a, c = seed.product(slug="b"), seed.product(slug="a"), seed.product(slug="c")
    assert u.products.list_after(None, 2) == [a, b]
    assert u.products.list_after("b", 2) == [c]
    assert u.products.list_after("c", 2) == []


def test_a_private_mirror_is_a_non_public_fork(seed: Seed) -> None:
    upstream = seed.repository()
    assert seed.uow.repositories.find_private_mirror(upstream.id) is None
    seed.repository(upstream_id=upstream.id, public=True)
    mirror = seed.repository(upstream_id=upstream.id, public=False)
    seed.repository(public=False)
    assert seed.uow.repositories.find_private_mirror(upstream.id) == mirror
    assert seed.uow.repositories.find_private_mirror(mirror.id) is None


def test_feed_after_reads_releases_by_record_time_and_resumes_after_ties(seed: Seed) -> None:
    releases = seed.uow.releases
    assert releases.feed_after(None, 10) == []
    product = seed.product()
    late = seed.release(product)
    tied = [seed.release(product) for _ in range(3)]
    table = repository_for(seed.uow, "release").table
    seed.uow.connection.execute(
        sa.update(table)
        .where(table.c.id.in_([r.id for r in tied]))
        .values(created_at=T0 - timedelta(days=1))
    )
    rows = sorted(
        (r for r in releases.list_for_product(product.id) if r.id != late.id),
        key=lambda r: str(r.id),
    )
    assert releases.feed_after(None, 10) == [*rows, late]
    assert releases.feed_after(None, 2) == rows[:2]
    for i, row in enumerate(rows):
        assert row.created_at is not None and row.id is not None
        assert releases.feed_after((row.created_at, row.id), 10) == [*rows[i + 1 :], late]


def test_refs_list_by_id(seed: Seed) -> None:
    refs = seed.uow.repository_refs
    one, two = seed.repository_ref(), seed.repository_ref()
    seed.repository_ref()
    assert same_rows(refs.list_by_ids([one.id, two.id]), [one, two])  # type: ignore[list-item]
    assert refs.list_by_ids([]) == []


def test_repositories_list_by_id(seed: Seed) -> None:
    repositories = seed.uow.repositories
    one, two = seed.repository(), seed.repository()
    seed.repository()
    assert same_rows(repositories.list_by_ids([one.id, two.id]), [one, two])  # type: ignore[list-item]
    assert repositories.list_by_ids([]) == []
