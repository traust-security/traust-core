from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query
from pydantic import Field

from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import Cursor, Page, PageRequest
from traust_core.v1.models.inventory import (
    Product,
    RefName,
    Repository,
    RepositoryFilter,
    RepositoryRef,
    SyncReport,
    Team,
    TeamName,
)
from traust_core.v1.models.values import GitSha
from traust_core.v1.models.vocabulary import RefKind
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.portfolio.service import Portfolio, Sync

router = APIRouter()

Sha = Annotated[str, Field(pattern=r"^[0-9a-f]{40}([0-9a-f]{24})?$")]


class RefRegistration(Model):
    sha: Sha
    name: Annotated[RefName, Field(min_length=1, max_length=256)] | None = None
    kind: RefKind | None = None


class BranchAttachment(Model):
    branch: Annotated[RefName, Field(min_length=1, max_length=256)]


class Owners(Model):
    teams: tuple[Annotated[TeamName, Field(min_length=1, max_length=256)], ...]


@router.get("/v1/repositories", responses=PROBLEMS(401, 422))
def list_repositories(
    portfolio: Portfolio,
    _: Caller,
    url: Annotated[str | None, Query(max_length=2048)] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    cursor: Cursor | None = None,
) -> Page[Repository]:
    """Every repository, paged; with `url`, the one registered there (or none)."""
    return portfolio.list_repositories(
        RepositoryFilter(url=url), PageRequest(limit=limit, cursor=cursor)
    )


@router.get("/v1/repositories/{repository_id}", responses=PROBLEMS(401, 404))
def get_repository(repository_id: UUID, portfolio: Portfolio, _: Caller) -> Repository:
    return portfolio.get_repository(repository_id)


@router.get("/v1/repositories/{repository_id}/refs", responses=PROBLEMS(401, 422))
def list_refs(
    repository_id: UUID, portfolio: Portfolio, _: Caller, sha: Sha | None = None
) -> list[RepositoryRef]:
    """The repository's refs; with `sha`, only that commit's."""
    return portfolio.inventory.list_refs(repository_id, sha)


@router.get("/v1/repositories/{repository_id}/refs/current-default", responses=PROBLEMS(401, 404))
def get_current_default_ref(repository_id: UUID, portfolio: Portfolio, _: Caller) -> RepositoryRef:
    ref = portfolio.current_default_ref(repository_id)
    if ref is None:
        raise NotFoundError(f"no current default ref for repository {repository_id}")
    return ref


@router.post("/v1/repositories/{repository_id}/refs", responses=PROBLEMS(401, 404, 422))
def register_ref(
    repository_id: UUID, body: RefRegistration, portfolio: Portfolio, _: Caller
) -> RepositoryRef:
    """Register a commit (and its branch or tag) of the repository; re-registering returns it."""
    return portfolio.register_ref(repository_id, GitSha.parse(body.sha), body.name, body.kind)


@router.post("/v1/repositories/{repository_id}/branches", responses=PROBLEMS(401, 404, 422))
def attach_branch(
    repository_id: UUID, body: BranchAttachment, sync: Sync, _: Caller
) -> RepositoryRef:
    """Attach a branch line to track: its current head is registered, and the repository's
    orders walk the line (the Snyk-style "scan this branch"). Re-attaching moves the line's
    ref to its current head."""
    return sync.attach_branch(repository_id, body.branch)


@router.get("/v1/repositories/{repository_id}/owners", responses=PROBLEMS(401, 404))
def list_owners(repository_id: UUID, portfolio: Portfolio, _: Caller) -> list[Team]:
    return portfolio.list_owners(repository_id)


@router.put("/v1/repositories/{repository_id}/owners", responses=PROBLEMS(401, 404, 422))
def set_owners(repository_id: UUID, body: Owners, portfolio: Portfolio, _: Caller) -> SyncReport:
    """Mirror the teams a source reports for the repository: new teams' ownership opens now, the
    rest closes now (`valid_from` / `valid_to`, so ownership stays queryable as of any time)."""
    return portfolio.set_owners(repository_id, body.teams)


@router.get("/v1/repositories/{repository_id}/products", responses=PROBLEMS(401, 404))
def list_products_of(repository_id: UUID, portfolio: Portfolio, _: Caller) -> list[Product]:
    return portfolio.list_products_of(repository_id)


@router.get("/v1/refs/{repository_ref_id}", responses=PROBLEMS(401, 404))
def get_ref(repository_ref_id: UUID, portfolio: Portfolio, _: Caller) -> RepositoryRef:
    return portfolio.inventory.get_ref(repository_ref_id)
