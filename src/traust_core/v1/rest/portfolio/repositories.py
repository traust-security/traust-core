from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query
from pydantic import Field

from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import Cursor, Page, PageRequest
from traust_core.v1.models.inventory import (
    Product,
    RefName,
    Repository,
    RepositoryFilter,
    RepositoryRef,
    RepositoryResolution,
    SyncReport,
    Team,
    TeamName,
)
from traust_core.v1.models.observation import ForgeFacts
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import RefKind
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.portfolio.service import Person, Portfolio

router = APIRouter()

Sha = Annotated[str, Field(pattern=r"^[0-9a-f]{40}([0-9a-f]{24})?$")]

# A page's worth of repositories per request, the batch routes' own bound (the orders
# filter's `repository_ids` shape): a set larger than this is a scope decision the
# route refuses to carry as one expanding statement.
MAX_REPOSITORY_IDS = 500


class RefRegistration(Model):
    sha: Sha
    name: Annotated[RefName, Field(min_length=1, max_length=256)] | None = None
    kind: RefKind | None = None


class DefaultRefNaming(Model):
    """The forge's default-branch answer for a repository: the branch and its head."""

    branch: Annotated[RefName, Field(min_length=1, max_length=256)]
    sha: Sha


class RepositoryResolutionRequest(Model):
    """A set of repository URL spellings, any fold core's canonicalizer performs."""

    urls: tuple[Annotated[str, Field(min_length=1, max_length=2048)], ...]


class Owners(Model):
    teams: tuple[Annotated[TeamName, Field(min_length=1, max_length=256)], ...]


class UrlCorrection(Model):
    url: Annotated[str, Field(min_length=1, max_length=2048)]


class RepositoryVerification(Model):
    """One deliberate observation of a repository and the disposition it left behind: the
    console's verify button renders the outcome (the facts' status and error) beside the
    repository's disposition — cleared on success, held with the new evidence on a
    gone-class failure, untouched on a transient one."""

    facts: ForgeFacts
    repository: Repository


@router.get("/v1/repositories", responses=PROBLEMS(401, 422))
def list_repositories(
    portfolio: Portfolio,
    _: Caller,
    url: Annotated[str | None, Query(max_length=2048)] = None,
    dispositioned: Annotated[bool | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    cursor: Cursor | None = None,
) -> Page[Repository]:
    """Every repository, paged; with `url`, the one registered there (or none). With
    `dispositioned`: only the repositories carrying (true) or not carrying (false) the
    unreachable disposition — false is the planner's universe, true its remediation
    worklist."""
    return portfolio.list_repositories(
        RepositoryFilter(url=url, dispositioned=dispositioned),
        PageRequest(limit=limit, cursor=cursor),
    )


@router.get("/v1/repositories/{repository_id}", responses=PROBLEMS(401, 404))
def get_repository(repository_id: UUID, portfolio: Portfolio, _: Caller) -> Repository:
    return portfolio.get_repository(repository_id)


# The batch identity resolution: the repository universe answered per URL spelling
# in one call, a page's worth of spellings per request (no set is a refusal).
@router.post("/v1/repositories:resolve", responses=PROBLEMS(401, 422))
def resolve_repositories(
    body: RepositoryResolutionRequest, portfolio: Portfolio, _: Caller
) -> list[RepositoryResolution]:
    """Resolve repository URL spellings to the repositories core knows: each answer
    carries the repository's own id with the upstream edge as the hint when the matched
    row carries one, and a URL correction's vacated spelling follows its edge to the
    repository that moved. Drifted spellings (trailing slash, .git, git@ ssh, host
    case) fold through core's own canonicalizer; several rows under one case-folded
    spelling answer as candidates; an unregistered or unparseable spelling answers
    the honest absence."""
    if not body.urls:
        raise ValidationError("resolve named repository urls; the set is required")
    if len(body.urls) > MAX_REPOSITORY_IDS:
        raise ValidationError(f"resolve at most {MAX_REPOSITORY_IDS} repository urls per request")
    return portfolio.resolve_repositories(body.urls)


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


@router.post("/v1/repositories/{repository_id}/refs/default", responses=PROBLEMS(401, 409, 422))
def mark_default_branch(
    repository_id: UUID, body: DefaultRefNaming, portfolio: Portfolio, _: Caller
) -> RepositoryRef:
    """Name the repository's default branch: the forge's answer (the branch and its
    head commit) recorded the way the repo_state observation records it — the line
    added when absent, the default flag named anew when the answer moves (a named
    line is immutable once recorded). Every verified caller names one."""
    return portfolio.mark_default_branch(repository_id, GitSha.parse(body.sha), body.branch)


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


@router.put("/v1/repositories/{repository_id}/url", responses=PROBLEMS(401, 403, 404, 409, 422))
def correct_repository_url(
    repository_id: UUID, body: UrlCorrection, portfolio: Portfolio, _: Person
) -> Repository:
    """Correct a moved repository's URL (foundry plan repo-unreachable): the row keeps its
    identity — every finding stays attached, so the fingerprints survive the move — and the
    change is recorded as the upstream link on the vacated URL's row, the same edge the
    fork resolution reads. The disposition, if any, holds until the verify succeeds."""
    return portfolio.correct_repository_url(
        repository_id, HttpsRepoUrl.parse(body.url, portfolio.inventory.hosts)
    )


@router.post("/v1/repositories/{repository_id}/verify", responses=PROBLEMS(401, 403, 404, 422))
def verify_repository(
    repository_id: UUID, portfolio: Portfolio, _: Person
) -> RepositoryVerification:
    """The on-demand observation (foundry plan repo-unreachable): the same path the
    repo_state asset runs, exposed as the door the SCI API calls for the console's verify
    button. On success the disposition clears and the repository re-enters the planner's
    universe; on a gone-class failure it holds with the new evidence; a transient failure
    holds it untouched."""
    facts = portfolio.verify_repository(repository_id)
    return RepositoryVerification(facts=facts, repository=portfolio.get_repository(repository_id))


# The refs collection: every recorded ref of several repositories in one
# listing — the batched `list_refs`, read in bounded batches — so a consumer
# resolving each repository's refs (a scanned ref's SHA, a default line) reads
# one call per bounded set instead of one listing per repository. The batch
# findings listing's own shape (a collection narrowed by a query parameter);
# a page's worth of repository ids per call, and no ids is a refusal, never
# a firehose of every ref.
@router.get("/v1/refs", responses=PROBLEMS(401, 422))
def list_refs_for_repositories(
    portfolio: Portfolio, _: Caller, repository_ids: Annotated[list[UUID] | None, Query()] = None
) -> list[RepositoryRef]:
    if not repository_ids:
        raise ValidationError("list refs for named repositories; the set is required")
    if len(repository_ids) > MAX_REPOSITORY_IDS:
        raise ValidationError(
            f"list refs for at most {MAX_REPOSITORY_IDS} repositories per request"
        )
    return portfolio.inventory.list_refs_of(repository_ids)


@router.get("/v1/refs/{repository_ref_id}", responses=PROBLEMS(401, 404))
def get_ref(repository_ref_id: UUID, portfolio: Portfolio, _: Caller) -> RepositoryRef:
    return portfolio.inventory.get_ref(repository_ref_id)
