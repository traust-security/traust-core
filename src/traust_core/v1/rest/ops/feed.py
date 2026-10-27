from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from traust_core.v1.models.common import Cursor, Page, PageRequest
from traust_core.v1.models.operations import FeedEvent
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.ops.service import Feed

router = APIRouter()


@router.get("/v1/feed", responses=PROBLEMS(401, 422))
def read_feed(
    feed: Feed,
    _: Caller,
    after: Cursor | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> Page[FeedEvent]:
    """Stopped or finished orders, new assessments and recorded releases, oldest change first."""
    return feed.list(PageRequest(limit=limit, cursor=after))
